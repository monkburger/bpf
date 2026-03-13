#!/usr/bin/env python3

import argparse
import os
import re
import sys
from datetime import datetime
from bcc import BPF
import subprocess
import textwrap
from typing import Any, Optional, Tuple


class MySQLQueryMonitor:
    BPF_PROGRAM = textwrap.dedent("""
    #include <uapi/linux/ptrace.h>
    #define DURATION_THRESHOLD %(duration_threshold)d

    struct data_t {
        u64 timestamp;
        u64 execution_time;
        char query[256];
        u64 query_length;
        u8 is_truncated;
    };

    BPF_HASH(temp_data, u32, struct data_t);
    BPF_PERF_OUTPUT(events);

    #define QUERY_STRING_OFFSET %(query_string_offset)d
    #define QUERY_LENGTH_OFFSET %(query_length_offset)d

    int start_trace(struct pt_regs *ctx) {
        u32 thread_id = bpf_get_current_pid_tgid();
        struct data_t data = {};
        data.timestamp = bpf_ktime_get_ns();

        void* thd_addr = (void*) PT_REGS_PARM1(ctx);
        void* query_addr;

        bpf_probe_read_user(&data.query_length, sizeof(data.query_length), thd_addr + QUERY_LENGTH_OFFSET);
        bpf_probe_read_user(&query_addr, sizeof(query_addr), thd_addr + QUERY_STRING_OFFSET);

        data.is_truncated = data.query_length > sizeof(data.query);
        bpf_probe_read_user_str(&data.query, sizeof(data.query), query_addr);

        temp_data.update(&thread_id, &data);
        return 0;
    }

    int end_trace(struct pt_regs *ctx) {
        u32 thread_id = bpf_get_current_pid_tgid();
        struct data_t* data = temp_data.lookup(&thread_id);
        if (!data) return 0;

        data->execution_time = bpf_ktime_get_ns() - data->timestamp;
        if (data->execution_time >= DURATION_THRESHOLD) {
            events.perf_submit(ctx, data, sizeof(*data));
        }

        temp_data.delete(&thread_id);
        return 0;
    }
    """)

    def __init__(self, mysql_path: str, duration_threshold_ms: int, pid: int, log_file: Optional[str]):
        self.duration_threshold_ns = duration_threshold_ms * 1_000_000
        self.mysql_path = mysql_path
        self.pid = pid
        self.log_file = log_file
        self.mysql_version = None
        self.output = None

        self._ensure_mysql_path_exists()
        self._ensure_pid_exists()
        self._get_mysql_version()
        self._initialize_bpf()

    def _ensure_mysql_path_exists(self) -> None:
        if not os.path.isfile(self.mysql_path):
            raise FileNotFoundError(
                f"MySQL binary not found at path: {self.mysql_path}")

    def _ensure_pid_exists(self) -> None:
        if not os.path.exists(f"/proc/{self.pid}"):
            raise ProcessLookupError(f"No process found with PID {self.pid}")

    def _get_mysql_version(self) -> str:
        try:
            result = subprocess.run(
                [self.mysql_path, "--version"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True  # Compatible with Python 3.6
            )
            version_str = result.stdout
            match = re.search(r"\b(8\.4|8\.0|5\.7)\b", version_str)
            if match:
                self.mysql_version = match.group(0)
                print(
                    f"Detected MySQL version {self.mysql_version} (Using offsets {self._determine_offsets()})")
            else:
                raise NotImplementedError(
                    f"Unsupported MySQL version detected: {version_str}")
        except subprocess.CalledProcessError as e:
            sys.exit(f"Failed to retrieve MySQL version: {e}")

    def _determine_offsets(self) -> Tuple[int, int]:
        version_offsets = {
            "8.4": (1296, 1304),
            "8.0": (1296, 1304),
            "5.7": (472, 480),
        }
        return version_offsets.get(self.mysql_version, (0, 0))

    def _initialize_bpf(self) -> None:
        query_string_offset, query_length_offset = self._determine_offsets()
        bpf_program = self.BPF_PROGRAM % {
            "duration_threshold": self.duration_threshold_ns,
            "query_string_offset": query_string_offset,
            "query_length_offset": query_length_offset,
        }
        self.bpf = BPF(text=bpf_program)

        for func_name, _ in set(BPF.get_user_functions_and_addresses(self.mysql_path, r"\w+mysql_execute_command\w+")):
            self.bpf.attach_uprobe(name=self.mysql_path,
                                   sym=func_name, fn_name="start_trace")
            self.bpf.attach_uretprobe(
                name=self.mysql_path, sym=func_name, fn_name="end_trace")

    def format_event(self, event: Any) -> str:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        execution_time_ms = event.execution_time / 1e6
        query_text = event.query.decode('utf-8', 'replace').strip()
        truncated = "Yes" if event.is_truncated else "No"
        return (
            f"{timestamp:<23} | Execution Time: {execution_time_ms:>7.2f} ms | "
            f"Length: {event.query_length:<8} | Truncated: {truncated:<12} | Query: {query_text}"
        )

    def handle_event(self, cpu: int, data: bytes, size: int) -> None:
        event = self.bpf["events"].event(data)
        formatted_event = self.format_event(event)
        if self.output:
            self.output.write(formatted_event + "\n")
            self.output.flush()
        else:
            print(formatted_event)

    def run(self) -> None:
        if self.log_file:
            with open(self.log_file, "a") as self.output:
                self._start_monitoring()
        else:
            self._start_monitoring()

    def _start_monitoring(self) -> None:
        self.bpf["events"].open_perf_buffer(self.handle_event, page_cnt=64)
        print("Monitoring MySQL queries... Press Ctrl+C to stop.")
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nStopping MySQL Query Monitor.")

    @staticmethod
    def parse_args() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description="Trace MySQL queries using BPF uprobes.")
        parser.add_argument(
            "-p", "--path", default="/usr/sbin/mysqld", help="Path to the MySQL binary")
        parser.add_argument("-d", "--duration-threshold", type=int,
                            default=0, help="Minimum query duration to log (in ms)")
        parser.add_argument("-l", "--log", type=str,
                            help="Path to the log file for storing output")
        parser.add_argument("pid", nargs="?", type=int,
                            default=1, help="PID of the MySQL server")
        return parser.parse_args()


if __name__ == "__main__":
    args = MySQLQueryMonitor.parse_args()
    monitor = MySQLQueryMonitor(
        mysql_path=args.path,
        duration_threshold_ms=args.duration_threshold,
        pid=args.pid,
        log_file=args.log
    )
    monitor.run()
