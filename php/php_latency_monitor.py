#!/usr/bin/python3
"""
php_latency_monitor.py

Measures end-to-end PHP request latency from php_request_startup to
php_request_shutdown, and captures the script filename for each request.
Works with FPM, CGI, and CLI binaries.

Run it when a server feels slow and you want to know which PHP scripts are
taking the time, without adding any instrumentation to the PHP code itself.

USAGE
-----
  sudo python3 php_latency_monitor.py
  sudo python3 php_latency_monitor.py --bin /usr/bin/php:cli:80
  sudo python3 php_latency_monitor.py --config /etc/bpf/php-bins.toml
  sudo python3 php_latency_monitor.py --threshold 500

FLAGS
-----
  --bin PATH:KIND:VER   Add a binary to monitor.
                        KIND is fpm, cgi, or cli.
                        VER is any integer (used as a label, e.g. 81 for PHP 8.1).
                        Repeat for multiple binaries.

  --config FILE         TOML file listing binaries to monitor.
                        See php-bins.toml.example for the format.

  --threshold MS        Only print requests slower than this many milliseconds.
                        Default: 0 (print everything).

  --no-color            Disable ANSI color output.

Both --bin and --config can be used together; entries are merged.
If neither is given, the built-in default (/usr/bin/php, kind=cli) is used.

REQUIREMENTS
------------
  python3-bcc  (dnf install python3-bcc)
  root / CAP_BPF privileges
  PHP binaries must exist on disk

CONFIG FILE FORMAT (TOML)
-------------------------
  [[binary]]
  path = "/usr/sbin/php-fpm"
  kind = "fpm"
  version = 81

  [[binary]]
  path = "/usr/bin/php"
  kind = "cli"
  version = 82
"""

# pylint: disable=missing-function-docstring

import sys
import os
import time
import pwd
import argparse

try:
    from bcc import BPF
except ImportError:
    print("[!] BCC Python bindings not found.  Install with:")
    print("      dnf install python3-bcc    # RHEL / AlmaLinux / Rocky")
    print("      apt install python3-bpfcc   # Debian / Ubuntu")
    sys.exit(1)

# TOML support: try the stdlib version (Python 3.11+) then fall back to
# the third-party tomllib/tomli package, then fall back to a minimal
# hand-rolled parser that only understands the [[binary]] table format
# used by this tool.
def _load_toml(path):
    try:
        import tomllib  # pylint: disable=import-outside-toplevel
        with open(path, "rb") as f:
            return tomllib.load(f)
    except ImportError:
        pass
    try:
        import tomli  # pylint: disable=import-outside-toplevel
        with open(path, "rb") as f:
            return tomli.load(f)
    except ImportError:
        pass
    result = {"binary": []}
    current = None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line == "[[binary]]":
                if current is not None:
                    result["binary"].append(current)
                current = {}
                continue
            if current is None:
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k == "version":
                    v = int(v)
                current[k] = v
    if current is not None:
        result["binary"].append(current)
    return result


# ---------------------------------------------------------------------------
# BPF C program
# ---------------------------------------------------------------------------

BPF_PREAMBLE = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <bcc/proto.h>

#define MAX_FN 256
struct fname_t { char s[MAX_FN]; };

struct data_t {
    u32  pid, tid;
    u64  start_ns, latency_ns;
    int  ret_status;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FN];
    u32  uid;
    int  version_id;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(start_times,      u32, u64);
BPF_HASH(script_filenames, u32, struct fname_t);
BPF_HASH(php_version_ids,  u32, int);
BPF_HASH(startup_set,      u32, int);

// FPM: the script filename comes back as the return value of a helper.
int probe_fpm_filename_ret(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    struct fname_t val = {};
    void *p = (void *)PT_REGS_RC(ctx);
    if (bpf_probe_read_user_str(val.s, sizeof(val.s), p) <= 1)
        return 0;
    script_filenames.update(&tid, &val);
    return 0;
}

// CGI: the full script path is passed as the second argument.
int probe_cgi_stream_opener(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    struct fname_t val = {};
    void *p = (void *)PT_REGS_PARM2(ctx);
    if (bpf_probe_read_user_str(val.s, sizeof(val.s), p) <= 1)
        return 0;
    script_filenames.update(&tid, &val);
    return 0;
}

// CLI: expand_filepath returns the absolute path.  Skip if a filename was
// already recorded by one of the other probes.
int probe_cli_expand_filepath_ret(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    if (script_filenames.lookup(&tid))
        return 0;
    struct fname_t val = {};
    void *ret = (void *)PT_REGS_RC(ctx);
    if (bpf_probe_read_user_str(val.s, sizeof(val.s), ret) <= 1)
        return 0;
    script_filenames.update(&tid, &val);
    return 0;
}
"""

# One startup probe per version ID.  Generated at runtime so each probe
# function has a unique name that BCC can attach independently.
STARTUP_TEMPLATE = """
int probe_request_startup_v{vid}(struct pt_regs *ctx)
{{
    u32 tid = bpf_get_current_pid_tgid();
    u64 ts  = bpf_ktime_get_ns();
    int one = 1, ver = {vid};
    start_times.update(&tid, &ts);
    php_version_ids.update(&tid, &ver);
    startup_set.update(&tid, &one);
    return 0;
}}
"""

BPF_SHUTDOWN = r"""
// Shutdown fires at the end of every PHP request lifecycle.
// Reads all the state stashed by the startup and filename probes,
// emits one event to userspace, then cleans up the BPF hash entries.
int probe_request_shutdown_ret(struct pt_regs *ctx)
{
    u32 tid   = bpf_get_current_pid_tgid();
    int *flag = startup_set.lookup(&tid);
    if (!flag || *flag != 1)
        goto cleanup;

    u64 *start = start_times.lookup(&tid);
    int *ver   = php_version_ids.lookup(&tid);
    if (!start || !ver)
        goto cleanup;

    struct data_t out = {};
    out.tid        = tid;
    out.pid        = bpf_get_current_pid_tgid() >> 32;
    out.start_ns   = *start;
    out.latency_ns = bpf_ktime_get_ns() - *start;
    out.ret_status = PT_REGS_RC(ctx);
    out.uid        = bpf_get_current_uid_gid();
    out.version_id = *ver;
    bpf_get_current_comm(out.comm, sizeof(out.comm));

    struct fname_t *fp = script_filenames.lookup(&tid);
    if (fp)
        bpf_probe_read_kernel(out.filename, sizeof(out.filename), fp->s);
    else
        bpf_probe_read_kernel_str(out.filename, sizeof(out.filename), "<unknown>");

    events.perf_submit(ctx, &out, sizeof(out));

cleanup:
    start_times.delete(&tid);
    script_filenames.delete(&tid);
    php_version_ids.delete(&tid);
    startup_set.delete(&tid);
    return 0;
}
"""

# ---------------------------------------------------------------------------
# Defaults: standard PHP binary location
# ---------------------------------------------------------------------------

DEFAULT_BINS = [
    ("/usr/bin/php", "cli", 0),
]

# ---------------------------------------------------------------------------
# ANSI color helpers
# ---------------------------------------------------------------------------

_COLOR = True

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


# pylint: disable=invalid-name
def RED(t):
    return _c("31;1", t)

def YELLOW(t):
    return _c("33;1", t)

def GREEN(t):
    return _c("32;1", t)

def BOLD(t):
    return _c("1", t)
# pylint: enable=invalid-name

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fmt_latency(ns):
    if ns < 1_000_000:
        return f"{ns / 1e6:.2f} ms"
    ms = ns / 1e6
    if ms < 1000:
        return f"{ms:.1f} ms"
    return f"{ms / 1000:.2f} s"


def parse_bin_arg(s):
    parts = s.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            f"Expected PATH:KIND:VER, e.g. /usr/bin/php:cli:80, got: {s}")
    path, kind, ver_str = parts
    kind = kind.strip().lower()
    if kind not in ("fpm", "cgi", "cli"):
        raise argparse.ArgumentTypeError(
            f"KIND must be fpm, cgi, or cli, got: {kind}")
    try:
        ver = int(ver_str)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"VER must be an integer, got: {ver_str}") from exc
    return (path, kind, ver)


def load_config(path):
    try:
        data = _load_toml(path)
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"[!] Could not read config file {path}: {e}")
        sys.exit(1)
    bins = []
    for entry in data.get("binary", []):
        try:
            bins.append((entry["path"], entry["kind"].lower(), int(entry["version"])))
        except (KeyError, ValueError) as e:
            print(f"[!] Skipping malformed config entry: {e}")
    return bins

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Measure PHP request latency using BPF uprobes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python3 php_latency_monitor.py\n"
            "  sudo python3 php_latency_monitor.py --bin /usr/bin/php:cli:80\n"
            "  sudo python3 php_latency_monitor.py --config /etc/bpf/php-bins.toml\n"
            "  sudo python3 php_latency_monitor.py --threshold 500 --no-color\n"
        ),
    )
    p.add_argument(
        "--bin", dest="bins", metavar="PATH:KIND:VER",
        type=parse_bin_arg, action="append", default=[],
        help="Binary to monitor: PATH:KIND:VER  (KIND = fpm|cgi|cli).  Repeatable.",
    )
    p.add_argument(
        "--config", metavar="FILE",
        help="TOML config file listing binaries to monitor.",
    )
    p.add_argument(
        "--threshold", metavar="MS", type=float, default=0.0,
        help="Only show requests slower than this many milliseconds (default: 0, show all).",
    )
    p.add_argument(
        "--no-color", dest="no_color", action="store_true",
        help="Disable ANSI color output.",
    )
    return p.parse_args()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    global _COLOR  # pylint: disable=global-statement
    args = parse_args()

    if args.no_color:
        _COLOR = False

    if os.geteuid() != 0:
        print("[!] Root privileges required (sudo).")
        sys.exit(1)

    # Build the list of binaries to monitor.
    # Priority: --bin flags + --config file; fall back to built-in defaults.
    bins = list(args.bins)
    if args.config:
        bins.extend(load_config(args.config))
    if not bins:
        bins = list(DEFAULT_BINS)

    # Deduplicate by path while preserving order.
    seen = set()
    deduped = []
    for entry in bins:
        if entry[0] not in seen:
            seen.add(entry[0])
            deduped.append(entry)
    bins = deduped

    # Collect unique version IDs to generate one startup probe per version.
    version_ids = sorted({ver for _, _, ver in bins})
    ver_labels  = {ver: f"php{ver}" for ver in version_ids}

    # Assemble and compile the BPF program.
    bpf_text = BPF_PREAMBLE
    for vid in version_ids:
        bpf_text += STARTUP_TEMPLATE.format(vid=vid)
    bpf_text += BPF_SHUTDOWN

    print("[*] Compiling BPF program...")
    try:
        b = BPF(text=bpf_text)
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"[!] BPF compile failed: {e}")
        sys.exit(1)
    print("    OK\n")

    # Attach probes.
    attached = 0
    for path, kind, vid in bins:
        if not os.path.isfile(path):
            print(f"[!] Not found, skipping: {path}")
            continue
        try:
            if kind == "fpm":
                b.attach_uretprobe(name=path, sym="fpm_php_script_filename",
                                   fn_name="probe_fpm_filename_ret")
            elif kind == "cgi":
                b.attach_uprobe(name=path, sym="php_plain_files_stream_opener",
                                fn_name="probe_cgi_stream_opener")
            else:
                b.attach_uretprobe(name=path, sym="expand_filepath",
                                   fn_name="probe_cli_expand_filepath_ret")

            b.attach_uprobe(name=path, sym="php_request_startup",
                            fn_name=f"probe_request_startup_v{vid}")
            b.attach_uretprobe(name=path, sym="php_request_shutdown",
                               fn_name="probe_request_shutdown_ret")

            print(f"[+] Attached: {path} ({kind}, label={ver_labels[vid]})")
            attached += 1
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"[!] Failed to attach {path}: {e}")

    if attached == 0:
        print("[!] No probes attached.  Nothing to trace.")
        sys.exit(1)

    thresh_ns = int(args.threshold * 1_000_000)
    print()
    if thresh_ns > 0:
        print(f"[*] Threshold: only showing requests >= {args.threshold:.1f} ms")
    print("[*] Tracing PHP request latency...  Ctrl-C to stop.\n")

    print(BOLD(
        f"{'TIME':<9} {'VERSION':<10} {'PID':<6} {'COMM':<16}"
        f" {'LATENCY':<10} {'USER':<10} {'RESULT':<7} SCRIPT"
    ))

    def handle_event(_cpu, data, _size):
        e = b["events"].event(data)

        if thresh_ns > 0 and e.latency_ns < thresh_ns:
            return

        try:
            user = pwd.getpwuid(e.uid).pw_name
        except KeyError:
            user = str(e.uid)

        ts      = time.strftime("%H:%M:%S", time.localtime(e.start_ns // 1_000_000_000))
        ver     = ver_labels.get(e.version_id, f"php{e.version_id}")
        lat_str = fmt_latency(e.latency_ns)
        script  = e.filename.decode(errors="replace")
        comm    = e.comm.decode(errors="replace")

        if e.ret_status == 0:
            result = GREEN("OK")
        else:
            result = RED("FAIL")

        lat_ms = e.latency_ns / 1e6
        if lat_ms >= 2000:
            lat_colored = RED(lat_str)
        elif lat_ms >= 500:
            lat_colored = YELLOW(lat_str)
        else:
            lat_colored = lat_str

        print(
            f"{ts:<9} {ver:<10} {e.pid:<6d} {comm:<16}"
            f" {lat_colored:<18} {user:<10} {result:<14} {script}"
        )

    b["events"].open_perf_buffer(handle_event)

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\n[*] Detaching probes.")


if __name__ == "__main__":
    main()
