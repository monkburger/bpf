#!/usr/bin/env python3
"""
nginx_upstream_latency.py  --  BETA

Traces nginx upstream request latency using BCC uprobes.  Hooks directly into
the nginx binary, so no config changes or restarts are needed.  All nginx
worker processes are covered at once.


STATUS: BETA
------------
This was developed and tested on AlmaLinux 9 / RHEL 9 with nginx 1.20.x.
It probably has bugs, and there's at least one known hard-coded struct offset
(U_OFF_STATE = 0x420) that was verified against one specific build and may
be wrong on a different nginx version or distro package.  If you're seeing
garbage latency numbers, that offset is the first thing to check.  In general,
if this disagrees with nginx's own $upstream_response_time logs, trust nginx.


HOW IT WORKS
------------
Two uprobes attach to the nginx binary:

  ngx_http_upstream_connect(r, u)
    Fires on every upstream attempt, whether it's a fresh TCP connection or
    a keepalive reuse.  Records a BPF timestamp in a hash map keyed by
    (pid, upstream_pointer).  On a retry, refreshes the timestamp.

  ngx_http_upstream_finalize_request(r, u, rc)
    Fires when nginx is done with the upstream request, for any reason
    (success, error, timeout).  Looks up the stored timestamp, computes
    wall-clock latency, reads nginx's own per-request timing from u->state,
    and emits an event to user space.

The peer server name is read from u->state->peer in the finalize probe, not
at connect entry.  This matters because peer.get() (which sets u->peer.name)
runs inside ngx_http_upstream_connect, AFTER our entry probe fires.  Reading
the name from u->state->peer instead sidesteps that race.


KEEPALIVE UPSTREAMS
-------------------
If upstream keepalives are on, the CONNECT column will always be 0 for
reused connections.  This is expected, not a bug.

For a keepalive cache hit, the keepalive module's peer.get() returns NGX_DONE
instead of NGX_OK, which means nginx's connect loop skips the TCP handshake
and calls ngx_http_upstream_send_request() almost immediately.  The connect_time
field in u->state is set inside send_request as:

    connect_time = ngx_current_msec - u->start_time

Since u->start_time was just set and there was no wait, this rounds to 0.
This matches what nginx's own $upstream_connect_time variable reports.

The overall wall-clock latency (TOTAL column) is still accurate for keepalive
connections.  It measures the full upstream request cycle from nginx's point
of view: from the connect call until finalize_request.


SYMBOL RESOLUTION
-----------------
The probe functions are static/LTO-compiled in packaged nginx builds and
aren't in the normal .dynsym symbol table.  RHEL/AlmaLinux packages embed a
.gnu_debugdata section in the binary: a tiny xz-compressed ELF with just a
symbol table.  At startup, this script unpacks that section and reads the
exact symbol names (e.g. ngx_http_upstream_finalize_request.lto_priv.0),
then passes them to BCC's attach_uprobe(sym=...) so BCC's own libelf does
the address lookup.  No addresses are hard-coded.

If there's no .gnu_debugdata (non-RHEL builds, custom compiles), the script
falls back to the plain undecorated names, which works on non-LTO builds.


STRUCT OFFSETS
--------------
Most field offsets are computed at startup from ctypes models of the nginx
structs.  The one exception is U_OFF_STATE = 0x420, the offset of u->state
inside ngx_http_upstream_t.  That struct is large and its layout depends on
many compile-time flags (NGX_HTTP_CACHE, NGX_HTTP_SSL, NGX_COMPAT, etc.),
so it can't be modeled with ctypes without knowing the exact build config.
Instead, 0x420 was verified from objdump disassembly of one specific build.


USAGE
-----
  sudo python3 nginx_upstream_latency.py
  sudo python3 nginx_upstream_latency.py --nginx /usr/sbin/nginx
  sudo python3 nginx_upstream_latency.py --threshold 100
  sudo python3 nginx_upstream_latency.py --interval 5
  sudo python3 nginx_upstream_latency.py --no-color


FLAGS
-----
  --nginx PATH     Path to nginx binary (default: auto-detect)
  --threshold MS   Only show requests slower than MS milliseconds
                   (default: 0, show all)
  --interval SEC   Print a per-peer summary every SEC seconds
                   (default: 0, only on exit)
  --no-color       Disable ANSI color output


REQUIREMENTS
------------
  python3-bcc          dnf install python3-bcc
  root privileges      or CAP_BPF + CAP_PERFMON
  .gnu_debugdata       standard in RHEL/AlmaLinux nginx packages
  Linux >= 5.8         needed for BPF_RINGBUF_OUTPUT and bpf_probe_read_user
"""

# pylint: disable=missing-function-docstring

import sys
import os
import time
import shutil
import signal
import subprocess
import tempfile
import argparse
import ctypes as ct
from collections import defaultdict

try:
    from bcc import BPF
except ImportError:
    print("[!] BCC Python bindings not found.  Install with:")
    print("      dnf install python3-bcc    # RHEL / AlmaLinux / Rocky")
    print("      apt install python3-bpfcc   # Debian / Ubuntu")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────────
# Probe symbol discovery
# ──────────────────────────────────────────────────────────────────────────────

def _debugdata_sym_names(nginx_bin):
    # type: (str) -> list
    """
    Returns all symbol names found in the .gnu_debugdata section of the nginx
    binary, or an empty list if the section is missing or the tools aren't
    available (objcopy, xz, nm are all needed).
    """
    tmpdir = tempfile.mkdtemp(prefix="ngx_bpf_")
    try:
        nginx_copy = os.path.join(tmpdir, "nginx")
        xz_path    = os.path.join(tmpdir, "dbgdata.xz")
        elf_path   = os.path.join(tmpdir, "dbgdata")

        shutil.copy2(nginx_bin, nginx_copy)

        r = subprocess.run(
            ["objcopy", "--dump-section",
             ".gnu_debugdata=" + xz_path, nginx_copy],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            check=False,
        )
        if r.returncode != 0 or not os.path.isfile(xz_path):
            return []

        r = subprocess.run(
            ["xz", "-d", xz_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            check=False,
        )
        if r.returncode != 0 or not os.path.isfile(elf_path):
            return []

        r = subprocess.run(
            ["nm", elf_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=15,
            check=False,
        )
        if r.returncode != 0:
            return []

        names = []
        for line in r.stdout.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3:
                names.append(parts[2])
        return names

    except Exception:  # pylint: disable=broad-exception-caught
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _find_probe_syms(nginx_bin):
    # type: (str) -> tuple
    """
    Returns (connect_sym, finalize_sym): the exact symbol names to hand to
    BCC's attach_uprobe(sym=...).

    LTO builds decorate static functions with a .lto_priv.N suffix (e.g.
    ngx_http_upstream_finalize_request.lto_priv.0), and BCC needs the exact
    decorated name.  We get it from .gnu_debugdata.  Falls back to the plain
    name if extraction fails, which works on non-LTO builds.
    """
    connect_sym  = "ngx_http_upstream_connect"
    finalize_sym = "ngx_http_upstream_finalize_request"

    for name in _debugdata_sym_names(nginx_bin):
        if name == "ngx_http_upstream_connect":
            connect_sym = name
        elif (name == "ngx_http_upstream_finalize_request"
              or name.startswith("ngx_http_upstream_finalize_request.")):
            finalize_sym = name

    return connect_sym, finalize_sym


def find_nginx_binary():
    # type: () -> str
    candidates = [
        "/usr/sbin/nginx",
        "/usr/local/sbin/nginx",
        "/usr/local/nginx/sbin/nginx",
        "/opt/nginx/sbin/nginx",
    ]
    try:
        r = subprocess.run(
            ["which", "nginx"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=5,
            check=False,
        )
        p = r.stdout.strip()
        if p:
            candidates.insert(0, p)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    for c in candidates:
        if os.path.isfile(c):
            return c
    return ""


# ──────────────────────────────────────────────────────────────────────────────
# Nginx struct offset computation
# ──────────────────────────────────────────────────────────────────────────────

def _compute_nginx_offsets():
    # type: () -> dict
    """
    Computes BPF struct field offsets from ctypes models of the nginx structs.
    Most of these are straightforward sequential 8-byte fields.  The only
    offset NOT computed here is U_OFF_STATE (the offset of u->state inside
    ngx_http_upstream_t), which is hard-coded as 0x420 because that struct
    is too large and build-config-dependent to model with ctypes.
    """
    # ngx_peer_connection_t (x86-64)
    #   connection  ptr   +0
    #   sockaddr    ptr   +8
    #   socklen     u32   +16  (4 bytes, then 4 bytes padding before next ptr)
    #   name        ptr   +24  (ngx_str_t *)
    class _NgxPeerConn(ct.Structure):  # pylint: disable=too-few-public-methods
        _fields_ = [
            ("connection", ct.c_void_p),
            ("sockaddr",   ct.c_void_p),
            ("socklen",    ct.c_uint32),
            ("_pad",       ct.c_uint32),
            ("name",       ct.c_void_p),
        ]

    # ngx_http_upstream_state_t: every field is 8 bytes (ngx_uint_t,
    # ngx_msec_t, off_t, or pointer), so no padding anywhere.
    # Full layout from ngx_http_upstream.h:
    #   status, response_time, connect_time, header_time, queue_time,
    #   response_length, bytes_received, bytes_sent, peer (ptr)
    class _NgxUpstreamState(ct.Structure):  # pylint: disable=too-few-public-methods
        _fields_ = [
            ("status",          ct.c_uint64),
            ("response_time",   ct.c_uint64),
            ("connect_time",    ct.c_uint64),
            ("header_time",     ct.c_uint64),
            ("queue_time",      ct.c_uint64),
            ("response_length", ct.c_int64),
            ("bytes_received",  ct.c_int64),
            ("bytes_sent",      ct.c_int64),
            ("peer_ptr",        ct.c_void_p),   # ngx_str_t * peer
        ]

    # ngx_http_upstream_t starts with two fn-pointer fields, then the inline
    # ngx_peer_connection_t.  So U_OFF_PEER_NAME = 2*ptr + offsetof(peer, name).
    upstream_peer_base = 2 * ct.sizeof(ct.c_void_p)

    return {
        "U_OFF_PEER_NAME":  upstream_peer_base + _NgxPeerConn.name.offset,
        "STATE_CONNECT_MS": _NgxUpstreamState.connect_time.offset,
        "STATE_HEADER_MS":  _NgxUpstreamState.header_time.offset,
        "STATE_BYTES_RX":   _NgxUpstreamState.bytes_received.offset,
        "STATE_PEER_PTR":   _NgxUpstreamState.peer_ptr.offset,
    }


# ──────────────────────────────────────────────────────────────────────────────
# BPF C program
# ──────────────────────────────────────────────────────────────────────────────

# The BPF offsets (#defines) are prepended by _make_bpf_program() at load
# time.  Keeping the body as a plain raw string means Python never tries to
# expand the C struct braces as format placeholders.
BPF_BODY = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_PEER 64

/*
 * Map key.  We use (pid, u_ptr) instead of just u_ptr because separate
 * nginx worker processes have separate address spaces and can reuse the
 * same virtual address for different requests.
 */
struct req_key_t {
    u32 pid;
    u32 _pad;
    u64 u_ptr;
};

/* Just the connect timestamp.  Peer name is read later in probe_finalize. */
struct inflight_t {
    u64 start_ns;
};

/*
 * Event pushed to user space.  connect_ms / header_ms / bytes_received come
 * from nginx's own per-request state struct (millisecond granularity).
 * If nginx hadn't written them yet when finalize fires (fast error paths),
 * those fields will be 0.
 */
struct event_t {
    u32  pid;
    u32  _pad;
    char comm[16];
    char peer[MAX_PEER];
    u8   peer_len;
    u64  latency_ns;
    s64  rc;           /* HTTP status code, or a negative nginx error code */
    u64  connect_ms;
    u64  header_ms;
    u64  bytes_received;
};

BPF_HASH(inflight, struct req_key_t, struct inflight_t, 65536);
/*
 * BPF_RINGBUF_OUTPUT is preferred over BPF_PERF_OUTPUT on Linux ≥ 5.8:
 * the buffer is shared across all CPUs (single allocation, not per-CPU),
 * and has lower latency.  16 pages = 64 KB.
 */
BPF_RINGBUF_OUTPUT(events, 16);

/*
 * Struct field offsets prepended as #defines by _make_bpf_program().
 * See _compute_nginx_offsets() in the Python code for how they are derived.
 *
 *   U_OFF_PEER_NAME   offset of u->peer.name (ngx_str_t *) from upstream base
 *   U_OFF_STATE       offset of u->state inside ngx_http_upstream_t (0x420,
 *                     hard-coded from disassembly -- varies by build)
 *   STATE_CONNECT_MS  connect_time field offset in ngx_http_upstream_state_t
 *   STATE_HEADER_MS   header_time field offset
 *   STATE_BYTES_RX    bytes_received field offset
 *   STATE_PEER_PTR    peer (ngx_str_t *) pointer, last field at offset +64
 */

/*
 * ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)
 *
 * Called once per upstream attempt (retries call it again too).  Just records
 * the BPF start timestamp.  On a retry we overwrite it so we measure the last
 * attempt, not the first.
 *
 * We do NOT read the peer name here.  peer.get() (which sets u->peer.name)
 * runs inside this function, after our entry probe fires.  At entry, the name
 * pointer is still NULL.  We read it from u->state->peer in probe_finalize
 * instead, where it's guaranteed to be set.
 */
int probe_connect(struct pt_regs *ctx)
{
    u64 u_ptr = PT_REGS_PARM2(ctx);
    if (!u_ptr) return 0;

    struct req_key_t key = {};
    key.pid   = bpf_get_current_pid_tgid() >> 32;
    key.u_ptr = u_ptr;

    struct inflight_t *existing = inflight.lookup(&key);
    if (existing) {
        /* Retry: just refresh the timestamp. */
        existing->start_ns = bpf_ktime_get_ns();
        return 0;
    }

    struct inflight_t val = {};
    val.start_ns = bpf_ktime_get_ns();
    inflight.update(&key, &val);
    return 0;
}

/*
 * probe_finalize -- entry of ngx_http_upstream_finalize_request(r, u, rc)
 *
 * Fires when nginx is done with the upstream request (success, error,
 * timeout -- everything).  Computes wall-clock latency, reads nginx's own
 * timing from u->state, and reads the peer name from u->state->peer.
 *
 * Reading peer name here rather than at connect entry is intentional:
 * nginx sets u->state->peer = u->peer.name inside ngx_http_upstream_connect,
 * after peer.get() has run.  The name is reliably set by the time we get
 * here.  On early error paths (NGX_ERROR before state->peer is assigned)
 * the peer will show as empty, which is fine.
 *
 * Keepalive note: for reused connections, connect_ms will be 0 or near-0.
 * That's correct -- there was no TCP handshake wait.
 */
int probe_finalize(struct pt_regs *ctx)
{
    u64 u_ptr = PT_REGS_PARM2(ctx);
    if (!u_ptr) return 0;

    struct req_key_t key = {};
    key.pid   = bpf_get_current_pid_tgid() >> 32;
    key.u_ptr = u_ptr;

    struct inflight_t *val = inflight.lookup(&key);
    if (!val) return 0;

    u64 now     = bpf_ktime_get_ns();
    u64 latency = now - val->start_ns;

    u64 connect_ms = 0, header_ms = 0, bytes_rx = 0;
    char peer[MAX_PEER] = {};
    u8   peer_len = 0;

    u64 state_ptr = 0;
    bpf_probe_read_user(&state_ptr, sizeof(state_ptr),
                        (void *)(u_ptr + U_OFF_STATE));
    if (state_ptr) {
        u64 ct = 0, ht = 0;
        bpf_probe_read_user(&ct, sizeof(ct),
                            (void *)(state_ptr + STATE_CONNECT_MS));
        bpf_probe_read_user(&ht, sizeof(ht),
                            (void *)(state_ptr + STATE_HEADER_MS));
        bpf_probe_read_user(&bytes_rx, sizeof(bytes_rx),
                            (void *)(state_ptr + STATE_BYTES_RX));
        /* nginx leaves these at (ngx_msec_t)-1 until it fills them in. */
        if (ct != (u64)-1) connect_ms = ct;
        if (ht != (u64)-1) header_ms  = ht;

        /* Read peer name from u->state->peer (ngx_str_t * at STATE_PEER_PTR). */
        u64 peer_nstr = 0;
        bpf_probe_read_user(&peer_nstr, sizeof(peer_nstr),
                            (void *)(state_ptr + STATE_PEER_PTR));
        if (peer_nstr) {
            u64 slen = 0, sdata = 0;
            bpf_probe_read_user(&slen,  sizeof(slen),  (void *)peer_nstr);
            bpf_probe_read_user(&sdata, sizeof(sdata), (void *)(peer_nstr + 8));
            if (slen > 0 && sdata) {
                peer_len = (u8)(slen < (MAX_PEER - 1) ? slen : (MAX_PEER - 1));
                bpf_probe_read_user(peer, peer_len, (void *)sdata);
            }
        }
    }

    struct event_t ev = {};
    ev.pid        = key.pid;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    __builtin_memcpy(ev.peer, peer, MAX_PEER);
    ev.peer_len       = peer_len;
    ev.latency_ns     = latency;
    ev.rc             = (s64)PT_REGS_PARM3(ctx);
    ev.connect_ms     = connect_ms;
    ev.header_ms      = header_ms;
    ev.bytes_received = bytes_rx;

    events.ringbuf_output(&ev, sizeof(ev), 0);
    inflight.delete(&key);
    return 0;
}
"""


def _make_bpf_program(offsets):
    # type: (dict) -> str
    """
    Glues the computed #defines onto the front of BPF_BODY.  Keeping the
    body as a raw string means Python's str.format() never touches the C
    braces.
    """
    lines = [
        f"#define U_OFF_PEER_NAME   {offsets['U_OFF_PEER_NAME']}",
        "/* U_OFF_STATE hard-coded from disassembly -- see module docstring */",
        "#define U_OFF_STATE       0x420",
        f"#define STATE_CONNECT_MS  {offsets['STATE_CONNECT_MS']}",
        f"#define STATE_HEADER_MS   {offsets['STATE_HEADER_MS']}",
        f"#define STATE_BYTES_RX    {offsets['STATE_BYTES_RX']}",
        f"#define STATE_PEER_PTR    {offsets['STATE_PEER_PTR']}",
        "",
    ]
    return "\n".join(lines) + BPF_BODY

# ──────────────────────────────────────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────────────────────────────────────

ANSI_RESET  = "\033[0m"
ANSI_BOLD   = "\033[1m"
ANSI_RED    = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_GREEN  = "\033[32m"
ANSI_CYAN   = "\033[36m"
ANSI_DIM    = "\033[2m"

_color_enabled = True  # pylint: disable=invalid-name


def _c(code, text):
    return code + text + ANSI_RESET if _color_enabled else text


def _fmt_bytes(n):
    if n >= 1_048_576:
        return f"{n / 1_048_576:.1f}M"
    if n >= 1_024:
        return f"{n / 1_024:.1f}K"
    return f"{n}B"


def _fmt_latency(ns):
    """Return a human-readable latency string from nanoseconds."""
    ms = ns / 1_000_000
    if ms >= 1000:
        return f"{ms / 1000:.2f}s"
    if ms >= 1:
        return f"{ms:.2f}ms"
    return f"{ns / 1000:.1f}µs"


def _latency_color(ns):
    ms = ns / 1_000_000
    if ms >= 500:
        return ANSI_RED
    if ms >= 100:
        return ANSI_YELLOW
    return ANSI_GREEN


def _rc_label(rc):
    """Map an ngx_http_upstream_finalize_request 'rc' value to a short label."""
    if rc == 0:
        return "OK"
    if 100 <= rc <= 599:
        return str(rc)
    # Common nginx error codes
    _ngx_errors = {
        -1:  "ERR",
        -2:  "AGAIN",
        -3:  "BUSY",
        -4:  "DONE",
        -5:  "DECLINED",
        -6:  "ABORT",
    }
    return _ngx_errors.get(rc, f"rc={rc}")


# ──────────────────────────────────────────────────────────────────────────────
# Per-peer statistics (accumulated in user-space)
# ──────────────────────────────────────────────────────────────────────────────

class PeerStats:
    """Accumulates latency statistics for a single upstream peer."""

    __slots__ = ("count", "errors", "total_ns", "min_ns", "max_ns",
                 "buckets")

    # Exponential histogram: each bucket i covers [2^i µs, 2^(i+1) µs).
    NUM_BUCKETS = 32

    def __init__(self):
        self.count   = 0
        self.errors  = 0
        self.total_ns = 0
        self.min_ns  = 2**63
        self.max_ns  = 0
        self.buckets = [0] * self.NUM_BUCKETS

    def record(self, latency_ns, is_error):
        self.count += 1
        if is_error:
            self.errors += 1
        self.total_ns += latency_ns
        self.min_ns = min(self.min_ns, latency_ns)
        self.max_ns = max(self.max_ns, latency_ns)
        # Bucket index: floor(log2(µs)) clamped to [0, NUM_BUCKETS-1]
        us = max(1, latency_ns // 1000)
        bucket = us.bit_length() - 1  # floor(log2(us))
        bucket = min(bucket, self.NUM_BUCKETS - 1)
        self.buckets[bucket] += 1

    @property
    def avg_ns(self):
        return self.total_ns // self.count if self.count else 0


def _print_peer_summary(peer_stats, color):
    # type: (dict, bool) -> None
    global _color_enabled  # pylint: disable=global-statement
    saved = _color_enabled
    _color_enabled = color

    if not peer_stats:
        print("  (no upstream requests recorded)")
        _color_enabled = saved
        return

    # Sort by total request count descending.
    rows = sorted(peer_stats.items(), key=lambda kv: -kv[1].count)

    hdr = f"{'UPSTREAM':<30}  {'REQUESTS':>8}  {'ERRORS':>6}  " \
          f"{'MIN':>8}  {'AVG':>8}  {'MAX':>8}"
    print(_c(ANSI_BOLD, hdr))
    print("─" * len(hdr))

    for peer, st in rows:
        peer_s = peer if len(peer) <= 30 else peer[:27] + "..."
        err_s = _c(ANSI_RED, str(st.errors)) if st.errors else str(st.errors)
        print(
            f"{peer_s:<30}  "
            f"{st.count:>8}  "
            f"{err_s:>15}  "   # ANSI codes inflate length; pad to 15
            f"{_fmt_latency(st.min_ns):>8}  "
            f"{_fmt_latency(st.avg_ns):>8}  "
            f"{_fmt_latency(st.max_ns):>8}"
        )

        # Mini ASCII histogram (show only if ≥10 data points)
        if st.count >= 10:
            _print_mini_hist(st)

    print()
    _color_enabled = saved


def _print_mini_hist(st):
    # type: (PeerStats) -> None
    """Print a one-line ASCII bar-chart of the latency distribution."""
    max_b = max(st.buckets) or 1
    bar_width = 30
    # Find used range
    first = next((i for i, v in enumerate(st.buckets) if v), 0)
    last  = next((i for i, v in reversed(list(enumerate(st.buckets))) if v), 0)

    parts = []
    for i in range(first, last + 1):
        b = st.buckets[i]
        bar_len  = max(1, round(b / max_b * bar_width)) if b else 0
        label    = f"{'≥'+str(2**i)+'µs':>8}"
        bar_fill = "█" * bar_len
        parts.append(f"  {_c(ANSI_DIM, label)} {_c(ANSI_CYAN, bar_fill)} {b}")

    if parts:
        print("\n".join(parts))


# ──────────────────────────────────────────────────────────────────────────────
# Event callback
# ──────────────────────────────────────────────────────────────────────────────

_MIN_KERNEL = (5, 8)      # BPF_RINGBUF_OUTPUT (5.8) + bpf_probe_read_user (5.5)
_HEADER_INTERVAL = 30   # re-print header every N events
_event_count  = 0         # pylint: disable=invalid-name
_peer_stats   = defaultdict(PeerStats)
_threshold_ns = 0         # set from args  # pylint: disable=invalid-name


def _print_header():
    hdr = (f"{'TIME':>8}  {'PID':>6}  {'COMM':<10}  "
           f"{'UPSTREAM':<22}  {'TOTAL':>8}  "
           f"{'CONNECT':>8}  {'TTFB':>8}  {'BYTES':>7}  STATUS")
    print(_c(ANSI_BOLD, hdr))
    print("─" * len(hdr))


def _handle_event(_ctx, data, _size):
    global _event_count  # pylint: disable=global-statement

    ev = _handle_event.bpf_ref["events"].event(data)

    peer_raw = bytes(ev.peer[:ev.peer_len])
    try:
        peer = peer_raw.decode("ascii", errors="replace")
    except Exception:  # pylint: disable=broad-exception-caught
        peer = repr(peer_raw)

    if not peer:
        peer = "<unknown>"

    latency_ns = ev.latency_ns
    if latency_ns < _threshold_ns:
        return

    is_error = not (ev.rc == 0 or 100 <= ev.rc <= 399)
    _peer_stats[peer].record(latency_ns, is_error)

    if _event_count % _HEADER_INTERVAL == 0:
        _print_header()
    _event_count += 1

    ts    = time.strftime("%H:%M:%S")
    comm  = bytes(ev.comm).rstrip(b"\x00").decode("ascii", errors="replace")
    peer_s = peer[:22]

    lat_str = _fmt_latency(latency_ns)
    lat_col = _latency_color(latency_ns)

    con_str  = f"{ev.connect_ms}ms"  if ev.connect_ms else "  -   "
    hdr_str  = f"{ev.header_ms}ms"   if ev.header_ms  else "  -   "
    byt_str  = _fmt_bytes(ev.bytes_received) if ev.bytes_received else "  -  "
    rc_str   = _rc_label(ev.rc)

    print(
        f"{_c(ANSI_DIM, ts):>8}  "
        f"{ev.pid:>6}  "
        f"{comm:<10}  "
        f"{peer_s:<22}  "
        f"{_c(lat_col, lat_str):>17}  "   # ANSI pads
        f"{con_str:>8}  "
        f"{hdr_str:>8}  "
        f"{byt_str:>7}  "
        f"{_c(ANSI_RED if is_error else ANSI_GREEN, rc_str)}"
    )


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def _check_kernel_version():
    # type: () -> None
    """Exit with a clear message if the running kernel is below _MIN_KERNEL."""
    release = os.uname().release          # e.g. "5.14.0-570.58.1.el9_6.x86_64"
    parts = release.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1])
    except (IndexError, ValueError):
        print(f"[!] Cannot parse kernel version from: {release!r}")
        sys.exit(1)
    if (major, minor) < _MIN_KERNEL:
        min_s = ".".join(str(v) for v in _MIN_KERNEL)
        print(
            f"[!] Kernel {major}.{minor} is too old. "
            f"This script requires Linux \u2265 {min_s} "
            f"(BPF_RINGBUF_OUTPUT, bpf_probe_read_user)."
        )
        sys.exit(1)


def _parse_args():
    ap = argparse.ArgumentParser(
        description="Monitor nginx upstream latency using BCC uprobes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--nginx", metavar="PATH", default="",
        help="Path to the nginx binary (default: auto-detect)",
    )
    ap.add_argument(
        "--threshold", metavar="MS", type=float, default=0.0,
        help="Only display requests slower than MS milliseconds (default: 0)",
    )
    ap.add_argument(
        "--interval", metavar="SEC", type=int, default=0,
        help="Print per-peer summary every SEC seconds (default: 0 = on exit only)",
    )
    ap.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour output",
    )
    return ap.parse_args()


def _print_run_banner(nginx_bin, connect_sym, finalize_sym, threshold):
    """Print the startup status lines shown after probes are attached."""
    print(f"[*] Tracing nginx upstream requests on {nginx_bin}")
    print(f"[*] connect  probe: {connect_sym}")
    print(f"[*] finalize probe: {finalize_sym}")
    if threshold > 0:
        print(f"[*] Showing only requests ≥ {threshold:.1f} ms")
    print("[*] Press Ctrl-C to stop and show summary.\n")


def _resolve_nginx_bin(path_arg):
    # type: (str) -> str
    """Return a validated nginx binary path, or exit with an error message."""
    nginx_bin = path_arg or find_nginx_binary()
    if not nginx_bin:
        print("[!] Cannot find nginx binary.  Pass --nginx /path/to/nginx.")
        sys.exit(1)
    if not os.path.isfile(nginx_bin):
        print(f"[!] nginx binary not found: {nginx_bin}")
        sys.exit(1)
    return nginx_bin


def main():
    global _color_enabled, _threshold_ns  # pylint: disable=global-statement

    _check_kernel_version()
    args = _parse_args()
    _color_enabled = not args.no_color and sys.stdout.isatty()
    _threshold_ns  = int(args.threshold * 1_000_000)

    nginx_bin = _resolve_nginx_bin(args.nginx)

    if os.geteuid() != 0:
        print("[!] This script must be run as root (or with CAP_BPF+CAP_PERFMON).")
        sys.exit(1)

    # ── Discover exact probe symbol names from .gnu_debugdata ─────────────────
    # LTO builds mangle static functions with a .lto_priv.N suffix; we must
    # pass the exact decorated name to attach_uprobe(sym=...).  BCC's libelf
    # then resolves the runtime address — no addresses hard-coded here.
    print(f"[*] Resolving probe symbols from {nginx_bin} …", end=" ", flush=True)
    connect_sym, finalize_sym = _find_probe_syms(nginx_bin)
    print(f"OK  ({connect_sym}, {finalize_sym})")

    # ── Build BPF program with computed struct offsets ────────────────────────
    offsets = _compute_nginx_offsets()
    bpf_program = _make_bpf_program(offsets)

    # ── Compile and load BPF program ──────────────────────────────────────────
    print("[*] Compiling BPF program …", end=" ", flush=True)
    b = BPF(text=bpf_program)
    print("OK")

    # ── Attach uprobes by symbol name ─────────────────────────────────────────
    # Using sym= (not addr=) means BCC's own libelf resolves the address from
    # the binary's symbol table.  Attaching by binary path (not PID) means all
    # current and future nginx workers are covered automatically.
    b.attach_uprobe(
        name=nginx_bin,
        sym=connect_sym,
        fn_name="probe_connect",
    )
    b.attach_uprobe(
        name=nginx_bin,
        sym=finalize_sym,
        fn_name="probe_finalize",
    )

    _print_run_banner(nginx_bin, connect_sym, finalize_sym, args.threshold)

    # ── Wire up ring buffer callback ───────────────────────────────────────────
    _handle_event.bpf_ref = b
    b["events"].open_ring_buffer(_handle_event)

    # ── Main loop ─────────────────────────────────────────────────────────────
    exiting = False
    last_summary = time.monotonic()

    def _on_sigint(_sig, _frame):
        nonlocal exiting
        exiting = True

    signal.signal(signal.SIGINT, _on_sigint)

    while not exiting:
        try:
            b.ring_buffer_poll(200)
        except KeyboardInterrupt:
            exiting = True
            break

        if args.interval > 0:
            now = time.monotonic()
            if now - last_summary >= args.interval:
                last_summary = now
                print(f"\n{'─'*60}")
                print(f"  Per-peer summary at {time.strftime('%H:%M:%S')}")
                print(f"{'─'*60}")
                _print_peer_summary(_peer_stats, _color_enabled)

    # ── Exit summary ──────────────────────────────────────────────────────────
    print(f"\n\n{'═'*60}")
    print(f"  Upstream latency summary: {_event_count} request(s) recorded")
    print(f"{'═'*60}")
    _print_peer_summary(_peer_stats, _color_enabled)


if __name__ == "__main__":
    main()
