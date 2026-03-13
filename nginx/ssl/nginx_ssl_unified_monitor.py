#!/usr/bin/env python3
"""
nginx_ssl_unified_monitor.py

Two BPF probe sets in one program.  Attaches uprobes to libssl.so.3 to track
TLS handshakes and resumptions at the OpenSSL boundary, and uprobes to the
nginx binary to watch the TLS 1.2 session-ID cache for forced evictions and
slab allocation failures.  Run it when you suspect resumption is broken or
the shared session cache is too small.

═══════════════════════════════════════════════════════════════════════════
LAYER 1 — libssl.so.3 uprobes
═══════════════════════════════════════════════════════════════════════════
Watches SSL_do_handshake, SSL_session_reused, SSL_version, SSL_is_server
in the shared libssl library.

  • Covers TLS 1.2 and TLS 1.3 without any nginx config changes.
  • It is the only reliable way to measure TLS 1.3 resumption under
    OpenSSL 3.x.  The ticket-key callback (SSL_CTX_set_tlsext_ticket_key_cb)
    with enc=0 is never invoked for TLS 1.3 — that code path is silently
    bypassed.  See: https://github.com/openssl/openssl/discussions/23449

Counters:   handshakes_new / handshakes_resumed / handshakes_failed
            tls12_resumed / tls13_resumed

═══════════════════════════════════════════════════════════════════════════
LAYER 2 — nginx binary uprobes
═══════════════════════════════════════════════════════════════════════════
Watches ngx_ssl_new_session, ngx_ssl_get_cached_session,
        ngx_ssl_expire_sessions, ngx_slab_alloc_locked
in the nginx binary itself.

  • Fires for TLS 1.2 session-ID operations only.  TLS 1.3 clients use PSK
    tickets and never touch the session-ID cache, so ngx_ssl_get_cached_session
    will never fire for a TLS 1.3 client.
  • The two signals that matter:
      forced_evictions  — nginx kicked out a valid, non-expired session because
                          the slab was full.  Cache is too small.
      alloc_failures    — slab returned NULL even after eviction.  nginx drops
                          the session silently.

Counters:   new_sessions_12 / cache_hits_12 / cache_misses_12
            routine_expires / forced_evictions / alloc_failures

═══════════════════════════════════════════════════════════════════════════
NGINX CONFIG AND WHAT THIS TOOL CAN SEE
═══════════════════════════════════════════════════════════════════════════

The three common configurations and what each one means for the counters:

  1. No session resumption
       ssl_session_tickets off;
       ssl_session_cache   off;

     Layer 1:  only full handshakes — resumption rate will be 0%.
     Layer 2:  no cache calls at all; all Layer 2 counters stay at zero.
     Useful as a baseline, or on servers where resumption is intentionally
     disabled.

  2. Session-ID resumption  (TLS 1.2 only)
       ssl_session_tickets off;
       ssl_session_cache   shared:SSL:10m;

     Layer 1:  full handshakes + TLS 1.2 resumptions.  TLS 1.3 clients
               cannot resume at all here — tickets are off and TLS 1.3 has
               no session-ID resumption path.
     Layer 2:  full cache metrics — hits, misses, evictions, alloc failures.
     Use this config when you want to measure the session-ID cache in
     isolation.

  3. Session-ticket resumption  (TLS 1.2 + TLS 1.3)
       ssl_session_tickets on;
       ssl_session_cache   off;

     Layer 1:  full handshakes + resumed handshakes for both versions.
               TLS 1.3 PSK resumptions show up in tls13_resumed.
     Layer 2:  all counters stay at zero — no session-ID cache in use.
     Note:     without a shared session cache, each worker holds its own
               in-memory ticket keys.  Requests that land on a different
               worker cannot resume.  Add ssl_session_cache shared:SSL:10m
               to sync ticket keys across workers.

═══════════════════════════════════════════════════════════════════════════
HOW TO READ THE COMBINED OUTPUT
═══════════════════════════════════════════════════════════════════════════

  Scenario A — low resumption rate + forced_evictions > 0
    → session-ID cache is full.  Increase ssl_session_cache size.

  Scenario B — low resumption rate + no forced evictions
    → problem is elsewhere: ssl_session_timeout too short, clients not
      storing tickets, or missing ssl_session_cache (each worker then holds
      its own ticket keys so cross-worker requests always start fresh).

  Scenario C — healthy resumption rate + some forced evictions
    → TLS 1.3 clients are resuming via tickets, but the TLS 1.2 session-ID
      cache is under pressure.  Still worth enlarging the shared zone.

  Scenario D — everything green
    → nothing to do.

═══════════════════════════════════════════════════════════════════════════
SYMBOL NOTES
═══════════════════════════════════════════════════════════════════════════

  nginx binary:  ngx_ssl_new_session, ngx_ssl_get_cached_session, and
  ngx_ssl_expire_sessions are static in the nginx source; BCC resolves them
  from .symtab via libelf.  ngx_slab_alloc_locked is exported in .dynsym.
  If the binary is stripped, point --nginx at an unstripped build.

  libssl:  all four OpenSSL symbols are exported in .dynsym with
  @@OPENSSL_3.0.0 versioning in OpenSSL 3.x.

USAGE
─────
  sudo python3 nginx_ssl_unified_monitor.py
  sudo python3 nginx_ssl_unified_monitor.py \\
        --nginx /usr/local/nginx/sbin/nginx \\
        --libssl /lib64/libssl.so.3
  sudo python3 nginx_ssl_unified_monitor.py --interval 5 --count 12

REQUIREMENTS
─────────────
  python3-bcc  (dnf install python3-bcc)
  nginx dynamically linked against libssl.so.3
  root / CAP_BPF privileges

  Confirm dynamic link:  ldd $(which nginx) | grep ssl
"""

# pylint: disable=missing-function-docstring

from typing import List

import sys
import os
import subprocess
import signal
import time
import argparse
import ctypes as ct

try:
    from bcc import BPF
except ImportError:
    print("[!] BCC Python bindings not found.  Install with:")
    print("      dnf install python3-bcc    # RHEL / AlmaLinux / Rocky")
    print("      apt install python3-bpfcc   # Debian / Ubuntu")
    sys.exit(1)

# ---------------------------------------------------------------------------
# BPF program — both probe sets share one counter array
# ---------------------------------------------------------------------------
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

// ── Single counter array for both layers ─────────────────────────────────
BPF_ARRAY(counters, u64, 11);

// Layer 2: nginx session-ID cache (TLS 1.2)
#define CTR_NEW_SESSIONS_12   0   // ngx_ssl_new_session called
#define CTR_CACHE_HITS_12     1   // ngx_ssl_get_cached_session → non-NULL
#define CTR_CACHE_MISSES_12   2   // ngx_ssl_get_cached_session → NULL
#define CTR_ROUTINE_EXPIRES   3   // ngx_ssl_expire_sessions(n=1)
#define CTR_FORCED_EVICTIONS  4   // ngx_ssl_expire_sessions(n=0) — cache full
#define CTR_ALLOC_FAILURES    5   // ngx_slab_alloc_locked → NULL inside new_session

// Layer 1: libssl resumption (TLS 1.2 + TLS 1.3)
#define CTR_HS_NEW            6   // full handshake  (session_reused = 0)
#define CTR_HS_RESUMED        7   // resumed         (session_reused = 1)
#define CTR_HS_FAILED         8   // SSL_do_handshake returned != 1
#define CTR_TLS12_RESUMED     9   // resumed, TLS 1.2 (version 0x0303)
#define CTR_TLS13_RESUMED    10   // resumed, TLS 1.3 (version 0x0304)

static __always_inline void inc_ctr(int idx) {
    u64 *v = counters.lookup(&idx);
    if (v) __sync_fetch_and_add(v, 1);
}

// Count only handshakes from processes named "nginx".
// Filtering by comm name (not PID) means new worker processes after an
// nginx reload are picked up automatically — no tool restart needed.
static __always_inline int is_nginx_comm() {
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    return (comm[0]=='n' && comm[1]=='g' && comm[2]=='i' &&
            comm[3]=='n' && comm[4]=='x' && comm[5]=='\0');
}

// ─────────────────────────────────────────────────────────────────────────
// LAYER 2: nginx binary probes
// ─────────────────────────────────────────────────────────────────────────

// Track which threads are inside ngx_ssl_new_session so slab alloc failures
// can be tied to SSL session storage rather than some other slab user in nginx.
BPF_HASH(in_new_session, u64, u8);

// ngx_ssl_new_session(ngx_ssl_conn_t *ssl_conn, ngx_ssl_session_t *sess)
int probe_new_session_entry(struct pt_regs *ctx) {
    inc_ctr(CTR_NEW_SESSIONS_12);
    u64 tid = bpf_get_current_pid_tgid();
    u8 one = 1;
    in_new_session.update(&tid, &one);
    return 0;
}
int probe_new_session_return(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    in_new_session.delete(&tid);
    return 0;
}

// ngx_ssl_get_cached_session(ssl_conn, id, len, copy)
//   returns ngx_ssl_session_t*: non-NULL = hit, NULL = miss
int probe_get_cached_session_return(struct pt_regs *ctx) {
    u64 ret = PT_REGS_RC(ctx);
    if (ret != 0) {
        inc_ctr(CTR_CACHE_HITS_12);
    } else {
        inc_ctr(CTR_CACHE_MISSES_12);
    }
    return 0;
}

// ngx_ssl_expire_sessions(cache, shpool, n)
//   n=1 → routine proactive expiry (expected, harmless)
//   n=0 → FORCED eviction because slab alloc just failed (cache too small)
int probe_expire_sessions_entry(struct pt_regs *ctx) {
    u64 n = (u64)PT_REGS_PARM3(ctx);
    if (n == 0) {
        inc_ctr(CTR_FORCED_EVICTIONS);
    } else {
        inc_ctr(CTR_ROUTINE_EXPIRES);
    }
    return 0;
}

// ngx_slab_alloc_locked(pool, size) → void*
//   Only count NULL returns while the thread is in ngx_ssl_new_session.
//   Other nginx subsystems call this too; we only care about the SSL path.
int probe_slab_alloc_locked_return(struct pt_regs *ctx) {
    u64 ret = PT_REGS_RC(ctx);
    if (ret == 0) {
        u64 tid = bpf_get_current_pid_tgid();
        u8 *flag = in_new_session.lookup(&tid);
        if (flag && *flag) {
            inc_ctr(CTR_ALLOC_FAILURES);
        }
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────
// LAYER 1: libssl.so.3 probes
//
// Per-connection state machine, keyed by SSL*:
//   SSL_do_handshake entry  → stash  tid → ssl_ptr
//   SSL_session_reused ret  → stash  ssl_ptr → reused flag
//   SSL_version ret         → stash  ssl_ptr → TLS version
//   SSL_is_server ret       → stash  ssl_ptr → server flag
//   SSL_do_handshake ret    → read all stashed state, emit counter, clean up
// ─────────────────────────────────────────────────────────────────────────
BPF_HASH(tid_to_ssl,     u64, u64);  // tid → ssl_ptr
BPF_HASH(reused_flag,    u64, u32);  // ssl_ptr → SSL_session_reused()
BPF_HASH(version_flag,   u64, u32);  // ssl_ptr → SSL_version()
BPF_HASH(is_server_flag, u64, u32);  // ssl_ptr → SSL_is_server()

// SSL_do_handshake(SSL *s)
int probe_handshake_entry(struct pt_regs *ctx) {
    if (!is_nginx_comm()) return 0;
    u64 ssl_ptr = (u64)PT_REGS_PARM1(ctx);
    u64 tid     = bpf_get_current_pid_tgid();
    tid_to_ssl.update(&tid, &ssl_ptr);
    return 0;
}

int probe_handshake_return(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();
    int ret = (int)PT_REGS_RC(ctx);

    u64 *ssl_ptr_p = tid_to_ssl.lookup(&tid);
    if (!ssl_ptr_p) return 0;
    u64 ssl_ptr = *ssl_ptr_p;
    tid_to_ssl.delete(&tid);

    // Skip client-side handshakes.  nginx connects to upstreams as a TLS
    // client too; those should not appear in the server-side counters.
    u32 *srv = is_server_flag.lookup(&ssl_ptr);
    if (srv && *srv != 0) {
        if (ret != 1) {
            inc_ctr(CTR_HS_FAILED);
        } else {
            u32 *ru = reused_flag.lookup(&ssl_ptr);
            u32 reused = (ru != NULL) ? *ru : 0;
            if (reused) {
                inc_ctr(CTR_HS_RESUMED);
                u32 *ver = version_flag.lookup(&ssl_ptr);
                if (ver) {
                    if      (*ver == 0x0304) inc_ctr(CTR_TLS13_RESUMED);
                    else if (*ver == 0x0303) inc_ctr(CTR_TLS12_RESUMED);
                }
            } else {
                inc_ctr(CTR_HS_NEW);
            }
        }
    }

    reused_flag.delete(&ssl_ptr);
    version_flag.delete(&ssl_ptr);
    is_server_flag.delete(&ssl_ptr);
    return 0;
}

// SSL_session_reused(const SSL *s) → int (0 or 1)
int probe_session_reused_return(struct pt_regs *ctx) {
    u32 ret = (u32)PT_REGS_RC(ctx);
    u64 tid = bpf_get_current_pid_tgid();
    u64 *ssl_ptr_p = tid_to_ssl.lookup(&tid);
    if (!ssl_ptr_p) return 0;
    reused_flag.update(ssl_ptr_p, &ret);
    return 0;
}

// SSL_version(const SSL *s) → int (e.g. 0x0303 for TLS 1.2, 0x0304 for 1.3)
int probe_ssl_version_return(struct pt_regs *ctx) {
    u32 ret = (u32)PT_REGS_RC(ctx);
    u64 tid = bpf_get_current_pid_tgid();
    u64 *ssl_ptr_p = tid_to_ssl.lookup(&tid);
    if (!ssl_ptr_p) return 0;
    version_flag.update(ssl_ptr_p, &ret);
    return 0;
}

// SSL_is_server(const SSL *s) → int (0 = client, 1 = server)
int probe_is_server_return(struct pt_regs *ctx) {
    u32 ret = (u32)PT_REGS_RC(ctx);
    u64 tid = bpf_get_current_pid_tgid();
    u64 *ssl_ptr_p = tid_to_ssl.lookup(&tid);
    if (!ssl_ptr_p) return 0;
    is_server_flag.update(ssl_ptr_p, &ret);
    return 0;
}
"""

# Counter indices (must match BPF #defines above)
CTR_NEW_SESSIONS_12  = 0
CTR_CACHE_HITS_12    = 1
CTR_CACHE_MISSES_12  = 2
CTR_ROUTINE_EXPIRES  = 3
CTR_FORCED_EVICTIONS = 4
CTR_ALLOC_FAILURES   = 5
CTR_HS_NEW           = 6
CTR_HS_RESUMED       = 7
CTR_HS_FAILED        = 8
CTR_TLS12_RESUMED    = 9
CTR_TLS13_RESUMED    = 10
NUM_CTRS             = 11

# ---------------------------------------------------------------------------
# System helpers
# ---------------------------------------------------------------------------

def find_nginx_binary():
    # type: () -> str
    candidates = [
        "/usr/sbin/nginx",
        "/usr/local/sbin/nginx",
        "/usr/local/nginx/sbin/nginx",
        "/opt/nginx/sbin/nginx",
    ]
    try:
        r = subprocess.run(["which", "nginx"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=5,
                           check=False)
        p = r.stdout.strip()
        if p:
            candidates.insert(0, p)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    for c in candidates:
        if os.path.isfile(c):
            return c
    return ""


def find_libssl():
    # type: () -> str
    candidates = [
        "/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    ]
    try:
        r = subprocess.run(["ldconfig", "-p"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=5,
                           check=False)
        for line in r.stdout.splitlines():
            if "libssl.so" in line and "=>" in line:
                path = line.split("=>")[-1].strip()
                if os.path.isfile(path):
                    return os.path.realpath(path)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    for c in candidates:
        if os.path.isfile(c):
            return os.path.realpath(c)
    return ""


def find_nginx_pids():
    # type: () -> List[int]
    try:
        r = subprocess.run(["pgrep", "-x", "nginx"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=5,
                           check=False)
        return [int(p) for p in r.stdout.split() if p.strip()]
    except Exception:  # pylint: disable=broad-exception-caught
        return []

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


# pylint: disable=invalid-name
def RED(t):
    return _c("31;1", t)

def YELLOW(t):
    return _c("33;1", t)

def GREEN(t):
    return _c("32;1", t)

def BOLD(t):
    return _c("1", t)

def DIM(t):
    return _c("2", t)

def CYAN(t):
    return _c("36;1", t)
# pylint: enable=invalid-name

# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

class NginxSSLUnifiedMonitor:  # pylint: disable=too-many-instance-attributes
    """Unified nginx TLS monitor: libssl resumption metrics and nginx session-ID cache health."""

    # nginx binary probes: (symbol, entry_fn, return_fn)
    _NGINX_PROBES = [
        ("ngx_ssl_new_session",
         "probe_new_session_entry",     "probe_new_session_return"),
        ("ngx_ssl_get_cached_session",
         None,                          "probe_get_cached_session_return"),
        ("ngx_ssl_expire_sessions",
         "probe_expire_sessions_entry", None),
        ("ngx_slab_alloc_locked",
         None,                          "probe_slab_alloc_locked_return"),
    ]

    # libssl probes: (symbol, entry_fn, return_fn)
    _LIBSSL_PROBES = [
        ("SSL_do_handshake",   "probe_handshake_entry",   "probe_handshake_return"),
        ("SSL_session_reused", None,                      "probe_session_reused_return"),
        ("SSL_version",        None,                      "probe_ssl_version_return"),
        ("SSL_is_server",      None,                      "probe_is_server_return"),
    ]

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            self, nginx_path, libssl_path, nginx_pids, interval, count):
        self.nginx_path  = nginx_path
        self.libssl_path = libssl_path
        self.nginx_pids  = nginx_pids
        self.interval    = interval
        self.count       = count
        self.bpf         = None
        self._running    = True
        self._prev       = [0] * NUM_CTRS
        self._iter       = 0
        self._cache_layer_ok = False
        signal.signal(signal.SIGINT,  self._stop)
        signal.signal(signal.SIGTERM, self._stop)

    def _stop(self, *_):
        self._running = False

    # ------------------------------------------------------------------
    def setup(self):  # pylint: disable=too-many-branches,too-many-statements
        # type: () -> bool
        if os.geteuid() != 0:
            print("[!] Root privileges required (sudo).")
            return False

        have_nginx  = os.path.isfile(self.nginx_path) if self.nginx_path else False
        have_libssl = os.path.isfile(self.libssl_path) if self.libssl_path else False

        if not have_libssl:
            print(f"[!] libssl not found: {self.libssl_path}")
            print("    The libssl layer is required.  Use --libssl /path/to/libssl.so.3")
            return False

        nginx_label = (
            self.nginx_path if have_nginx
            else "(not found \u2014 Layer 2 / cache metrics disabled)"
        )
        print(f"[*] nginx binary : {nginx_label}")
        print(f"[*] libssl       : {self.libssl_path}")
        pids_str = (
            ", ".join(str(p) for p in self.nginx_pids)
            if self.nginx_pids else "none detected"
        )
        print(f"[*] nginx PIDs   : {pids_str} (informational only)")
        print("[*] libssl filter: comm=nginx in BPF  (covers new workers created after reload)")
        print()

        print("[*] Compiling BPF program...")
        try:
            self.bpf = BPF(text=BPF_PROGRAM)
        except Exception as e:  # pylint: disable=broad-exception-caught
            print(f"[!] BPF compile failed: {e}")
            return False
        print("    OK")
        print()

        # ── Attach libssl probes (per nginx PID) ──────────────────────
        print("[*] Attaching Layer 1 — libssl uprobes (TLS 1.2 + TLS 1.3 resumption)...")
        pids_for_libssl = self.nginx_pids if self.nginx_pids else [None]
        for sym, entry_fn, ret_fn in self._LIBSSL_PROBES:
            for pid in pids_for_libssl:
                kw = {"name": self.libssl_path, "sym": sym}
                if pid:
                    kw["pid"] = pid
                if entry_fn:
                    try:
                        self.bpf.attach_uprobe(fn_name=entry_fn, **kw)
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        print(f"    [warn] uprobe {sym}: {e}")
                if ret_fn:
                    try:
                        self.bpf.attach_uretprobe(fn_name=ret_fn, **kw)
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        print(f"    [warn] uretprobe {sym}: {e}")
            pid_label = (
                f"pid={pids_for_libssl[0]}..{pids_for_libssl[-1]}"
            ) if self.nginx_pids else "all pids"
            print(f"    {sym:<30} ({pid_label})")

        # ── Attach nginx binary probes ─────────────────────────────────
        print()
        if have_nginx:
            print("[*] Attaching Layer 2 — nginx binary uprobes (TLS 1.2 cache / slab)...")
            ok = 0
            for sym, entry_fn, ret_fn in self._NGINX_PROBES:
                kw = {"name": self.nginx_path, "sym": sym}
                if entry_fn:
                    try:
                        self.bpf.attach_uprobe(fn_name=entry_fn, **kw)
                        ok += 1
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        print(f"    [warn] uprobe {sym}: {e}")
                if ret_fn:
                    try:
                        self.bpf.attach_uretprobe(fn_name=ret_fn, **kw)
                        ok += 1
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        print(f"    [warn] uretprobe {sym}: {e}")
                print(f"    {sym:<30}")
            self._cache_layer_ok = ok > 0
        else:
            print("[!] Layer 2 (nginx cache) disabled — nginx binary not found.")
            print("    Resumption metrics (Layer 1) will still work.")
            self._cache_layer_ok = False

        print()
        return True

    # ------------------------------------------------------------------
    def _read(self):
        # type: () -> List[int]
        t = self.bpf["counters"]
        return [t[ct.c_int(i)].value for i in range(NUM_CTRS)]

    @staticmethod
    def _rate(delta, elapsed):
        return delta / elapsed if elapsed > 0 else 0.0

    # ------------------------------------------------------------------
    def _print_header(self):
        w = 76
        print("=" * w)
        print(BOLD("  Nginx SSL Unified Monitor  (libssl + nginx binary uprobes)"))
        print("=" * w)
        print(f"  nginx    : {self.nginx_path or '(disabled)'}")
        print(f"  libssl   : {self.libssl_path}")
        count_str = f"  ({self.count} intervals)" if self.count else ""
        print(f"  interval : {self.interval}s{count_str}")
        print("=" * w)
        print()

    def _print_interval(  # pylint: disable=too-many-locals,too-many-statements
            self, vals, elapsed):
        self._iter += 1
        ts = time.strftime("%H:%M:%S")
        d = [vals[i] - self._prev[i] for i in range(NUM_CTRS)]

        # ── Layer 1: resumption outcomes (libssl) ──────────────────────
        hs_new     = d[CTR_HS_NEW]
        hs_resumed = d[CTR_HS_RESUMED]
        hs_failed  = d[CTR_HS_FAILED]
        tls12_res  = d[CTR_TLS12_RESUMED]
        tls13_res  = d[CTR_TLS13_RESUMED]
        total_hs   = hs_new + hs_resumed
        res_rate   = (hs_resumed / total_hs * 100) if total_hs > 0 else None

        # ── Layer 2: cache layer (nginx) ───────────────────────────────
        new_12     = d[CTR_NEW_SESSIONS_12]
        hits_12    = d[CTR_CACHE_HITS_12]
        misses_12  = d[CTR_CACHE_MISSES_12]
        routine    = d[CTR_ROUTINE_EXPIRES]
        forced     = d[CTR_FORCED_EVICTIONS]
        alloc_fail = d[CTR_ALLOC_FAILURES]

        lookups_12 = hits_12 + misses_12
        hit_rate_12 = (hits_12 / lookups_12 * 100) if lookups_12 > 0 else None

        # ── Combined health ────────────────────────────────────────────
        if alloc_fail > 0:
            health = RED("CRITICAL")
            advice = RED(
                "Cache is too small: slab alloc failed after forced eviction.\n"
                "  nginx is silently dropping sessions it cannot store.\n"
                "  Increase ssl_session_cache shared:NAME:SIZE immediately.")
        elif forced > 0:
            ratio = forced / max(new_12, 1)
            if ratio >= 0.5:
                health = RED("CRITICAL")
                advice = RED(
                    f"Heavy forced evictions ({ratio * 100:.0f}% of new TLS 1.2 sessions).\n"
                    "  Valid sessions evicted before expiry.  Double the cache size.")
            else:
                health = YELLOW("WARNING")
                advice = YELLOW(
                    "Forced evictions detected: some valid sessions evicted early.\n"
                    "  Consider increasing ssl_session_cache size.")
        elif res_rate is not None and res_rate < 40:
            health = YELLOW("WARNING")
            advice = YELLOW(
                f"Resumption rate {res_rate:.1f}% is low.\n"
                "  If no forced evictions above: check ssl_session_timeout,\n"
                "  or add ssl_session_cache shared:SSL:10m for cross-worker\n"
                "  ticket-key synchronisation.")
        elif res_rate is not None and res_rate >= 40:
            health = GREEN("OK" if res_rate >= 70 else "FAIR")
            advice = GREEN(f"Resumption rate {res_rate:.1f}%.")
        else:
            health = DIM("WAITING")
            advice = DIM("No completed handshakes observed yet.")

        # ── Table layout ───────────────────────────────────────────────
        w   = 76
        sep = "\u2500" * w
        c1  = 42
        c2  = 8
        c3  = 9

        def row(label, delta, total, note=""):
            r = self._rate(delta, elapsed)
            return f"  {label:<{c1}} {r:{c2}.1f}/s  {delta:{c3}d}  {total:{c3}d}    {note}"

        print(f"\n[{ts}  interval #{self._iter}]")
        print(sep)
        print(f"  {'Metric':<{c1}} {'Rate':>{c2}}   {'Interval':>{c3}}  {'Total':>{c3}}")
        print(sep)

        # ── Section 1: libssl / all TLS versions ──
        print(CYAN("  \u2500\u2500 Layer 1: TLS Resumption  "
                   "(libssl \u2014 all versions) \u2500\u2500"))
        print(row("Full handshakes  (new session)",
                  hs_new,     vals[CTR_HS_NEW]))
        print(row("Resumed handshakes",
                  hs_resumed, vals[CTR_HS_RESUMED],
                  GREEN("OK") if hs_resumed > 0 else ""))
        print(row("Failed handshakes",
                  hs_failed,  vals[CTR_HS_FAILED],
                  RED("\u2190 check error log") if hs_failed > 0 else ""))
        if res_rate is not None:
            fmt = (GREEN if res_rate >= 70 else (YELLOW if res_rate >= 40 else RED))
            rate_str = fmt(f"{res_rate:.1f}%")
            res_lbl = "Resumption rate  (resumed / total)"
            print(f"  {res_lbl:<{c1}} {'':>{c2}}   {'':>{c3}}  {'':>{c3}}    {rate_str}")
        _ver_lbl = "  \u2514 by TLS version:"
        tls_ver_label = f"  {_ver_lbl:<{c1}}"
        print(DIM(tls_ver_label))
        print(row("    TLS 1.2 resumed", tls12_res, vals[CTR_TLS12_RESUMED]))
        print(row("    TLS 1.3 resumed", tls13_res, vals[CTR_TLS13_RESUMED]))

        # ── Section 2: nginx cache / TLS 1.2 only ──
        print(CYAN("  \u2500\u2500 Layer 2: Session-ID Cache  "
                   "(nginx binary \u2014 TLS 1.2 only) \u2500\u2500"))
        if not self._cache_layer_ok:
            print(DIM("  (disabled \u2014 nginx binary not found or probes failed)"))
        else:
            print(row("New sessions stored  (TLS 1.2)",
                      new_12,    vals[CTR_NEW_SESSIONS_12]))
            print(row("Session-ID hit  (TLS 1.2 cache hit)",
                      hits_12,   vals[CTR_CACHE_HITS_12]))
            print(row("Session-ID miss  (TLS 1.2 full handshake)",
                      misses_12, vals[CTR_CACHE_MISSES_12]))
            if hit_rate_12 is not None:
                fmt = (GREEN if hit_rate_12 >= 70 else (YELLOW if hit_rate_12 >= 50 else RED))
                hr_str = fmt(f"{hit_rate_12:.1f}%")
                hr_lbl = "TLS 1.2 session-ID hit rate"
                print(f"  {hr_lbl:<{c1}} {'':>{c2}}   {'':>{c3}}  {'':>{c3}}    {hr_str}")
            _evict_lbl = "  \u2514 eviction / allocation:"
            evict_label = f"  {_evict_lbl:<{c1}}"
            print(DIM(evict_label))
            print(row("    Routine expiries  (expired entries, normal)",
                      routine,    vals[CTR_ROUTINE_EXPIRES]))
            print(row(BOLD("    Forced evictions  (non-expired!)"),
                      forced,    vals[CTR_FORCED_EVICTIONS],
                      (RED("\u2190 CACHE FULL") if forced > 0 else GREEN("OK"))))
            print(row(BOLD("    Slab alloc failures"),
                      alloc_fail, vals[CTR_ALLOC_FAILURES],
                      (RED("\u2190 CRITICAL") if alloc_fail > 0 else GREEN("OK"))))

        print(sep)
        print(f"  Health: {health}")
        print(f"  {advice}")
        print()
        self._prev = vals

    # ------------------------------------------------------------------
    def _print_summary(self, elapsed):
        final = self._read()
        total_hs   = final[CTR_HS_NEW] + final[CTR_HS_RESUMED]
        res_rate   = (final[CTR_HS_RESUMED] / total_hs * 100) if total_hs else None
        lookups_12 = final[CTR_CACHE_HITS_12] + final[CTR_CACHE_MISSES_12]
        hit_rate_12 = (final[CTR_CACHE_HITS_12] / lookups_12 * 100) if lookups_12 else None

        print()
        print(BOLD("\u2500\u2500 Summary " + "\u2500" * 49))
        print(f"  elapsed                  : {elapsed:.0f}s")
        print()
        print("  [Layer 1: libssl]")
        print(f"  full handshakes          : {final[CTR_HS_NEW]}")
        resumed_str = GREEN(str(final[CTR_HS_RESUMED])) if final[CTR_HS_RESUMED] > 0 \
            else str(final[CTR_HS_RESUMED])
        failed_str = RED(str(final[CTR_HS_FAILED])) if final[CTR_HS_FAILED] else GREEN("0")
        print(f"  resumed handshakes       : {resumed_str}")
        print(f"  failed handshakes        : {failed_str}")
        if res_rate is not None:
            fmt = GREEN if res_rate >= 70 else (YELLOW if res_rate >= 40 else RED)
            print(f"  overall resumption rate  : {fmt(f'{res_rate:.1f}%')}")
        print(f"    TLS 1.2 resumed        : {final[CTR_TLS12_RESUMED]}")
        print(f"    TLS 1.3 resumed        : {final[CTR_TLS13_RESUMED]}")
        print()
        if self._cache_layer_ok:
            print("  [Layer 2: nginx cache]")
            print(f"  new sessions (TLS 1.2)   : {final[CTR_NEW_SESSIONS_12]}")
            hit_str = (GREEN if (hit_rate_12 or 0) >= 70 else YELLOW)(f"{hit_rate_12:.1f}%") \
                if hit_rate_12 is not None else DIM("n/a")
            evict_str = RED(str(final[CTR_FORCED_EVICTIONS])) \
                if final[CTR_FORCED_EVICTIONS] else GREEN("0")
            alloc_str = RED(str(final[CTR_ALLOC_FAILURES])) \
                if final[CTR_ALLOC_FAILURES] else GREEN("0")
            print(f"  session-ID hit rate      : {hit_str}")
            print(f"  forced evictions         : {evict_str}")
            print(f"  slab alloc failures      : {alloc_str}")
            print()
            self._print_sizing_hint(final, elapsed)

    def _print_sizing_hint(self, vals, elapsed):
        total_new = vals[CTR_NEW_SESSIONS_12]
        if total_new == 0 or elapsed < 5:
            return
        sessions_per_sec = total_new / elapsed
        timeout_s = 300   # nginx default ssl_session_timeout 5m
        peak = sessions_per_sec * timeout_s * 1.25
        mb = peak / 4000  # nginx: ~4000 sessions/MB
        print(BOLD("  \u2500\u2500 Sizing estimate (TLS 1.2, ssl_session_timeout 5m) ──"))
        print(f"  observed TLS 1.2 session rate : {sessions_per_sec:.1f}/s")
        print(f"  recommended cache size        : ~{max(1, mb):.0f} MB")
        print()
        print("  Suggested nginx config:")
        print(f"    ssl_session_cache  shared:SSL:{max(1, int(mb) + 1)}m;")
        print("    ssl_session_timeout 5m;")
        print()

    # ------------------------------------------------------------------
    def run(self):
        self._print_header()
        print("[*] Tracing TLS handshakes...  Ctrl-C to stop.\n")
        self._prev = self._read()
        start = time.monotonic()
        last  = start
        done  = 0

        while self._running:
            time.sleep(0.25)
            now = time.monotonic()
            if now - last < self.interval:
                continue
            elapsed = now - last
            last = now
            self._print_interval(self._read(), elapsed)
            done += 1
            if self.count and done >= self.count:
                break

        self._print_summary(time.monotonic() - start)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "Unified nginx TLS monitor: libssl resumption (TLS 1.2 + 1.3)\n"
            "and nginx shared session-ID cache health in one dashboard."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--nginx", "-n", metavar="PATH", default="",
                   help="Path to nginx binary (auto-detected if omitted)")
    p.add_argument("--libssl", metavar="PATH", default="",
                   help="Path to libssl.so.3 (auto-detected if omitted)")
    p.add_argument("--pid", type=int, metavar="PID", default=0,
                   help="Attach libssl probes to this PID only (default: all nginx workers)")
    p.add_argument("--interval", "-i", type=int, default=5, metavar="SECONDS",
                   help="Reporting interval in seconds (default: 5)")
    p.add_argument("--count", "-c", type=int, default=0, metavar="N",
                   help="Number of intervals then exit (0 = run until Ctrl-C)")
    return p.parse_args()


def main():
    args = parse_args()

    nginx_path = args.nginx or find_nginx_binary()
    libssl_path = os.path.realpath(args.libssl) if args.libssl else find_libssl()

    if not libssl_path:
        print("[!] Cannot locate libssl.so.3.  Use --libssl /path/to/libssl.so.3")
        sys.exit(1)

    if args.pid:
        nginx_pids = [args.pid]
    else:
        nginx_pids = find_nginx_pids()
        if nginx_pids:
            print(f"[*] Detected nginx PIDs: {', '.join(str(p) for p in nginx_pids)}")
        else:
            print("[!] No nginx processes found; libssl probes will attach to all processes.")
            nginx_pids = []

    m = NginxSSLUnifiedMonitor(
        nginx_path=nginx_path,
        libssl_path=libssl_path,
        nginx_pids=nginx_pids,
        interval=args.interval,
        count=args.count,
    )
    if not m.setup():
        sys.exit(1)
    m.run()


if __name__ == "__main__":
    main()
