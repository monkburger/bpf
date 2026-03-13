# nginx SSL monitor

BPF tool for measuring TLS session resumption and figuring out the right
`ssl_session_cache` size for nginx.

---

## Why this exists

The standard nginx docs tell you to set `ssl_session_cache shared:SSL:10m` and
move on.  What they don't tell you is how to know if 10m is actually enough, or
whether your resumption rate is good in the first place.  When you start digging
into it:

- nginx has no built-in metric for forced session evictions (where it kicks out
  a valid, non-expired session just to make room)
- nginx's `$ssl_session_reused` access-log variable works, but only per request,
  and it tells you nothing about *why* resumption is failing
- TLS 1.3 resumption (PSK tickets) is completely invisible to session ID cache
  metrics. The two mechanisms are entirely separate.
- The OpenSSL 3.x ticket-key callback (`SSL_CTX_set_tlsext_ticket_key_cb`) is
  never invoked for TLS 1.3, so any tool that hooks that callback will silently
  miss all TLS 1.3 resumptions. See the [OpenSSL discussion here](https://github.com/openssl/openssl/discussions/23449).

This tool attaches BPF uprobes directly to libssl.so.3 and the nginx binary at
runtime.  No recompile, no nginx config change, no restart. The probes fire on
the live process.

---

## What it measures

Two probe sets run in parallel:

**Layer 1: libssl uprobes**

Hooks into `SSL_do_handshake`, `SSL_session_reused`, `SSL_version`, and
`SSL_is_server` in libssl.so.3.  This catches every TLS handshake completion
regardless of version or resumption method.

| Counter | What it means |
|---------|---------------|
| Full handshakes | Client started fresh, no resumption |
| Resumed handshakes | Client reused an existing session |
| Failed handshakes | `SSL_do_handshake` returned an error |
| TLS 1.2 resumed | Resumed handshakes on TLS 1.2 specifically |
| TLS 1.3 resumed | Resumed handshakes on TLS 1.3 (PSK tickets) |

**Layer 2: nginx binary uprobes**

Hooks into `ngx_ssl_new_session`, `ngx_ssl_get_cached_session`,
`ngx_ssl_expire_sessions`, and `ngx_slab_alloc_locked` in the nginx binary
itself.  Tracks the TLS 1.2 session ID shared memory cache.

| Counter | What it means |
|---------|---------------|
| New sessions (TLS 1.2) | Sessions written into the shared cache |
| Session ID hit | Client presented a session ID that was found in cache |
| Session ID miss | Session ID not found; requires a full handshake |
| Routine expiries | Expired entries cleaned up, normal housekeeping |
| **Forced evictions** | nginx evicted a *valid, non-expired* session to free space |
| **Slab alloc failures** | Allocator returned NULL even after eviction; nginx drops the session silently |

Forced evictions and slab alloc failures are the two signals you actually want
to watch.  If they're not zero, the cache is too small.

---

## How nginx config affects what you can see

The tool behaves differently depending on your nginx SSL settings:

**No session resumption**
```nginx
ssl_session_tickets off;
ssl_session_cache   off;
```
Layer 1 will only show full handshakes; resumption rate stays at 0%.  Layer 2
counters stay at zero since there's no cache to talk to.  Good as a baseline.

**Session ID resumption (TLS 1.2 only)**
```nginx
ssl_session_tickets off;
ssl_session_cache   shared:SSL:10m;
```
Layer 1 shows full handshakes plus TLS 1.2 resumptions.  TLS 1.3 clients cannot
resume here at all because tickets are off and TLS 1.3 has no session ID path.
Layer 2 shows full cache metrics.  This is the config to use if you specifically
want to measure and size the session ID cache.

**Session ticket resumption (TLS 1.2 + TLS 1.3)**
```nginx
ssl_session_tickets on;
ssl_session_cache   off;
```
Layer 1 shows resumed handshakes for both versions.  TLS 1.3 PSK resumptions
appear in `tls13_resumed`.  Layer 2 counters stay at zero since there is no
session ID cache in use.  **Important:** without `ssl_session_cache`, each nginx
worker holds its own in-memory ticket keys.  A client whose request lands on a
different worker than the original handshake cannot resume.  Add
`ssl_session_cache shared:SSL:10m` alongside tickets to share keys across
workers.

---

## Reading the output

```
[14:22:05  interval #3]
────────────────────────────────────────────────────────────────────────────
  Metric                                       Rate   Interval      Total
────────────────────────────────────────────────────────────────────────────
── Layer 1: TLS Resumption  (libssl - all versions) ──
  Full handshakes  (new session)              2.4/s         12        108
  Resumed handshakes                          7.1/s         35        318   OK
  Failed handshakes                           0.0/s          0          0
  Resumption rate  (resumed / total)                                        76.4%
    └ by TLS version:
    TLS 1.2 resumed                           1.8/s          9         81
    TLS 1.3 resumed                           5.3/s         26        237
── Layer 2: Session-ID Cache  (nginx binary - TLS 1.2 only) ──
  New sessions stored  (TLS 1.2)              2.4/s         12        108
  Session-ID hit  (TLS 1.2 cache hit)         1.8/s          9         81
  Session-ID miss  (TLS 1.2 full handshake)   0.6/s          3         27
  TLS 1.2 session-ID hit rate                                               75.0%
    └ eviction / allocation:
    Routine expiries  (expired entries, normal)  0.0/s        0          0
    Forced evictions  (non-expired!)          0.0/s          0          0   OK
    Slab alloc failures                       0.0/s          0          0   OK
────────────────────────────────────────────────────────────────────────────
  Health: OK
  Resumption rate 76.4%.
```

**Scenario A:** low resumption rate with `forced_evictions > 0`
The session ID cache is full and kicking out valid sessions.  Increase
`ssl_session_cache` size.

**Scenario B:** low resumption rate with no forced evictions
The problem is elsewhere.  Check `ssl_session_timeout` (default 5 minutes),
check that clients are actually storing tickets, or check whether
`ssl_session_cache` is missing entirely (workers then have independent ticket
keys and cross-worker requests always start fresh).

**Scenario C:** healthy resumption rate with some forced evictions
TLS 1.3 clients are resuming fine via tickets, but the TLS 1.2 session ID
cache is under pressure.  Worth enlarging the shared zone anyway.

**Scenario D:** everything green
Nothing to do.

At the end of a run the tool prints a sizing estimate:

```
── Sizing estimate (TLS 1.2, ssl_session_timeout 5m) ──
  observed TLS 1.2 session rate : 12.3/s
  recommended cache size        : ~23 MB

  Suggested nginx config:
    ssl_session_cache  shared:SSL:24m;
    ssl_session_timeout 5m;
```

The estimate is based on observed session rate x `ssl_session_timeout` x 1.25
headroom, at nginx's ~4000 sessions/MB density.

---

## Install

```
dnf install python3-bcc    # RHEL / AlmaLinux / Rocky
# or
apt install python3-bpfcc   # Debian / Ubuntu
```

Verify nginx is dynamically linked against libssl:

```
ldd $(which nginx) | grep ssl
```

If that comes back empty nginx was built with OpenSSL statically linked and the
libssl layer won't work.  The nginx binary layer will still work.

---

## Run

```bash
# defaults: auto-detect nginx and libssl, 5-second intervals, run until Ctrl-C
sudo python3 nginx_ssl_unified_monitor.py

# specify paths explicitly
sudo python3 nginx_ssl_unified_monitor.py \
    --nginx  /usr/local/nginx/sbin/nginx \
    --libssl /lib64/libssl.so.3

# 12 intervals of 5 seconds then exit
sudo python3 nginx_ssl_unified_monitor.py --interval 5 --count 12

# pin to a single already-known nginx PID
sudo python3 nginx_ssl_unified_monitor.py --pid 12345
```

| Flag | Default | Description |
|------|---------|-------------|
| `--nginx` / `-n` | auto detected | Path to nginx binary |
| `--libssl` | auto detected | Path to libssl.so.3 |
| `--pid` | all workers | Attach libssl probes to this PID only |
| `--interval` / `-i` | `5` | Reporting interval in seconds |
| `--count` / `-c` | `0` (unlimited) | Stop after N intervals |

The tool needs root or `CAP_BPF`.  It picks up new workers after an nginx reload
automatically. Filtering is done by process name in the BPF program, not by
PID, so you don't need to restart it on reload.

---

## Symbol availability

The nginx binary probes (`ngx_ssl_new_session`, `ngx_ssl_get_cached_session`,
`ngx_ssl_expire_sessions`) are `static` functions in nginx source.  BCC
resolves them from `.symtab` via libelf.  If your nginx binary is stripped those
symbols are gone and Layer 2 will fail to attach. Point `--nginx` at an
unstripped or debug build.

`ngx_slab_alloc_locked` is a public symbol in `.dynsym` and survives stripping.

All four libssl symbols (`SSL_do_handshake`, `SSL_session_reused`,
`SSL_version`, `SSL_is_server`) are exported in `.dynsym` with
`@@OPENSSL_3.0.0` versioning in OpenSSL 3.x.

---

## Requirements

- Linux kernel 4.14+ (BPF uprobe support)
- python3-bcc
- nginx built against libssl.so.3 (OpenSSL 3.x)
- root or `CAP_BPF + CAP_PERFMON`
