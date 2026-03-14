# bpf

A collection of BPF/BCC observability tools for Linux servers. Each tool
attaches uprobes or kprobes to running processes at runtime with no code
changes, no restarts, and no added instrumentation to the software being
observed.

All tools require root or `CAP_BPF + CAP_PERFMON` and a kernel with BPF
uprobe support (4.14+).

---

## Tools

### `nginx/ssl/nginx_ssl_unified_monitor.py`

Unified TLS session resumption and nginx session-ID cache health monitor.

Attaches to two layers simultaneously:

- **Layer 1 — libssl.so.3**: watches `SSL_do_handshake`, `SSL_session_reused`,
  `SSL_version`, and `SSL_is_server` to count full vs. resumed handshakes for
  both TLS 1.2 and TLS 1.3, without any nginx config changes.
- **Layer 2 — nginx binary**: watches `ngx_ssl_new_session`,
  `ngx_ssl_get_cached_session`, `ngx_ssl_expire_sessions`, and
  `ngx_slab_alloc_locked` to measure session-ID cache hit rate, routine
  expiries, forced evictions (cache too small), and slab allocation failures.

Prints a live dashboard at a configurable interval. Includes a sizing estimate
that recommends an `ssl_session_cache` value based on the observed TLS 1.2
session rate.

See [nginx/ssl/README.md](nginx/ssl/README.md) for full usage.

---

### `php/php_latency_monitor.py`

Measures end-to-end PHP request latency in real time by attaching uprobes to
`php_request_startup` and `php_request_shutdown` in the PHP binary. Captures
the script filename and OS user for each completed request.

Works with FPM, CGI, and CLI binaries simultaneously. Supports monitoring
multiple PHP binaries in one run via `--bin PATH:KIND:VER` flags or a TOML
config file. Color-coded latency output (plain / yellow / red thresholds) with
an optional `--threshold` flag to filter out fast requests.

Useful for identifying slow scripts without enabling FPM slow logging, and for
detecting suspicious patterns such as PHP webshells executing from upload or
cache directories.

See [php/README.md](php/README.md) for full usage, use cases, and examples.

---

### `nginx/nginx_upstream_latency.py` *(BETA)*

> This tool is BETA and might not work correctly on all builds.  One struct
> offset (`U_OFF_STATE = 0x420`) is hard-coded from a disassembly of a
> specific nginx build and may be wrong on a different version or package.

Traces nginx upstream request latency in real time using BCC uprobes. Hooks
directly into the nginx binary with no config changes and no restarts required.
Covers all nginx worker processes at once.

Attaches two uprobes:

- **`ngx_http_upstream_connect`**: records a BPF timestamp on every upstream
  attempt, including retries.
- **`ngx_http_upstream_finalize_request`**: computes wall-clock latency, reads
  nginx's own per-request timing (`connect_time`, `header_time`,
  `bytes_received`) and the upstream peer name from `u->state`, then emits an
  event to user space.

Prints a live event table with columns for total latency, TCP connect time,
time to first byte, bytes received, and HTTP status. On exit (or at a
configurable interval) prints a per-peer summary with min/avg/max and an ASCII
latency histogram.

Keepalive note: for reused keepalive connections, the CONNECT column will show
0. This is expected -- there was no TCP handshake. The TOTAL column is still
accurate.

See [nginx/README.md](nginx/README.md) for full usage, flags, and known
limitations.

---

### `mysql/mysql_query_log_bpf.py`

Captures live MySQL query text and execution time by attaching a uprobe to
`mysql_execute_command` in the running mysqld binary. No query log config
changes needed. Version-aware: uses struct offsets specific to MySQL 5.7, 8.0,
and 8.4 to read internal query state.

Prints each query with its timestamp and latency in milliseconds, and flags
truncated queries.

See [mysql/README.md](mysql/README.md) for full usage.

---

## Requirements

```
dnf install python3-bcc    # RHEL / AlmaLinux / Rocky
apt install python3-bpfcc   # Debian / Ubuntu
```

Root or `CAP_BPF + CAP_PERFMON`. Linux kernel 4.14+.

Target binaries must be dynamically linked and have the required symbols
available (not fully stripped).

---

## License

[2-Clause BSD](LICENSE)
