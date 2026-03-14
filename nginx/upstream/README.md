# nginx_upstream_latency.py

> **BETA** -- tested on AlmaLinux 9 / RHEL 9 with nginx 1.20.x.  There are
> probably bugs and edge cases.  One struct offset (`U_OFF_STATE = 0x420`) is
> hard-coded from a disassembly of one specific build and may be wrong on a
> different nginx version or distro package.  If you see garbage latency
> numbers, that's the first thing to check.

Traces nginx upstream request latency in real-time using BCC uprobes -- no
nginx config changes, no restarts.  Works against the running binary for all
worker processes at once.

---

## What it shows

```
    TIME     PID  COMM        UPSTREAM                TOTAL  CONNECT     TTFB    BYTES  STATUS
08:14:01   31042  nginx       127.0.0.1:8080          3.21ms     1ms     2ms     4.2K  200
08:14:01   31042  nginx       127.0.0.1:8080          1.05ms       -       -     1.1K  200
```

| Column  | Meaning |
|---------|---------|
| TOTAL   | Wall-clock latency: time from `ngx_http_upstream_connect` to `ngx_http_upstream_finalize_request` |
| CONNECT | TCP handshake time, from nginx's own `u->state->connect_time` (ms resolution) |
| TTFB    | Time to first response byte, from `u->state->header_time` (ms resolution) |
| BYTES   | Response bytes received, from `u->state->bytes_received` |
| STATUS  | HTTP status code, or a short nginx error label (ERR, ABORT, etc.) |

On exit (or every `--interval` seconds) a per-peer summary is printed with
min/avg/max latency and a small ASCII histogram.

---

## Requirements

- Linux >= 5.8 (needed for `BPF_RINGBUF_OUTPUT` and `bpf_probe_read_user`)
- Root, or `CAP_BPF` + `CAP_PERFMON`
- BCC Python bindings:
  ```
  dnf install python3-bcc    # RHEL / AlmaLinux / Rocky
  apt install python3-bpfcc  # Debian / Ubuntu
  ```
- `objcopy`, `xz`, `nm` -- for reading `.gnu_debugdata` symbol names (standard
  on RHEL/AlmaLinux; optional -- falls back to plain symbol names without them)

---

## Quick start

```bash
# Basic -- trace all upstream requests
sudo python3 nginx_upstream_latency.py

# Only show requests slower than 100ms
sudo python3 nginx_upstream_latency.py --threshold 100

# Print a per-peer summary every 10 seconds
sudo python3 nginx_upstream_latency.py --interval 10

# Specify nginx binary explicitly
sudo python3 nginx_upstream_latency.py --nginx /usr/local/nginx/sbin/nginx

# No colour (e.g. piping to a file)
sudo python3 nginx_upstream_latency.py --no-color
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--nginx PATH` | auto-detect | Path to the nginx binary to probe |
| `--threshold MS` | 0 | Only show requests slower than MS milliseconds |
| `--interval SEC` | 0 (exit only) | Print per-peer summary every SEC seconds |
| `--no-color` | off | Disable ANSI colour output |

---

## Keepalive upstreams

If nginx keepalives are on (`keepalive N` in the upstream block), the CONNECT
column will show 0 for reused connections.  **This is correct behaviour, not a
bug.**

For a keepalive cache hit, the keepalive module returns `NGX_DONE` from
`peer.get()`, which tells nginx to skip the TCP handshake and go straight to
sending the request.  nginx's `connect_time` is computed as:

```c
connect_time = ngx_current_msec - u->start_time;
```

Since `u->start_time` was just set and there was no wait, this rounds to 0.
That matches what nginx's own `$upstream_connect_time` variable reports.

The TOTAL column is still accurate for keepalive connections -- it measures
the full upstream request cycle from nginx's perspective.

---

## Known limitations / things to double-check

- **`U_OFF_STATE = 0x420`**: The offset of `u->state` inside
  `ngx_http_upstream_t` is hard-coded.  This struct is large and its layout
  depends on compile-time flags (`NGX_HTTP_CACHE`, `NGX_HTTP_SSL`,
  `NGX_COMPAT`, etc.).  `0x420` was verified by hand from a disassembly of
  the AlmaLinux 9 nginx 1.20.x package.  On a different build you may need to
  adjust it.  If latency numbers look wrong or peer names are always empty,
  this is likely the culprit.

- **Peer name missing on early error paths**: The peer name is read from
  `u->state->peer` in the finalize probe.  On very early error paths where
  nginx errors out before writing that field, the peer will show as empty.

- **Retries**: On a retry, the start timestamp is overwritten so we measure
  the last attempt.  The TOTAL latency shown is for the last attempt only.

- **LTO-decorated symbols**: On RHEL/AlmaLinux packages, static functions get
  a `.lto_priv.N` suffix from link-time optimization.  The script reads these
  exact names from the `.gnu_debugdata` section embedded in the binary.  On
  non-RHEL builds without `.gnu_debugdata`, it falls back to the plain
  undecorated names, which works for non-LTO builds.

- **Stripped binaries with no `.gnu_debugdata`**: Symbol lookup will fall back
  to plain names.  If nginx was compiled without that symbol in the binary at
  all, the attach will fail with an error from BCC.

---

## How it works

Two uprobes attach to the nginx binary:

1. `ngx_http_upstream_connect(r, u)` -- entry probe.  Records a BPF
   timestamp in a hash map keyed by `(pid, upstream_pointer)`.

2. `ngx_http_upstream_finalize_request(r, u, rc)` -- entry probe.  Reads the
   stored timestamp, computes wall-clock latency, then reads nginx's own
   timing fields from `u->state` (`connect_time`, `header_time`,
   `bytes_received`), and reads the peer name from `u->state->peer`.  Emits
   everything to a BPF ring buffer.

A Python callback drains the ring buffer, accumulates per-peer stats, and
prints each event to stdout.

Struct field offsets for `inflight_t` and `ngx_http_upstream_state_t` are
computed at startup with ctypes.  The only exception is `U_OFF_STATE`, which
is hard-coded (see above).

Symbol names are resolved from the binary's `.gnu_debugdata` section before
attaching, so BCC's own libelf does the final address lookup.  No addresses
are hard-coded.
