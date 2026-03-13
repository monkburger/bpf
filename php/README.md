# PHP request latency monitor

BPF tool that shows you exactly how long each PHP request took and which script
ran it, in real time, with no changes to your PHP code or web server config.

---

## Why this exists

When a server is slow the usual approach is to grep logs, maybe enable slow
logging in FPM, stare at `top`, and guess. That works sometimes, but:

- FPM slow logging is coarse and requires a config change plus a reload.
  If the slowness is intermittent you may not catch it before the next restart.
- PHP access logs show request time at the end of the request. By then
  the information is cold.
- You usually cannot tell whether the slow requests are concentrated on a
  specific script, a specific user, a specific PHP version, or whether it
  is random.

This tool attaches BPF uprobes directly to the PHP binary at runtime. It fires
when `php_request_startup` is called, records the timestamp, then fires again
when `php_request_shutdown` returns and emits the elapsed time along with the
script filename and the OS user that ran it. No PHP code changes, no FPM config
changes, no web server restart.

It also works on servers running multiple PHP versions at the same time.

---

## What it shows

One line per completed PHP request:

```
TIME      VERSION    PID    COMM             LATENCY    USER       RESULT  SCRIPT
14:22:01  php        12304  php-fpm          43.2 ms    nobody     OK      /home/alice/public_html/index.php
14:22:01  php        12301  php-fpm          2341.0 ms  nobody     OK      /home/bob/public_html/wp-cron.php
14:22:02  php        12304  php-fpm          18.7 ms    nobody     OK      /home/alice/public_html/cart.php
14:22:02  php        12308  php              1.2 ms     alice      OK      /home/alice/bin/send_email.php
```

Latency is color coded: under 500 ms is plain, 500 ms to 2 s is yellow, over
2 s is red. Failed requests (non-zero return from `php_request_shutdown`) show
FAIL in red.

---

## Use cases

### Performance: find what's slowing down a site

Run with a threshold to cut noise and focus on slow requests:

```bash
sudo python3 php_latency_monitor.py --threshold 500
```

If a site suddenly feels sluggish this tells you in seconds which script is
responsible. To rank the worst offenders over a window, capture to a log and
count by script path:

```bash
sudo python3 php_latency_monitor.py --no-color | tee /tmp/php-latency.log
```

```bash
# after collecting a sample:
awk '{print $NF}' /tmp/php-latency.log | sort | uniq -c | sort -rn | head -20
```

This gives a request count per script, which makes it obvious if one path is
consuming a disproportionate share of worker time.

To sort by slowest request during the session:

```bash
sudo python3 php_latency_monitor.py --no-color | \
    awk 'NR>1 {print $5, $NF}' | sort -k1 -rn | head -20
```

### Performance: long-running background jobs saturating FPM workers

WP-cron, scheduled import scripts, and similar jobs can swamp an FPM pool
while the site shows normal traffic. They show up as a recurring slow line
from the same script. Capture everything (no threshold) and look for scripts
that appear many times with high latency:

```bash
sudo python3 php_latency_monitor.py --no-color | tee /tmp/php-all.log
```

```bash
awk '$8=="OK" {print $5, $NF}' /tmp/php-all.log | \
    sort -k2 | awk '{sum[$2]+=$1; count[$2]++} END {for (s in sum) printf "%6d req  %10.1f ms total  %s\n", count[s], sum[s], s}' | \
    sort -k3 -rn | head -20
```

### Performance: comparing PHP versions or apps on the same server

On a server running FPM pools for multiple apps, attach to each binary so the
VERSION column separates them in the output:

```bash
sudo python3 php_latency_monitor.py \
    --bin /usr/sbin/php-fpm:fpm:80 \
    --bin /usr/sbin/php83-fpm:fpm:83
```

If latency spikes only in one version the VERSION column makes that obvious
immediately, without having to correlate timestamps across separate log files.

### Security: detecting PHP webshell activity

PHP webshells run as ordinary PHP requests. They tend to have a few
distinguishing characteristics:

- They execute from writable directories the web server should not be running
  PHP from: upload dirs, cache dirs, `/tmp`, backup dirs, or paths with
  random-looking filenames.
- They often run as the web server user (`nobody`, `apache`, `www-data`) from
  paths that are not part of the normal application code.
- They fire repeatedly with very low latency because they are doing simple
  things like running shell commands or exfiltrating files.

Watch for this in real time by filtering on suspicious path patterns:

```bash
sudo python3 php_latency_monitor.py --no-color | \
    grep -iE "/(tmp|uploads?|cache|backup|images?|media|assets)/.*\.php"
```

Or log everything and mine it afterward:

```bash
sudo python3 php_latency_monitor.py --no-color > /tmp/php-audit.log &

# check for activity in paths that should not execute PHP:
grep -iE "/(tmp|uploads?|cache|backup|images?)/" /tmp/php-audit.log | \
    awk '{print $7, $NF}' | sort | uniq -c | sort -rn
```

A script that fires dozens or hundreds of times from an upload directory in a
short window is a strong signal. The USER column (field 7) helps too: a script
running as the web server user from a path outside the document root, or
running as `root` from any upload-adjacent directory, is almost certainly not
legitimate application traffic.

### Security: building a baseline and flagging anomalies

Capture a representative window of normal traffic and save the set of script
paths that ran. Then pipe live output through the baseline to surface anything
new:

```bash
# capture a 10-minute baseline during normal traffic
sudo timeout 600 python3 php_latency_monitor.py --no-color | \
    awk 'NR>1 {print $NF}' | sort -u > /tmp/php-baseline.txt

# later: print any script path not seen during the baseline
sudo python3 php_latency_monitor.py --no-color | \
    awk 'NR>1 {print $NF}' | grep -vFf /tmp/php-baseline.txt
```

This is not a full IDS but it is extremely low effort. Newly deployed scripts,
injected files, and anything that was not running during baseline collection
show up immediately.

---

## Install

```
dnf install python3-bcc    # RHEL / AlmaLinux / Rocky
apt install python3-bpfcc   # Debian / Ubuntu
```

You need root or `CAP_BPF + CAP_PERFMON`.

---

## Run

**Default (/usr/bin/php):**
```bash
sudo python3 php_latency_monitor.py
```

**Monitor a specific binary:**
```bash
sudo python3 php_latency_monitor.py --bin /usr/bin/php:cli:83
```

**Monitor several at once:**
```bash
sudo python3 php_latency_monitor.py \
    --bin /usr/bin/php:cli:83 \
    --bin /usr/sbin/php-fpm:fpm:83
```

**Use a config file:**
```bash
cp php-bins.toml.example php-bins.toml
# edit php-bins.toml
sudo python3 php_latency_monitor.py --config php-bins.toml
```

**Only show requests that took longer than 500 ms:**
```bash
sudo python3 php_latency_monitor.py --threshold 500
```

**No color output (for piping to a file or log aggregator):**
```bash
sudo python3 php_latency_monitor.py --no-color | tee /tmp/php-latency.log
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--bin PATH:KIND:VER` | none | Binary to monitor. KIND is fpm, cgi, or cli. VER is an integer label. Repeatable. |
| `--config FILE` | none | TOML file listing binaries. See php-bins.toml.example. |
| `--threshold MS` | 0 (show all) | Only print requests at or above this latency in milliseconds. |
| `--no-color` | off | Disable ANSI color output. |

`--bin` and `--config` can be used together. If neither is given the built-in
`--bin` and `--config` can be combined. If neither is given the tool monitors
`/usr/bin/php` as a CLI binary.

---

## Config file

The config file is TOML. Copy `php-bins.toml.example` and edit it:

```toml
[[binary]]
path    = "/usr/sbin/php-fpm"
kind    = "fpm"
version = 83

[[binary]]
path    = "/usr/bin/php"
kind    = "cli"
version = 83
```

`kind` must be `fpm`, `cgi`, or `cli`. `version` is just a label that shows up
in the VERSION column; use whatever integer makes sense for your setup.

The tool tries to load TOML using the Python 3.11+ standard library first,
then falls back to the third-party `tomli` package if available, then falls
back to a minimal built-in parser that handles the `[[binary]]` format used
here.

---

## How it works (briefly)

PHP has two functions at the boundary of every request lifecycle:
`php_request_startup` is called when a new request begins and
`php_request_shutdown` is called when it finishes. BPF uprobes let us attach
handler functions to those symbols in the running binary without modifying it.

On the entry side the tool records the current kernel timestamp and the thread
ID. On the return side it calculates the elapsed time and looks up the script
filename, which is captured via a separate probe on the filename-resolution
function for each binary type (FPM, CGI, and CLI each use a different internal
symbol).

The per-thread state lives in BPF hash maps and is cleaned up after each event
is emitted, so there is no accumulation of stale entries.

---

## Limitations

The tool needs the PHP binary to be dynamically linked and to have the relevant
symbols available. Statically linked PHP builds or very aggressively stripped
binaries may not work.

If a binary is not found on disk it is skipped with a warning. If BCC cannot
attach to a symbol (e.g. it is stripped or has a different name in that build)
it prints a warning and continues with the remaining binaries.

---

## Requirements

- Linux kernel 4.14+ (BPF uprobe support)
- python3-bcc
- PHP binaries that exist on disk
- root or `CAP_BPF + CAP_PERFMON`
