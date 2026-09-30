# Port Scanner

A simple TCP port scanner written in Python — scans a target for open
ports, with support for concurrent scanning and basic banner grabbing.

It started as a small script using `socket.connect()` to test a single
port (basically an `nc -z` equivalent) and evolved into a command-line
tool with port range parsing, concurrent scanning, and banner reading.

## Features

- Scan ports via range (`1-1000`), list (`22,80,443`), or a combination
  of both (`22,80,1000-2000`)
- Concurrent scanning with `ThreadPoolExecutor` — configurable thread
  count
- Configurable per-port timeout
- Optional banner grabbing (`--banner`) — attempts to read the service's
  response on open ports; if the service doesn't respond on its own, it
  falls back to a basic HTTP request

## Usage

```bash
# Scan a range
python3 port_scanner.py -t 192.168.1.1 -p 1-1000

# Scan specific ports
python3 port_scanner.py -t 192.168.1.1 -p 22,80,443

# Full scan with banner grabbing and more threads
python3 port_scanner.py -t scanme.nmap.org -p 1-1000 --threads 50 --banner
```

### Arguments

| Argument        | Required | Description                                   | Default |
|-----------------|:--------:|------------------------------------------------|:-------:|
| `-t, --target`  |   yes    | Target IP or hostname                           | —       |
| `-p, --ports`   |   yes    | Ports to scan (`1-1000`, `22,80`, etc)          | —       |
| `--timeout`     |    no    | Per-port timeout, in seconds                    | `1.0`   |
| `--threads`     |    no    | Concurrent threads                               | `100`   |
| `--banner`      |    no    | Attempt to read a banner/response on open ports  | `False` |

## How it works

At its core, this tool does the same thing as `nc -z <host> <port>`: open
a TCP socket and check whether `connect()` succeeds, times out, or is
refused. The difference is what's built around that:

1. **Concurrency** — instead of testing ports one at a time (which takes
   minutes on a large range), the scan runs in parallel using a
   `ThreadPoolExecutor`.
2. **`connect_ex()` instead of `connect()`** — returns an error code
   instead of raising an exception on every closed port, simplifying the
   loop.
3. **Port range parsing** — accepts several port notations and normalizes
   them into a list of unique integers, validating the 1-65535 range.
4. **Banner grabbing** — on open ports, it first tries to read whatever
   the service sends on its own (SSH banner, FTP banner, etc); if nothing
   comes back, it sends a basic `GET / HTTP/1.1` request to force a
   response from HTTP services.

## Possible improvements

- `--discover`: ping sweep across a `/24` range to find live hosts before
  scanning ports
- Structured output in JSON/CSV
- Service detection based on banner signature (not just default port)
- UDP scan support

## Disclaimer

Only use this against targets you own or have explicit authorization to
test (e.g. your own network, `scanme.nmap.org`). Scanning third-party
hosts without permission may violate terms of service and, depending on
the jurisdiction, local law.
