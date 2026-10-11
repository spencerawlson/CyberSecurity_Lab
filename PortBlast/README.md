# PortBlast

A small, **scope-gated** wrapper that chains real security tools into one
authorized-assessment workflow: fast port discovery, service enumeration,
Exploit-DB lookup, credential testing, local hash cracking, and single-module
exploitation.

Unlike the other labs in this repo (which are loopback-only *simulations* of
attack traces), PortBlast drives **real tooling against real hosts**. Its safety
model is therefore an **explicit scope allowlist**, not a sandbox:

- Every network-facing action validates its target against
  [`scope.json`](scope.json) first. A target that is not a literal IP inside an
  authorized network is refused before a single packet is sent.
- The default scope is private lab ranges only (`192.168.1.0/24`,
  `10.10.10.0/24`). Edit `scope.json` to match your engagement.
- `crack` is the one command that is *not* scope-gated — it reads a local hash
  file and does no network I/O.

> Run this only against systems and networks you own or are explicitly
> authorized to test. See the repo's
> [operator's manual](../docs/DETECTION_LAB_MANUAL.md) *Rules of engagement*.

## Requirements

- **Python 3.9+** (standard library only — nothing to `pip install`).
- The external tools you want to use, on your `PATH`. PortBlast detects but does
  not install them:

  | Tool | Used by | Required? |
  | --- | --- | --- |
  | [RustScan](https://github.com/RustScan/RustScan) | `scan` (discovery) | optional — falls back to a full Nmap scan |
  | [Nmap](https://nmap.org/) | `scan` (enumeration) | **required for `scan`** |
  | [SearchSploit](https://gitlab.com/exploit-database/exploitdb) | `scan` (auto, passive) | optional |
  | [Hydra](https://github.com/vanhauser-thc/thc-hydra) | `bruteforce` | required for that command |
  | [John the Ripper](https://www.openwall.com/john/) | `crack` | required for that command |
  | [Metasploit](https://www.metasploit.com/) | `exploit` | required for that command |

Check what's installed:

```powershell
py portblast.py tools
```

## Commands

### `scan` — discover + enumerate + research

```powershell
py portblast.py scan 192.168.1.50
```

Runs RustScan for fast port discovery (if present), then Nmap `-sV` service/
version detection on the open ports. When SearchSploit is installed it then
looks up each enumerated product/version in the local Exploit-DB and lists any
matches inline (`! EDB-<id>`). Results — services and their exploit matches —
are written to `reports/<ip>_<UTC timestamp>.json`. Use `--silent` to suppress
console output (the report is still written).

### `crack` — John the Ripper (local, not scope-gated)

```powershell
py portblast.py crack hashes.txt --format raw-md5 --wordlist rockyou.txt
```

Runs a cracking pass, then `john --show`, and prints the recovered
`username  password` pairs.

### `bruteforce` — Hydra (scope-gated)

```powershell
py portblast.py bruteforce 192.168.1.50 ssh -l root -P passwords.txt
```

Tests credentials against a single service. Supply a single username (`-l`) or a
list (`-L`), and a single password (`-p`) or a list (`-P`). `service` is a Hydra
module name (`ssh`, `ftp`, `http-get`, …). Recovered credentials are printed.

### `exploit` — Metasploit (scope-gated)

```powershell
py portblast.py exploit 192.168.1.50 --module exploit/multi/handler --option LPORT=4444
```

Builds a one-shot Metasploit resource script (`use` → `set RHOSTS` → your
`--option KEY=VALUE` pairs → `run` → `exit`) and runs it under `msfconsole -q`.
You choose the module and options — PortBlast does not auto-select exploits off
the scan results.

## Configuring scope

[`scope.json`](scope.json):

```json
{
    "authorized_networks": [
        "192.168.1.0/24",
        "10.10.10.0/24"
    ]
}
```

Both IPv4 and IPv6 networks are accepted (anything `ipaddress.ip_network`
understands). An empty or missing list is an error — PortBlast will not run a
network command with no scope defined.

## Tests

```powershell
py test_portblast.py
```

The suite mocks out every external binary, so it runs with none of them
installed. It covers scope validation, the RustScan and Nmap-XML parsers, the
SearchSploit JSON parser, the Hydra output regex, the John `--show` filter, the
Metasploit resource-script builder, and the `key=value` option parser.

## Layout

| File | Responsibility |
| --- | --- |
| [portblast.py](portblast.py) | CLI entry point and command dispatch |
| [scope.py](scope.py) | Scope allowlist loading and target validation |
| [scanner.py](scanner.py) | RustScan discovery + Nmap enumeration/XML parsing |
| [vuln.py](vuln.py) | SearchSploit (Exploit-DB) lookup |
| [creds.py](creds.py) | Hydra credential testing + John hash cracking |
| [exploit.py](exploit.py) | Metasploit module execution |
| [reporting.py](reporting.py) | JSON report writer |
| [models.py](models.py) | `Service` / `Target` dataclasses |
| [tools.py](tools.py) | Tool + platform detection |
