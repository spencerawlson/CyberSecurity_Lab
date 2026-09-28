# CyberSecurity_Lab — Blue-Team Detection Training Labs

A collection of **safe, self-contained simulations** that reproduce the
*observable traces* of common attacks, so defenders can practise **detecting**
them with real tooling (Sysmon, EDR, Procmon, Wireshark/tcpdump).

These are **detection-training simulations, not attack tools.** Every lab:

- keeps all traffic on **loopback (`127.0.0.1`)** by default — reaching another
  host needs an explicit `--allow-lan`, which permits **private/lab ranges only**
  (RFC1918 / CGNAT / link-local / loopback); **public addresses are always refused**;
- does **no source-IP spoofing** and runs **no real payloads** (dummy files, fixed
  `TEST_*` events, logged-not-executed injection probes, bounded resource use);
- writes an `events.jsonl` **answer key** and ships `report` (timeline + IOCs) and
  `detect` (hunting guidance) commands.

> **Optional real telemetry (gift-card lab only).** Its `--with-monitoring` flag
> additionally starts real *local* host-telemetry collectors — keystrokes,
> clipboard, periodic screenshots, and the active-window/process list — so you
> can generate genuine endpoint telemetry to hunt in. It is **off by default**,
> prints/saves only locally, sends nothing off the box, and is separate from the
> simulated payload (which only writes fixed `TEST_*` events). See
> [gift_card_lab/README.md](gift_card_lab/README.md#optional-real-host-monitoring).

> Run these only on systems and networks you own or are explicitly authorized to
> test. See the manual's *Rules of engagement* before you start.

## The labs

| Lab | Folder | Protocol / port | Simulates | MITRE |
| --- | --- | --- | --- | --- |
| Gift-Card IR | [gift_card_lab/](gift_card_lab/) | TCP/HTTP **8765** | Lure → payload → **persistence** → C2 beacon → exfil | T1036, T1204, T1547.001, T1053.005, T1071, T1041 |
| DDoS | [ddos_lab/](ddos_lab/) | TCP/HTTP **8768** | Volumetric, slow-rate & **HTTP/2 rapid reset** (CVE-2023-44487) | T1498, T1499 |
| Amplification | [amplification_lab/](amplification_lab/) | **UDP 8769** | UDP reflection / amplification — **DNS/NTP/SSDP/memcached** profiles | T1498.002 |
| Web-Attack | [web_attack_lab/](web_attack_lab/) | TCP/HTTP **8770** | Credential stuffing, enumeration, injection, **SSRF**, **path traversal**, port scan | T1110, T1595, T1190, T1083, T1552.005 |

Each folder is self-contained: the lab script, its tests, and a `README.md`. The
gift-card and DDoS labs also ship a `RUN-TRAINING-SIMULATION.cmd` double-click
launcher (plus a `make-shortcut.ps1`); run the amplification and web-attack labs
from a terminal — see each lab's `README.md`.

## The operator's manual

**[docs/DETECTION_LAB_MANUAL.md](docs/DETECTION_LAB_MANUAL.md)** (also as
**[PDF](docs/DETECTION_LAB_MANUAL.pdf)**) is the full guide to running every lab
with Sysmon, EDR, Procmon, and packet capture (Wireshark / tcpdump) — properly,
efficiently, and ethically. It covers tool setup, the efficient run→capture→
compare workflow, per-lab playbooks with ready-to-paste queries/filters, and the
rules of engagement.

## Quick start

Requires **Python 3.9+** (standard library only — nothing to install for the core
labs; the gift-card lab's optional `--with-monitoring` needs `requirements.txt`).

```powershell
cd gift_card_lab
py gift_card_lab.py run --announce --auto-serve   # run a scenario
py gift_card_lab.py report                         # see the answer key
py gift_card_lab.py detect                         # see what to hunt for
py gift_card_lab.py reset                          # clean up
```

Every lab follows the same `serve` / attack / `run` / `report` / `detect` /
`reset` pattern — see each lab's own `README.md` for its specific modes and flags.

## Running the tests

From any lab folder:

```powershell
py -m pytest -q
```

Every push and pull request also runs all four suites on Ubuntu and Windows
(Python 3.9 and 3.13) via GitHub Actions — see
[.github/workflows/tests.yml](.github/workflows/tests.yml).

## Repository layout

```
CyberSecurity_Lab/
├─ README.md                     (this file)
├─ docs/
│  ├─ DETECTION_LAB_MANUAL.md
│  └─ DETECTION_LAB_MANUAL.pdf
├─ site/                         static page for spencerlab.tech/labs/ (deploy notes inside)
├─ gift_card_lab/                lure → payload → persistence → C2 beacon → exfil
├─ ddos_lab/                     volumetric, slow-rate & HTTP/2 rapid reset
├─ amplification_lab/            UDP reflection / amplification (DNS/NTP/SSDP/memcached)
└─ web_attack_lab/               credstuff / enum / inject / ssrf / traversal / portscan
```

## Published site

A static write-up of these labs is published at
**[spencerlab.tech/labs](https://spencerlab.tech/labs/)**. The page source lives in
[`site/`](site/) — see [site/README.md](site/README.md) for the (CSP-aware) deploy steps.

---

*For authorized detection training only. You are responsible for using these labs
lawfully and on systems you own or are permitted to test.*
