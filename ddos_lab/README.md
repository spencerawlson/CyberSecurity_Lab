# DDoS IR Training Lab

A **safe, self-contained** simulation of the observable traces a denial-of-service
attack leaves behind, so defenders can practise **detecting** them.

It is **not an attack tool and not disguised**:

- Everything stays on the loopback interface (`127.0.0.1`) by default. Reaching
  another machine requires the explicit `--allow-lan` flag, and even then both
  halves accept **private/lab ranges only** — any public/routable address is
  refused. See `assert_lab_target()` / `assert_lab_bind()`. It cannot target the
  internet.
- "Attacker" sources are simulated with a header label drawn from the RFC 5737
  documentation ranges (`203.0.113.0/24`, etc.). Nothing is spoofed; no real
  source address is forged.
- Worker count and duration are **hard-capped** (`MAX_WORKERS=256`,
  `MAX_DURATION=300`), so it produces a short, clear spike — not an open-ended hog.
- Every step is logged to `events.jsonl` as an answer key.

Run it on a lab/training VM. Requires Python 3.9+ (no packages to install).

## Quick start

**Double-click** `RUN-TRAINING-SIMULATION.cmd`, or from a terminal in this folder:

```powershell
py ddos_sim.py run --announce --attack volumetric
```

(`run` starts the loopback victim in-process, captures a baseline, generates the
flood, and prints the before/after. Use `python` instead of `py` if `py` isn't on
your system. Add `--gui` for a popup banner during class demos.)

Try the other attack styles too — each has a different detection signature:

```powershell
py ddos_sim.py run --announce --attack slowloris   # slow-rate: holds headers
py ddos_sim.py run --announce --attack rudy         # slow-rate: holds POST body
py ddos_sim.py run --announce --attack slowread     # slow-rate: reads response slowly
py ddos_sim.py run --announce --attack cachebust    # volumetric: every URL unique
py ddos_sim.py run --announce --attack connflood    # connection churn (fresh socket each)
py ddos_sim.py run --announce --attack bodyflood    # bandwidth: large POST bodies
py ddos_sim.py run --announce --attack rapidreset   # HTTP/2 rapid reset (CVE-2023-44487)
```

| Attack | Signature at the victim |
| --- | --- |
| `volumetric` | high requests/sec, many sources, connections reused |
| `cachebust` | high **unique-URL** count — cache/CDN can't absorb it |
| `connflood` | connections ≈ requests (fresh socket each) — accept-queue exhaustion |
| `bodyflood` | inbound **bytes** spike — bandwidth exhaustion |
| `rapidreset` | **aborted connections** spike; streams opened then cancelled, few complete (CVE-2023-44487) |
| `slowloris` | concurrency climbs, requests never complete (held headers) |
| `rudy` | concurrency climbs, held POST body |
| `slowread` | completes request, then drains response at a trickle |

`detect` explains which lab metric exposes each one.

## Two-window version (same machine)

Watch the victim server absorb the load separately:

```powershell
py ddos_sim.py serve                       # window 1: loopback-only victim, leave running
py ddos_sim.py flood --attack volumetric   # window 2: the simulated flood
```

Live metrics while it runs: `http://127.0.0.1:8768/stats`.

## Cross-host (two VMs on your lab network)

By default everything stays on loopback. To run the victim and the attacker on
**separate machines you control**, add `--allow-lan` on both sides. It permits
**private/lab ranges only** (RFC1918 `10/8`, `172.16/12`, `192.168/16`, CGNAT
`100.64/10`, link-local, IPv6 ULA/loopback); any **public** address is refused,
so this can't be pointed at the internet.

On the **victim** VM (e.g. UbuntuServ / Debian), bind to its LAN IP or all
interfaces:

```bash
py ddos_sim.py serve --allow-lan --bind 0.0.0.0 --port 8768
# find its IP with:  ip a
```

On the **attacker** VM (e.g. Kali), point the flood at the victim's IP:

```bash
py ddos_sim.py flood --allow-lan --target 192.168.1.50 --attack volumetric --workers 80 --duration 20
py ddos_sim.py flood --allow-lan --target 192.168.1.50 --attack slowloris  --workers 120 --duration 20
```

Then run `report` **on the victim** (that's where `events.jsonl` lives).

> **Networking note:** Kali (VMware) and Debian/UbuntuServ (Proxmox) are on
> different hypervisors, so they must be **bridged onto the same physical LAN**
> to reach each other — host-only/NAT networks won't span the two hosts.
> Confirm with `ping <victim-ip>` from Kali before running the drill. Only do
> this on a lab network you own.

## After a run

```powershell
py ddos_sim.py report   # timeline + attack-signature summary (the answer key)
py ddos_sim.py detect   # blue-team hunting guide (T1498/T1499, queries, mitigations)
py ddos_sim.py reset    # wipe the lab dir to repeat cleanly
```

## The exercise

While it runs, have your detection tooling active — a rate/latency dashboard,
web-server metrics, `netstat`, or a loopback packet capture. Then compare what
your tools caught against `report`, using `detect` for what to hunt for:

- **Volumetric flood** → request rate jumps from baseline to a large spike, many
  sources, latency climbs. Watch `rate_threshold_exceeded` in the timeline.
- **Slowloris** → concurrent connections climb and stay open while completed
  requests stay flat. Watch `connection_threshold_exceeded`.

Everything stays on `127.0.0.1`.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--lab-dir PATH` | `%USERPROFILE%\ddos_ir_lab` | Where `events.jsonl` is written |
| `--port N` | `8768` | Port for the victim server |
| `--bind HOST` | `127.0.0.1` | Address the victim listens on (`serve`); use a LAN IP or `0.0.0.0` with `--allow-lan` |
| `--target HOST` | `127.0.0.1` | Address to send load to (`flood`); a private/lab host, needs `--allow-lan` |
| `--allow-lan` | off | Permit binding/targeting your **private** lab network; public addresses are always refused |
| `--attack NAME` | `volumetric` | Attack style: `volumetric`, `cachebust`, `connflood`, `bodyflood`, `rapidreset`, `slowloris`, `rudy`, `slowread` |
| `--workers N` | `50` | Simulated attacker workers (max `256`) |
| `--duration N` | `10` | Seconds to generate load (max `300`) |
| `--alert-rps N` | `100` | Requests/sec that fires the mock volumetric alert |
| `--alert-conns N` | `100` | Concurrent conns that fires the mock slowloris alert |
| `--announce` | off | Print the "TRAINING SIMULATION — SAFE" banner (`run`) |
| `--gui` | off | Also show the banner as a popup, if available (`run`) |

## Modes

| Mode | Role | What it does |
| --- | --- | --- |
| `serve` | Victim | HTTP server (loopback, or a lab IP with `--allow-lan`); measures rate, connections, sources, latency |
| `flood` | Attacker | Generates simulated `volumetric` or `slowloris` load against the victim (loopback, or a lab IP with `--allow-lan`) |
| `run` | Both | One-click: victim in-process + baseline + flood + summary |
| `report` | — | Prints the timeline and attack-signature summary |
| `detect` | — | Prints blue-team detection guidance |
| `reset` | — | Deletes the lab directory (guarded so it won't delete a non-lab path) |

## Files

- `ddos_sim.py` — the lab
- `test_ddos_sim.py` — tests (`py test_ddos_sim.py`)
- `RUN-TRAINING-SIMULATION.cmd` — honest double-click launcher
- `make-shortcut.ps1` — creates a clearly-labelled desktop shortcut (standard icon, no disguise)

## Optional: desktop shortcut

```powershell
powershell -ExecutionPolicy Bypass -File make-shortcut.ps1
```
