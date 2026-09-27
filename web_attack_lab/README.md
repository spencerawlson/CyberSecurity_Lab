# Web-Attack IR Training Lab

A **safe, self-contained** simulation of the traces common web attacks leave in
access logs and connection telemetry, so defenders can practise **detecting**
them. Loopback-only by default; `--allow-lan` reaches **private lab ranges
only** (public addresses are refused). The victim **only logs** what it
receives — injection payloads are recorded, never executed.

Requires Python 3.9+ (no packages).

## Quick start

```powershell
py web_attack_lab.py run --announce --attack credstuff
py web_attack_lab.py run --announce --attack enum
py web_attack_lab.py run --announce --attack inject
py web_attack_lab.py run --announce --attack portscan
```

`run` starts the victim (web app + a bank of TCP sensor ports) in-process, runs
the attack, and prints the observed 200/401/404 counts and scan width.

## Two-window / cross-host

```powershell
py web_attack_lab.py serve                          # victim (loopback)
py web_attack_lab.py attack --attack credstuff      # attacker
```

Across VMs (private lab only): `serve --allow-lan --bind 0.0.0.0` on the victim,
`attack --allow-lan --target <victim-ip>` on the attacker.

## After a run

```powershell
py web_attack_lab.py report   # timeline + signature summary (answer key)
py web_attack_lab.py detect   # blue-team hunting guide (T1110 / T1595 / T1190)
py web_attack_lab.py reset    # wipe the lab dir
```

## Attacks & signatures

| Attack | MITRE | Signature at the victim |
| --- | --- | --- |
| `credstuff` | T1110 | 401 burst, many **usernames**, one endpoint (`/login`); one 200 = a hit |
| `enum` | T1595 | 404 burst across many **distinct paths**; a few 200s reveal real content |
| `inject` | T1190 | request params carry SQLi/XSS/traversal markers (**logged, not run**) |
| `portscan` | T1595.001 | one source touches **many ports** in a short window |

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--attack NAME` | `credstuff` | `credstuff`, `enum`, `inject`, `portscan` |
| `--port N` | `8770` | Victim web port (sensor ports are `N+1..N+16`) |
| `--bind HOST` | `127.0.0.1` | Victim listen address (`serve`); LAN IP/`0.0.0.0` needs `--allow-lan` |
| `--target HOST` | `127.0.0.1` | Address to attack (`attack`); private/lab host, needs `--allow-lan` |
| `--allow-lan` | off | Permit **private** lab network; public addresses refused |
| `--workers N` | `20` | Concurrent workers (max `128`) |
| `--rounds N` | `3` | Repeat the cred/word list N times (max `50`) |
| `--alert-401 / --alert-404 / --alert-scan` | `25/25/8` | Thresholds that fire the mock alerts |

## Modes

`serve` (victim + port sensors) · `attack` (generate one attack) · `run`
(one-click) · `report` · `detect` · `reset`.
