# UDP Amplification Concept Lab

A **safe** demonstration of *why* reflection/amplification DDoS works: a tiny
query provokes a large response. You measure the **amplification factor** and
learn to detect the pattern.

**It is not a usable attack tool.** There is **no source-IP spoofing** and no
way to add it, so the amplified responses only ever come back to **you** —
you cannot aim them at a third party. That is the entire difference between this
lab and a weapon. Loopback-only by default; `--allow-lan` reaches **private lab
ranges only** (public refused). Response size and query count are capped.

Requires Python 3.9+ (no packages).

## Quick start

```powershell
py amp_lab.py run --announce --factor 100 --queries 200
```

Starts the reflector in-process, sends small queries, and reports how many bytes
came back per byte sent (the amplification factor).

## Two-window / cross-host

```powershell
py amp_lab.py serve --factor 100        # reflector (loopback)
py amp_lab.py reflect --queries 500     # measure the factor
```

Across VMs (private lab only): `serve --allow-lan --bind 0.0.0.0` on one box,
`reflect --allow-lan --target <reflector-ip>` on another.

## After a run

```powershell
py amp_lab.py report   # timeline + amplification summary
py amp_lab.py detect   # blue-team guide (MITRE T1498.002) — as victim AND as reflector
py amp_lab.py reset
```

## The lesson

Real attacks forge the **victim's** IP as the query source so the big responses
flood the victim, off reflectors like open DNS resolvers, NTP `monlist`, or
memcached (factors from ~28× to tens of thousands×). `detect` covers spotting it
both as the target and as an unwitting amplifier, plus BCP38 ingress filtering
and shutting down open amplifiers.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--factor N` | `50` | Response-to-query size ratio (capped at ~60 KB response) |
| `--queries N` | `200` | Queries to send (max `20000`) |
| `--port N` | `8769` | UDP port for the reflector |
| `--bind HOST` | `127.0.0.1` | Reflector listen address (`serve`); LAN IP/`0.0.0.0` needs `--allow-lan` |
| `--target HOST` | `127.0.0.1` | Reflector address (`reflect`); private/lab host, needs `--allow-lan` |
| `--allow-lan` | off | Permit **private** lab network; public refused |
