# Gift-Card IR Training Lab

A **safe, self-contained** simulation of the observable traces a "gift card scam"
malware infection leaves behind, so defenders can practise **detecting** them.

It is **not malware and not disguised**:

- All traffic stays on the loopback interface (`127.0.0.1`) by default. Running
  the halves on separate lab VMs requires the explicit `--allow-lan` flag, which
  permits **private/lab ranges only** (RFC1918 / CGNAT / link-local / loopback);
  any public address is refused. See the [Cross-host](#cross-host-two-vms-on-your-lab-network) section.
- The "download" is a plain text file that says it is simulated.
- The "keylogger" never reads the keyboard — it writes three fixed `TEST_*`
  events.
- Every step is logged to `events.jsonl` as an answer key.

Run it on a lab/training VM. Requires Python 3.9+ (no packages to install).

## Quick start

**Double-click** `RUN-TRAINING-SIMULATION.cmd`, or from a terminal in this folder:

```powershell
py gift_card_lab.py run --announce --auto-serve
```

(`--auto-serve` starts the loopback server in-process, so this is all you need.
Use `python` instead of `py` if `py` isn't on your system. Add `--gui` for a
popup banner during class demos.)

## Two-window version (same machine)

Watch the "attacker" server separately:

```powershell
py gift_card_lab.py serve          # window 1: local-only server, leave running
py gift_card_lab.py run --announce  # window 2: the victim opening the lure
```

## Cross-host (two VMs on your lab network)

To play the "attacker" server and the "victim" on **separate machines you
control**, add `--allow-lan` on both sides. It permits **private/lab ranges
only** (RFC1918, CGNAT `100.64/10`, link-local, IPv6 ULA, loopback); any
**public** address is refused.

On the **attacker** VM (e.g. Kali), host the lure server:

```bash
py gift_card_lab.py serve --allow-lan --bind 0.0.0.0 --port 8765
# find its IP with:  ip a
```

On the **victim** VM (e.g. UbuntuServ / Debian), open the lure against it:

```bash
py gift_card_lab.py run --announce --allow-lan --server 192.168.1.50 --port 8765
```

`report` on each side shows its own half; the server records the victim's real
source IP under `client`. Don't combine `--server` with `--auto-serve` (that
starts a *local* server) — use `serve` on the other machine instead.

> **Networking note:** Kali (VMware) and Debian/UbuntuServ (Proxmox) are on
> different hypervisors, so they must be **bridged onto the same physical LAN**
> to reach each other — host-only/NAT networks won't span the two hosts.
> Confirm with `ping <server-ip>` first. Only do this on a lab network you own.

## After a run

```powershell
py gift_card_lab.py report   # timeline + IOC summary (the answer key)
py gift_card_lab.py detect   # blue-team hunting guide (Sysmon / KQL queries)
py gift_card_lab.py reset    # wipe the lab dir to repeat cleanly
```

## The exercise

While it runs, have your detection tooling active — Sysmon, EDR, Procmon, or a
loopback packet capture. Then compare what your tools caught against `report`,
using `detect` for what to hunt for (process chain, file writes, the loopback
connection). Everything stays on `127.0.0.1`.

## Post-compromise: C2 beaconing & exfil

Two extra modes model what a real implant does *after* the lure runs. Start the
server (`serve`, in another window or on the attacker VM), then:

```powershell
py gift_card_lab.py beacon --beacons 20 --interval 3 --jitter 1   # regular C2 check-ins
py gift_card_lab.py exfil  --exfil-bytes 262144 --chunk 16384     # staged data theft
```

- **`beacon`** does evenly-spaced `/c2-beacon` check-ins (with jitter) — graph
  the `c2_beacon_sent` timestamps and you'll see the periodicity defenders hunt
  for (MITRE T1071).
- **`exfil`** dribbles dummy "sensitive" bytes out in fixed chunks to `/exfil` —
  the `exfil_chunk_sent` events tally the growing outbound volume (MITRE T1041).

Both are harmless (no real data, capped, private-network only) and pair with the
new sections in `detect`. Add `--server <ip> --allow-lan` to beacon/exfil across
VMs. **Tip:** on the *same host*, give the server and the client separate
`--lab-dir` values (or use `run`) so their shared `events.jsonl` stays pristine.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--lab-dir PATH` | `%USERPROFILE%\gift_card_ir_lab` | Where artifacts and `events.jsonl` are written |
| `--port N` | `8765` | Port for the lab server |
| `--bind HOST` | `127.0.0.1` | Address the server listens on (`serve`); use a LAN IP or `0.0.0.0` with `--allow-lan` |
| `--server HOST` | `127.0.0.1` | Address the victim reaches (`run`); a private/lab host, needs `--allow-lan` |
| `--allow-lan` | off | Permit binding/reaching your **private** lab network; public addresses are always refused |
| `--announce` | off | Print the "TRAINING SIMULATION — SAFE" banner (`run`) |
| `--gui` | off | Also show the banner as a popup, if available (`run`) |
| `--auto-serve` | off | Start the loopback server in-process (`run`) |

## Modes

| Mode | Role | What it does |
| --- | --- | --- |
| `serve` | Attacker host | HTTP server: serves the lure, receives telemetry, C2 beacons, and exfil |
| `run` | Victim | Opens the lure, downloads the file, records its hash, spawns the child |
| `child` | Payload | Writes fixed `TEST_*` events and POSTs them back over loopback (spawned by `run`; not run directly) |
| `beacon` | Implant | Regular C2 check-ins with jitter (T1071) — `--beacons/--interval/--jitter` |
| `exfil` | Implant | Staged outbound data theft in chunks (T1041) — `--exfil-bytes/--chunk` |
| `report` | — | Prints a timeline and IOC summary |
| `detect` | — | Prints blue-team detection guidance |
| `reset` | — | Deletes the lab directory (guarded so it won't delete a non-lab path) |

## Files

- `gift_card_lab.py` — the lab
- `test_gift_card_lab.py` — tests (`py test_gift_card_lab.py`)
- `RUN-TRAINING-SIMULATION.cmd` — honest double-click launcher
- `make-shortcut.ps1` — creates a clearly-labelled desktop shortcut (standard icon, no disguise)

## Optional: desktop shortcut

```powershell
powershell -ExecutionPolicy Bypass -File make-shortcut.ps1
```
