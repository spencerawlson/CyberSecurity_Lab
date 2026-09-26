# Gift-Card IR Training Lab

A **safe, self-contained** simulation of the observable traces a "gift card scam"
malware infection leaves behind, so defenders can practise **detecting** them.

It is **not malware and not disguised**:

- All traffic stays on the loopback interface (`127.0.0.1`); the server refuses
  to bind anywhere else.
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

## Two-window version

Watch the "attacker" server separately:

```powershell
py gift_card_lab.py serve          # window 1: local-only server, leave running
py gift_card_lab.py run --announce  # window 2: the victim opening the lure
```

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

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--lab-dir PATH` | `%USERPROFILE%\gift_card_ir_lab` | Where artifacts and `events.jsonl` are written |
| `--port N` | `8765` | Loopback port for the lab server |
| `--announce` | off | Print the "TRAINING SIMULATION — SAFE" banner (`run`) |
| `--gui` | off | Also show the banner as a popup, if available (`run`) |
| `--auto-serve` | off | Start the loopback server in-process (`run`) |

## Modes

| Mode | Role | What it does |
| --- | --- | --- |
| `serve` | Attacker host | Local-only HTTP server: serves the file, receives dummy telemetry |
| `run` | Victim | Opens the lure, downloads the file, records its hash, spawns the child |
| `child` | Payload | Writes fixed `TEST_*` events and POSTs them back over loopback (spawned by `run`; not run directly) |
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
