# Running the Simulations

Command reference for the four detection labs. Linux, `python3` (3.9+), standard
library only — nothing to install.

Every lab is self-contained: each `run` starts its own server **in-process**, so
a normal drill needs just **one terminal per lab**, opened in that lab's folder.
Two terminals / two hosts are only for watching the "attacker" and "victim"
halves separately.

## Run all four simulations (one terminal, from the repo root)

```bash
cd gift_card_lab        && python3 gift_card_lab.py run --announce --auto-serve && python3 gift_card_lab.py report
cd ../ddos_lab          && python3 ddos_sim.py run --attack volumetric --announce && python3 ddos_sim.py report
cd ../amplification_lab && python3 amp_lab.py run --announce                       && python3 amp_lab.py report
cd ../web_attack_lab    && python3 web_attack_lab.py run --attack credstuff --announce && python3 web_attack_lab.py report
cd ..
```

Add `--gui` to any `run` for a popup banner (best-effort; needs a display).

## Where to run what — per lab

| Lab | Folder (cd here) | One-click (single terminal) | Read-outs |
| --- | --- | --- | --- |
| Gift-Card | `gift_card_lab` | `python3 gift_card_lab.py run --announce --auto-serve` | `report` · `detect` · `reset` |
| DDoS | `ddos_lab` | `python3 ddos_sim.py run --attack volumetric --announce` | `report` · `detect` · `reset` |
| Amplification | `amplification_lab` | `python3 amp_lab.py run --announce` | `report` · `detect` · `reset` |
| Web-Attack | `web_attack_lab` | `python3 web_attack_lab.py run --attack credstuff --announce` | `report` · `detect` · `reset` |

- `report` — timeline + IOC/metrics answer key
- `detect` — blue-team hunting guidance (indicators, queries, capture filters)
- `reset` — delete the lab working directory to repeat cleanly

## All attack / scenario variants

```bash
# DDoS (ddos_lab) — swap the --attack value
python3 ddos_sim.py run --attack volumetric --announce   # also: cachebust connflood
python3 ddos_sim.py run --attack slowloris   --announce   #       bodyflood rudy slowread

# Web-Attack (web_attack_lab)
python3 web_attack_lab.py run --attack credstuff --announce   # also: enum inject portscan

# Gift-Card extras (C2 beacon + exfil) — need a server running first:
python3 gift_card_lab.py serve                                    # terminal 1 (leave running)
python3 gift_card_lab.py beacon --beacons 20 --interval 2 --jitter 0.5   # terminal 2
python3 gift_card_lab.py exfil  --exfil-bytes 262144 --chunk 16384        # terminal 2

# Optional: real LOCAL host telemetry during a run (keystrokes/clipboard/
# screenshots/processes). Off by default; own/authorized machines only. Needs
# `pip install -r gift_card_lab/requirements.txt`. See gift_card_lab/README.md.
python3 gift_card_lab.py run --announce --auto-serve --with-monitoring
```

## Two terminals on one machine (watch the listener separately)

Roles differ per lab, so terminal 1 is always the listener:

| Lab | Terminal 1 — listener | Terminal 2 — generator |
| --- | --- | --- |
| Gift-Card | `python3 gift_card_lab.py serve` *(attacker host)* | `python3 gift_card_lab.py run --announce` *(victim)* |
| DDoS | `python3 ddos_sim.py serve` *(victim)* | `python3 ddos_sim.py flood --attack volumetric` *(attacker)* |
| Amplification | `python3 amp_lab.py serve` *(reflector)* | `python3 amp_lab.py reflect` *(client)* |
| Web-Attack | `python3 web_attack_lab.py serve` *(victim)* | `python3 web_attack_lab.py attack --attack enum` *(attacker)* |

## Two hosts (only on a lab network you own)

Add `--allow-lan` on **both** sides; bind the server to all interfaces and point
the client at its IP. Private/lab ranges only — public addresses are always
refused. The client flag is `--server` for gift-card, `--target` for ddos/amp/web.

```bash
# server VM
python3 gift_card_lab.py serve --allow-lan --bind 0.0.0.0
ip a                                            # find this box's IP
# client / victim VM
python3 gift_card_lab.py run   --allow-lan --server 192.168.1.50
python3 ddos_sim.py      flood --allow-lan --target 192.168.1.50 --attack volumetric
```

## Reading results afterward

You **don't** need a packet capture to see what a run did — every lab writes an
`events.jsonl` answer key that you can read any time after the run:

```bash
cd ddos_lab
python3 ddos_sim.py report     # timeline + metrics (prints the events.jsonl path)
python3 ddos_sim.py detect     # what a defender should hunt for
cat ~/ddos_ir_lab/events.jsonl # the raw JSON-lines answer key
```

Same for the others — the default lab directory is under your home:
`~/gift_card_ir_lab`, `~/ddos_ir_lab`, `~/amp_ir_lab`, `~/web_attack_lab`.

Packets, on the other hand, exist **only if `tcpdump` was running during the
run** — nothing stores them otherwise. See
[Capturing packets reliably](#capturing-packets-reliably) below for how to catch
them, including leaving a capture running so timing never bites you.

In short: **`report` / `detect` = what happened (always available); a `.pcap` =
the packets (only if you captured during the run).**

## Capturing packets reliably

`tcpdump` only records while it is actually running, so an **empty capture**
(reading it prints just the `reading from file …` header and no packets) almost
always means the capture and the traffic didn't overlap in time — not a filter or
interface problem. Two habits avoid it: start the capture **before** the sim, and
**verify** it caught something.

### Verify it works (two terminals)

Run a live view first — if packets scroll while the sim runs, your interface and
filter are correct:

```bash
# Terminal A — live view, no file
sudo tcpdump -i lo -nn -vvv port 8768
# Terminal B — generate traffic
python3 ddos_sim.py run --attack volumetric --announce
```

Then capture to a file and trust the count `tcpdump` prints when you stop it:

```bash
sudo tcpdump -i lo -nn -w ddos.pcap port 8768      # Ctrl+C after the sim finishes
#  -> "NNN packets captured"   <-- must be > 0
tcpdump -r ddos.pcap -nn | wc -l                   # sanity-count afterward
```

### One terminal (background, with a real delay)

The usual reason a backgrounded capture comes back empty is that the sim starts
(and finishes) before `tcpdump` has attached. Give it a proper `sleep`, and let
it run a beat past the end of the run:

```bash
sudo tcpdump -i lo -nn -w ddos.pcap port 8768 &    # needs sudo
sleep 2                                             # let tcpdump attach FIRST
python3 ddos_sim.py run --attack volumetric --announce
sleep 1                                             # let the tail of the traffic land
sudo pkill -INT -f 'tcpdump.*ddos.pcap'             # -INT stops it AND prints the count
tcpdump -r ddos.pcap -nn | wc -l
```

(Capturing needs `sudo`; reading a `.pcap` back does not. Don't use `sudo kill
%1` — `%1` is a shell job-spec `sudo` can't resolve; use `pkill` as above.)

### Where the file lands

`-w ddos.pcap` writes **relative to the directory `tcpdump` was launched from**,
so a capture started from your home directory leaves `~/ddos.pcap`, not one in
`ddos_lab/`. Use an absolute path to keep captures beside their lab:

```bash
sudo tcpdump -i lo -nn -w ~/CyberSecurity_Lab/ddos_lab/ddos.pcap port 8768
find ~ -name '*.pcap' 2>/dev/null                  # locate strays if unsure
```

### Leave it running (continuous / always-on capture)

**Yes — `tcpdump` is built to run for days, and on a defender box like UbuntuServ
you can absolutely leave it running.** A persistent capture filtered to the lab
ports is in fact the cleanest fix for the timing problem: start it once, then run
any sim whenever and it is recorded. The only thing to manage is **disk**, so use
a **ring buffer** (`-C` = size per file in MB, `-W` = number of files → bounded
total) and drop root right after the capture socket opens (`-Z`):

```bash
mkdir -p ~/captures
sudo tcpdump -i lo -nn -Z "$USER" \
  -w ~/captures/lab.pcap -C 50 -W 10 \
  'port 8765 or port 8768 or udp port 8769 or portrange 8770-8790'
#  -> lab.pcap0 .. lab.pcap9, ~50 MB each, oldest recycled (~500 MB ceiling)
```

Prefer time-based files? Rotate hourly (unique strftime name; add `-W 24` to keep
a rolling day):

```bash
sudo tcpdump -i lo -nn -Z "$USER" -G 3600 -W 24 \
  -w '~/captures/lab-%Y%m%d-%H.pcap' \
  'port 8765 or port 8768 or udp port 8769 or portrange 8770-8790'
```

Make it survive an SSH logout with **tmux** (quickest):

```bash
tmux new -s cap        # run the tcpdump line inside; Ctrl-b then d to detach
tmux attach -t cap     # come back later; Ctrl-C to stop
```

Or run it as a **systemd service** so it starts on boot and restarts on failure
(replace `youruser` below with your own login name) —
`/etc/systemd/system/lab-capture.service`:

```ini
[Unit]
Description=Loopback lab packet capture (ring buffer)
After=network.target

[Service]
ExecStart=/usr/bin/tcpdump -i lo -nn -Z youruser -w /home/youruser/captures/lab.pcap -C 50 -W 10 port 8765 or port 8768 or udp port 8769 or portrange 8770-8790
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /home/youruser/captures
sudo systemctl enable --now lab-capture
sudo systemctl status lab-capture      # confirm it's active
journalctl -u lab-capture -f           # watch it
```

Notes for a long-running capture:

- On exit `tcpdump` reports "packets dropped by kernel"; if that's non-zero on a
  busy link, raise the buffer (`-B 4096`, in KiB) or tighten the filter. On the
  labs' loopback traffic the volume is tiny, so drops are a non-issue.
- Full-packet capture records payloads. That's fine on your own lab loopback, but
  treat the `.pcap`s as sensitive on any real network, and prefer `-Z "$USER"` so
  the files aren't owned by root.
- Reading any rotated file works the same way: `tcpdump -r ~/captures/lab.pcap3
  -nn -vvv -A`, or merge them with `mergecap -w all.pcap ~/captures/lab.pcap*`.

## Cleanup & packet capture

```bash
python3 gift_card_lab.py reset       # likewise: ddos_sim.py / amp_lab.py / web_attack_lab.py reset

# capture on the loopback interface (lo); open the .pcap later in Wireshark:
sudo tcpdump -i lo -n port 8765 -w giftcard.pcap                        # Gift-Card  8765/tcp
sudo tcpdump -i lo -n port 8768 -w ddos.pcap                            # DDoS       8768/tcp
sudo tcpdump -i lo -n udp port 8769 -w amp.pcap                         # Amplif.    8769/udp
sudo tcpdump -i lo -n 'port 8770 or portrange 8771-8790' -w web.pcap    # Web-Attack 8770/tcp
```

### Verbose live capture (print to screen)

Watch packets in detail instead of writing a file. Swap the port for another lab
(`8765` gift-card, `udp port 8769` amplification, `port 8770 or portrange
8771-8790` web-attack).

```bash
sudo tcpdump -i lo -nn -vvv -tttt port 8768             # verbose, wall-clock timestamps
sudo tcpdump -i lo -nn -vvv -A port 8768                # + ASCII payload (see HTTP)
sudo tcpdump -i lo -nn -vvv -X port 8768                # + hex & ASCII payload
sudo tcpdump -i lo -nn -vvv -S 'port 8768 and tcp[tcpflags] & tcp-syn != 0'  # SYNs only
```

| Flag | Effect |
| --- | --- |
| `-nn` | no DNS **and** no port-name lookups (raw `IP:port`) |
| `-v` / `-vv` / `-vvv` | increasing verbosity (TTL, IP id, options, checksums) |
| `-tttt` | human-readable wall-clock timestamp per packet |
| `-A` / `-X` | print payload as ASCII / as hex+ASCII |
| `-S` | absolute TCP sequence numbers (track a held connection) |
| `-e` | also show the link-layer (Ethernet) header |
| `-c 200` | stop after N packets |

`-v` / `-A` / `-X` affect **screen** output, so they don't combine with `-w`. To
save now and inspect verbosely later:

```bash
sudo tcpdump -i lo -nn -w ddos.pcap port 8768      # capture to file
tcpdump -r ddos.pcap -nn -vvv -A                   # replay verbose (no sudo needed)
```

Ports at a glance: Gift-Card **8765/tcp**, DDoS **8768/tcp**, Amplification
**8769/udp**, Web-Attack **8770/tcp** (+ sensor ports 8771–8786).

See [docs/DETECTION_LAB_MANUAL.md](docs/DETECTION_LAB_MANUAL.md) for the full
operator's manual (tool setup, per-lab detection playbooks, ethics).
