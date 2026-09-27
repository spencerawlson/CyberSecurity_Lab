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
run** — nothing stores them otherwise. To capture without a second terminal,
background it, run the sim, then stop it and read the file back:

```bash
sudo tcpdump -i lo -nn -w ddos.pcap port 8768 &   # start capture in background
python3 ddos_sim.py run --attack volumetric --announce
sudo kill %1                                       # stop it (or: sudo pkill tcpdump)
tcpdump -r ddos.pcap -nn -vvv -A                   # read the saved packets back
```

In short: **`report` / `detect` = what happened (always available); a `.pcap` =
the packets (only if you captured during the run).**

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
