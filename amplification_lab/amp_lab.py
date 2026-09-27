"""UDP reflection / amplification concept lab.

A self-contained, harmless demonstration of *why* reflection/amplification DDoS
works -- a small query provokes a large response -- so defenders can understand
the amplification factor and practise detecting the pattern.

Why this is safe and NOT a usable attack tool:
  * There is NO source-IP spoofing, and no way to add it. In a real
    amplification attack the abuse comes from forging the victim's address as
    the query source so the big responses flood the victim. Here the query goes
    from you to a reflector you run and the response comes straight back to YOU.
    You measure the amplification factor; you cannot aim it at anyone.
  * The reflector and the client refuse any target except loopback by default;
    --allow-lan permits ONLY private/lab ranges (public addresses are refused).
  * The response size and query count are bounded.
  * Every step is written to events.jsonl as an answer key.

Modes:
  serve    Run the UDP reflector (small query in -> large response out).
  reflect  Send small queries and MEASURE the amplification factor.
  run      One-click: reflector in-process + reflect + summary.
  report   Timeline + amplification summary.
  detect   Blue-team guidance (MITRE T1498.002 Reflection Amplification).
  reset    Delete the lab directory.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LAB = Path.home() / "amp_ir_lab"
DEFAULT_PORT = 8769
HOST = "127.0.0.1"

DEFAULT_FACTOR = 50          # response = factor x query (capped)
MAX_RESPONSE_BYTES = 60_000  # keep the reflector's answer lab-sized
DEFAULT_QUERIES = 200
MAX_QUERIES = 20_000
QUERY = b"AMPLIFY?\n"        # the tiny request that provokes a big answer

RUN_ID_ENV = "AMP_LAB_RUN_ID"
LAB_DIR_ENV = "AMP_LAB_DIR"
PORT_ENV = "AMP_LAB_PORT"

LOOPBACK = ("127.0.0.1", "localhost", "::1")
CGNAT = ipaddress.ip_network("100.64.0.0/10")
BIND_ANY = ("0.0.0.0", "::")


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_lab_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return False
    return bool(
        ip.is_loopback or ip.is_private or ip.is_link_local or (ip.version == 4 and ip in CGNAT)
    )


def assert_lab_target(host: str, allow_lan: bool) -> None:
    if host in LOOPBACK:
        return
    if not allow_lan:
        raise SystemExit(
            f"refusing to use non-loopback host {host!r}; pass --allow-lan for "
            "your private lab network"
        )
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise SystemExit(f"could not resolve {host!r}: {exc}")
    for addr in sorted(addrs):
        if not _is_lab_ip(addr):
            raise SystemExit(
                f"refusing to use {host!r} -> {addr}: not a private/lab address"
            )


def assert_lab_bind(host: str, allow_lan: bool) -> None:
    if host in LOOPBACK:
        return
    if not allow_lan:
        raise SystemExit(f"refusing to bind non-loopback {host!r}; pass --allow-lan")
    if host in BIND_ANY:
        return
    if not _is_lab_ip(host):
        raise SystemExit(f"refusing to bind {host!r}: not a private/lab address")


BANNER = r"""
+--------------------------------------------------------------+
|            *** TRAINING SIMULATION -- SAFE ***               |
|                                                              |
|   UDP amplification CONCEPT lab. NOT an attack tool: there   |
|   is no source-IP spoofing and no way to add it, so the big  |
|   responses only ever come back to YOU. Loopback by default; |
|   --allow-lan reaches your private lab network only. Every   |
|   step is written to events.jsonl as an answer key.          |
|                                                              |
|   Run `python amp_lab.py detect` for the hunting guide.      |
+--------------------------------------------------------------+
"""


def announce() -> None:
    print(BANNER)


def write_event(lab: Path, run_id: str, event: str, **details) -> dict:
    lab.mkdir(exist_ok=True)
    record = {"time_utc": timestamp(), "run_id": run_id, "event": event,
              "pid": os.getpid(), **details}
    with (lab / "events.jsonl").open("a", encoding="utf-8") as log:
        log.write(json.dumps(record) + "\n")
    return record


# --------------------------------------------------------------------------- #
# Reflector.
# --------------------------------------------------------------------------- #


def _reflector_loop(sock: socket.socket, factor: int, stop: threading.Event,
                    stats: dict, lock: threading.Lock) -> None:
    resp_size = min(MAX_RESPONSE_BYTES, max(1, factor) * len(QUERY))
    response = b"R" * resp_size
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            continue
        try:
            sock.sendto(response, addr)  # straight back to the sender -- no spoofing
        except OSError:
            continue
        with lock:
            stats["queries"] += 1
            stats["bytes_in"] += len(data)
            stats["bytes_out"] += len(response)


def _make_reflector(port: int, factor: int, bind_host: str, allow_lan: bool):
    assert_lab_bind(bind_host, allow_lan)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_host, port))
    except OSError as exc:
        raise SystemExit(f"could not bind UDP {bind_host}:{port} ({exc})")
    sock.settimeout(0.5)
    return sock


def serve(lab: Path, port: int, run_id: str, factor: int,
          bind_host: str = HOST, allow_lan: bool = False) -> None:
    sock = _make_reflector(port, factor, bind_host, allow_lan)
    stop = threading.Event()
    stats = {"queries": 0, "bytes_in": 0, "bytes_out": 0}
    lock = threading.Lock()
    threading.Thread(target=_reflector_loop, args=(sock, factor, stop, stats, lock),
                     daemon=True).start()
    scope = "loopback only" if bind_host in LOOPBACK else "private lab network"
    write_event(lab, run_id, "reflector_started", address=f"{bind_host}:{port}",
                factor=factor)
    print(f"UDP reflector on {bind_host}:{port} (~{factor}x, {scope}). Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        sock.close()
        write_event(lab, run_id, "reflector_stopped", **stats)


# --------------------------------------------------------------------------- #
# Reflect client (measures amplification; cannot target a third party).
# --------------------------------------------------------------------------- #


def reflect(lab: Path, port: int, run_id: str, queries: int,
            target_host: str = HOST, allow_lan: bool = False) -> dict:
    assert_lab_target(target_host, allow_lan)
    queries = max(1, min(queries, MAX_QUERIES))
    scope = "loopback only" if target_host in LOOPBACK else "private lab network"
    write_event(lab, run_id, "reflect_started", queries=queries,
                target=f"{target_host}:{port}")
    print(f"Sending {queries} small queries to reflector {target_host}:{port} ({scope}).")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    sent_bytes = recv_bytes = answered = 0
    for _ in range(queries):
        try:
            sock.sendto(QUERY, (target_host, port))
            sent_bytes += len(QUERY)
            data, _addr = sock.recvfrom(65535)
            recv_bytes += len(data)
            answered += 1
        except OSError:
            continue
    sock.close()

    factor = round(recv_bytes / sent_bytes, 2) if sent_bytes else 0.0
    result = {"queries_sent": queries, "answered": answered,
              "bytes_sent": sent_bytes, "bytes_received": recv_bytes,
              "amplification_factor": factor}
    write_event(lab, run_id, "reflect_completed", **result)
    print(f"Amplification: {sent_bytes} B out -> {recv_bytes} B back "
          f"= {factor}x (this all returned to YOU; no spoofing).")
    return result


def run(lab: Path, port: int, run_id: str, factor: int, queries: int,
        show_banner: bool = False) -> None:
    if show_banner:
        announce()
    lab.mkdir(exist_ok=True)
    sock = _make_reflector(port, factor, HOST, False)
    stop = threading.Event()
    stats = {"queries": 0, "bytes_in": 0, "bytes_out": 0}
    lock = threading.Lock()
    threading.Thread(target=_reflector_loop, args=(sock, factor, stop, stats, lock),
                     daemon=True).start()
    write_event(lab, run_id, "reflector_started", address=f"{HOST}:{port}", factor=factor)
    time.sleep(0.5)
    result = reflect(lab, port, run_id, queries)
    stop.set()
    sock.close()
    write_event(lab, run_id, "simulation_completed", **result)
    print(f"\nOne small query provoked ~{factor}x the bytes back. In a REAL attack the "
          "query source would be spoofed to a victim; this lab cannot do that.")
    print("Run `report` for the timeline, `detect` for the hunting guide.")


# --------------------------------------------------------------------------- #
# Reporting.
# --------------------------------------------------------------------------- #


def load_events(lab: Path) -> list[dict]:
    path = lab / "events.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # tolerate a rare interleaved line (shared-dir two-window mode)
    return out


def report(lab: Path) -> None:
    events = load_events(lab)
    if not events:
        print(f"no events recorded in {lab}")
        return
    print(f"Timeline ({len(events)} events from {lab / 'events.jsonl'}):\n")
    for e in events:
        tag = (e.get("run_id") or "")[:8]
        print(f"  {e['time_utc']}  [{tag}] {e['event']}")
    done = next((e for e in reversed(events)
                 if e["event"] in ("reflect_completed", "simulation_completed")), None)
    print("\nAmplification summary:")
    if done:
        print(f"  queries sent        : {done.get('queries_sent', 0)}")
        print(f"  bytes sent          : {done.get('bytes_sent', 0)}")
        print(f"  bytes received      : {done.get('bytes_received', 0)}")
        print(f"  amplification factor: {done.get('amplification_factor', 0)}x")
        print("  (all responses returned to the sender -- no third party involved)")


DETECTION_GUIDE = r"""
BLUE-TEAM HUNTING GUIDE -- reflection/amplification (MITRE T1498.002)
=====================================================================
This lab shows the mechanic: a small query provokes a large response. Real
attacks weaponise it by SPOOFING the victim's IP as the query source, so the
amplified responses flood the victim. This lab does not and cannot spoof -- the
responses come back to the sender -- so you study the factor and its detection
safely.

WHY IT'S DANGEROUS IN THE WILD
   - Attacker sends tiny queries to many open UDP "reflectors" (misconfigured
     DNS, NTP monlist, memcached, SSDP, CLDAP...) with the victim's IP forged as
     the source. Each reflector answers the victim with a much larger packet.
   - Amplification factors: DNS ~28-54x, NTP ~556x, memcached ~10,000-50,000x.

DETECTION (as the VICTIM)
   - Large inbound UDP from source ports 53/123/1900/11211 you never queried.
   - Bandwidth saturation with high packets/sec from many reflector IPs.
   - NetFlow: many sources, one dst, one/few source ports, big response sizes.

DETECTION (as an unwitting REFLECTOR -- don't be the amplifier)
   - Outbound UDP responses to hosts that never legitimately queried you.
   - Requests for records/commands with high response ratios (ANY, monlist,
     memcached stats). This lab's reflector logs bytes_in vs bytes_out; a real
     monitor watches that ratio per service.

PACKET CAPTURE (measure the factor yourself)
   This is fundamentally a packet-size story, so watch it on the wire:
     tcpdump -i lo -n udp port 8769 -w amp.pcap   (on Windows capture on the
     Npcap loopback adapter)
   - In Wireshark filter `udp.port == 8769` and compare the query packet length
     to the response length -- that ratio IS the amplification factor.
   - Statistics > Conversations (UDP) shows bytes-out vs bytes-in per flow; the
     oversized responses are what a spoofed victim would be drowned in.

MITIGATIONS
   - BCP38 / ingress filtering so spoofed source IPs can't leave a network.
   - Disable/restrict amplifiers: NTP monlist off, memcached not on UDP/public,
     DNS response-rate limiting (RRL), close open resolvers.
   - Upstream scrubbing / anycast absorption; rate-limit UDP by source port.

TABLETOP MAPPING (lab event -> what the detector should see)
   reflector_started / _stopped -> the amplifier's bytes_in vs bytes_out ratio
   reflect_completed            -> the amplification_factor you measured
"""


def detect() -> None:
    print(DETECTION_GUIDE)


LAB_MARKERS = ("events.jsonl",)


def reset(lab: Path) -> None:
    lab = lab.resolve()
    if not lab.exists():
        print(f"nothing to remove; {lab} does not exist")
        return
    dangerous = {Path.home().resolve(), Path.cwd().resolve()} | set(
        Path(lab.anchor).resolve().parents)
    dangerous.add(Path(lab.anchor).resolve())
    if lab in dangerous or (lab / ".git").exists():
        raise SystemExit(f"refusing to delete {lab}: not a lab directory")
    if not (lab == DEFAULT_LAB.resolve() or any((lab / m).exists() for m in LAB_MARKERS)):
        raise SystemExit(f"refusing to delete {lab}: no lab files present")
    shutil.rmtree(lab)
    print(f"removed {lab}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["serve", "reflect", "run", "report", "detect", "reset"])
    parser.add_argument("--lab-dir", type=Path,
                        default=Path(os.environ.get(LAB_DIR_ENV, DEFAULT_LAB)))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get(PORT_ENV, DEFAULT_PORT)))
    parser.add_argument("--factor", type=int, default=DEFAULT_FACTOR,
                        help=f"response-to-query size ratio (default {DEFAULT_FACTOR})")
    parser.add_argument("--queries", type=int, default=DEFAULT_QUERIES,
                        help=f"queries to send (default {DEFAULT_QUERIES}, max {MAX_QUERIES})")
    parser.add_argument("--bind", default=HOST,
                        help="reflector listen address (serve); LAN IP/0.0.0.0 needs --allow-lan")
    parser.add_argument("--target", default=HOST,
                        help="reflector address (reflect); private/lab host, needs --allow-lan")
    parser.add_argument("--allow-lan", action="store_true",
                        help="permit private lab network; public addresses refused")
    parser.add_argument("--announce", action="store_true")
    args = parser.parse_args(argv)

    lab = args.lab_dir
    run_id = os.environ.get(RUN_ID_ENV) or uuid.uuid4().hex

    if args.mode == "serve":
        serve(lab, args.port, run_id, args.factor, bind_host=args.bind, allow_lan=args.allow_lan)
    elif args.mode == "reflect":
        reflect(lab, args.port, run_id, args.queries, target_host=args.target, allow_lan=args.allow_lan)
    elif args.mode == "run":
        run(lab, args.port, run_id, args.factor, args.queries, show_banner=args.announce)
    elif args.mode == "report":
        report(lab)
    elif args.mode == "detect":
        detect()
    else:
        reset(lab)


if __name__ == "__main__":
    main()
