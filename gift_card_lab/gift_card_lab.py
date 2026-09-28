"""Gift-card incident-response training lab.

A self-contained, harmless simulation of the *observable traces* left by a
"gift card scam" malware infection, built so defenders can practise detecting
them (Sysmon, EDR, Procmon, loopback packet capture, etc.).

Nothing here is malicious:
  * All network traffic stays on the loopback interface (127.0.0.1); the
    server refuses to bind to any other address.
  * The "download" is a plain text file whose contents say it is simulated.
  * The "keylogger" never reads the keyboard -- it writes three fixed,
    clearly-labelled TEST_* events.
  * Every step appends a JSON line to ``events.jsonl`` in the lab directory,
    which acts as an answer key for the exercise.

Modes:
  serve   Run the local-only HTTP server (the "attacker" host).
  run     Play out the victim opening the lure and the payload running.
          Add --announce for a loud "TRAINING SIMULATION" banner, and
          --auto-serve to start the loopback server in-process (one click).
  child   Internal: the child process spawned by ``run`` (not run directly).
  report  Print a timeline and IOC summary from the recorded events.
  detect  Print blue-team hunting guidance for the technique this lab imitates
          (masquerading / lures) -- indicators plus Sysmon and KQL queries.
  reset   Delete the lab directory so the exercise can be repeated cleanly.
"""

from __future__ import annotations


import argparse
import hashlib
import ipaddress
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

DEFAULT_LAB = Path.home() / "gift_card_ir_lab"
DEFAULT_PORT = 8765
HOST = "127.0.0.1"  # loopback by default; see assert_lab_target/assert_lab_bind
MAX_BODY_BYTES = 1 * 1024 * 1024  # reject oversized telemetry posts
RUN_ID_ENV = "GIFT_CARD_LAB_RUN_ID"
LAB_DIR_ENV = "GIFT_CARD_LAB_DIR"
PORT_ENV = "GIFT_CARD_LAB_PORT"
SERVER_ENV = "GIFT_CARD_LAB_SERVER"  # where the victim reaches the lab server
ALLOW_LAN_ENV = "GIFT_CARD_LAB_ALLOW_LAN"  # inherited by the child process

LOOPBACK = ("127.0.0.1", "localhost", "::1")
CGNAT = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598, older Python misses it
BIND_ANY = ("0.0.0.0", "::")  # bind to all local interfaces


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def assert_loopback(host: str) -> None:
    """Guarantee the lab only ever talks to itself (loopback-only default)."""
    if host not in LOOPBACK:
        raise SystemExit(
            f"refusing to use non-loopback host {host!r}; this lab is "
            "loopback-only by design"
        )


def _url_host(host: str) -> str:
    """Wrap IPv6 literals in brackets for use in a URL."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _is_lab_ip(ip_str: str) -> bool:
    """True only for private/lab address space -- never a public host."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])  # drop IPv6 scope id
    except ValueError:
        return False
    return bool(
        ip.is_loopback or ip.is_private or ip.is_link_local or (ip.version == 4 and ip in CGNAT)
    )


def assert_lab_target(host: str, allow_lan: bool) -> None:
    """Allow loopback always; with allow_lan, allow ONLY private/lab hosts.

    Every address the host resolves to must be private (RFC1918 / CGNAT /
    link-local / loopback / IPv6 ULA); a single public address refuses the
    whole run. This keeps the two halves talking across your lab VMs without
    the lab ever reaching a public host.
    """
    if host in LOOPBACK:
        return
    if not allow_lan:
        raise SystemExit(
            f"refusing to use non-loopback host {host!r}; pass --allow-lan to "
            "reach another machine on your private lab network"
        )
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise SystemExit(f"could not resolve {host!r}: {exc}")
    for addr in sorted(addrs):
        if not _is_lab_ip(addr):
            raise SystemExit(
                f"refusing to use {host!r} -> {addr}: not a private/lab "
                "address. This lab only talks to RFC1918/CGNAT/link-local/"
                "loopback networks you control, never a public host."
            )


def assert_lab_bind(host: str, allow_lan: bool) -> None:
    """Bind to loopback always; with allow_lan, a private IP or all-interfaces."""
    if host in LOOPBACK:
        return
    if not allow_lan:
        raise SystemExit(
            f"refusing to bind non-loopback address {host!r}; pass --allow-lan "
            "to serve on your private lab network"
        )
    if host in BIND_ANY:
        return  # all interfaces on a lab box; fine on an isolated lab network
    if not _is_lab_ip(host):
        raise SystemExit(
            f"refusing to bind {host!r}: not a private/lab address. Bind to a "
            "loopback/RFC1918/link-local address or 0.0.0.0 on a lab box."
        )


BANNER = r"""
+--------------------------------------------------------------+
|                                                              |
|            *** TRAINING SIMULATION -- SAFE ***               |
|                                                              |
|   This is the Gift-Card IR detection lab. It is NOT malware. |
|   It talks to 127.0.0.1 by default (or, with --allow-lan,    |
|   only your PRIVATE lab network -- never a public host),     |
|   writes clearly-labelled dummy files, and logs every step   |
|   to events.jsonl as an answer key. Nothing is disguised.    |
|                                                              |
|   Run `python gift_card_lab.py detect` to see what a         |
|   defender should hunt for.                                  |
|                                                              |
+--------------------------------------------------------------+
"""


def announce(gui: bool = False) -> None:
    """Show an unmistakable 'this is a simulation' notice before running."""
    print(BANNER)
    if gui:
        # Best-effort popup for classroom demos; never fatal if unavailable.
        try:
            import tkinter
            from tkinter import messagebox

            root = tkinter.Tk()
            root.withdraw()
            messagebox.showinfo(
                "Training Simulation -- SAFE",
                "Gift-Card IR detection lab.\n\n"
                "This is a SAFE training simulation, not malware. It stays on "
                "127.0.0.1 (or, with --allow-lan, only your private lab "
                "network) and writes only clearly-labelled dummy files.",
            )
            root.destroy()
        except Exception as exc:  # tkinter missing / headless / display error
            print(f"(gui banner unavailable: {exc})")


def write_event(lab: Path, run_id: str, event: str, **details) -> dict:
    lab.mkdir(exist_ok=True)
    record = {
        "time_utc": timestamp(),
        "run_id": run_id,
        "event": event,
        "pid": os.getpid(),
        **details,
    }
    with (lab / "events.jsonl").open("a", encoding="utf-8") as log:
        log.write(json.dumps(record) + "\n")
    print(json.dumps(record))
    return record


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_handler(lab: Path, run_id: str):
    class LabHandler(BaseHTTPRequestHandler):
        server_version = "GiftCardLab/2.0"

        def do_GET(self):  # noqa: N802 (http.server API)
            if self.path == "/gift-card":
                content = (
                    b"Gift card investigation lab\n"
                    b"This is a harmless simulated download.\n"
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header(
                    "Content-Disposition", 'attachment; filename="gift_card.txt"'
                )
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                write_event(
                    lab, run_id, "gift_card_download_served", client=self.client_address[0]
                )
                return

            # Simulated C2 check-in: the "implant" polls for a task and the
            # "server" hands back a harmless no-op. This is what a defender sees
            # as regular, low-and-slow beaconing.
            if self.path.startswith("/c2-beacon"):
                task = b'{"task":"noop","note":"simulated C2 task (harmless)"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(task)))
                self.end_headers()
                self.wfile.write(task)
                write_event(lab, run_id, "c2_beacon_received", client=self.client_address[0])
                return

            self.send_error(404)

        def do_POST(self):  # noqa: N802 (http.server API)
            if self.path not in ("/lab-telemetry", "/exfil"):
                self.send_error(404)
                return

            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "invalid Content-Length")
                return
            if size < 0 or size > MAX_BODY_BYTES:
                self.send_error(413, "body too large")
                return

            body = self.rfile.read(size)

            if self.path == "/exfil":
                # Simulated staged exfiltration: the receiver only tallies the
                # dummy bytes so a defender can watch outbound data grow.
                write_event(lab, run_id, "exfil_chunk_received",
                            bytes_received=len(body), client=self.client_address[0])
                self.send_response(204)
                self.end_headers()
                return

            # /lab-telemetry: store the dummy lab data (timestamped filename).
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
            out = lab / f"received_telemetry_{stamp}.json"
            out.write_bytes(body)
            write_event(
                lab,
                run_id,
                "dummy_telemetry_received",
                bytes_received=len(body),
                path=str(out),
            )

            self.send_response(204)
            self.end_headers()

        def log_message(self, format_string, *args):
            pass

    return LabHandler


def serve(
    lab: Path, port: int, run_id: str, bind_host: str = HOST, allow_lan: bool = False
) -> None:
    assert_lab_bind(bind_host, allow_lan)
    lab.mkdir(exist_ok=True)
    try:
        server = ThreadingHTTPServer((bind_host, port), make_handler(lab, run_id))
    except OSError as exc:
        raise SystemExit(
            f"could not bind {bind_host}:{port} ({exc}); try a different --port"
        )
    scope = "loopback only" if bind_host in LOOPBACK else "private lab network"
    write_event(lab, run_id, "local_server_started", address=f"{bind_host}:{port}")
    print(f"Lab server listening on {bind_host}:{port} ({scope}). Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def child(
    lab: Path, port: int, run_id: str, server_host: str = HOST, allow_lan: bool = False
) -> None:
    assert_lab_target(server_host, allow_lan)
    write_event(lab, run_id, "child_process_started", parent_pid=os.getppid())

    # These are fixed test events, not keyboard input.
    dummy_events = [
        {"time_utc": timestamp(), "event": "TEST_KEY_A"},
        {"time_utc": timestamp(), "event": "TEST_KEY_B"},
        {"time_utc": timestamp(), "event": "TEST_ENTER"},
    ]
    output = lab / "dummy_input_events.json"
    output.write_text(json.dumps(dummy_events, indent=2), encoding="utf-8")
    write_event(lab, run_id, "dummy_event_file_created", path=str(output))

    request = Request(
        f"http://{_url_host(server_host)}:{port}/lab-telemetry",
        data=output.read_bytes(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            write_event(lab, run_id, "loopback_request_sent", http_status=response.status)
    except URLError as exc:
        raise SystemExit(
            f"could not reach the lab server on {server_host}:{port} ({exc.reason}); "
            "start it first with `serve`"
        )

    time.sleep(3)  # Briefly leaves the child visible in process listings.


MAX_BEACONS = 500
MAX_EXFIL_BYTES = 5 * 1024 * 1024


def beacon(
    lab: Path, port: int, run_id: str, count: int, interval: float, jitter: float,
    server_host: str = HOST, allow_lan: bool = False,
) -> None:
    """Simulated C2 beaconing: check in on a regular interval with jitter.

    Regular, low-volume callbacks are the signature defenders hunt for -- so the
    lesson is the *periodicity*, not the volume."""
    assert_lab_target(server_host, allow_lan)
    count = max(1, min(count, MAX_BEACONS))
    write_event(lab, run_id, "c2_beaconing_started", beacons=count,
                interval_s=interval, jitter_s=jitter, server=f"{server_host}:{port}")
    print(f"Beaconing {count}x to {server_host}:{port} every ~{interval}s (+/-{jitter}s jitter).")
    url = f"http://{_url_host(server_host)}:{port}/c2-beacon"
    for i in range(count):
        try:
            with urlopen(url, timeout=5) as response:
                write_event(lab, run_id, "c2_beacon_sent", seq=i + 1,
                            http_status=response.status)
        except URLError as exc:
            raise SystemExit(
                f"could not reach the lab server on {server_host}:{port} "
                f"({exc.reason}); start it first with `serve`"
            )
        if i < count - 1:
            time.sleep(max(0.1, interval + random.uniform(-jitter, jitter)))
    write_event(lab, run_id, "c2_beaconing_completed", beacons=count)
    print(f"Sent {count} beacons.")


def exfil(
    lab: Path, port: int, run_id: str, total_bytes: int, chunk: int,
    server_host: str = HOST, allow_lan: bool = False,
) -> None:
    """Simulated staged exfiltration: dribble dummy 'sensitive' data outbound in
    chunks so a defender can watch outbound volume grow."""
    assert_lab_target(server_host, allow_lan)
    total_bytes = max(1, min(total_bytes, MAX_EXFIL_BYTES))
    chunk = max(1, min(chunk, MAX_BODY_BYTES))
    payload = b"SIMULATED-DUMMY-EXFIL-DATA;" * ((chunk // 27) + 1)
    write_event(lab, run_id, "exfil_started", total_bytes=total_bytes,
                chunk_bytes=chunk, server=f"{server_host}:{port}")
    print(f"Exfiltrating {total_bytes} dummy bytes to {server_host}:{port} "
          f"in {chunk}-byte chunks.")
    sent = seq = 0
    while sent < total_bytes:
        this = payload[: min(chunk, total_bytes - sent)]
        request = Request(
            f"http://{_url_host(server_host)}:{port}/exfil",
            data=this, headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=5) as response:
                seq += 1
                sent += len(this)
                write_event(lab, run_id, "exfil_chunk_sent", seq=seq,
                            bytes_sent=len(this), cumulative=sent,
                            http_status=response.status)
        except URLError as exc:
            raise SystemExit(
                f"could not reach the lab server on {server_host}:{port} "
                f"({exc.reason}); start it first with `serve`"
            )
        time.sleep(0.2)
    write_event(lab, run_id, "exfil_completed", chunks=seq, bytes_sent=sent)
    print(f"Exfiltrated {sent} dummy bytes in {seq} chunks.")


def _start_background_server(lab: Path, port: int, run_id: str):
    """Start the loopback server in a daemon thread for one-click runs."""
    import threading

    server = ThreadingHTTPServer((HOST, port), make_handler(lab, run_id))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    write_event(lab, run_id, "local_server_started", address=f"{HOST}:{port}")
    return server


def run(
    lab: Path,
    port: int,
    run_id: str,
    server_host: str = HOST,
    allow_lan: bool = False,
    show_banner: bool = False,
    gui_banner: bool = False,
    auto_serve: bool = False,
) -> None:
    assert_lab_target(server_host, allow_lan)
    if auto_serve and server_host not in LOOPBACK:
        raise SystemExit(
            "--auto-serve starts a LOCAL loopback server, which the victim "
            f"cannot combine with --server {server_host}. Run `serve` on that "
            "machine instead, and drop --auto-serve here."
        )
    if show_banner:
        announce(gui=gui_banner)
    lab.mkdir(exist_ok=True)

    server = None
    if auto_serve:
        server = _start_background_server(lab, port, run_id)

    write_event(lab, run_id, "gift_card_lure_opened", scenario="training simulation")

    url = f"http://{_url_host(server_host)}:{port}/gift-card"
    try:
        with urlopen(url, timeout=5) as response:
            downloaded = response.read()
    except URLError as exc:
        raise SystemExit(
            f"could not reach the lab server on {server_host}:{port} ({exc.reason}); "
            "start it first with `serve`"
        )

    file_path = lab / "gift_card.txt"
    file_path.write_bytes(downloaded)
    write_event(
        lab,
        run_id,
        "gift_card_file_downloaded",
        path=str(file_path),
        sha256=sha256(file_path),
    )

    write_event(lab, run_id, "child_process_launch_requested")
    env = dict(
        os.environ,
        **{
            RUN_ID_ENV: run_id,
            LAB_DIR_ENV: str(lab),
            PORT_ENV: str(port),
            SERVER_ENV: server_host,
            ALLOW_LAN_ENV: "1" if allow_lan else "",
        },
    )
    child_cmd = [sys.executable, str(Path(__file__).resolve()), "child", "--port", str(port)]
    if server_host not in LOOPBACK:
        child_cmd += ["--server", server_host]
    if allow_lan:
        child_cmd += ["--allow-lan"]
    subprocess.run(child_cmd, check=True, env=env)
    write_event(lab, run_id, "simulation_completed")
    if server is not None:
        server.shutdown()
        server.server_close()


def load_events(lab: Path) -> list[dict]:
    path = lab / "events.jsonl"
    if not path.exists():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # tolerate a rare interleaved line (shared-dir two-window mode)
    return events


def report(lab: Path) -> None:
    events = load_events(lab)
    if not events:
        print(f"no events recorded in {lab}")
        return

    print(f"Timeline ({len(events)} events from {lab / 'events.jsonl'}):\n")
    for e in events:
        run_tag = (e.get("run_id") or "")[:8]
        print(f"  {e['time_utc']}  [{run_tag}] pid={e.get('pid'):<7} {e['event']}")

    hashes = {e["sha256"] for e in events if "sha256" in e}
    pids = {e["pid"] for e in events if "pid" in e}
    addresses = {e["address"] for e in events if "address" in e}
    paths = {e["path"] for e in events if "path" in e}
    runs = {e["run_id"] for e in events if e.get("run_id")}

    print("\nIOC summary:")
    print(f"  runs observed : {len(runs)}")
    print(f"  process IDs   : {sorted(pids)}")
    print(f"  listen addrs  : {sorted(addresses) or ['-']}")
    print(f"  file hashes   : {sorted(hashes) or ['-']}")
    print("  artifact paths:")
    for p in sorted(paths):
        print(f"    - {p}")


DETECTION_GUIDE = r"""
BLUE-TEAM HUNTING GUIDE -- masquerading & malicious lures (MITRE T1036 / T1204)
==============================================================================
This lab imitates a "gift card" lure so you can practise DETECTING it. Real
attackers disguise an executable as a harmless document (a spoofed icon, a
double extension like `gift_card.pdf.exe`) and rely on a person to double-click
it. Below is what to hunt for. Map each item to the events this lab records
(run `report` to see them) so you can confirm your tooling actually caught it.

1. MASQUERADING ARTIFACTS ON DISK
   - Double / mismatched extensions: name says `.pdf`/`.txt`/`.jpg` but the
     real type is `.exe`/`.scr`/`.js`/`.lnk`. Hunt files where the extension
     shown to the user differs from the file's magic bytes.
   - Icon vs. type mismatch: a document-looking icon on an executable.
   - Unusual launch parents: a "document" that is actually a script spawning
     an interpreter (python/wscript/powershell) -> this lab's parent->child
     python chain is the analogue.
   - Mark-of-the-Web: files downloaded from a browser carry a Zone.Identifier
     Alternate Data Stream. Downloaded payloads that then execute are high
     signal. Check with:  Get-Content <file> -Stream Zone.Identifier

2. PROCESS TELEMETRY (Sysmon Event ID 1 -- Process Create)
   Look for an interpreter spawned from a user-writable/download location, and
   for a suspicious parent/child chain. Example Sysmon-style filter:
     Image ENDS WITH \python.exe (or wscript.exe, mshta.exe, powershell.exe)
     AND ParentImage in a download/temp/Desktop path
   KQL (Microsoft Defender Advanced Hunting):
     DeviceProcessEvents
     | where InitiatingProcessFileName in~ ("python.exe","wscript.exe","powershell.exe")
     | where FolderPath has_any ("\\Downloads\\","\\Temp\\","\\Desktop\\")
     | project Timestamp, DeviceName, FileName, ProcessCommandLine,
               InitiatingProcessFileName, InitiatingProcessCommandLine

3. FILE-WRITE TELEMETRY (Sysmon Event ID 11 -- File Create)
   The payload writing new files into the user profile (this lab writes
   dummy_input_events.json / received_telemetry_*.json). KQL:
     DeviceFileEvents
     | where FolderPath has_any ("\\Downloads\\","\\Temp\\","gift_card_ir_lab")
     | project Timestamp, DeviceName, FileName, FolderPath,
               InitiatingProcessFileName

4. NETWORK TELEMETRY (Sysmon Event ID 3 -- Network Connect)
   Real malware beacons to a remote host; this lab uses 127.0.0.1 so you can
   practise safely. In production, hunt an interpreter making outbound
   connections shortly after a document was "opened". KQL:
     DeviceNetworkEvents
     | where InitiatingProcessFileName in~ ("python.exe","powershell.exe","wscript.exe")
     | project Timestamp, DeviceName, RemoteIP, RemotePort,
               InitiatingProcessFileName, InitiatingProcessCommandLine

5. MOTW / DOWNLOAD PROVENANCE (Sysmon Event ID 15 -- FileCreateStreamHash)
   Fires when a downloaded file gets a Zone.Identifier stream. Correlate an
   EID 15 for a "document" with a later EID 1 where that same file executes.

6. C2 BEACONING (MITRE T1071 / T1573) -- the `beacon` mode
   After a host is compromised, the implant "checks in" with its server on a
   regular schedule. Hunt for PERIODICITY, not volume:
   - Repeated connections to the same destination at a near-constant interval
     (even with jitter) -> beacon analysis. Low bytes, high regularity.
   - Uniform request sizes / URIs; odd or empty User-Agent; long-lived pattern.
   - KQL sketch: DeviceNetworkEvents | summarize hits=count(),
     span=max(Timestamp)-min(Timestamp) by RemoteIP, InitiatingProcessFileName
     | where hits > 10  // then inspect inter-arrival regularity
   This lab's `c2_beacon_sent` events are evenly spaced -- graph their timestamps.

7. DATA EXFILTRATION (MITRE T1041 Exfil over C2 channel) -- the `exfil` mode
   Staged upload of data out of the network. Hunt for OUTBOUND volume anomalies:
   - Upload bytes to an external/unusual host climbing over a short window,
     often in fixed-size chunks. Egress >> normal for that host/process.
   - Correlate with the beacon: same destination, then a data burst.
   This lab's `exfil_chunk_*` events tally the growing dummy byte count.

TABLETOP MAPPING (lab event -> what the detector should see)
   gift_card_file_downloaded   -> file create + (in the real world) MOTW stream
   child_process_launch_requested / child_process_started
                               -> Sysmon EID 1 parent->child process chain
   dummy_event_file_created    -> Sysmon EID 11 file create in user profile
   loopback_request_sent       -> Sysmon EID 3 network connect (127.0.0.1 here)
   c2_beacon_sent (evenly spaced) -> periodic-beacon detection (T1071)
   exfil_chunk_sent (growing)     -> outbound data-volume anomaly (T1041)

PREVENTIVE CONTROLS worth demoing alongside the hunt:
   - Show file extensions in Explorer; block/inspect double extensions.
   - Attack Surface Reduction rules for Office/script child processes.
   - SmartScreen / MOTW enforcement; block execution from Downloads.
   - Application control (WDAC/AppLocker) so unsigned lures cannot run.
"""


def detect() -> None:
    print(DETECTION_GUIDE)


# Files the lab itself creates; reset will only delete a directory that
# looks like one of ours, to avoid nuking a mistyped path.
LAB_MARKERS = ("events.jsonl", "gift_card.txt", "dummy_input_events.json")


def reset(lab: Path) -> None:
    lab = lab.resolve()
    if not lab.exists():
        print(f"nothing to remove; {lab} does not exist")
        return

    # Guard against deleting something important via a mistyped --lab-dir.
    dangerous = {Path.home().resolve(), Path.cwd().resolve()} | set(
        Path(lab.anchor).resolve().parents
    )
    dangerous.add(Path(lab.anchor).resolve())  # drive/filesystem root
    if lab in dangerous or (lab / ".git").exists():
        raise SystemExit(
            f"refusing to delete {lab}: it is not a lab directory "
            "(looks like your home, cwd, a filesystem root, or a git repo)"
        )
    looks_like_lab = lab == DEFAULT_LAB.resolve() or any(
        (lab / marker).exists() for marker in LAB_MARKERS
    )
    if not looks_like_lab:
        raise SystemExit(
            f"refusing to delete {lab}: it does not contain any lab files "
            f"({', '.join(LAB_MARKERS)}); delete it yourself if you are sure"
        )

    shutil.rmtree(lab)
    print(f"removed {lab}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "mode",
        choices=["serve", "run", "child", "beacon", "exfil", "report", "detect", "reset"],
    )
    parser.add_argument(
        "--lab-dir",
        type=Path,
        default=Path(os.environ.get(LAB_DIR_ENV, DEFAULT_LAB)),
        help=f"lab working directory (default: {DEFAULT_LAB})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get(PORT_ENV, DEFAULT_PORT)),
        help=f"port for the lab server (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--bind",
        default=HOST,
        help="address the lab server listens on (serve mode; default "
             "127.0.0.1). Use your lab IP or 0.0.0.0 with --allow-lan.",
    )
    parser.add_argument(
        "--server",
        default=os.environ.get(SERVER_ENV) or HOST,
        help="address of the lab server the victim reaches (run/child; "
             "default 127.0.0.1). Requires --allow-lan for a remote lab host.",
    )
    parser.add_argument(
        "--allow-lan",
        action="store_true",
        default=bool(os.environ.get(ALLOW_LAN_ENV)),
        help="permit binding/reaching your PRIVATE lab network instead of "
             "loopback only. Public/routable addresses are always refused.",
    )
    parser.add_argument(
        "--announce",
        action="store_true",
        help="print a loud 'TRAINING SIMULATION -- SAFE' banner (run mode)",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="also show the banner as a popup window, if available (run mode)",
    )
    parser.add_argument(
        "--auto-serve",
        action="store_true",
        help="start the loopback server in-process so `run` works in one step",
    )
    parser.add_argument("--beacons", type=int, default=10,
                        help=f"beacon mode: number of check-ins (max {MAX_BEACONS})")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="beacon mode: seconds between check-ins")
    parser.add_argument("--jitter", type=float, default=0.5,
                        help="beacon mode: +/- random seconds added to each interval")
    parser.add_argument("--exfil-bytes", type=int, default=262144,
                        help=f"exfil mode: total dummy bytes (max {MAX_EXFIL_BYTES})")
    parser.add_argument("--chunk", type=int, default=16384,
                        help="exfil mode: bytes per POST chunk")
    args = parser.parse_args(argv)

    lab: Path = args.lab_dir
    # A run id ties together every event from one exercise; child processes
    # inherit it via the environment.
    run_id = os.environ.get(RUN_ID_ENV) or uuid.uuid4().hex

    if args.mode == "serve":
        serve(lab, args.port, run_id, bind_host=args.bind, allow_lan=args.allow_lan)
    elif args.mode == "run":
        run(
            lab,
            args.port,
            run_id,
            server_host=args.server,
            allow_lan=args.allow_lan,
            show_banner=args.announce,
            gui_banner=args.gui,
            auto_serve=args.auto_serve,
        )
    elif args.mode == "child":
        child(lab, args.port, run_id, server_host=args.server, allow_lan=args.allow_lan)
    elif args.mode == "beacon":
        beacon(lab, args.port, run_id, args.beacons, args.interval, args.jitter,
               server_host=args.server, allow_lan=args.allow_lan)
    elif args.mode == "exfil":
        exfil(lab, args.port, run_id, args.exfil_bytes, args.chunk,
              server_host=args.server, allow_lan=args.allow_lan)
    elif args.mode == "report":
        report(lab)
    elif args.mode == "detect":
        detect()
    else:
        reset(lab)

if __name__ == "__main__":
    main()
