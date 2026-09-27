"""Smoke tests for the gift-card IR training lab.

Run with:  python -m pytest test_gift_card_lab.py   (or: python test_gift_card_lab.py)
"""

import contextlib
import io
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import gift_card_lab as lab


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve_in_thread(lab_dir: Path, port: int, run_id: str):
    server = ThreadingHTTPServer(("127.0.0.1", port), lab.make_handler(lab_dir, run_id))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_full_flow(tmp_path: Path):
    lab_dir = tmp_path / "labdir"
    port = _free_port()
    run_id = "testrun00000000"

    server = _serve_in_thread(lab_dir, port, run_id)
    try:
        lab.run(lab_dir, port, run_id)
    finally:
        server.shutdown()

    events = lab.load_events(lab_dir)
    names = [e["event"] for e in events]

    # Parent lifecycle
    assert "gift_card_lure_opened" in names
    assert "gift_card_file_downloaded" in names
    assert "simulation_completed" in names
    # Child ran as a separate process and phoned home over loopback
    assert "child_process_started" in names
    assert "loopback_request_sent" in names
    assert "dummy_telemetry_received" in names

    # Artifacts exist and the recorded hash matches the downloaded file
    downloaded = lab_dir / "gift_card.txt"
    assert downloaded.exists()
    hash_event = next(e for e in events if e["event"] == "gift_card_file_downloaded")
    assert hash_event["sha256"] == lab.sha256(downloaded)

    # The "keylogger" only ever wrote the fixed TEST_* events
    dummy = json.loads((lab_dir / "dummy_input_events.json").read_text())
    assert [e["event"] for e in dummy] == ["TEST_KEY_A", "TEST_KEY_B", "TEST_ENTER"]

    # Parent and child are distinct PIDs (a detectable process chain)
    pids = {e["pid"] for e in events}
    assert len(pids) >= 2


def test_run_without_server_errors_clearly(tmp_path: Path):
    port = _free_port()  # nothing listening
    try:
        lab.run(tmp_path / "labdir", port, "run0")
    except SystemExit as exc:
        assert "start it first" in str(exc)
    else:
        raise AssertionError("expected SystemExit when server is down")


def test_reset_refuses_non_lab_dir(tmp_path: Path):
    victim = tmp_path / "important"
    victim.mkdir()
    (victim / "keep.txt").write_text("do not delete me")
    try:
        lab.reset(victim)
    except SystemExit:
        pass
    else:
        raise AssertionError("reset should refuse a directory with no lab files")
    assert (victim / "keep.txt").exists()


def test_reset_removes_real_lab(tmp_path: Path):
    lab_dir = tmp_path / "labdir"
    lab.write_event(lab_dir, "r", "gift_card_lure_opened")  # creates events.jsonl
    assert lab_dir.exists()
    lab.reset(lab_dir)
    assert not lab_dir.exists()


def test_run_auto_serve_starts_own_server(tmp_path: Path):
    lab_dir = tmp_path / "labdir"
    port = _free_port()  # nothing is listening; --auto-serve must provide it
    lab.run(lab_dir, port, "auto0", auto_serve=True)

    names = [e["event"] for e in lab.load_events(lab_dir)]
    assert "local_server_started" in names
    assert "dummy_telemetry_received" in names
    assert "simulation_completed" in names


def test_beacon_sends_periodic_checkins(tmp_path: Path):
    # Server and client use SEPARATE lab dirs (as in real two-host mode) so the
    # two threads never contend for the same events.jsonl.
    server_dir = tmp_path / "server"
    client_dir = tmp_path / "client"
    port = _free_port()
    run_id = "beacon0000000000"

    server = _serve_in_thread(server_dir, port, run_id)
    try:
        lab.beacon(client_dir, port, run_id, count=3, interval=0.0, jitter=0.0)
    finally:
        server.shutdown()

    client_names = [e["event"] for e in lab.load_events(client_dir)]
    assert "c2_beaconing_started" in client_names
    assert "c2_beaconing_completed" in client_names
    # The client logs one c2_beacon_sent per check-in ...
    sent = [e for e in lab.load_events(client_dir) if e["event"] == "c2_beacon_sent"]
    assert [e["seq"] for e in sent] == [1, 2, 3]
    # ... and the server logs receiving each one.
    received = [e for e in lab.load_events(server_dir)
                if e["event"] == "c2_beacon_received"]
    assert len(received) == 3


def test_beacon_count_is_capped(tmp_path: Path):
    # Ask for more than the hard cap; only MAX_BEACONS should be attempted.
    # The started-event records the clamped count without sending anything.
    lab_dir = tmp_path / "labdir"
    port = _free_port()  # nothing listening; we only inspect the started event
    try:
        lab.beacon(lab_dir, port, "cap0", count=lab.MAX_BEACONS + 50,
                   interval=0.0, jitter=0.0)
    except SystemExit:
        pass  # first send fails (no server) -- expected; we want the pre-send log
    started = next(e for e in lab.load_events(lab_dir)
                   if e["event"] == "c2_beaconing_started")
    assert started["beacons"] == lab.MAX_BEACONS


def test_exfil_streams_dummy_bytes(tmp_path: Path):
    # Separate server/client dirs (see test_beacon_sends_periodic_checkins).
    server_dir = tmp_path / "server"
    client_dir = tmp_path / "client"
    port = _free_port()
    run_id = "exfil00000000000"

    server = _serve_in_thread(server_dir, port, run_id)
    try:
        lab.exfil(client_dir, port, run_id, total_bytes=100, chunk=40)
    finally:
        server.shutdown()

    client_events = lab.load_events(client_dir)
    assert "exfil_started" in [e["event"] for e in client_events]
    completed = next(e for e in client_events if e["event"] == "exfil_completed")
    # 100 bytes in 40-byte chunks -> 40 + 40 + 20 = 3 chunks, 100 bytes total.
    assert completed["bytes_sent"] == 100
    assert completed["chunks"] == 3
    chunks = [e for e in client_events if e["event"] == "exfil_chunk_sent"]
    assert [e["bytes_sent"] for e in chunks] == [40, 40, 20]
    assert chunks[-1]["cumulative"] == 100
    # The receiver only tallies dummy bytes -- it never writes real files.
    received = [e for e in lab.load_events(server_dir)
                if e["event"] == "exfil_chunk_received"]
    assert len(received) == 3
    assert not list(server_dir.glob("received_telemetry_*.json"))


def test_exfil_payload_is_clearly_dummy(tmp_path: Path):
    # The bytes on the wire must announce themselves as simulated, not carry
    # anything that looks like real data. Capture the POST body with a minimal
    # sink handler and confirm the self-labelling marker is present.
    lab_dir = tmp_path / "labdir"
    port = _free_port()
    captured: list[bytes] = []

    class Sniffer(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            size = int(self.headers.get("Content-Length", "0"))
            captured.append(self.rfile.read(size))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Sniffer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        lab.exfil(lab_dir, port, "sniff0", total_bytes=60, chunk=60)
    finally:
        server.shutdown()

    assert captured and b"SIMULATED-DUMMY-EXFIL-DATA" in captured[0]


def test_detect_prints_guide():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        lab.detect()
    out = buf.getvalue()
    assert "T1036" in out
    assert "DeviceProcessEvents" in out  # a real hunting query is present
    assert "T1071" in out  # C2 beaconing section (beacon mode)
    assert "T1041" in out  # data-exfiltration section (exfil mode)


def test_announce_prints_banner():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        lab.announce(gui=False)
    assert "TRAINING SIMULATION" in buf.getvalue()


def test_assert_loopback_rejects_public_host():
    try:
        lab.assert_loopback("0.0.0.0")
    except SystemExit:
        pass
    else:
        raise AssertionError("assert_loopback should reject non-loopback hosts")


if __name__ == "__main__":
    import tempfile

    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            arg_count = fn.__code__.co_argcount
            if arg_count:
                with tempfile.TemporaryDirectory() as d:
                    fn(Path(d))
            else:
                fn()
            print(f"ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
