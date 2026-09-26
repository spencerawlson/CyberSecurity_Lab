"""Smoke tests for the gift-card IR training lab.

Run with:  python -m pytest test_gift_card_lab.py   (or: python test_gift_card_lab.py)
"""

import contextlib
import io
import json
import socket
import threading
from http.server import ThreadingHTTPServer
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


def test_detect_prints_guide():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        lab.detect()
    out = buf.getvalue()
    assert "T1036" in out
    assert "DeviceProcessEvents" in out  # a real hunting query is present


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
