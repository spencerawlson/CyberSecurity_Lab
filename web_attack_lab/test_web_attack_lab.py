"""Tests for the web-attack IR lab. Run:  py test_web_attack_lab.py"""

from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from pathlib import Path

import web_attack_lab as lab


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class GuardTests(unittest.TestCase):
    def test_target_requires_allow_lan(self):
        lab.assert_lab_target("127.0.0.1", False)
        with self.assertRaises(SystemExit):
            lab.assert_lab_target("192.168.1.9", False)

    def test_public_refused_even_with_allow_lan(self):
        lab.assert_lab_target("10.0.0.9", True)
        with self.assertRaises(SystemExit):
            lab.assert_lab_target("8.8.8.8", True)


class AttackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.lab_dir = Path(self.tmp.name)
        self.port = _free_port()
        self.server, self.metrics = lab._build_server(self.port, "127.0.0.1", False)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.stop = threading.Event()
        self.sensors = lab._start_sensors(
            self.port, "127.0.0.1", self.metrics, self.lab_dir, "t", self.stop, 8
        )

    def tearDown(self):
        self.stop.set()
        for s in self.sensors:
            s.close()
        self.server.shutdown()
        self.server.server_close()

    def test_credstuff_yields_401s_and_many_usernames(self):
        res = lab.credstuff("127.0.0.1", self.port, workers=10, rounds=1, source="203.0.113.1")
        self.assertGreater(res["failed"], 10)
        self.assertGreaterEqual(res["success"], 1)  # the one valid pair works
        snap = self.metrics.snapshot()
        self.assertGreaterEqual(snap["unique_usernames"], 5)
        self.assertGreater(snap["status_401"], 10)

    def test_enum_yields_404_spike(self):
        res = lab.enum("127.0.0.1", self.port, workers=10, rounds=1, source="203.0.113.2")
        self.assertGreater(res["not_found_404"], 5)
        self.assertGreaterEqual(res["found_200"], 1)  # some real paths exist

    def test_inject_probes_are_logged_not_executed(self):
        lab.inject("127.0.0.1", self.port, workers=4, rounds=1, source="203.0.113.3")
        self.assertGreater(self.metrics.snapshot()["injection_probes"], 0)

    def test_ssrf_probes_logged_not_fetched(self):
        lab.ssrf("127.0.0.1", self.port, workers=4, rounds=1, source="203.0.113.4")
        snap = self.metrics.snapshot()
        # Most SSRF payloads are pure-SSRF; a file:///etc/passwd probe is
        # legitimately both SSRF and LFI, so we only require the SSRF signal here.
        self.assertGreaterEqual(snap["ssrf_probes"], len(lab.SSRF_PAYLOADS) - 1)

    def test_traversal_probes_logged_not_opened(self):
        lab.traversal("127.0.0.1", self.port, workers=4, rounds=1, source="203.0.113.5")
        snap = self.metrics.snapshot()
        self.assertGreater(snap["traversal_probes"], 0)

    def test_ssrf_marker_detection_covers_metadata_and_schemes(self):
        for p in ("/x?url=http://169.254.169.254/latest/meta-data/",
                  "/y?target=file:///etc/passwd",
                  "/z?src=http://metadata.google.internal/"):
            self.assertTrue(any(m in p.lower() for m in lab.SSRF_MARKERS), p)

    def test_portscan_trips_many_sensor_ports(self):
        res = lab.portscan("127.0.0.1", self.port, source="127.0.0.1")
        self.assertGreater(res["open"], 5)  # sensor bank answered
        self.assertGreaterEqual(self.metrics.snapshot()["widest_port_scan"], 5)


class ReportingTests(unittest.TestCase):
    def test_run_writes_answer_key(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        lab_dir = Path(tmp.name)
        lab.run(lab_dir, _free_port(), "d1", kind="credstuff", workers=15, rounds=1,
                alert_401=1, alert_404=1, alert_scan=8)
        names = {e["event"] for e in lab.load_events(lab_dir)}
        self.assertIn("attack_started", names)
        self.assertIn("victim_metrics_final", names)
        self.assertIn("auth_failure_threshold_exceeded", names)

    def test_reset_refuses_non_lab_dir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with self.assertRaises(SystemExit):
            lab.reset(Path(tmp.name))


class DetectGuideTest(unittest.TestCase):
    def test_detect_covers_technique_and_capture(self):
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            lab.detect()
        out = buf.getvalue()
        self.assertIn("T1110", out)   # brute force / credential stuffing
        self.assertIn("T1595", out)   # active scanning
        self.assertIn("T1552.005", out)  # cloud instance metadata (SSRF)
        self.assertIn("SSRF", out)       # server-side request forgery section
        self.assertIn("T1083", out)      # file/dir discovery (traversal)
        self.assertIn("tcp.flags.syn", out)  # packet-capture guidance present
        self.assertIn("8770", out)           # scoped to the victim port


if __name__ == "__main__":
    unittest.main(verbosity=2)
