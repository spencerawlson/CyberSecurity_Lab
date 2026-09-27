"""Tests for the DDoS IR training lab.

These prove the safety guarantees (loopback-only, capped) and that the
detection signal (rate spike / connection growth) actually shows up in the
recorded events, so the exercise has an honest answer key.

Run:  py test_ddos_sim.py
"""

from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import ddos_sim as lab


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SafetyGuardTests(unittest.TestCase):
    def test_assert_loopback_allows_localhost(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            lab.assert_loopback(host)  # must not raise

    def test_assert_loopback_refuses_remote(self):
        for host in ("8.8.8.8", "example.com", "0.0.0.0", "10.0.0.5"):
            with self.assertRaises(SystemExit):
                lab.assert_loopback(host)

    def test_sim_source_uses_documentation_ranges(self):
        for i in range(0, 800, 37):
            self.assertTrue(
                lab.sim_source(i).startswith(lab.DOC_NETS),
                f"{lab.sim_source(i)} is not an RFC 5737 documentation address",
            )

    def test_flood_caps_workers_and_duration(self):
        # A request for absurd load must be clamped, not honoured.
        self.assertLessEqual(lab.MAX_WORKERS, 256)
        self.assertLessEqual(lab.MAX_DURATION, 300)

    def test_lab_target_requires_allow_lan_for_non_loopback(self):
        # Without --allow-lan, only loopback is permitted.
        lab.assert_lab_target("127.0.0.1", allow_lan=False)
        with self.assertRaises(SystemExit):
            lab.assert_lab_target("192.168.1.10", allow_lan=False)

    def test_lab_target_allows_private_refuses_public(self):
        for private in ("10.0.0.5", "192.168.50.20", "172.16.4.4", "169.254.1.1", "100.64.0.1"):
            lab.assert_lab_target(private, allow_lan=True)  # must not raise
        for public in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
            with self.assertRaises(SystemExit):
                lab.assert_lab_target(public, allow_lan=True)

    def test_lab_bind_rules(self):
        lab.assert_lab_bind("127.0.0.1", allow_lan=False)
        with self.assertRaises(SystemExit):
            lab.assert_lab_bind("0.0.0.0", allow_lan=False)
        lab.assert_lab_bind("0.0.0.0", allow_lan=True)  # all interfaces on a lab box
        lab.assert_lab_bind("10.1.2.3", allow_lan=True)
        with self.assertRaises(SystemExit):
            lab.assert_lab_bind("8.8.8.8", allow_lan=True)

    def test_is_lab_ip_classifies_ranges(self):
        self.assertTrue(lab._is_lab_ip("10.0.0.1"))
        self.assertTrue(lab._is_lab_ip("fc00::1"))       # IPv6 ULA
        self.assertTrue(lab._is_lab_ip("fe80::1%eth0"))  # link-local w/ scope id
        self.assertFalse(lab._is_lab_ip("8.8.8.8"))
        self.assertFalse(lab._is_lab_ip("not-an-ip"))


class VictimMetricsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lab_dir = Path(self.tmp.name)
        self.port = _free_port()
        self.server, self.metrics = lab._build_server(self.port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def test_volumetric_flood_registers_requests_and_sources(self):
        result = lab.flood(
            self.lab_dir, self.port, "run-vol", "volumetric", workers=8, duration=2
        )
        self.assertGreater(result["sent"], 0)
        snap = self.metrics.snapshot()
        self.assertGreater(snap["total_requests"], 0)
        # Each worker uses a distinct fake source, so fan-out should be visible.
        self.assertGreaterEqual(snap["unique_sources"], 2)

    def test_slowloris_raises_concurrency_without_completing_requests(self):
        before = self.metrics.snapshot()["total_requests"]
        lab.flood(
            self.lab_dir, self.port, "run-slow", "slowloris", workers=10, duration=2
        )
        snap = self.metrics.snapshot()
        # Slowloris holds sockets open -> peak concurrency climbs, but the
        # requests never complete, so total_requests barely moves.
        self.assertGreaterEqual(snap["peak_concurrent"], 5)
        self.assertLessEqual(snap["total_requests"] - before, 2)

    def test_stats_endpoint_returns_json(self):
        conn = __import__("http.client", fromlist=["HTTPConnection"]).HTTPConnection(
            "127.0.0.1", self.port, timeout=5
        )
        conn.request("GET", "/stats")
        payload = json.loads(conn.getresponse().read())
        conn.close()
        self.assertIn("total_requests", payload)
        self.assertIn("peak_concurrent", payload)

    def test_cachebust_produces_many_unique_urls(self):
        lab.flood(self.lab_dir, self.port, "cb", "cachebust", workers=6, duration=2)
        snap = self.metrics.snapshot()
        # Every request has a unique path -> unique_urls tracks total_requests.
        self.assertGreater(snap["unique_urls"], 10)
        self.assertGreaterEqual(snap["unique_urls"], snap["total_requests"] // 2)

    def test_connflood_opens_a_connection_per_request(self):
        lab.flood(self.lab_dir, self.port, "cf", "connflood", workers=6, duration=2)
        snap = self.metrics.snapshot()
        # Fresh socket each time -> connections ~= requests (no keep-alive reuse).
        self.assertGreater(snap["total_connections"], 10)
        self.assertGreaterEqual(snap["total_connections"], snap["total_requests"])

    def test_volumetric_reuses_connections(self):
        lab.flood(self.lab_dir, self.port, "v", "volumetric", workers=6, duration=2)
        snap = self.metrics.snapshot()
        # Keep-alive -> far more requests than connections.
        self.assertGreater(snap["total_requests"], snap["total_connections"] * 3)

    def test_bodyflood_registers_inbound_bytes(self):
        lab.flood(self.lab_dir, self.port, "bf", "bodyflood", workers=4, duration=2)
        snap = self.metrics.snapshot()
        self.assertGreater(snap["total_bytes_in"], 100_000)

    def test_rudy_holds_connections_open(self):
        lab.flood(self.lab_dir, self.port, "r", "rudy", workers=8, duration=2)
        snap = self.metrics.snapshot()
        # Slow POST body holds the server blocked reading -> concurrency climbs.
        self.assertGreaterEqual(snap["peak_concurrent"], 4)


class ReportingTests(unittest.TestCase):
    def test_run_writes_answer_key_with_spike(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        lab_dir = Path(tmp.name)
        port = _free_port()
        # Low alert threshold so the mock alert reliably fires in a short test.
        lab.run(
            lab_dir, port, "drill-1", attack="volumetric", workers=12, duration=2,
            alert_rps=1, alert_conns=100000,
        )
        events = lab.load_events(lab_dir)
        names = {e["event"] for e in events}
        self.assertIn("baseline_captured", names)
        self.assertIn("flood_started", names)
        self.assertIn("victim_metrics_final", names)
        self.assertIn("simulation_completed", names)
        self.assertIn("rate_threshold_exceeded", names)

    def test_reset_refuses_non_lab_dir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        empty = Path(tmp.name)  # no events.jsonl marker
        with self.assertRaises(SystemExit):
            lab.reset(empty)
        self.assertTrue(empty.exists())


class DetectGuideTest(unittest.TestCase):
    def test_detect_covers_technique_and_capture(self):
        import contextlib
        import io

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            lab.detect()
        out = buf.getvalue()
        self.assertIn("T1498", out)   # network DoS
        self.assertIn("T1499", out)   # endpoint DoS
        self.assertIn("tcpdump", out)  # packet-capture guidance present
        self.assertIn("8768", out)     # scoped to the victim port


if __name__ == "__main__":
    unittest.main(verbosity=2)
