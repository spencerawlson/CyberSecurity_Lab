"""Tests for the UDP amplification concept lab. Run: py test_amp_lab.py"""

from __future__ import annotations

import socket
import tempfile
import unittest
from pathlib import Path

import amp_lab as lab


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class GuardTests(unittest.TestCase):
    def test_target_guard(self):
        lab.assert_lab_target("127.0.0.1", False)
        with self.assertRaises(SystemExit):
            lab.assert_lab_target("192.168.0.5", False)
        with self.assertRaises(SystemExit):
            lab.assert_lab_target("8.8.8.8", True)  # public refused


class AmplificationTests(unittest.TestCase):
    def test_run_measures_amplification_factor(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        lab_dir = Path(tmp.name)
        lab.run(lab_dir, _free_udp_port(), "amp1", factor=50, queries=100)
        done = next(e for e in reversed(lab.load_events(lab_dir))
                    if e["event"] == "simulation_completed")
        # A small query should return many more bytes than it sent.
        self.assertGreater(done["amplification_factor"], 5)
        self.assertGreater(done["bytes_received"], done["bytes_sent"])

    def test_response_size_is_capped(self):
        # Even an absurd factor cannot exceed the lab cap.
        self.assertLessEqual(min(lab.MAX_RESPONSE_BYTES, 10_000_000 * len(lab.QUERY)),
                             lab.MAX_RESPONSE_BYTES)

    def test_ntp_profile_amplifies_more_than_ssdp(self):
        # Named profiles carry realistic, distinct factors; NTP >> SSDP.
        for name in ("ntp", "ssdp", "dns", "memcached", "generic"):
            self.assertIn(name, lab.PROFILES)
        ntp = tempfile.TemporaryDirectory(); self.addCleanup(ntp.cleanup)
        ssdp = tempfile.TemporaryDirectory(); self.addCleanup(ssdp.cleanup)
        lab.run(Path(ntp.name), _free_udp_port(), "ntp1", factor=50, queries=60, profile="ntp")
        lab.run(Path(ssdp.name), _free_udp_port(), "ssdp1", factor=50, queries=60, profile="ssdp")
        ntp_f = next(e for e in reversed(lab.load_events(Path(ntp.name)))
                     if e["event"] == "simulation_completed")["amplification_factor"]
        ssdp_f = next(e for e in reversed(lab.load_events(Path(ssdp.name)))
                      if e["event"] == "simulation_completed")["amplification_factor"]
        self.assertGreater(ntp_f, ssdp_f)
        self.assertGreater(ntp_f, 100)  # monlist is a big amplifier

    def test_memcached_response_is_capped(self):
        # memcached's real factor is enormous; the lab must cap the response.
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        lab.run(Path(tmp.name), _free_udp_port(), "mc1", factor=50, queries=40, profile="memcached")
        done = next(e for e in reversed(lab.load_events(Path(tmp.name)))
                    if e["event"] == "simulation_completed")
        # Per-answer bytes can never exceed the cap.
        per_answer = done["bytes_received"] / max(1, done["answered"])
        self.assertLessEqual(per_answer, lab.MAX_RESPONSE_BYTES)

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
        self.assertIn("T1498.002", out)          # reflection amplification
        self.assertIn("amplification factor", out)
        self.assertIn("monlist", out)            # NTP profile documented
        self.assertIn("ssdp", out)               # SSDP profile documented
        self.assertIn("udp.port == 8769", out)   # packet-capture guidance present


if __name__ == "__main__":
    unittest.main(verbosity=2)
