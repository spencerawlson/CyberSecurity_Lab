"""Tests for PortBlast. Run:  py test_portblast.py

These mock out the external binaries (RustScan, Nmap, SearchSploit,
Hydra, John, Metasploit), so they run without any tool installed.
"""

from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import creds
import exploit
import portblast
import scanner
import vuln
from scope import Scope, ScopeError


def _result(stdout="", stderr="", returncode=0):
    return types.SimpleNamespace(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
    )


class ScopeTests(unittest.TestCase):
    def test_in_scope_target_accepted(self):
        scope = Scope()
        self.assertEqual(
            str(scope.validate("192.168.1.50")),
            "192.168.1.50",
        )

    def test_out_of_scope_target_refused(self):
        scope = Scope()
        with self.assertRaises(ScopeError):
            scope.validate("8.8.8.8")

    def test_non_ip_refused(self):
        scope = Scope()
        with self.assertRaises(ScopeError):
            scope.validate("example.com")


class OptionParserTests(unittest.TestCase):
    def test_parses_pairs(self):
        self.assertEqual(
            portblast.parse_options(["RPORT=445", "LHOST=10.10.10.5"]),
            {"RPORT": "445", "LHOST": "10.10.10.5"},
        )

    def test_value_may_contain_equals(self):
        self.assertEqual(
            portblast.parse_options(["PAYLOAD=a=b"]),
            {"PAYLOAD": "a=b"},
        )

    def test_missing_equals_rejected(self):
        with self.assertRaises(scanner.ScannerError):
            portblast.parse_options(["bogus"])

    def test_none_is_empty(self):
        self.assertEqual(portblast.parse_options(None), {})


class RustScanParserTests(unittest.TestCase):
    def test_parses_and_sorts_open_ports(self):
        out = "Open 192.168.1.50:80\nOpen 192.168.1.50:22\nnoise\n"
        with mock.patch.object(scanner, "run_command", return_value=_result(out)):
            self.assertEqual(scanner.rustscan("192.168.1.50"), [22, 80])

    def test_no_open_ports(self):
        with mock.patch.object(scanner, "run_command", return_value=_result("")):
            self.assertEqual(scanner.rustscan("192.168.1.50"), [])


class NmapXmlParserTests(unittest.TestCase):
    SAMPLE = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <hostnames><hostname name="lab.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    def test_parses_open_services_only(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".xml", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(self.SAMPLE)
            path = Path(handle.name)

        try:
            target = scanner.parse_nmap_xml(path)
        finally:
            path.unlink(missing_ok=True)

        self.assertEqual(target.address, "192.168.1.50")
        self.assertEqual(target.hostname, "lab.local")
        self.assertEqual(len(target.services), 1)

        service = target.services[0]
        self.assertEqual(service.port, 22)
        self.assertEqual(service.name, "ssh")
        self.assertEqual(service.product, "OpenSSH")
        self.assertEqual(service.version, "8.9")


class SearchSploitTests(unittest.TestCase):
    JSON = (
        '{"RESULTS_EXPLOIT": [{"Title": "OpenSSH 8.9 RCE", '
        '"EDB-ID": "50000", "Path": "/x/50000.py"}]}'
    )

    def test_parses_json_results(self):
        with mock.patch.object(vuln, "run_command", return_value=_result(self.JSON)):
            results = vuln.search_exploits("OpenSSH", "8.9")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["edb_id"], "50000")
        self.assertEqual(results[0]["title"], "OpenSSH 8.9 RCE")

    def test_no_product_skips_lookup(self):
        with mock.patch.object(vuln, "run_command") as runner:
            self.assertEqual(vuln.search_exploits("", ""), [])
            runner.assert_not_called()

    def test_empty_output(self):
        with mock.patch.object(vuln, "run_command", return_value=_result("")):
            self.assertEqual(vuln.search_exploits("OpenSSH"), [])

    def test_bad_json_is_tolerated(self):
        with mock.patch.object(vuln, "run_command", return_value=_result("not json")):
            self.assertEqual(vuln.search_exploits("OpenSSH"), [])


class HydraTests(unittest.TestCase):
    OUTPUT = (
        "[DATA] attacking ssh://192.168.1.50:22\n"
        "[22][ssh] host: 192.168.1.50   login: root   password: toor\n"
    )

    def test_parses_recovered_credentials(self):
        with mock.patch.object(creds, "run_command", return_value=_result(self.OUTPUT)):
            found = creds.hydra("192.168.1.50", "ssh", username="root", password_list=None, password="toor")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["login"], "root")
        self.assertEqual(found[0]["password"], "toor")
        self.assertEqual(found[0]["port"], 22)

    def test_requires_username(self):
        with self.assertRaises(scanner.ScannerError):
            creds.hydra("192.168.1.50", "ssh", password="toor")

    def test_requires_password(self):
        with self.assertRaises(scanner.ScannerError):
            creds.hydra("192.168.1.50", "ssh", username="root")

    def test_missing_wordlist_rejected(self):
        with self.assertRaises(scanner.ScannerError):
            creds.hydra(
                "192.168.1.50", "ssh",
                username="root",
                password_list="does-not-exist.txt",
            )


class JohnTests(unittest.TestCase):
    SHOW = (
        "admin:Password1:::::\n"
        "bob:hunter2:::::\n"
        "\n"
        "2 password hashes cracked, 0 left\n"
    )

    def test_parses_cracked_credentials(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write("admin:$1$...\n")
            path = handle.name

        try:
            with mock.patch.object(creds, "run_command", return_value=_result(self.SHOW)):
                cracked = creds.john(path)
        finally:
            Path(path).unlink(missing_ok=True)

        self.assertEqual(len(cracked), 2)
        self.assertEqual(cracked[0], {"username": "admin", "password": "Password1"})
        self.assertEqual(cracked[1], {"username": "bob", "password": "hunter2"})

    def test_missing_hash_file_rejected(self):
        with self.assertRaises(scanner.ScannerError):
            creds.john("does-not-exist.hashes")


class MetasploitTests(unittest.TestCase):
    def test_resource_script_contents(self):
        script = exploit.build_resource_script(
            "exploit/multi/handler",
            "10.10.10.5",
            {"LPORT": "4444"},
        )
        self.assertIn("use exploit/multi/handler", script)
        self.assertIn("set RHOSTS 10.10.10.5", script)
        self.assertIn("set LPORT 4444", script)
        self.assertTrue(script.strip().endswith("exit"))

    def test_nonzero_exit_raises(self):
        with mock.patch.object(exploit, "run_command", return_value=_result(stderr="boom", returncode=1)):
            with self.assertRaises(scanner.ScannerError):
                exploit.metasploit("exploit/x", "10.10.10.5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
