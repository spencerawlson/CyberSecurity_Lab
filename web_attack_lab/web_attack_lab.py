"""Web-attack incident-response training lab.

A self-contained, harmless simulation of the *observable traces* left by common
web attacks -- credential stuffing, endpoint enumeration (dir-busting),
injection probes, and port scanning -- so defenders can practise detecting them
in access logs and connection telemetry.

Nothing here can attack anything real:
  * The victim web app and the attack generator BOTH refuse any target except
    loopback by default; --allow-lan permits ONLY private/lab ranges (RFC1918 /
    CGNAT / link-local / IPv6 ULA / loopback). Public addresses are refused.
  * The victim only ever *logs* what it receives -- injection payloads are
    recorded, never executed or evaluated.
  * "Sources" are tagged with RFC 5737 documentation IPs; nothing is spoofed.
  * Attempt counts, port ranges and duration are bounded.
  * Every step appends a JSON line to events.jsonl as an answer key.

Modes:
  serve   Run the victim web app (+ a small bank of TCP "sensor" ports so a
          port scan has something to trip).
  attack  Generate a simulated web attack against the loopback victim.
          Types: credstuff, enum, inject, portscan.
  run     One-click drill: start the victim in-process, run the attack, summarise.
  report  Timeline + attack-signature summary from recorded events.
  detect  Blue-team hunting guidance (MITRE T1110 / T1595 / T1190).
  reset   Delete the lab directory so the exercise can be repeated cleanly.
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import os
import shutil
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote

DEFAULT_LAB = Path.home() / "web_attack_lab"
DEFAULT_PORT = 8770
HOST = "127.0.0.1"

SENSOR_PORTS = 16  # extra TCP ports the victim opens so a scan has targets
MAX_WORKERS = 128
MAX_DURATION = 120
DEFAULT_WORKERS = 20
DEFAULT_ALERT_401 = 25   # failed logins/sec that fires the brute-force alert
DEFAULT_ALERT_404 = 25   # 404s/sec that fires the enumeration alert
DEFAULT_ALERT_SCAN = 8   # distinct ports one source touches -> scan alert
MAX_BODY_BYTES = 64 * 1024
SET_CAP = 200_000

RUN_ID_ENV = "WEB_LAB_RUN_ID"
LAB_DIR_ENV = "WEB_LAB_DIR"
PORT_ENV = "WEB_LAB_PORT"

DOC_NETS = ("203.0.113", "198.51.100", "192.0.2")
LOOPBACK = ("127.0.0.1", "localhost", "::1")
CGNAT = ipaddress.ip_network("100.64.0.0/10")
BIND_ANY = ("0.0.0.0", "::")

# The victim's "real" content. Anything else is a 404 (enumeration signal).
REAL_PATHS = {"/", "/login", "/dashboard", "/api/health", "/robots.txt", "/favicon.ico"}
VALID_CREDS = {"admin": "S3cure-Lab-Pw!"}  # one valid pair; stuffing mostly fails

# Obvious attack payload markers the victim LOGS (never executes).
INJECTION_MARKERS = ("' or ", "\" or ", "union select", "<script", "../", "; drop ",
                     "onerror=", "sleep(", "|| ", "&&", "%27")


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def sim_source(index: int) -> str:
    net = DOC_NETS[(index // 254) % len(DOC_NETS)]
    return f"{net}.{(index % 254) + 1}"


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
                f"refusing to target {host!r} -> {addr}: not a private/lab "
                "address. This lab only targets networks you control."
            )


def assert_lab_bind(host: str, allow_lan: bool) -> None:
    if host in LOOPBACK:
        return
    if not allow_lan:
        raise SystemExit(
            f"refusing to bind non-loopback address {host!r}; pass --allow-lan"
        )
    if host in BIND_ANY:
        return
    if not _is_lab_ip(host):
        raise SystemExit(f"refusing to bind {host!r}: not a private/lab address")


BANNER = r"""
+--------------------------------------------------------------+
|            *** TRAINING SIMULATION -- SAFE ***               |
|                                                              |
|   Web-attack IR detection lab. It is NOT an attack tool.     |
|   Traffic stays on loopback by default; with --allow-lan it  |
|   reaches ONLY your private lab network. The victim only     |
|   LOGS what it receives (payloads are never executed), and   |
|   every step is written to events.jsonl as an answer key.    |
|                                                              |
|   Run `python web_attack_lab.py detect` for the hunt guide.  |
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
# Victim: web app + access metrics + port sensors.
# --------------------------------------------------------------------------- #


class Metrics:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.start = time.monotonic()
        self.total_requests = 0
        self.status_counts: dict[int, int] = collections.defaultdict(int)
        self.buckets_401: dict[int, int] = collections.defaultdict(int)
        self.buckets_404: dict[int, int] = collections.defaultdict(int)
        self.usernames: set[str] = set()
        self.paths: set[str] = set()
        self.injections = 0
        self.scan_map: dict[str, set[int]] = collections.defaultdict(set)
        self.peak_401_rps = 0
        self.peak_404_rps = 0

    def _sec(self) -> int:
        return int(time.monotonic() - self.start)

    def on_request(self, status: int, path: str, username: str | None,
                   injection: bool) -> None:
        with self.lock:
            self.total_requests += 1
            self.status_counts[status] += 1
            if path and len(self.paths) < SET_CAP:
                self.paths.add(path)
            if status == 401:
                self.buckets_401[self._sec()] += 1
            if status == 404:
                self.buckets_404[self._sec()] += 1
            if username and len(self.usernames) < SET_CAP:
                self.usernames.add(username)
            if injection:
                self.injections += 1

    def on_port_connect(self, source: str, port: int) -> int:
        with self.lock:
            self.scan_map[source].add(port)
            return len(self.scan_map[source])

    def snapshot(self) -> dict:
        with self.lock:
            widest_scan = max((len(p) for p in self.scan_map.values()), default=0)
            return {
                "elapsed_s": round(time.monotonic() - self.start, 3),
                "total_requests": self.total_requests,
                "status_200": self.status_counts.get(200, 0),
                "status_401": self.status_counts.get(401, 0),
                "status_404": self.status_counts.get(404, 0),
                "unique_usernames": len(self.usernames),
                "unique_paths": len(self.paths),
                "injection_probes": self.injections,
                "peak_401_rps": self.peak_401_rps,
                "peak_404_rps": self.peak_404_rps,
                "widest_port_scan": widest_scan,
            }


def make_handler(metrics: Metrics):
    class VictimHandler(BaseHTTPRequestHandler):
        server_version = "WebLabVictim/1.0"
        protocol_version = "HTTP/1.1"
        timeout = 30

        def _source(self) -> str:
            return self.headers.get("X-Sim-Source") or self.client_address[0]

        def _send(self, status: int, body: bytes, ctype="text/plain") -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (ConnectionError, OSError):
                pass

        def _path_only(self) -> str:
            return self.path.split("?", 1)[0]

        def _has_injection(self) -> bool:
            # A WAF inspects DECODED input, so decode before matching.
            low = unquote(self.path).lower()
            return any(m in low for m in INJECTION_MARKERS)

        def do_GET(self):  # noqa: N802
            path = self._path_only()
            if path == "/stats":
                self._send(200, json.dumps(metrics.snapshot()).encode(),
                           "application/json")
                return
            injection = self._has_injection()
            if injection:
                metrics.on_request(200, path, None, True)
                self._send(200, b"query received (logged, not executed)\n")
                return
            if path in REAL_PATHS:
                status = 200
                body = b"web lab: OK (simulated page)\n"
            else:
                status = 404
                body = b"not found\n"
            metrics.on_request(status, path, None, False)
            self._send(status, body)

        def do_POST(self):  # noqa: N802
            path = self._path_only()
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send(400, b"bad length\n")
                return
            if size < 0 or size > MAX_BODY_BYTES:
                self._send(413, b"too large\n")
                return
            raw = self.rfile.read(size).decode("utf-8", "replace")
            fields = dict(
                kv.split("=", 1) for kv in raw.split("&") if "=" in kv
            )
            if path == "/login":
                user = fields.get("username", "")
                pw = fields.get("password", "")
                ok = VALID_CREDS.get(user) == pw and user != ""
                status = 200 if ok else 401
                metrics.on_request(status, path, user or None, False)
                self._send(status, b"ok\n" if ok else b"invalid credentials\n")
                return
            metrics.on_request(200, path, None, self._has_injection())
            self._send(204 if path != "/login" else 200, b"")

        def log_message(self, *a):
            pass

    return VictimHandler


def _sensor_loop(sock: socket.socket, port: int, metrics: Metrics, lab: Path,
                 run_id: str, stop: threading.Event, alert_scan: int,
                 alerted: set) -> None:
    while not stop.is_set():
        try:
            conn, addr = sock.accept()
        except (socket.timeout, OSError):
            continue
        source = addr[0]
        conn.close()
        distinct = metrics.on_port_connect(source, port)
        if distinct >= alert_scan and source not in alerted:
            alerted.add(source)
            write_event(lab, run_id, "port_scan_detected", source=source,
                        distinct_ports=distinct, threshold=alert_scan,
                        note="one source touched many ports -> scan alert")


def _start_sensors(base_port: int, bind_host: str, metrics: Metrics, lab: Path,
                   run_id: str, stop: threading.Event, alert_scan: int) -> list:
    socks = []
    alerted: set = set()
    for p in range(base_port + 1, base_port + 1 + SENSOR_PORTS):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((bind_host, p))
            s.listen(32)
            s.settimeout(0.5)
        except OSError:
            continue
        threading.Thread(
            target=_sensor_loop,
            args=(s, p, metrics, lab, run_id, stop, alert_scan, alerted),
            daemon=True,
        ).start()
        socks.append(s)
    return socks


def _monitor(metrics: Metrics, lab: Path, run_id: str, stop: threading.Event,
             alert_401: int, alert_404: int) -> None:
    state = {"a401": False, "a404": False}
    while not stop.wait(1.0):
        with metrics.lock:
            sec = metrics._sec() - 1
            r401 = metrics.buckets_401.get(sec, 0)
            r404 = metrics.buckets_404.get(sec, 0)
            metrics.peak_401_rps = max(metrics.peak_401_rps, r401)
            metrics.peak_404_rps = max(metrics.peak_404_rps, r404)
        if r401 > 0 or r404 > 0:
            write_event(lab, run_id, "traffic_window", second=sec,
                        failed_logins=r401, not_found=r404)
        if r401 >= alert_401 and not state["a401"]:
            state["a401"] = True
            write_event(lab, run_id, "auth_failure_threshold_exceeded",
                        failed_logins=r401, threshold=alert_401,
                        note="credential-stuffing / brute-force alert would fire")
        if r404 >= alert_404 and not state["a404"]:
            state["a404"] = True
            write_event(lab, run_id, "not_found_threshold_exceeded",
                        not_found=r404, threshold=alert_404,
                        note="endpoint-enumeration / dir-busting alert would fire")


def _build_server(port: int, bind_host: str, allow_lan: bool):
    assert_lab_bind(bind_host, allow_lan)
    metrics = Metrics()
    try:
        server = ThreadingHTTPServer((bind_host, port), make_handler(metrics))
    except OSError as exc:
        raise SystemExit(f"could not bind {bind_host}:{port} ({exc})")
    server.daemon_threads = True
    return server, metrics


def serve(lab: Path, port: int, run_id: str, alert_401: int, alert_404: int,
          alert_scan: int, bind_host: str = HOST, allow_lan: bool = False) -> None:
    server, metrics = _build_server(port, bind_host, allow_lan)
    stop = threading.Event()
    threading.Thread(target=_monitor,
                     args=(metrics, lab, run_id, stop, alert_401, alert_404),
                     daemon=True).start()
    sensors = _start_sensors(port, bind_host, metrics, lab, run_id, stop, alert_scan)
    scope = "loopback only" if bind_host in LOOPBACK else "private lab network"
    write_event(lab, run_id, "victim_server_started", address=f"{bind_host}:{port}",
                sensor_ports=len(sensors))
    print(f"Victim web app on {bind_host}:{port} (+{len(sensors)} sensor ports) "
          f"({scope}). Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        for s in sensors:
            s.close()
        server.shutdown()
        server.server_close()
        write_event(lab, run_id, "victim_server_stopped", **metrics.snapshot())


# --------------------------------------------------------------------------- #
# Attacks (loopback / lab only, all bounded).
# --------------------------------------------------------------------------- #

COMMON_USERS = ["admin", "root", "administrator", "test", "guest", "user",
                "operator", "backup", "oracle", "postgres", "www", "deploy",
                "support", "info", "sales", "jsmith", "mjones", "svc-account",
                "helpdesk", "sysadmin"]
COMMON_PASSWORDS = ["123456", "password", "admin", "letmein", "welcome",
                    "P@ssw0rd", "changeme", "qwerty", "iloveyou", "root"]
WORDLIST = ["/admin", "/login", "/wp-admin", "/.git/config", "/.env", "/backup",
            "/config.php", "/phpmyadmin", "/api", "/api/v1/users", "/server-status",
            "/robots.txt", "/dashboard", "/uploads", "/test", "/old", "/dev",
            "/.svn", "/db", "/secret", "/private", "/tmp", "/logs", "/shell.php",
            "/administrator", "/cgi-bin", "/api/health", "/status", "/debug"]
INJECT_PAYLOADS = ["/search?q=' OR '1'='1", "/search?q=1 UNION SELECT NULL--",
                   "/search?q=<script>alert(1)</script>", "/item?id=1; DROP TABLE users",
                   "/file?path=../../../../etc/passwd", "/search?q=admin'--",
                   "/api?cb=1&x=sleep(5)", "/p?u=<img src=x onerror=alert(1)>"]


def _safe_path(path: str) -> str:
    """Percent-encode a path/query so it is a valid request-target (a real
    attacker encodes payloads too; the victim decodes them for inspection)."""
    if "?" in path:
        base, query = path.split("?", 1)
        return quote(base, safe="/") + "?" + quote(query, safe="=&")
    return quote(path, safe="/")


def _http_get(host, port, path, source):
    conn = HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", _safe_path(path), headers={"X-Sim-Source": source})
        return conn.getresponse().status
    finally:
        conn.close()


def _http_post(host, port, path, body, source):
    conn = HTTPConnection(host, port, timeout=5)
    try:
        conn.request("POST", path, body=body,
                     headers={"X-Sim-Source": source,
                              "Content-Type": "application/x-www-form-urlencoded"})
        return conn.getresponse().status
    finally:
        conn.close()


def credstuff(host, port, workers, rounds, source):
    combos = [(u, p) for u in COMMON_USERS for p in COMMON_PASSWORDS] * rounds
    combos.append(("admin", "S3cure-Lab-Pw!"))  # the one that works, buried in noise
    results = {"attempts": 0, "success": 0, "failed": 0}
    lock = threading.Lock()

    def attempt(cred):
        u, p = cred
        status = _http_post(host, port, "/login", f"username={u}&password={p}", source)
        with lock:
            results["attempts"] += 1
            if status == 200:
                results["success"] += 1
            else:
                results["failed"] += 1

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(attempt, combos))
    return results


def enum(host, port, workers, rounds, source):
    paths = WORDLIST * rounds
    results = {"requests": 0, "found_200": 0, "not_found_404": 0}
    lock = threading.Lock()

    def probe(path):
        status = _http_get(host, port, path, source)
        with lock:
            results["requests"] += 1
            if status == 200:
                results["found_200"] += 1
            elif status == 404:
                results["not_found_404"] += 1

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(probe, paths))
    return results


def inject(host, port, workers, rounds, source):
    payloads = INJECT_PAYLOADS * rounds
    results = {"probes_sent": len(payloads)}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(lambda p: _http_get(host, port, p, source), payloads))
    return results


def portscan(host, port, source):
    """TCP connect scan across the victim's port bank (+ a few closed ports)."""
    lo, hi = port + 1, port + 1 + SENSOR_PORTS + 8  # include closed ports too
    open_ports, closed = [], 0
    for p in range(lo, hi):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            if s.connect_ex((host, p)) == 0:
                open_ports.append(p)
            else:
                closed += 1
        except OSError:
            closed += 1
        finally:
            s.close()
    return {"ports_scanned": hi - lo, "open": len(open_ports), "closed": closed}


ATTACKS = ("credstuff", "enum", "inject", "portscan")


def attack(lab: Path, port: int, run_id: str, kind: str, workers: int,
           rounds: int, target_host: str = HOST, allow_lan: bool = False) -> dict:
    assert_lab_target(target_host, allow_lan)
    workers = max(1, min(workers, MAX_WORKERS))
    rounds = max(1, min(rounds, 50))
    scope = "loopback only" if target_host in LOOPBACK else "private lab network"
    write_event(lab, run_id, "attack_started", attack=kind, workers=workers,
                rounds=rounds, target=f"{target_host}:{port}")
    print(f"Generating SIMULATED {kind} against {target_host}:{port} ({scope}).")
    src = sim_source(1)
    if kind == "credstuff":
        result = credstuff(target_host, port, workers, rounds, src)
    elif kind == "enum":
        result = enum(target_host, port, workers, rounds, src)
    elif kind == "inject":
        result = inject(target_host, port, workers, rounds, src)
    else:
        result = portscan(target_host, port, src)
    write_event(lab, run_id, "attack_completed", attack=kind, **result)
    print(f"Attack complete: {json.dumps(result)}")
    return result


# --------------------------------------------------------------------------- #
# One-click drill.
# --------------------------------------------------------------------------- #


def run(lab: Path, port: int, run_id: str, kind: str, workers: int, rounds: int,
        alert_401: int, alert_404: int, alert_scan: int,
        show_banner: bool = False) -> None:
    if show_banner:
        announce()
    lab.mkdir(exist_ok=True)
    server, metrics = _build_server(port, HOST, False)
    stop = threading.Event()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    threading.Thread(target=_monitor,
                     args=(metrics, lab, run_id, stop, alert_401, alert_404),
                     daemon=True).start()
    sensors = _start_sensors(port, HOST, metrics, lab, run_id, stop, alert_scan)
    write_event(lab, run_id, "victim_server_started", address=f"{HOST}:{port}",
                sensor_ports=len(sensors))
    time.sleep(1.0)

    attack(lab, port, run_id, kind, workers, rounds)

    time.sleep(1.5)
    final = metrics.snapshot()
    write_event(lab, run_id, "victim_metrics_final", **final)
    write_event(lab, run_id, "simulation_completed")
    stop.set()
    for s in sensors:
        s.close()
    server.shutdown()
    server.server_close()

    print("\nObserved at the victim:")
    print(f"  200 / 401 / 404      : {final['status_200']} / {final['status_401']} "
          f"/ {final['status_404']}")
    print(f"  unique usernames     : {final['unique_usernames']}")
    print(f"  unique paths         : {final['unique_paths']}")
    print(f"  injection probes     : {final['injection_probes']}")
    print(f"  widest port scan     : {final['widest_port_scan']} ports from one source")
    print("\nRun `report` for the timeline, `detect` for the hunting guide.")


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
        extra = ""
        if e["event"] == "traffic_window":
            extra = f"  401/s={e.get('failed_logins')} 404/s={e.get('not_found')}"
        elif e["event"].endswith(("_threshold_exceeded", "_detected")):
            extra = f"  !! {e.get('note', '')}"
        elif e["event"] == "attack_started":
            extra = f"  attack={e.get('attack')}"
        print(f"  {e['time_utc']}  [{tag}] {e['event']}{extra}")

    final = next((e for e in reversed(events)
                  if e["event"] in ("victim_metrics_final", "victim_server_stopped")), None)
    alerts = [e for e in events if e["event"].endswith(("_threshold_exceeded", "_detected"))]
    print("\nAttack signature summary:")
    if final:
        print(f"  200 / 401 / 404   : {final.get('status_200', 0)} / "
              f"{final.get('status_401', 0)} / {final.get('status_404', 0)}")
        print(f"  unique usernames  : {final.get('unique_usernames', 0)}")
        print(f"  unique paths      : {final.get('unique_paths', 0)}")
        print(f"  injection probes  : {final.get('injection_probes', 0)}")
        print(f"  widest port scan  : {final.get('widest_port_scan', 0)}")
    print(f"  alerts fired      : {len(alerts)}")
    for a in alerts:
        print(f"    - {a['event']} ({a.get('note', '')})")


DETECTION_GUIDE = r"""
BLUE-TEAM HUNTING GUIDE -- web attacks (MITRE T1110 / T1595 / T1190)
====================================================================
This lab imitates four web attacks. Map each to the recorded events (`report`)
and confirm your tooling caught it.

  credstuff (T1110 Brute Force / Credential Stuffing)
    Signature: burst of 401s, MANY distinct usernames, one/few sources, one
    endpoint (/login). Lab metric: status_401 spike, unique_usernames high.
  enum (T1595 Active Scanning / dir-busting)
    Signature: burst of 404s across many DISTINCT paths from one source; a few
    200s reveal what exists. Lab metric: status_404 spike, unique_paths high.
  inject (T1190 Exploit Public-Facing App -- SQLi/XSS/traversal probes)
    Signature: request parameters carrying payload markers (' OR 1=1, UNION
    SELECT, <script>, ../). Lab metric: injection_probes > 0 (logged, never run).
  portscan (T1595.001)
    Signature: one source opening connections to MANY ports in a short window.
    Lab metric: widest_port_scan high; port_scan_detected event.

1. AUTHENTICATION MONITORING
   - Alert on failed-login rate per source and per account; watch for one source
     trying many usernames (stuffing) or many sources one account (spraying).
   - KQL: SigninLogs | where ResultType != 0 | summarize fails=count(),
     users=dcount(UserPrincipalName) by bin(TimeGenerated,1m), IPAddress
   - Follow-through: did any 401 burst end in a 200 (success)? That is the one
     to chase. Lock-outs, MFA, and rate limits are the controls to demo.

2. WEB-LOG ANOMALIES (enumeration)
   - 404 rate per source; count of distinct URLs per source per minute.
   - Scanner user-agents, sequential/alphabetical path probing, hits on
     /.git, /.env, /wp-admin, /phpmyadmin, /server-status.

3. INJECTION PROBES
   - WAF / log pattern match for SQLi/XSS/traversal signatures in query and body.
   - High signal when payloads hit params that normally take plain values.
   - Controls: parameterised queries, input validation, WAF, output encoding.

4. SCANNING / RECON
   - Connections to many closed ports from one source (SYN to no listener),
     high connection-attempt fan-out. NetFlow: one src -> many dst ports.
   - Controls: rate limit, tarpit, alert, and reduce exposed surface.

5. PACKET-CAPTURE VIEW (on the wire)
   The logs tell most of the story, but capture confirms it and catches the
   scan the app never sees. Capture the victim + its sensor ports:
     tcpdump -i lo -n 'port 8770 or portrange 8771-8790' -w web.pcap   (on
     Windows capture on the Npcap loopback adapter)
   - credstuff / enum: Wireshark `http.request` shows the POST /login burst;
     `http.response.code == 404` isolates the enumeration sweep.
   - inject: the payload markers are visible in the request URI/body on the wire
     (and logged, never executed).
   - portscan: `tcp.flags.syn==1 && tcp.flags.ack==0` reveals one source's SYNs
     fanning across many ports (connections to closed ports draw a RST).

TABLETOP MAPPING (lab event -> what the detector should see)
   auth_failure_threshold_exceeded -> brute-force / credential-stuffing alert
   not_found_threshold_exceeded    -> enumeration / dir-busting alert
   injection_probes (final)        -> WAF/log payload matches
   port_scan_detected              -> scan detection on the port sensors
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
    parser.add_argument("mode", choices=["serve", "attack", "run", "report", "detect", "reset"])
    parser.add_argument("--lab-dir", type=Path,
                        default=Path(os.environ.get(LAB_DIR_ENV, DEFAULT_LAB)))
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get(PORT_ENV, DEFAULT_PORT)))
    parser.add_argument("--attack", choices=ATTACKS, default="credstuff",
                        help="attack type (attack/run modes)")
    parser.add_argument("--bind", default=HOST,
                        help="victim listen address (serve); LAN IP/0.0.0.0 needs --allow-lan")
    parser.add_argument("--target", default=HOST,
                        help="address to attack (attack); private/lab host, needs --allow-lan")
    parser.add_argument("--allow-lan", action="store_true",
                        help="permit private lab network; public addresses refused")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"concurrent workers (default {DEFAULT_WORKERS}, max {MAX_WORKERS})")
    parser.add_argument("--rounds", type=int, default=3,
                        help="how many times to repeat the wordlist/cred list (default 3)")
    parser.add_argument("--alert-401", type=int, default=DEFAULT_ALERT_401)
    parser.add_argument("--alert-404", type=int, default=DEFAULT_ALERT_404)
    parser.add_argument("--alert-scan", type=int, default=DEFAULT_ALERT_SCAN)
    parser.add_argument("--announce", action="store_true")
    args = parser.parse_args(argv)

    lab = args.lab_dir
    run_id = os.environ.get(RUN_ID_ENV) or uuid.uuid4().hex

    if args.mode == "serve":
        serve(lab, args.port, run_id, args.alert_401, args.alert_404, args.alert_scan,
              bind_host=args.bind, allow_lan=args.allow_lan)
    elif args.mode == "attack":
        attack(lab, args.port, run_id, args.attack, args.workers, args.rounds,
               target_host=args.target, allow_lan=args.allow_lan)
    elif args.mode == "run":
        run(lab, args.port, run_id, args.attack, args.workers, args.rounds,
            args.alert_401, args.alert_404, args.alert_scan, show_banner=args.announce)
    elif args.mode == "report":
        report(lab)
    elif args.mode == "detect":
        detect()
    else:
        reset(lab)


if __name__ == "__main__":
    main()
