import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

LAB = Path.home() / "gift_card_ir_lab"
PORT = 8765


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def write_event(event, **details):
    LAB.mkdir(exist_ok=True)
    record = {"time_utc": timestamp(), "event": event, "pid": os.getpid(), **details}

    with (LAB / "events.jsonl").open("a", encoding="utf-8") as log:
        log.write(json.dumps(record) + "\n")

    print(json.dumps(record))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/gift-card":
            self.send_error(404)
            return

        content = (
            b"Gift card investigation lab\n"
            b"This is a harmless simulated download.\n"
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", 'attachment; filename="gift_card.txt"')
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)
        write_event("gift_card_download_served", client=self.client_address[0])

    def do_POST(self):
        if self.path != "/lab-telemetry":
            self.send_error(404)
            return

        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)

        # The receiver stores only dummy lab data.
        (LAB / "received_telemetry.json").write_bytes(body)
        write_event("dummy_telemetry_received", bytes_received=len(body))

        self.send_response(204)
        self.end_headers()

    def log_message(self, format_string, *args):
        pass


def serve():
    LAB.mkdir(exist_ok=True)
    server = HTTPServer(("127.0.0.1", PORT), LabHandler)
    write_event("local_server_started", address=f"127.0.0.1:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


def child():
    write_event("child_process_started", parent_pid=os.getppid())

    # These are fixed test events, not keyboard input.
    dummy_events = [
        {"time_utc": timestamp(), "event": "TEST_KEY_A"},
        {"time_utc": timestamp(), "event": "TEST_KEY_B"},
        {"time_utc": timestamp(), "event": "TEST_ENTER"},
    ]
    output = LAB / "dummy_input_events.json"
    output.write_text(json.dumps(dummy_events, indent=2), encoding="utf-8")
    write_event("dummy_event_file_created", path=str(output))

    request = Request(
        f"http://127.0.0.1:{PORT}/lab-telemetry",
        data=output.read_bytes(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        write_event("loopback_request_sent", http_status=response.status)

    time.sleep(3)  # Briefly leaves the child visible in process listings.


def run():
    LAB.mkdir(exist_ok=True)
    write_event("gift_card_lure_opened", scenario="training simulation")

    url = f"http://127.0.0.1:{PORT}/gift-card"
    with urlopen(url, timeout=5) as response:
        downloaded = response.read()

    file_path = LAB / "gift_card.txt"
    file_path.write_bytes(downloaded)
    write_event(
        "gift_card_file_downloaded",
        path=str(file_path),
        sha256=sha256(file_path),
    )

    write_event("child_process_launch_requested")
    subprocess.run([sys.executable, str(Path(__file__).resolve()), "child"], check=True)
    write_event("simulation_completed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["serve", "run", "child"])
    mode = parser.parse_args().mode

    if mode == "serve":
        serve()
    elif mode == "run":
        run()
    else:
        child()