"""Web entrypoint for the gift-card IR training lab.

Wraps the stdlib simulation in a small FastAPI app so the lab can be
explored from a browser: trigger a simulation, inspect the recorded
events (the answer key), read the IOC report, and pull the blue-team
detection guide.

Deploy targets:
  * Vercel — this file is auto-detected as the Python entrypoint
    (project root = gift_card_lab/, requirements.txt supplies fastapi).
  * Local — `uvicorn api.index:app` from the gift_card_lab/ directory.

The safety model is unchanged from the CLI lab:
  * All network traffic stays on the loopback interface (127.0.0.1).
  * The lab writes only inside its own directory (``/tmp`` on serverless,
    where the filesystem is read-only elsewhere).
  * ``reset`` refuses to delete anything that does not look like a lab
    directory.
"""

from __future__ import annotations

import socket
import sys
import threading
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.responses import PlainTextResponse  # noqa: E402

import gift_card_lab as lab  # noqa: E402

# Serverless filesystems are read-only outside /tmp; keep the lab there.
LAB_DIR = Path("/tmp/gift_card_ir_lab")

app = FastAPI(
    title="Gift Card IR Training Lab",
    description=(
        "Web front-end for the gift-card incident-response training lab. "
        "Simulates the observable traces of a gift-card scam infection "
        "(loopback only, harmless by design) so defenders can practise "
        "detecting them."
    ),
    version="1.0.0",
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ioc_summary(events: list[dict]) -> dict:
    """Same IOC aggregation as lab.report(), returned as data."""
    hashes = sorted({e["sha256"] for e in events if "sha256" in e})
    pids = sorted({e["pid"] for e in events if "pid" in e})
    addresses = sorted({e["address"] for e in events if "address" in e})
    paths = sorted(
        {e["path"] for e in events if "path" in e}
        | {e["artifact"] for e in events if "artifact" in e}
    )
    runs = sorted({e["run_id"] for e in events if e.get("run_id")})
    persistence_iocs = [
        e for e in events
        if e["event"] in ("persistence_run_key_set",
                          "persistence_scheduled_task_created")
    ]
    return {
        "event_count": len(events),
        "runs_observed": runs,
        "process_ids": pids,
        "listen_addresses": addresses,
        "file_hashes": hashes,
        "artifact_paths": paths,
        "persistence_iocs": persistence_iocs,
    }


@app.get("/", summary="Lab overview")
def index() -> dict:
    return {
        "lab": "gift-card incident-response training lab",
        "safety": "loopback-only simulation; nothing malicious, nothing leaves the host",
        "endpoints": {
            "POST /simulate": "run the full attack-chain simulation in-process",
            "GET /events": "recorded event timeline (the answer key)",
            "GET /report": "IOC summary derived from recorded events",
            "GET /detect": "blue-team hunting guide (masquerading / lures)",
            "POST /reset": "delete the lab directory so the exercise can repeat",
        },
    }


@app.get("/detect", summary="Blue-team detection guide",
         response_class=PlainTextResponse)
def detect() -> str:
    return lab.DETECTION_GUIDE.strip() + "\n"


@app.get("/events", summary="Recorded event timeline")
def events() -> dict:
    evts = lab.load_events(LAB_DIR)
    return {"lab_dir": str(LAB_DIR), "event_count": len(evts), "events": evts}


@app.get("/report", summary="IOC summary")
def report() -> dict:
    return {"lab_dir": str(LAB_DIR), **_ioc_summary(lab.load_events(LAB_DIR))}


@app.post("/simulate", summary="Run the attack-chain simulation")
def simulate() -> dict:
    """Play out lure -> download -> persistence -> beacon -> exfil.

    Runs fully in-process against a loopback server started in a
    background thread (the CLI's ``child`` subprocess mode is skipped;
    serverless environments cannot spawn it reliably).
    """
    run_id = uuid.uuid4().hex[:16]
    port = _free_port()
    LAB_DIR.mkdir(parents=True, exist_ok=True)

    server = ThreadingHTTPServer(
        ("127.0.0.1", port), lab.make_handler(LAB_DIR, run_id)
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        lab.write_event(LAB_DIR, run_id, "gift_card_lure_opened",
                        scenario="training simulation (web)")
        # Victim downloads the lure from the loopback "attacker" host.
        from urllib.request import urlopen
        with urlopen(f"http://127.0.0.1:{port}/gift-card", timeout=5) as resp:
            downloaded = resp.read()
        gift_card = LAB_DIR / "gift_card.txt"
        gift_card.write_bytes(downloaded)
        lab.write_event(LAB_DIR, run_id, "gift_card_file_downloaded",
                        path=str(gift_card), sha256=lab.sha256(gift_card))
        # Persistence stage (artifact files only; touches nothing real).
        lab.persistence(LAB_DIR, port, run_id)
        # Short C2 beacon + staged exfil so defenders see the pattern.
        lab.beacon(LAB_DIR, port, run_id, count=3, interval=0.3, jitter=0.1)
        lab.exfil(LAB_DIR, port, run_id, total_bytes=2048, chunk=512)
        lab.write_event(LAB_DIR, run_id, "simulation_completed")
    except SystemExit as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        server.shutdown()
        server.server_close()

    return {"run_id": run_id, "lab_dir": str(LAB_DIR),
            "events": lab.load_events(LAB_DIR)}


@app.post("/reset", summary="Reset the lab directory")
def reset() -> dict:
    try:
        lab.reset(LAB_DIR)
    except SystemExit as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"lab_dir": str(LAB_DIR), "reset": True}
