"""Smoke tests for the gift-card lab web entrypoint (api/index.py).

FastAPI is an optional dependency here: the CI workflow installs only
pytest (the labs are stdlib-only), so these tests skip when fastapi is
not importable. Install requirements.txt to run them.
"""

import pytest

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")  # TestClient transport

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient

import api.index as webapp


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "LAB_DIR", tmp_path / "weblab")
    return TestClient(webapp.app)


def test_index_lists_endpoints(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert "endpoints" in body
    assert "POST /simulate" in body["endpoints"]


def test_detect_returns_guide(client):
    resp = client.get("/detect")
    assert resp.status_code == 200
    assert "Sysmon" in resp.text or "sysmon" in resp.text.lower()


def test_simulate_records_full_chain(client):
    resp = client.post("/simulate")
    assert resp.status_code == 200
    names = [e["event"] for e in resp.json()["events"]]
    for expected in (
        "gift_card_lure_opened",
        "gift_card_file_downloaded",
        "persistence_run_key_set",
        "c2_beacon_sent",
        "exfil_chunk_sent",
        "simulation_completed",
    ):
        assert expected in names, f"missing event: {expected}"


def test_report_summarizes_iocs(client):
    client.post("/simulate")
    resp = client.get("/report")
    assert resp.status_code == 200
    body = resp.json()
    assert body["event_count"] > 0
    assert body["persistence_iocs"], "expected persistence IOCs in report"


def test_events_empty_before_simulation(client):
    resp = client.get("/events")
    assert resp.status_code == 200
    assert resp.json()["events"] == []


def test_reset_clears_lab(client):
    client.post("/simulate")
    assert client.get("/events").json()["event_count"] > 0
    resp = client.post("/reset")
    assert resp.status_code == 200
    assert resp.json()["reset"] is True
    assert client.get("/events").json()["events"] == []
