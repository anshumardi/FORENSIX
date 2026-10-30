from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi.testclient import TestClient

from app import adapters
from app import worker as worker_module
from app.config import Settings


@dataclass(frozen=True)
class SyntheticAdapter:
    name: str = "synthetic-text"
    version: str = "fixture-1"
    supported_types: tuple[str, ...] = (".txt",)

    def run(self, context):
        context.progress(50, "Synthetic adapter checkpoint")
        return {"available": True, "status": "completed", "message": "synthetic fixture completed", "tool_version": self.version}


def test_job_lifecycle_runs_in_worker_and_records_bounded_result(client: TestClient, app_settings: Settings, monkeypatch):
    adapter = SyntheticAdapter()
    monkeypatch.setattr(adapters, "ADAPTERS", (adapter,))
    uploaded = client.post("/api/evidence", files={"file": ("worker-fixture.txt", b"synthetic worker evidence", "text/plain")})
    assert uploaded.status_code == 201, uploaded.text
    evidence_id = uploaded.json()["id"]

    queued = client.post("/api/analysis-jobs", json={"evidence_id": evidence_id, "adapter": adapter.name})
    assert queued.status_code == 201, queued.text
    assert queued.json()["status"] == "queued"
    assert queued.json()["progress"] == 0

    worker_module.run_worker(app_settings, once=True)
    finished = client.get(f"/api/analysis-jobs/{queued.json()['id']}")
    assert finished.status_code == 200
    body = finished.json()
    assert body["status"] == "succeeded"
    assert body["progress"] == 100
    assert "Synthetic adapter checkpoint" in body["log"]


def test_cancelled_job_never_runs_adapter(client: TestClient, app_settings: Settings, monkeypatch):
    adapter = SyntheticAdapter()
    monkeypatch.setattr(adapters, "ADAPTERS", (adapter,))
    uploaded = client.post("/api/evidence", files={"file": ("cancel-fixture.txt", b"cancel me", "text/plain")})
    evidence_id = uploaded.json()["id"]
    queued = client.post("/api/analysis-jobs", json={"evidence_id": evidence_id, "adapter": adapter.name}).json()

    cancelled = client.post(f"/api/analysis-jobs/{queued['id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["cancel_requested"] is True
    worker_module.run_worker(app_settings, once=True)
    finished = client.get(f"/api/analysis-jobs/{queued['id']}").json()
    assert finished["status"] == "failed"
    assert finished["error"] == "cancelled before worker claim"


def test_network_analysis_endpoint_queues_instead_of_blocking(client: TestClient):
    uploaded = client.post("/api/evidence", files={"file": ("capture.pcap", b"synthetic pcap fixture", "application/vnd.tcpdump.pcap")})
    assert uploaded.status_code == 201
    response = client.post(f"/api/evidence/{uploaded.json()['id']}/network-analysis")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "queued"
    assert body["packet_count"] == 0
    job = client.get(f"/api/analysis-jobs/{body['job_id']}")
    assert job.json()["status"] == "queued"
