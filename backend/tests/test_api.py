from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from app.database import connection, row_dict


def create_case(client: TestClient) -> dict:
    response = client.post(
        "/api/cases",
        json={"title": "Workstation investigation", "description": "Test case", "severity": "high", "tags": ["endpoint"]},
        headers={"X-Actor": "tester"},
    )
    assert response.status_code == 201
    return response.json()


def test_case_evidence_integrity_and_audit(client: TestClient, app_settings):
    case = create_case(client)
    payload = b"forensic fixture\n"
    response = client.post(
        "/api/evidence",
        files={"file": ("capture.pcap", payload, "application/vnd.tcpdump.pcap")},
        data={"case_id": str(case["id"]), "source": "pytest"},
    )
    assert response.status_code == 201
    evidence = response.json()
    assert evidence["name"] == "capture.pcap"
    assert evidence["sha256"] == hashlib.sha256(payload).hexdigest()
    assert evidence["integrity_status"] == "pending"
    assert client.get(evidence["download_url"]).content == payload

    verified = client.post(f"/api/evidence/{evidence['id']}/verify")
    assert verified.status_code == 200
    assert verified.json()["verified"] is True

    with connection(app_settings) as conn:
        stored = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence["id"],)).fetchone())
    assert stored is not None
    tampered_path = app_settings.evidence_dir / stored["stored_name"]
    tampered_path.chmod(0o644)
    tampered_path.write_bytes(b"tampered")
    tampered_path.chmod(0o444)
    failed = client.post(f"/api/evidence/{evidence['id']}/verify")
    assert failed.status_code == 200
    assert failed.json()["verified"] is False
    assert failed.json()["status"] == "failed"
    history = client.get(f"/api/evidence/{evidence['id']}/verification-history")
    assert history.status_code == 200
    assert [entry["result"] for entry in history.json()] == ["failed", "verified"]

    audit = client.get("/api/audit-events").json()
    event_types = {event["event_type"] for event in audit}
    assert {"created", "uploaded", "integrity_verified", "integrity_failed"} <= event_types


def test_upload_limit_and_private_storage_boundary(client: TestClient, app_settings):
    response = client.post(
        "/api/evidence",
        files={"file": ("too-large.bin", b"x" * 65, "application/octet-stream")},
    )
    assert response.status_code == 413
    assert list(app_settings.evidence_dir.iterdir()) == []

    # There is a controlled download route, but no static evidence directory mount.
    assert client.get("/evidence/anything").status_code == 404

    traversal = client.post("/api/evidence", files={"file": ("../../escape.txt", b"no", "text/plain")})
    assert traversal.status_code == 400


def test_case_update_preview_and_duplicate_are_explicit(client: TestClient):
    case = create_case(client)
    updated = client.patch(f"/api/cases/{case['id']}", json={"status": "in_progress", "assignee": "reviewer"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "in_progress"
    assert updated.json()["assignee"] == "reviewer"

    payload = b'{"event":"login","ok":true}\n'
    uploaded = client.post("/api/evidence", files={"file": ("events.json", payload, "application/json")}, data={"case_id": str(case["id"])})
    assert uploaded.status_code == 201
    evidence = uploaded.json()
    preview = client.get(f"/api/evidence/{evidence['id']}/preview")
    assert preview.status_code == 200
    assert preview.json()["kind"] == "json"
    assert '"event"' in preview.json()["content"]
    duplicate = client.post("/api/evidence", files={"file": ("events-copy.json", payload, "application/json")}, data={"case_id": str(case["id"])})
    assert duplicate.status_code == 409


def test_timeline_findings_transparent_graph_and_report(client: TestClient):
    case = create_case(client)
    timeline = client.post(
        "/api/timeline",
        json={"case_id": case["id"], "timestamp": "2026-02-01T10:00:00Z", "title": "Image acquired", "source": "chain-of-custody"},
    )
    assert timeline.status_code == 201
    finding = client.post(
        "/api/findings",
        json={"case_id": case["id"], "title": "Suspicious persistence", "confidence": 0.9, "source": "manual review"},
    )
    assert finding.status_code == 201

    graph = client.get(f"/api/graph?case_id={case['id']}")
    assert graph.status_code == 200
    graph_body = graph.json()
    assert graph_body["methodology"].startswith("Transparent graph derived")
    assert any(node["entity_type"] == "case" for node in graph_body["nodes"])
    assert any(edge["relationship"] == "contains" for edge in graph_body["edges"])
    assert all("provenance" in item for item in graph_body["nodes"] + graph_body["edges"])

    report = client.post("/api/reports", json={"case_id": case["id"], "name": "test-report.pdf"})
    assert report.status_code == 201, report.text
    report_body = report.json()
    assert report_body["status"] == "ready"
    downloaded = client.get(report_body["download_url"])
    assert downloaded.status_code == 200
    assert downloaded.content.startswith(b"%PDF")


def test_timeline_json_import_reports_rows_and_timezone_assumption(client: TestClient):
    case = create_case(client)
    response = client.post(
        "/api/timeline/import",
        data={"case_id": str(case["id"])},
        files={
            "file": (
                "events.json",
                b'[{"timestamp":"2026-02-01T10:00:00","title":"Imported observation"},{"title":"Rejected row"}]',
                "application/json",
            )
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["imported_count"] == 1
    assert body["rejected"] == [{"row": 2, "error": "timestamp is required"}]
    event = client.get(f"/api/timeline?case_id={case['id']}").json()[0]
    assert event["timestamp"].endswith("+00:00")
    assert event["timestamp_uncertain"] is True


def test_demo_seed_is_labeled(tmp_path: Path):
    from fastapi.testclient import TestClient

    from app.config import Settings
    from app.main import create_app

    settings = Settings(
        base_dir=tmp_path,
        database_path=tmp_path / "db.sqlite3",
        evidence_dir=tmp_path / "evidence",
        reports_dir=tmp_path / "reports",
        seed_demo=True,
    )
    with TestClient(create_app(settings)) as client:
        bootstrap = client.post("/api/auth/bootstrap", json={"username": "demo-admin", "password": "demo-password-123"})
        assert bootstrap.status_code == 201, bootstrap.text
        client.headers.update({"Authorization": f"Bearer {bootstrap.json()['token']}"})
        cases = client.get("/api/cases").json()
        assert any(case["case_number"] == "DEMO-2026-001" and case["title"].startswith("[DEMO]") for case in cases)
        evidence = client.get("/api/evidence").json()
        assert any(item["metadata"]["synthetic"] is True for item in evidence)
