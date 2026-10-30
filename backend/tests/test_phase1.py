from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.database import connection
from app.main import create_app


def test_multihash_vault_custody_and_rehash_alert(client: TestClient, app_settings: Settings):
    payload = b"phase one synthetic evidence\n"
    uploaded = client.post("/api/evidence", files={"file": ("fixture.txt", payload, "text/plain")})
    assert uploaded.status_code == 201, uploaded.text
    evidence = uploaded.json()
    assert evidence["md5"] == hashlib.md5(payload).hexdigest()
    assert evidence["sha1"] == hashlib.sha1(payload).hexdigest()
    assert evidence["sha256"] == hashlib.sha256(payload).hexdigest()

    stored_path = app_settings.evidence_dir / next(app_settings.evidence_dir.iterdir()).name
    assert stored_path.stat().st_mode & 0o777 == 0o444

    custody = client.get(f"/api/evidence/{evidence['id']}/custody")
    assert custody.status_code == 200
    assert custody.json()[0]["hash_at_handoff"] == evidence["sha256"]
    added = client.post(
        f"/api/evidence/{evidence['id']}/custody",
        json={"from_party": "analyst", "to_party": "reviewer", "reason": "Synthetic handoff"},
    )
    assert added.status_code == 201, added.text

    verified = client.post(f"/api/evidence/{evidence['id']}/verify")
    assert verified.status_code == 200
    assert verified.json()["observed_md5"] == evidence["md5"]
    assert verified.json()["observed_sha1"] == evidence["sha1"]

    stored_path.chmod(0o644)
    stored_path.write_bytes(b"tampered synthetic evidence\n")
    stored_path.chmod(0o444)
    rehashed = client.post(f"/api/evidence/{evidence['id']}/rehash")
    assert rehashed.status_code == 200
    assert rehashed.json()["status"] == "failed"
    alerts = client.get(f"/api/evidence/{evidence['id']}/integrity-alerts")
    assert alerts.status_code == 200
    assert alerts.json()[0]["alert_type"] == "integrity_drift"
    jobs = client.get(f"/api/analysis-jobs?evidence_id={evidence['id']}").json()
    assert jobs[0]["action"] == "rehash"


def test_audit_chain_verification_detects_tampering(client: TestClient, app_settings: Settings):
    created = client.post("/api/cases", json={"title": "Synthetic audit case"})
    assert created.status_code == 201
    verified = client.get("/api/audit-events/verify")
    assert verified.status_code == 200
    assert verified.json()["ok"] is True

    with connection(app_settings) as conn:
        conn.execute("DROP TRIGGER audit_events_immutable_update")
        conn.execute("UPDATE audit_events SET details_json = ? WHERE id = (SELECT MIN(id) FROM audit_events)", (json.dumps({"tampered": True}),))
        conn.execute(
            """
            CREATE TRIGGER audit_events_immutable_update
            BEFORE UPDATE ON audit_events
            BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END;
            """
        )
    broken = client.get("/api/audit-events/verify")
    assert broken.status_code == 200
    assert broken.json()["ok"] is False
    assert broken.json()["broken_entry_id"] is not None


def test_reviewer_can_read_but_cannot_mutate(client: TestClient):
    created = client.post("/api/auth/users", json={"username": "read-only", "password": "reviewer-password-123", "role": "reviewer"})
    assert created.status_code == 201, created.text
    login = client.post("/api/auth/login", json={"username": "read-only", "password": "reviewer-password-123"})
    assert login.status_code == 200, login.text
    client.headers.update({"Authorization": f"Bearer {login.json()['token']}"})

    assert client.get("/api/cases").status_code == 200
    denied = client.post("/api/cases", json={"title": "Should be denied"})
    assert denied.status_code == 403


def test_first_run_bootstrap_has_no_default_password(tmp_path: Path):
    settings = Settings(
        base_dir=tmp_path,
        database_path=tmp_path / "forensix.sqlite3",
        evidence_dir=tmp_path / "evidence",
        reports_dir=tmp_path / "reports",
        seed_demo=False,
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/auth/status").json() == {"initialized": False}
        assert client.post("/api/cases", json={"title": "No anonymous access"}).status_code == 401
        assert client.post("/api/auth/login", json={"username": "admin", "password": "not-a-real-default"}).status_code == 401
        bootstrap = client.post("/api/auth/bootstrap", json={"username": "first-admin", "password": "first-admin-password"})
        assert bootstrap.status_code == 201
        assert client.post("/api/auth/bootstrap", json={"username": "second-admin", "password": "second-admin-password"}).status_code == 409


def test_legacy_database_migrates_and_rehashes_vault(tmp_path: Path):
    database_path = tmp_path / "legacy.sqlite3"
    evidence_dir = tmp_path / "evidence"
    reports_dir = tmp_path / "reports"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "legacy.txt"
    evidence_path.write_bytes(b"legacy synthetic evidence\n")
    with sqlite3.connect(database_path) as conn:
        conn.executescript(
            """
            CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT, actor TEXT NOT NULL, details_json TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER, original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE, media_type TEXT, size INTEGER NOT NULL, sha256 TEXT NOT NULL, integrity_status TEXT NOT NULL, source TEXT, uploaded_by TEXT, investigator_notes TEXT, metadata_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE analysis_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, evidence_id INTEGER, integration_id TEXT NOT NULL, action TEXT NOT NULL, arguments_json TEXT NOT NULL, tool_version TEXT, status TEXT NOT NULL, output TEXT NOT NULL, error TEXT, started_at TEXT NOT NULL, finished_at TEXT);
            INSERT INTO audit_events (event_type, entity_type, actor, details_json, created_at) VALUES ('legacy', 'test', 'legacy-user', '{}', '2026-01-01T00:00:00+00:00');
            INSERT INTO evidence (original_name, stored_name, media_type, size, sha256, integrity_status, metadata_json, created_at, updated_at) VALUES ('legacy.txt', 'legacy.txt', 'text/plain', 26, 'legacy-sha', 'pending', '{}', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00');
            INSERT INTO analysis_jobs (evidence_id, integration_id, action, arguments_json, status, output, started_at) VALUES (1, 'legacy', 'probe', '[]', 'completed', 'legacy output', '2026-01-01T00:00:00+00:00');
            """
        )
    settings = Settings(base_dir=tmp_path, database_path=database_path, evidence_dir=evidence_dir, reports_dir=reports_dir, seed_demo=False)
    with TestClient(create_app(settings)) as client:
        bootstrap = client.post("/api/auth/bootstrap", json={"username": "migrated-admin", "password": "migrated-password"})
        assert bootstrap.status_code == 201, bootstrap.text
        client.headers.update({"Authorization": f"Bearer {bootstrap.json()['token']}"})
        assert client.get("/api/audit-events/verify").json()["ok"] is True
        evidence = client.get("/api/evidence").json()[0]
        assert evidence["md5"] is None
        assert evidence["sha1"] is None
        assert oct(evidence_path.stat().st_mode & 0o777) == "0o444"
        legacy_job = client.get("/api/analysis-jobs").json()[0]
        assert legacy_job["progress"] == 0
        assert legacy_job["created_at"] == "2026-01-01T00:00:00+00:00"
