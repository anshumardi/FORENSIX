"""SQLite schema and connection helpers."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import Settings


SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT 'medium',
    assignee TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    media_type TEXT,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    integrity_status TEXT NOT NULL DEFAULT 'pending',
    source TEXT,
    uploaded_by TEXT,
    investigator_notes TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    event_timestamp TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    event_type TEXT,
    source TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    timestamp_uncertain INTEGER NOT NULL DEFAULT 0,
    raw_metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    confidence REAL,
    source TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (finding_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS integrity_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    expected_hash TEXT NOT NULL,
    observed_hash TEXT,
    result TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS analysis_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
    integration_id TEXT NOT NULL,
    action TEXT NOT NULL,
    arguments_json TEXT NOT NULL DEFAULT '[]',
    tool_version TEXT,
    status TEXT NOT NULL,
    output TEXT NOT NULL DEFAULT '',
    error TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    actor TEXT NOT NULL DEFAULT 'system',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'pdf',
    status TEXT NOT NULL DEFAULT 'ready',
    stored_name TEXT UNIQUE,
    size INTEGER,
    error TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_timeline_case_id ON timeline_events(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_evidence_id ON finding_evidence(evidence_id);
CREATE INDEX IF NOT EXISTS idx_integrity_verifications_evidence_id ON integrity_verifications(evidence_id);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_evidence_id ON analysis_jobs(evidence_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_reports_case_id ON reports(case_id);

CREATE TRIGGER IF NOT EXISTS audit_events_immutable_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_events_immutable_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


@contextmanager
def connection(settings: Settings) -> Iterator[sqlite3.Connection]:
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(settings.database_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize_database(settings: Settings) -> None:
    with connection(settings) as conn:
        conn.executescript(SCHEMA)
        # Keep local installations created by earlier FORENSIX revisions usable.
        # SQLite has no portable IF NOT EXISTS form for adding a column.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(timeline_events)").fetchall()}
        migrations = {
            "evidence_id": "ALTER TABLE timeline_events ADD COLUMN evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL",
            "timestamp_uncertain": "ALTER TABLE timeline_events ADD COLUMN timestamp_uncertain INTEGER NOT NULL DEFAULT 0",
            "raw_metadata_json": "ALTER TABLE timeline_events ADD COLUMN raw_metadata_json TEXT NOT NULL DEFAULT '{}'",
        }
        for name, statement in migrations.items():
            if name not in columns:
                conn.execute(statement)
        evidence_columns = {row[1] for row in conn.execute("PRAGMA table_info(evidence)").fetchall()}
        if "investigator_notes" not in evidence_columns:
            conn.execute("ALTER TABLE evidence ADD COLUMN investigator_notes TEXT")


def row_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def ensure_within_directory(path: Path, directory: Path) -> Path:
    """Resolve a path and reject traversal outside the intended directory."""

    resolved_directory = directory.resolve()
    resolved_path = path.resolve()
    try:
        resolved_path.relative_to(resolved_directory)
    except ValueError as exc:
        raise ValueError("path escapes its managed directory") from exc
    return resolved_path
