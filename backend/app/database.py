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
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin', 'analyst', 'reviewer')),
    is_system INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

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
    md5 TEXT,
    sha1 TEXT,
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
    confidence REAL,
    timestamp_uncertain INTEGER NOT NULL DEFAULT 0,
    raw_metadata_json TEXT NOT NULL DEFAULT '{}',
    provenance_json TEXT NOT NULL DEFAULT '{}',
    attack_techniques_json TEXT NOT NULL DEFAULT '[]',
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
    attack_techniques_json TEXT NOT NULL DEFAULT '[]',
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
    expected_md5 TEXT,
    expected_sha1 TEXT,
    expected_hash TEXT NOT NULL,
    observed_md5 TEXT,
    observed_sha1 TEXT,
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
    progress INTEGER NOT NULL DEFAULT 0,
    log TEXT NOT NULL DEFAULT '',
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    created_at TEXT,
    updated_at TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    actor TEXT NOT NULL DEFAULT 'system',
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '',
    entry_hash TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS custody_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    from_party TEXT NOT NULL,
    to_party TEXT NOT NULL,
    reason TEXT NOT NULL,
    event_timestamp TEXT NOT NULL,
    hash_at_handoff TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS integrity_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL,
    message TEXT NOT NULL,
    expected_hash TEXT,
    observed_hash TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    evidence_id INTEGER REFERENCES evidence(id) ON DELETE CASCADE,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    defanged_value TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5,
    source_record TEXT,
    parser TEXT NOT NULL,
    parser_version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    provenance_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE (evidence_id, ioc_type, value)
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'pdf',
    status TEXT NOT NULL DEFAULT 'ready',
    stored_name TEXT UNIQUE,
    template TEXT NOT NULL DEFAULT 'technical',
    signature_name TEXT,
    signer_fingerprint TEXT,
    size INTEGER,
    error TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK (target_type IN ('evidence', 'timeline', 'case')),
    target_id INTEGER NOT NULL,
    offset INTEGER,
    title TEXT NOT NULL,
    markdown TEXT NOT NULL,
    pinned INTEGER NOT NULL DEFAULT 0,
    author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
    record_type UNINDEXED,
    record_id UNINDEXED,
    case_id UNINDEXED,
    title,
    body,
    source
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256_size ON evidence(sha256, size);
CREATE INDEX IF NOT EXISTS idx_timeline_case_id ON timeline_events(case_id);
CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_evidence_id ON finding_evidence(evidence_id);
CREATE INDEX IF NOT EXISTS idx_integrity_verifications_evidence_id ON integrity_verifications(evidence_id);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_evidence_id ON analysis_jobs(evidence_id);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_status ON analysis_jobs(status, id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_custody_evidence_id ON custody_events(evidence_id);
CREATE INDEX IF NOT EXISTS idx_integrity_alerts_evidence_id ON integrity_alerts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_iocs_case_id ON iocs(case_id);
CREATE INDEX IF NOT EXISTS idx_iocs_evidence_id ON iocs(evidence_id);
CREATE INDEX IF NOT EXISTS idx_reports_case_id ON reports(case_id);
CREATE INDEX IF NOT EXISTS idx_notes_case_id ON notes(case_id);
CREATE INDEX IF NOT EXISTS idx_notes_target ON notes(target_type, target_id);

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
        # Audit rows are immutable after the migration/backfill has completed.
        # Existing installations may have audit rows without the new columns.
        conn.execute("DROP TRIGGER IF EXISTS audit_events_immutable_update")
        conn.execute("DROP TRIGGER IF EXISTS audit_events_immutable_delete")

        user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "is_system" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_system INTEGER NOT NULL DEFAULT 0")
        if "disabled" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")

        # A non-login system identity keeps automated/startup audit entries bound
        # to a user ID without creating a usable default password.
        system_user = conn.execute("SELECT id FROM users WHERE username = 'system'").fetchone()
        if system_user is None:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, is_system, disabled, created_at) VALUES ('system', '', 'admin', 1, 1, ?)",
                (utc_now(),),
            )

        evidence_columns = {row[1] for row in conn.execute("PRAGMA table_info(evidence)").fetchall()}
        evidence_migrations = {
            "md5": "ALTER TABLE evidence ADD COLUMN md5 TEXT",
            "sha1": "ALTER TABLE evidence ADD COLUMN sha1 TEXT",
        }
        for name, statement in evidence_migrations.items():
            if name not in evidence_columns:
                conn.execute(statement)

        verification_columns = {row[1] for row in conn.execute("PRAGMA table_info(integrity_verifications)").fetchall()}
        verification_migrations = {
            "expected_md5": "ALTER TABLE integrity_verifications ADD COLUMN expected_md5 TEXT",
            "expected_sha1": "ALTER TABLE integrity_verifications ADD COLUMN expected_sha1 TEXT",
            "observed_md5": "ALTER TABLE integrity_verifications ADD COLUMN observed_md5 TEXT",
            "observed_sha1": "ALTER TABLE integrity_verifications ADD COLUMN observed_sha1 TEXT",
        }
        for name, statement in verification_migrations.items():
            if name not in verification_columns:
                conn.execute(statement)

        timeline_columns = {row[1] for row in conn.execute("PRAGMA table_info(timeline_events)").fetchall()}
        timeline_migrations = {
            "confidence": "ALTER TABLE timeline_events ADD COLUMN confidence REAL",
            "provenance_json": "ALTER TABLE timeline_events ADD COLUMN provenance_json TEXT NOT NULL DEFAULT '{}'",
            "attack_techniques_json": "ALTER TABLE timeline_events ADD COLUMN attack_techniques_json TEXT NOT NULL DEFAULT '[]'",
        }
        for name, statement in timeline_migrations.items():
            if name not in timeline_columns:
                conn.execute(statement)

        finding_columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
        if "attack_techniques_json" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN attack_techniques_json TEXT NOT NULL DEFAULT '[]'")

        report_columns = {row[1] for row in conn.execute("PRAGMA table_info(reports)").fetchall()}
        report_migrations = {
            "template": "ALTER TABLE reports ADD COLUMN template TEXT NOT NULL DEFAULT 'technical'",
            "signature_name": "ALTER TABLE reports ADD COLUMN signature_name TEXT",
            "signer_fingerprint": "ALTER TABLE reports ADD COLUMN signer_fingerprint TEXT",
        }
        for name, statement in report_migrations.items():
            if name not in report_columns:
                conn.execute(statement)

        job_columns = {row[1] for row in conn.execute("PRAGMA table_info(analysis_jobs)").fetchall()}
        job_migrations = {
            "progress": "ALTER TABLE analysis_jobs ADD COLUMN progress INTEGER NOT NULL DEFAULT 0",
            "log": "ALTER TABLE analysis_jobs ADD COLUMN log TEXT NOT NULL DEFAULT ''",
            "cancel_requested": "ALTER TABLE analysis_jobs ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0",
            "created_at": "ALTER TABLE analysis_jobs ADD COLUMN created_at TEXT",
            "updated_at": "ALTER TABLE analysis_jobs ADD COLUMN updated_at TEXT",
        }
        for name, statement in job_migrations.items():
            if name not in job_columns:
                conn.execute(statement)
        conn.execute("UPDATE analysis_jobs SET created_at = COALESCE(created_at, started_at), updated_at = COALESCE(updated_at, finished_at, started_at)")

        audit_columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
        audit_migrations = {
            "user_id": "ALTER TABLE audit_events ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL",
            "prev_hash": "ALTER TABLE audit_events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''",
            "entry_hash": "ALTER TABLE audit_events ADD COLUMN entry_hash TEXT NOT NULL DEFAULT ''",
        }
        for name, statement in audit_migrations.items():
            if name not in audit_columns:
                conn.execute(statement)

        # Backfill old rows in ID order. The helper is imported lazily to avoid
        # a module import cycle during application startup.
        from .audit import backfill_audit_chain

        system_id = int(conn.execute("SELECT id FROM users WHERE username = 'system'").fetchone()[0])
        backfill_audit_chain(conn, system_id)

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
        if "investigator_notes" not in evidence_columns:
            conn.execute("ALTER TABLE evidence ADD COLUMN investigator_notes TEXT")

        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_events(user_id);
            CREATE INDEX IF NOT EXISTS idx_analysis_jobs_status ON analysis_jobs(status, id);

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
        )


def rebuild_search_index(conn: sqlite3.Connection) -> None:
    """Refresh the local FTS5 mirror from SQLite records.

    The index is a derived convenience view. Rebuilding it keeps migrations and
    legacy databases deterministic while the source tables remain authoritative.
    """

    conn.execute("DELETE FROM search_index")
    conn.execute(
        "INSERT INTO search_index (record_type, record_id, case_id, title, body, source) SELECT 'case', id, id, title, COALESCE(description, ''), 'cases' FROM cases"
    )
    conn.execute(
        "INSERT INTO search_index (record_type, record_id, case_id, title, body, source) SELECT 'timeline', id, case_id, title, COALESCE(description, '') || ' ' || COALESCE(raw_metadata_json, ''), COALESCE(source, 'timeline') FROM timeline_events"
    )
    conn.execute(
        "INSERT INTO search_index (record_type, record_id, case_id, title, body, source) SELECT 'finding', id, case_id, title, COALESCE(description, ''), COALESCE(source, 'finding') FROM findings"
    )
    conn.execute(
        "INSERT INTO search_index (record_type, record_id, case_id, title, body, source) SELECT 'ioc', id, case_id, ioc_type, value || ' ' || defanged_value, parser FROM iocs"
    )
    conn.execute(
        "INSERT INTO search_index (record_type, record_id, case_id, title, body, source) SELECT 'note', id, case_id, title, markdown, target_type FROM notes"
    )


def search_index(conn: sqlite3.Connection, query: str, case_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
    tokens = [token for token in query.replace('"', ' ').split() if token.isalnum() or '_' in token or '-' in token or '.' in token]
    if not tokens:
        return []
    match = " AND ".join(f'"{token}"*' for token in tokens)
    sql = "SELECT record_type, record_id, case_id, title, body, source, snippet(search_index, 4, '[', ']', '…', 24) AS snippet FROM search_index WHERE search_index MATCH ?"
    params: list[Any] = [match]
    if case_id is not None:
        sql += " AND case_id = ?"
        params.append(str(case_id))
    sql += " ORDER BY rank LIMIT ?"
    params.append(max(1, min(500, limit)))
    return [dict(row) for row in conn.execute(sql, tuple(params)).fetchall()]


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
