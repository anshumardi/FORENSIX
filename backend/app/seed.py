"""Clearly labeled local demonstration data for a first-run installation."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .config import Settings
from .database import connection, json_dumps, utc_now
from .storage import managed_file


DEMO_CASE_NUMBER = "DEMO-2026-001"


def seed_demo_data(settings: Settings) -> None:
    now = utc_now()
    with connection(settings) as conn:
        existing = conn.execute("SELECT id FROM cases WHERE case_number = ?", (DEMO_CASE_NUMBER,)).fetchone()
        if existing:
            return
        case_cursor = conn.execute(
            """
            INSERT INTO cases (case_number, title, description, status, severity, assignee, tags_json, created_at, updated_at)
            VALUES (?, ?, ?, 'in_progress', 'high', ?, ?, ?, ?)
            """,
            (
                DEMO_CASE_NUMBER,
                "[DEMO] Suspicious workstation activity",
                "Clearly labeled sample data for validating the FORENSIX workflow. Not real evidence.",
                "Demo Analyst",
                json_dumps(["demo", "sample", "training"]),
                now,
                now,
            ),
        )
        case_id = case_cursor.lastrowid
        conn.execute(
            """
            INSERT INTO timeline_events (case_id, event_timestamp, title, description, event_type, source, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                "2026-01-15T09:30:00+00:00",
                "[DEMO] Sample workstation triage started",
                "Synthetic timeline event inserted by the optional demo seed.",
                "triage",
                "demo-seed",
                "info",
                now,
            ),
        )
        conn.execute(
            """
            INSERT INTO findings (case_id, title, description, severity, status, confidence, source, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)
            """,
            (
                case_id,
                "[DEMO] Review synthetic outbound connection",
                "This finding is synthetic and exists to demonstrate case review and reporting.",
                "medium",
                0.72,
                "demo-seed",
                now,
                now,
            ),
        )
        sample = b"FORENSIX DEMO SAMPLE\nThis file is synthetic training data.\n"
        stored_name = "demo-sample.txt"
        path = managed_file(settings, stored_name)
        if not path.exists():
            path.write_bytes(sample)
        digest = hashlib.sha256(sample).hexdigest()
        conn.execute(
            """
            INSERT INTO evidence (case_id, original_name, stored_name, media_type, size, sha256, integrity_status, source, uploaded_by, metadata_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                "demo-sample.txt",
                stored_name,
                "text/plain",
                len(sample),
                digest,
                "demo-seed",
                "demo-seed",
                json_dumps({"synthetic": True, "label": "DEMO SAMPLE - NOT REAL EVIDENCE"}),
                now,
                now,
            ),
        )
        conn.execute(
            """
            INSERT INTO audit_events (event_type, entity_type, entity_id, actor, details_json, created_at)
            VALUES ('demo_seeded', 'case', ?, 'system', ?, ?)
            """,
            (str(case_id), json_dumps({"label": "DEMO", "source": "startup seed"}), now),
        )
