"""SQLite-backed FORENSIX analysis worker.

Run with ``python -m worker`` from the backend directory. The API only enqueues
jobs; this process claims and executes them through registered adapters.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from .adapters import AdapterContext, adapter_supports, get_adapter
from .audit import record_audit
from .config import Settings
from .database import connection, json_dumps, row_dict, utc_now
from .storage import managed_file

MAX_LOG_BYTES = 20_000
MAX_OUTPUT_BYTES = 20_000


def _append_log(settings: Settings, job_id: int, message: str) -> None:
    with connection(settings) as conn:
        row = conn.execute("SELECT log FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone()
        previous = str(row[0] or "") if row else ""
        combined = (previous + ("\n" if previous else "") + message)[:MAX_LOG_BYTES]
        conn.execute("UPDATE analysis_jobs SET log = ?, updated_at = ? WHERE id = ?", (combined, utc_now(), job_id))


def _set_progress(settings: Settings, job_id: int, progress: int, message: str) -> None:
    progress = max(0, min(100, int(progress)))
    _append_log(settings, job_id, message)
    with connection(settings) as conn:
        conn.execute("UPDATE analysis_jobs SET progress = ?, updated_at = ? WHERE id = ?", (progress, utc_now(), job_id))


def _cancel_requested(settings: Settings, job_id: int) -> bool:
    with connection(settings) as conn:
        row = conn.execute("SELECT cancel_requested FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone()
    return bool(row and row[0])


def claim_next_job(settings: Settings) -> dict[str, Any] | None:
    with connection(settings) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = row_dict(conn.execute("SELECT * FROM analysis_jobs WHERE status = 'queued' ORDER BY id ASC LIMIT 1").fetchone())
        if row is None:
            return None
        now = utc_now()
        if row.get("cancel_requested"):
            conn.execute(
                "UPDATE analysis_jobs SET status = 'failed', progress = 100, error = 'cancelled before worker claim', finished_at = ?, updated_at = ? WHERE id = ?",
                (now, now, row["id"]),
            )
            return None
        conn.execute(
            "UPDATE analysis_jobs SET status = 'running', progress = 1, started_at = ?, updated_at = ? WHERE id = ? AND status = 'queued'",
            (now, now, row["id"]),
        )
        row["status"] = "running"
        row["started_at"] = now
        row["updated_at"] = now
        row["progress"] = 1
        return row


def _finish(settings: Settings, job_id: int, status: str, output: str = "", error: str | None = None, progress: int = 100, tool_version: str | None = None) -> None:
    now = utc_now()
    with connection(settings) as conn:
        conn.execute(
            "UPDATE analysis_jobs SET status = ?, progress = ?, output = ?, error = ?, tool_version = COALESCE(?, tool_version), finished_at = ?, updated_at = ? WHERE id = ?",
            (status, max(0, min(100, progress)), output[:MAX_OUTPUT_BYTES], error[:2_000] if error else None, tool_version, now, now, job_id),
        )


def _persist_derived(settings: Settings, job: dict[str, Any], evidence: dict[str, Any], result: dict[str, Any], adapter: Any) -> None:
    provenance = result.get("provenance") or {"source_evidence_id": evidence["id"], "parser": adapter.name, "parser_version": adapter.version, "timestamp": utc_now()}
    created_at = utc_now()
    iocs = result.get("iocs") or []
    events = result.get("timeline_events") or []
    with connection(settings) as conn:
        for item in iocs[:2_000]:
            conn.execute(
                "INSERT OR IGNORE INTO iocs (case_id, evidence_id, ioc_type, value, defanged_value, confidence, source_record, parser, parser_version, observed_at, provenance_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (evidence.get("case_id"), evidence["id"], item.get("ioc_type", "unknown"), str(item.get("value", ""))[:2_000], str(item.get("defanged_value", item.get("value", "")))[:2_000], float(item.get("confidence", 0.5)), item.get("source_record"), adapter.name, adapter.version, provenance.get("timestamp", created_at), json_dumps(provenance), created_at),
            )
        for event in events[:2_000]:
            event_provenance = event.get("provenance") or provenance
            conn.execute(
                "INSERT INTO timeline_events (case_id, evidence_id, event_timestamp, title, description, event_type, source, severity, confidence, timestamp_uncertain, raw_metadata_json, provenance_json, attack_techniques_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (evidence.get("case_id"), evidence["id"], event.get("timestamp") or created_at, str(event.get("title", "Derived event"))[:200], str(event.get("description", ""))[:10_000], event.get("event_type", adapter.name), event.get("source", evidence["original_name"]), event.get("severity", "info"), event.get("confidence"), int(bool(event.get("timestamp_uncertain", False))), json_dumps(event.get("raw_metadata") or {}), json_dumps(event_provenance), json_dumps(event.get("attack_techniques") or []), created_at),
            )
    if iocs or events:
        record_audit(settings, "derived_records_created", "analysis_job", job["id"], {"adapter": adapter.name, "evidence_id": evidence["id"], "iocs": len(iocs), "timeline_events": len(events)})


def process_job(settings: Settings, job: dict[str, Any]) -> None:
    job_id = int(job["id"])
    evidence_id = job.get("evidence_id")
    if evidence_id is None:
        _finish(settings, job_id, "failed", error="an evidence item is required")
        return
    try:
        with connection(settings) as conn:
            evidence = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
        if evidence is None:
            raise FileNotFoundError("evidence not found")
        adapter = get_adapter(str(job["integration_id"]))
        if not adapter_supports(adapter, evidence["original_name"], evidence.get("media_type")):
            raise ValueError(f"adapter {adapter.name} does not support this evidence type")
        path = managed_file(settings, evidence["stored_name"])
        if not path.is_file():
            raise FileNotFoundError("evidence file is missing")
        context = AdapterContext(
            settings=settings,
            job_id=job_id,
            evidence_id=int(evidence_id),
            evidence_path=path,
            original_name=evidence["original_name"],
            media_type=evidence.get("media_type"),
            arguments=json.loads(job.get("arguments_json") or "{}") if isinstance(job.get("arguments_json"), str) else (job.get("arguments_json") or {}),
            progress=lambda progress, message: _set_progress(settings, job_id, progress, message),
            cancelled=lambda: _cancel_requested(settings, job_id),
        )
        result = adapter.run(context)
        _persist_derived(settings, job, evidence, result, adapter)
        output = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        if _cancel_requested(settings, job_id) or result.get("status") == "cancelled":
            _append_log(settings, job_id, "Cancellation requested; job stopped")
            _finish(settings, job_id, "failed", output=output, error="cancelled", tool_version=str(result.get("tool_version") or adapter.version), progress=100)
        elif result.get("available", True) is False or result.get("status") in {"failed", "unavailable"}:
            _finish(settings, job_id, "failed", output=output, error=str(result.get("message") or "adapter failed"), tool_version=str(result.get("tool_version") or adapter.version))
        else:
            _finish(settings, job_id, "succeeded", output=output, tool_version=str(result.get("tool_version") or adapter.version))
    except Exception as exc:
        _append_log(settings, job_id, f"Worker error: {exc}")
        _finish(settings, job_id, "failed", error=str(exc))


def run_worker(settings: Settings | None = None, *, once: bool = False, poll_seconds: float = 1.0) -> None:
    current = settings or Settings.from_env()
    current.ensure_directories()
    from .database import initialize_database

    initialize_database(current)
    while True:
        job = claim_next_job(current)
        if job is not None:
            process_job(current, job)
        elif once:
            return
        else:
            time.sleep(poll_seconds)
