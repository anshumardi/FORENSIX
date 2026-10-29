"""FastAPI application for the FORENSIX forensic workspace."""

from __future__ import annotations

import importlib.util
import csv
import io
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import __version__
from .audit import list_audit, record_audit
from .config import Settings
from .database import connection, initialize_database, json_dumps, json_loads, row_dict, utc_now
from .integrations import TOOLS, analyze_pcap, integration_status, run_action
from .reports import create_report, list_reports, report_file
from .schemas import (
    AuditOut,
    AnalysisJobOut,
    CaseCreate,
    CaseOut,
    CaseUpdate,
    EvidenceOut,
    EvidencePreviewOut,
    FindingCreate,
    FindingOut,
    GraphOut,
    HealthOut,
    IntegrityOut,
    NetworkAnalysisOut,
    VerificationHistoryOut,
    IntegrationAction,
    IntegrationActionOut,
    IntegrationOut,
    ReportCreate,
    ReportOut,
    TimelineCreate,
    TimelineImportOut,
    TimelineOut,
)
from .seed import seed_demo_data
from .storage import managed_file, safe_preview, save_upload, sha256_file


def _settings(app: FastAPI) -> Settings:
    return app.state.settings


def _actor(actor: str | None) -> str:
    return (actor or "api").strip()[:200] or "api"


def _case_or_404(settings: Settings, case_id: int) -> dict[str, Any]:
    with connection(settings) as conn:
        row = row_dict(conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone())
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="case not found")
    return row


def _case_dict(settings: Settings, row: dict[str, Any]) -> dict[str, Any]:
    with connection(settings) as conn:
        evidence_count = conn.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (row["id"],)).fetchone()[0]
        finding_count = conn.execute("SELECT COUNT(*) FROM findings WHERE case_id = ?", (row["id"],)).fetchone()[0]
    result = dict(row)
    result["tags"] = json_loads(result.pop("tags_json", "[]"), [])
    result["evidence_count"] = evidence_count
    result["finding_count"] = finding_count
    return result


def _evidence_dict(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["name"] = result.pop("original_name")
    result["hash"] = result["sha256"]
    result["metadata"] = json_loads(result.pop("metadata_json", "{}"), {})
    result["download_url"] = f"/api/evidence/{result['id']}/download"
    return result


def _timeline_dict(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["timestamp"] = result.pop("event_timestamp")
    result["timestamp_uncertain"] = bool(result.get("timestamp_uncertain", 0))
    result["raw_metadata"] = json_loads(result.pop("raw_metadata_json", "{}"), {})
    return result


def _finding_dict(settings: Settings, row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    with connection(settings) as conn:
        references = conn.execute(
            "SELECT evidence_id FROM finding_evidence WHERE finding_id = ? ORDER BY evidence_id",
            (row["id"],),
        ).fetchall()
    result["evidence_ids"] = [int(item[0]) for item in references]
    return result


def _report_dict(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    stored_name = result.pop("stored_name", None)
    result["download_url"] = f"/api/reports/{result['id']}/download" if stored_name and result.get("status") == "ready" else None
    return result


def _check_case_reference(settings: Settings, case_id: int | None) -> None:
    if case_id is not None:
        _case_or_404(settings, case_id)


def _check_evidence_reference(settings: Settings, evidence_id: int | None, case_id: int | None = None) -> None:
    if evidence_id is None:
        return
    with connection(settings) as conn:
        row = row_dict(conn.execute("SELECT id, case_id FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
    if case_id is not None and row.get("case_id") not in {None, case_id}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="evidence belongs to a different case")


def _build_graph(settings: Settings, case_id: int | None) -> dict[str, Any]:
    with connection(settings) as conn:
        case_query = "SELECT * FROM cases"
        evidence_query = "SELECT * FROM evidence"
        finding_query = "SELECT * FROM findings"
        timeline_query = "SELECT * FROM timeline_events"
        params: tuple[Any, ...] = ()
        if case_id is not None:
            params = (case_id,)
            case_query += " WHERE id = ?"
            evidence_query += " WHERE case_id = ?"
            finding_query += " WHERE case_id = ?"
            timeline_query += " WHERE case_id = ?"
        cases = [row_dict(row) or {} for row in conn.execute(case_query, params).fetchall()]
        evidence = [row_dict(row) or {} for row in conn.execute(evidence_query, params).fetchall()]
        findings = [row_dict(row) or {} for row in conn.execute(finding_query, params).fetchall()]
        timeline = [row_dict(row) or {} for row in conn.execute(timeline_query, params).fetchall()]
        finding_ids = tuple(item["id"] for item in findings)
        finding_refs = []
        if finding_ids:
            placeholders = ",".join("?" for _ in finding_ids)
            finding_refs = [
                row_dict(row) or {}
                for row in conn.execute(
                    f"SELECT finding_id, evidence_id FROM finding_evidence WHERE finding_id IN ({placeholders})",
                    finding_ids,
                ).fetchall()
            ]

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    node_ids: set[str] = set()

    def node(node_id: str, label: str, group: str, entity_type: str, entity_id: int | None, provenance: dict[str, Any], value: int = 1) -> None:
        if node_id not in node_ids:
            nodes.append({"id": node_id, "label": label, "group": group, "value": value, "entity_type": entity_type, "entity_id": entity_id, "provenance": provenance})
            node_ids.add(node_id)

    def edge(source: str, target: str, label: str, relationship: str, provenance: dict[str, Any]) -> None:
        edges.append({"id": f"{source}-{relationship}-{target}", "source": source, "target": target, "label": label, "relationship": relationship, "provenance": provenance})

    for case in cases:
        node(f"case:{case['id']}", f"{case['case_number']} — {case['title']}", "case", "case", case["id"], {"table": "cases", "field": "id"}, 2)
    for item in evidence:
        item_id = f"evidence:{item['id']}"
        node(item_id, item["original_name"], "evidence", "evidence", item["id"], {"table": "evidence", "field": "id", "sha256": item["sha256"]})
        parent = f"case:{item['case_id']}" if item.get("case_id") is not None else "case:unassigned"
        if item.get("case_id") is None:
            node("case:unassigned", "Unassigned evidence", "case", "case", None, {"reason": "evidence.case_id is null"})
        edge(parent, item_id, "contains evidence", "contains", {"basis": "evidence.case_id", "evidence_id": item["id"]})
    for finding in findings:
        finding_id = f"finding:{finding['id']}"
        node(finding_id, finding["title"], "finding", "finding", finding["id"], {"table": "findings", "field": "id"})
        parent = f"case:{finding['case_id']}" if finding.get("case_id") is not None else "case:unassigned"
        if finding.get("case_id") is None:
            node("case:unassigned", "Unassigned records", "case", "case", None, {"reason": "finding.case_id is null"})
        edge(parent, finding_id, "contains finding", "contains", {"basis": "findings.case_id", "finding_id": finding["id"]})
    for reference in finding_refs:
        source_id = reference["evidence_id"]
        if any(item["id"] == source_id for item in evidence):
            edge(
                f"evidence:{source_id}",
                f"finding:{reference['finding_id']}",
                "supports finding",
                "supports",
                {"basis": "finding_evidence", "finding_id": reference["finding_id"], "evidence_id": source_id},
            )
    for event in timeline:
        event_id = f"timeline:{event['id']}"
        node(event_id, event["title"], "timeline", "timeline", event["id"], {"table": "timeline_events", "field": "id"})
        parent = f"case:{event['case_id']}" if event.get("case_id") is not None else "case:unassigned"
        if event.get("case_id") is None:
            node("case:unassigned", "Unassigned records", "case", "case", None, {"reason": "timeline_events.case_id is null"})
        edge(parent, event_id, "contains timeline event", "contains", {"basis": "timeline_events.case_id", "timeline_id": event["id"]})
        if event.get("evidence_id") is not None and any(item["id"] == event["evidence_id"] for item in evidence):
            edge(
                f"evidence:{event['evidence_id']}",
                event_id,
                "supports timeline event",
                "supports",
                {"basis": "timeline_events.evidence_id", "timeline_id": event["id"], "evidence_id": event["evidence_id"]},
            )

    return {
        "nodes": nodes,
        "edges": edges,
        "generated_at": utc_now(),
        "methodology": "Transparent graph derived from explicit case_id foreign keys and an explicit findings.source value formatted as evidence:<id>; no relationships are inferred from file contents.",
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = app.state.settings
    settings.ensure_directories()
    initialize_database(settings)
    if settings.seed_demo:
        seed_demo_data(settings)
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(title="FORENSIX API", version=__version__, lifespan=lifespan)
    app.state.settings = settings or Settings.from_env()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(app.state.settings.cors_origins),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def reject_grossly_oversized_uploads(request, call_next):
        """Reject obviously oversized multipart requests before parsing their body.

        The upload service performs the authoritative exact byte check while streaming the
        file; this guard avoids handing an unexpectedly large request to the multipart parser.
        """

        if request.method == "POST" and request.url.path == "/api/evidence":
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = 0
                # Multipart framing and fields are small; the streaming check below remains exact.
                if declared_length > app.state.settings.max_upload_size_bytes + 1_048_576:
                    return JSONResponse(status_code=status.HTTP_413_CONTENT_TOO_LARGE, content={"detail": "evidence upload request is too large"})
        return await call_next(request)

    @app.get("/health", response_model=HealthOut)
    def health() -> dict[str, Any]:
        current = _settings(app)
        try:
            with connection(current) as conn:
                conn.execute("SELECT 1").fetchone()
            db_status = "ready"
        except Exception:
            db_status = "unavailable"
        return {
            "status": "ok" if db_status == "ready" else "degraded",
            "version": __version__,
            "services": {
                "database": db_status,
                "evidence_storage": "ready" if current.evidence_dir.is_dir() else "unavailable",
                "reportlab": "ready" if importlib.util.find_spec("reportlab") else "unavailable",
            },
        }

    @app.get("/api/cases", response_model=list[CaseOut])
    def get_cases(current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        with connection(current) as conn:
            rows = [row_dict(row) or {} for row in conn.execute("SELECT * FROM cases ORDER BY updated_at DESC, id DESC").fetchall()]
        return [_case_dict(current, row) for row in rows]

    @app.post("/api/cases", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
    def create_case(
        payload: CaseCreate,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        now = utc_now()
        case_number = f"FRX-{now[:4]}-{uuid.uuid4().hex[:8].upper()}"
        with connection(current) as conn:
            cursor = conn.execute(
                """
                INSERT INTO cases (case_number, title, description, status, severity, assignee, tags_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (case_number, payload.title.strip(), payload.description, payload.status, payload.severity, payload.assignee, json_dumps(payload.tags), now, now),
            )
            case_id = int(cursor.lastrowid)
            row = row_dict(conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()) or {}
        record_audit(current, "created", "case", case_id, {"case_number": case_number}, _actor(actor))
        return _case_dict(current, row)

    @app.get("/api/cases/{case_id}", response_model=CaseOut)
    def get_case(case_id: int, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        return _case_dict(current, _case_or_404(current, case_id))

    @app.patch("/api/cases/{case_id}", response_model=CaseOut)
    @app.put("/api/cases/{case_id}", response_model=CaseOut)
    def update_case(
        case_id: int,
        payload: CaseUpdate,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        _case_or_404(current, case_id)
        changes = payload.model_dump(exclude_unset=True)
        if not changes:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="provide at least one case field to update")
        now = utc_now()
        assignments: list[str] = []
        values: list[Any] = []
        for column in ("title", "description", "status", "severity", "assignee", "tags"):
            if column not in changes:
                continue
            value = changes[column]
            if column == "tags":
                value = json_dumps(value or [])
            assignments.append(f"{column if column != 'tags' else 'tags_json'} = ?")
            values.append(value)
        if "status" in changes and changes["status"] in {"closed", "resolved"}:
            assignments.append("closed_at = COALESCE(closed_at, ?)")
            values.append(now)
        elif "status" in changes:
            assignments.append("closed_at = NULL")
        assignments.append("updated_at = ?")
        values.extend([now, case_id])
        with connection(current) as conn:
            conn.execute(f"UPDATE cases SET {', '.join(assignments)} WHERE id = ?", values)
            row = row_dict(conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()) or {}
        record_audit(current, "updated", "case", case_id, {"fields": sorted(changes)}, _actor(actor))
        return _case_dict(current, row)

    @app.get("/api/evidence", response_model=list[EvidenceOut])
    def get_evidence(
        case_id: int | None = Query(default=None),
        current: Settings = Depends(lambda: _settings(app)),
    ) -> list[dict[str, Any]]:
        with connection(current) as conn:
            if case_id is None:
                rows = conn.execute("SELECT e.*, c.case_number FROM evidence e LEFT JOIN cases c ON c.id = e.case_id ORDER BY e.created_at DESC, e.id DESC").fetchall()
            else:
                rows = conn.execute("SELECT e.*, c.case_number FROM evidence e LEFT JOIN cases c ON c.id = e.case_id WHERE e.case_id = ? ORDER BY e.created_at DESC, e.id DESC", (case_id,)).fetchall()
        return [_evidence_dict(row_dict(row) or {}) for row in rows]

    @app.post("/api/evidence", response_model=EvidenceOut, status_code=status.HTTP_201_CREATED)
    async def upload_evidence(
        file: UploadFile = File(...),
        case_id: int | None = Form(default=None),
        source: str | None = Form(default=None),
        uploaded_by: str | None = Form(default=None),
        investigator_notes: str | None = Form(default=None),
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        _check_case_reference(current, case_id)
        original_name, stored_name, size, digest = await save_upload(current, file)
        now = utc_now()
        try:
            with connection(current) as conn:
                duplicate = conn.execute(
                    "SELECT id, original_name FROM evidence WHERE sha256 = ? AND size = ? AND (case_id = ? OR (case_id IS NULL AND ? IS NULL)) LIMIT 1",
                    (digest, size, case_id, case_id),
                ).fetchone()
                if duplicate is not None:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"duplicate evidence already recorded as item {duplicate[0]} ({duplicate[1]})",
                    )
                cursor = conn.execute(
                    """
                    INSERT INTO evidence (case_id, original_name, stored_name, media_type, size, sha256, integrity_status, source, uploaded_by, investigator_notes, metadata_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
                    """,
                    (case_id, original_name, stored_name, file.content_type, size, digest, source, uploaded_by, investigator_notes, json_dumps({"upload": "local", "sha256_algorithm": "SHA-256"}), now, now),
                )
                evidence_id = int(cursor.lastrowid)
                row = row_dict(conn.execute("SELECT e.*, c.case_number FROM evidence e LEFT JOIN cases c ON c.id = e.case_id WHERE e.id = ?", (evidence_id,)).fetchone()) or {}
        except Exception:
            managed_file(current, stored_name).unlink(missing_ok=True)
            raise
        record_audit(current, "uploaded", "evidence", evidence_id, {"sha256": digest, "size": size}, _actor(actor))
        return _evidence_dict(row)

    @app.get("/api/evidence/{evidence_id}", response_model=EvidenceOut)
    def get_evidence_item(evidence_id: int, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT e.*, c.case_number FROM evidence e LEFT JOIN cases c ON c.id = e.case_id WHERE e.id = ?", (evidence_id,)).fetchone())
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        return _evidence_dict(row)

    @app.get("/api/evidence/{evidence_id}/preview", response_model=EvidencePreviewOut)
    def preview_evidence(evidence_id: int, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        try:
            path = managed_file(current, row["stored_name"])
            kind, content, truncated, size = safe_preview(path, row["original_name"], row.get("media_type"))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence file is missing") from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=str(exc)) from exc
        record_audit(current, "previewed", "evidence", evidence_id, {"kind": kind, "truncated": truncated}, "api")
        return {
            "evidence_id": evidence_id,
            "kind": kind,
            "content": content,
            "truncated": truncated,
            "size": size,
            "message": "Bounded UTF-8 preview only; evidence was not executed or rendered as HTML.",
        }

    @app.get("/api/evidence/{evidence_id}/download")
    def download_evidence(evidence_id: int, current: Settings = Depends(lambda: _settings(app))) -> FileResponse:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        try:
            path = managed_file(current, row["stored_name"])
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="stored evidence path is invalid") from exc
        if not path.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence file is missing")
        record_audit(current, "downloaded", "evidence", evidence_id, {}, "api")
        return FileResponse(path, media_type=row["media_type"] or "application/octet-stream", filename=row["original_name"])

    @app.post("/api/evidence/{evidence_id}/verify", response_model=IntegrityOut)
    def verify_evidence(
        evidence_id: int,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        checked_at = utc_now()
        observed: str | None = None
        try:
            path = managed_file(current, row["stored_name"])
            if path.is_file():
                _, observed = sha256_file(path)
        except (OSError, ValueError):
            observed = None
        verified = observed is not None and observed.lower() == row["sha256"].lower()
        integrity_status = "verified" if verified else "failed"
        message = "SHA-256 matches the recorded evidence hash" if verified else "SHA-256 does not match or the evidence file is unavailable"
        with connection(current) as conn:
            conn.execute("UPDATE evidence SET integrity_status = ?, updated_at = ? WHERE id = ?", (integrity_status, checked_at, evidence_id))
            conn.execute(
                "INSERT INTO integrity_verifications (evidence_id, expected_hash, observed_hash, result, checked_at, actor) VALUES (?, ?, ?, ?, ?, ?)",
                (evidence_id, row["sha256"], observed, integrity_status, checked_at, _actor(actor)),
            )
        record_audit(current, "integrity_verified" if verified else "integrity_failed", "evidence", evidence_id, {"expected_hash": row["sha256"], "observed_hash": observed}, _actor(actor))
        return {"verified": verified, "status": integrity_status, "expected_hash": row["sha256"], "observed_hash": observed, "message": message, "checked_at": checked_at}

    @app.get("/api/evidence/{evidence_id}/verification-history", response_model=list[VerificationHistoryOut])
    def verification_history(evidence_id: int, current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        with connection(current) as conn:
            exists = conn.execute("SELECT 1 FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
            if exists is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
            rows = conn.execute(
                "SELECT * FROM integrity_verifications WHERE evidence_id = ? ORDER BY checked_at DESC, id DESC",
                (evidence_id,),
            ).fetchall()
        return [row_dict(row) or {} for row in rows]

    @app.post("/api/evidence/{evidence_id}/network-analysis", response_model=NetworkAnalysisOut)
    def network_analysis(evidence_id: int, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        suffix = Path(row["original_name"]).suffix.lower()
        media_type = (row.get("media_type") or "").lower()
        if suffix not in {".pcap", ".pcapng", ".cap"} and "pcap" not in media_type and "pcapng" not in media_type:
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="network analysis requires a PCAP, PCAPNG, or CAP evidence item")
        try:
            path = managed_file(current, row["stored_name"])
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="stored evidence path is invalid") from exc
        if not path.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence file is missing")
        started_at = utc_now()
        result = analyze_pcap(current, path)
        finished_at = utc_now()
        with connection(current) as conn:
            conn.execute(
                "INSERT INTO analysis_jobs (evidence_id, integration_id, action, arguments_json, tool_version, status, output, error, started_at, finished_at) VALUES (?, 'tshark', 'pcap_metadata', ?, ?, ?, ?, ?, ?, ?)",
                (
                    evidence_id,
                    json_dumps(["fixed TShark metadata field extraction"]),
                    result.get("tool_version"),
                    result.get("status", "failed"),
                    json_dumps(result),
                    None if result.get("available") else result.get("message"),
                    started_at,
                    finished_at,
                ),
            )
        record_audit(current, "network_analysis", "evidence", evidence_id, {"status": result.get("status"), "packet_count": result.get("packet_count", 0)}, "system")
        return {"evidence_id": evidence_id, **result}

    @app.get("/api/timeline", response_model=list[TimelineOut])
    def get_timeline(case_id: int | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        with connection(current) as conn:
            if case_id is None:
                rows = conn.execute("SELECT * FROM timeline_events ORDER BY event_timestamp DESC, id DESC").fetchall()
            else:
                rows = conn.execute("SELECT * FROM timeline_events WHERE case_id = ? ORDER BY event_timestamp DESC, id DESC", (case_id,)).fetchall()
        return [_timeline_dict(row_dict(row) or {}) for row in rows]

    @app.post("/api/timeline", response_model=TimelineOut, status_code=status.HTTP_201_CREATED)
    def create_timeline(
        payload: TimelineCreate,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        _check_case_reference(current, payload.case_id)
        _check_evidence_reference(current, payload.evidence_id, payload.case_id)
        now = utc_now()
        with connection(current) as conn:
            cursor = conn.execute(
                """
                INSERT INTO timeline_events (case_id, evidence_id, event_timestamp, title, description, event_type, source, severity, timestamp_uncertain, raw_metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.case_id,
                    payload.evidence_id,
                    payload.timestamp.isoformat(),
                    payload.title,
                    payload.description,
                    payload.event_type,
                    payload.source,
                    payload.severity,
                    int(payload.timestamp_uncertain),
                    json_dumps(payload.raw_metadata),
                    now,
                ),
            )
            event_id = int(cursor.lastrowid)
            row = row_dict(conn.execute("SELECT * FROM timeline_events WHERE id = ?", (event_id,)).fetchone()) or {}
        record_audit(current, "created", "timeline_event", event_id, {"case_id": payload.case_id}, _actor(actor))
        return _timeline_dict(row)

    @app.post("/api/timeline/import", response_model=TimelineImportOut)
    async def import_timeline(
        file: UploadFile = File(...),
        case_id: int | None = Form(default=None),
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        _check_case_reference(current, case_id)
        raw_bytes = await file.read(5 * 1024 * 1024 + 1)
        await file.close()
        if len(raw_bytes) > 5 * 1024 * 1024:
            raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="timeline import exceeds the 5 MiB limit")
        try:
            text = raw_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="timeline import must be UTF-8 JSON or CSV") from exc
        try:
            if Path(file.filename or "").suffix.lower() == ".json" or text.lstrip().startswith(("[", "{")):
                parsed = json.loads(text)
                records = parsed.get("events", parsed) if isinstance(parsed, dict) else parsed
                if not isinstance(records, list):
                    raise ValueError("JSON must be an array or an object with an events array")
            else:
                records = list(csv.DictReader(io.StringIO(text)))
        except (ValueError, json.JSONDecodeError, csv.Error) as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"could not parse timeline import: {exc}") from exc
        if len(records) > 2_000:
            raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="timeline import contains more than 2,000 rows")

        event_ids: list[int] = []
        rejected: list[dict[str, Any]] = []
        for index, record in enumerate(records, start=1):
            try:
                if not isinstance(record, dict):
                    raise ValueError("row must be an object")
                timestamp_value = record.get("timestamp") or record.get("event_timestamp")
                if not timestamp_value:
                    raise ValueError("timestamp is required")
                timestamp = datetime.fromisoformat(str(timestamp_value).replace("Z", "+00:00"))
                timestamp_uncertain = record.get("timestamp_uncertain", False)
                if isinstance(timestamp_uncertain, str):
                    timestamp_uncertain = timestamp_uncertain.strip().lower() in {"1", "true", "yes", "y"}
                raw_metadata = record.get("raw_metadata")
                if isinstance(raw_metadata, str):
                    raw_metadata = json.loads(raw_metadata) if raw_metadata.strip() else {}
                if not isinstance(raw_metadata, dict):
                    raw_metadata = {"imported_row": record}
                row_case_id = record.get("case_id") or case_id
                row_evidence_id = record.get("evidence_id") or None
                payload = TimelineCreate.model_validate(
                    {
                        "case_id": int(row_case_id) if row_case_id not in {None, ""} else None,
                        "evidence_id": int(row_evidence_id) if row_evidence_id not in {None, ""} else None,
                        "timestamp": timestamp,
                        "title": record.get("title") or record.get("summary") or "",
                        "description": record.get("description") or record.get("notes"),
                        "event_type": record.get("event_type") or record.get("type"),
                        "source": record.get("source") or file.filename,
                        "severity": record.get("severity") or "info",
                        "timestamp_uncertain": bool(timestamp_uncertain) or timestamp.tzinfo is None,
                        "raw_metadata": raw_metadata,
                    }
                )
                if payload.timestamp.tzinfo is None:
                    payload.timestamp = payload.timestamp.replace(tzinfo=timezone.utc)
                _check_case_reference(current, payload.case_id)
                _check_evidence_reference(current, payload.evidence_id, payload.case_id)
                now = utc_now()
                with connection(current) as conn:
                    cursor = conn.execute(
                        "INSERT INTO timeline_events (case_id, evidence_id, event_timestamp, title, description, event_type, source, severity, timestamp_uncertain, raw_metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (payload.case_id, payload.evidence_id, payload.timestamp.isoformat(), payload.title, payload.description, payload.event_type, payload.source, payload.severity, int(payload.timestamp_uncertain), json_dumps(payload.raw_metadata), now),
                    )
                    event_ids.append(int(cursor.lastrowid))
            except (TypeError, ValueError, HTTPException, json.JSONDecodeError) as exc:
                detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
                rejected.append({"row": index, "error": detail})
        record_audit(current, "timeline_imported", "timeline", None, {"filename": file.filename, "imported": len(event_ids), "rejected": len(rejected)}, _actor(actor))
        return {"imported_count": len(event_ids), "event_ids": event_ids, "rejected": rejected}

    @app.get("/api/findings", response_model=list[FindingOut])
    def get_findings(case_id: int | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        with connection(current) as conn:
            if case_id is None:
                rows = conn.execute("SELECT * FROM findings ORDER BY updated_at DESC, id DESC").fetchall()
            else:
                rows = conn.execute("SELECT * FROM findings WHERE case_id = ? ORDER BY updated_at DESC, id DESC", (case_id,)).fetchall()
        return [_finding_dict(current, row_dict(row) or {}) for row in rows]

    @app.post("/api/findings", response_model=FindingOut, status_code=status.HTTP_201_CREATED)
    def create_finding(
        payload: FindingCreate,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        _check_case_reference(current, payload.case_id)
        for evidence_id in payload.evidence_ids:
            _check_evidence_reference(current, evidence_id, payload.case_id)
        now = utc_now()
        with connection(current) as conn:
            cursor = conn.execute(
                """
                INSERT INTO findings (case_id, title, description, severity, status, confidence, source, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)
                """,
                (payload.case_id, payload.title, payload.description, payload.severity, payload.confidence, payload.source, now, now),
            )
            finding_id = int(cursor.lastrowid)
            for evidence_id in sorted(set(payload.evidence_ids)):
                conn.execute(
                    "INSERT INTO finding_evidence (finding_id, evidence_id, created_at) VALUES (?, ?, ?)",
                    (finding_id, evidence_id, now),
                )
            row = row_dict(conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()) or {}
        record_audit(current, "created", "finding", finding_id, {"case_id": payload.case_id}, _actor(actor))
        return _finding_dict(current, row)

    @app.get("/api/audit-events", response_model=list[AuditOut])
    def get_audit_events(limit: int = Query(default=200, ge=1, le=1_000), current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        return list_audit(current, limit)

    @app.get("/api/reports", response_model=list[ReportOut])
    def get_reports(case_id: int | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        return [_report_dict(row) for row in list_reports(current, case_id)]

    @app.post("/api/reports", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
    def generate_report(
        payload: ReportCreate,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        try:
            row = create_report(current, payload.case_id, payload.name)
        except LookupError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
        record_audit(current, "generated", "report", row.get("id"), {"case_id": payload.case_id, "format": "pdf"}, _actor(actor))
        return _report_dict(row)

    @app.get("/api/reports/{report_id}/download")
    def download_report(report_id: int, current: Settings = Depends(lambda: _settings(app))) -> FileResponse:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone())
        if row is None or row.get("status") != "ready" or not row.get("stored_name"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ready report not found")
        try:
            path = report_file(current, row["stored_name"])
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="stored report path is invalid") from exc
        if not path.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report file is missing")
        record_audit(current, "downloaded", "report", report_id, {}, "api")
        return FileResponse(path, media_type="application/pdf", filename=row["name"])

    @app.get("/api/integrations", response_model=list[IntegrationOut])
    def get_integrations() -> list[dict[str, Any]]:
        return [integration_status(tool.id) for tool in TOOLS]

    @app.post("/api/integrations/{integration_id}/check", response_model=IntegrationOut)
    def check_integration(integration_id: str) -> dict[str, Any]:
        try:
            return integration_status(integration_id)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown integration") from exc

    @app.post("/api/integrations/{integration_id}/actions", response_model=IntegrationActionOut)
    def integration_action(
        integration_id: str,
        payload: IntegrationAction,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        try:
            # The evidence path comes only from a validated database row and managed directory.
            evidence_path: Path | None = None
            if payload.evidence_id is not None:
                with connection(current) as conn:
                    evidence = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (payload.evidence_id,)).fetchone())
                if evidence is None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
                evidence_path = managed_file(current, evidence["stored_name"])
                if not evidence_path.is_file():
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence file is missing")
            started_at = utc_now()
            result = run_action(current, integration_id, payload.action, evidence_path)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown integration") from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="stored evidence path is invalid") from exc
        finished_at = utc_now()
        tool_status = integration_status(integration_id)
        with connection(current) as conn:
            conn.execute(
                """
                INSERT INTO analysis_jobs (evidence_id, integration_id, action, arguments_json, tool_version, status, output, error, started_at, finished_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.evidence_id,
                    integration_id,
                    payload.action,
                    json_dumps([]),
                    tool_status.get("version"),
                    "completed" if result["available"] else "failed",
                    result.get("output", ""),
                    result.get("error"),
                    started_at,
                    finished_at,
                ),
            )
        record_audit(current, "integration_action", "integration", integration_id, {"action": payload.action, "evidence_id": payload.evidence_id, "available": result["available"]}, _actor(actor))
        return result

    @app.get("/api/analysis-jobs", response_model=list[AnalysisJobOut])
    def get_analysis_jobs(
        evidence_id: int | None = Query(default=None),
        current: Settings = Depends(lambda: _settings(app)),
    ) -> list[dict[str, Any]]:
        with connection(current) as conn:
            if evidence_id is None:
                rows = conn.execute("SELECT * FROM analysis_jobs ORDER BY id DESC LIMIT 200").fetchall()
            else:
                rows = conn.execute("SELECT * FROM analysis_jobs WHERE evidence_id = ? ORDER BY id DESC LIMIT 200", (evidence_id,)).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = row_dict(row) or {}
            item["arguments"] = json_loads(item.pop("arguments_json", "[]"), [])
            results.append(item)
        return results

    @app.get("/api/graph", response_model=GraphOut)
    def get_graph(case_id: int | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        _check_case_reference(current, case_id)
        return _build_graph(current, case_id)

    @app.get("/api/network")
    def get_network(case_id: int | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        graph = _build_graph(current, case_id)
        return {
            "nodes": [{"id": node["id"], "label": node["label"], "type": node["group"], "risk": "info"} for node in graph["nodes"]],
            "edges": [{"id": edge["id"], "source": edge["source"], "target": edge["target"], "label": edge["label"], "protocol": edge["relationship"]} for edge in graph["edges"]],
            "generated_at": graph["generated_at"],
            "methodology": graph["methodology"],
        }

    return app


app = create_app()
