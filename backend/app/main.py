"""FastAPI application for the FORENSIX forensic workspace."""

from __future__ import annotations

import importlib.util
import csv
import io
import json
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from . import __version__, schemas
from .attack import TECHNIQUE_MAP, coverage_for_rows, normalize_techniques, stix_bundle
from .audit import list_audit, record_audit, verify_audit_chain
from .adapters import adapter_supports, get_adapter
from .auth import create_session, create_user, find_user, list_users, non_system_user_count, public_user, revoke_token, user_from_token, verify_password
from .config import Settings
from .database import connection, initialize_database, json_dumps, json_loads, rebuild_search_index, row_dict, search_index, utc_now
from .integrations import TOOLS, integration_status, run_action
from .reports import create_report, list_reports, report_file
from .schemas import (
    AuditOut,
    AuditChainVerifyOut,
    AnalysisJobOut,
    AnalysisJobCreate,
    CaseCreate,
    CaseOut,
    CaseUpdate,
    CustodyCreate,
    CustodyOut,
    EvidenceOut,
    EvidencePreviewOut,
    FindingCreate,
    FindingOut,
    GraphOut,
    HealthOut,
    AttackCoverageOut,
    AttackTechniqueOut,
    IOCOut,
    IntegrityOut,
    IntegrityAlertOut,
    NetworkAnalysisOut,
    NoteCreate,
    NoteOut,
    SearchResultOut,
    HexViewOut,
    VerificationHistoryOut,
    IntegrationAction,
    IntegrationActionOut,
    IntegrationOut,
    ReportCreate,
    ReportOut,
    TimelineCreate,
    TimelineImportOut,
    TimelineOut,
    YaraScanCreate,
)
from .seed import seed_demo_data
from .storage import enforce_read_only_vault, hash_file, managed_file, safe_preview, save_upload


def _settings(app: FastAPI) -> Settings:
    return app.state.settings


def _actor(actor: str | None, request: Request | None = None) -> str:
    user = getattr(getattr(request, "state", None), "user", None) if request is not None else None
    if user:
        return str(user["username"])[:200]
    return (actor or "api").strip()[:200] or "api"


def _user_id(request: Request | None) -> int | None:
    user = getattr(getattr(request, "state", None), "user", None) if request is not None else None
    return int(user["id"]) if user else None


def _require_role(request: Request, allowed: set[str] = {"admin", "analyst"}) -> dict[str, Any]:
    user = getattr(request.state, "user", None)
    if not user or user.get("role") not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="your role is read-only for this action")
    return user


def _record_request_audit(
    settings: Settings,
    request: Request,
    event_type: str,
    entity_type: str,
    entity_id: int | str | None,
    details: dict[str, Any] | None = None,
    actor: str | None = None,
) -> None:
    user = getattr(request.state, "user", None)
    record_audit(
        settings,
        event_type,
        entity_type,
        entity_id,
        details,
        actor or (str(user["username"]) if user else "system"),
        int(user["id"]) if user else None,
    )


def _authorization_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return request.cookies.get("forensix_session")


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


def _custody_dict(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["from_party"] = result.pop("from_party", result.get("from", ""))
    result["to_party"] = result.pop("to_party", result.get("to", ""))
    return result


def _timeline_dict(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["timestamp"] = result.pop("event_timestamp")
    result["timestamp_uncertain"] = bool(result.get("timestamp_uncertain", 0))
    result["raw_metadata"] = json_loads(result.pop("raw_metadata_json", "{}"), {})
    result["provenance"] = json_loads(result.pop("provenance_json", "{}"), {})
    result["attack_techniques"] = json_loads(result.pop("attack_techniques_json", "[]"), [])
    return result


def _finding_dict(settings: Settings, row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    with connection(settings) as conn:
        references = conn.execute(
            "SELECT evidence_id FROM finding_evidence WHERE finding_id = ? ORDER BY evidence_id",
            (row["id"],),
        ).fetchall()
    result["evidence_ids"] = [int(item[0]) for item in references]
    result["attack_techniques"] = json_loads(result.pop("attack_techniques_json", "[]"), [])
    return result


def _report_dict(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    stored_name = result.pop("stored_name", None)
    result["download_url"] = f"/api/reports/{result['id']}/download" if stored_name and result.get("status") == "ready" else None
    result["signature_url"] = f"/api/reports/{result['id']}/signature" if result.get("signature_name") and result.get("status") == "ready" else None
    return result


def _note_dict(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["pinned"] = bool(result.get("pinned", 0))
    return result


def _analysis_job_dict(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    result["arguments"] = json_loads(result.pop("arguments_json", "[]"), [])
    result["cancel_requested"] = bool(result.get("cancel_requested", 0))
    return result


def _queue_adapter_job(settings: Settings, evidence_id: int, adapter_name: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    with connection(settings) as conn:
        evidence = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
    try:
        adapter = get_adapter(adapter_name)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown analysis adapter") from exc
    if not adapter_supports(adapter, evidence["original_name"], evidence.get("media_type")):
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=f"adapter {adapter.name} does not support this evidence type")
    now = utc_now()
    with connection(settings) as conn:
        cursor = conn.execute(
            "INSERT INTO analysis_jobs (evidence_id, integration_id, action, arguments_json, tool_version, status, output, error, progress, log, cancel_requested, created_at, updated_at, started_at, finished_at) VALUES (?, ?, 'analyze', ?, ?, 'queued', '', NULL, 0, ?, 0, ?, ?, ?, NULL)",
            (evidence_id, adapter.name, json_dumps(options or {}), adapter.version, f"Queued {adapter.name} adapter", now, now, now),
        )
        return row_dict(conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (cursor.lastrowid,)).fetchone()) or {}


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


def _build_graph(settings: Settings, case_id: int | None, pivot_id: str | None = None) -> dict[str, Any]:
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

    if pivot_id:
        linked = {pivot_id}
        for item in edges:
            if item["source"] == pivot_id:
                linked.add(item["target"])
            if item["target"] == pivot_id:
                linked.add(item["source"])
        nodes = [item for item in nodes if item["id"] in linked]
        edges = [item for item in edges if item["source"] in linked and item["target"] in linked]

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
    enforce_read_only_vault(settings)
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
    async def authenticate_local_requests(request: Request, call_next):
        """Require a local session for API resources and enforce read-only reviewers."""

        path = request.url.path
        public_paths = {
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/auth/status",
            "/api/auth/bootstrap",
            "/api/auth/login",
        }
        if request.method == "OPTIONS" or path in public_paths or not path.startswith("/api/"):
            return await call_next(request)

        user = user_from_token(_settings(app), _authorization_token(request))
        if user is None:
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": "authentication required"})
        request.state.user = user

        # Integration version checks do not mutate evidence or metadata. All
        # other write-shaped API calls require an analyst or administrator.
        read_only_post = request.method == "POST" and path.startswith("/api/integrations/") and path.endswith("/check")
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not read_only_post and user["role"] == "reviewer":
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content={"detail": "reviewer role is read-only"})
        return await call_next(request)

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

    @app.get("/api/auth/status")
    def auth_status(current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        return {"initialized": non_system_user_count(current) > 0}

    @app.post("/api/auth/bootstrap", response_model=schemas.AuthSessionOut, status_code=status.HTTP_201_CREATED)
    def bootstrap_admin(
        payload: schemas.AuthCredentials,
        current: Settings = Depends(lambda: _settings(app)),
    ) -> dict[str, Any]:
        if non_system_user_count(current) > 0:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="an administrator already exists")
        try:
            row = create_user(current, payload.username.strip(), payload.password, "admin")
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username is already in use") from exc
        token, expires_at = create_session(current, int(row["id"]))
        # The bootstrap event is the first user-bound audit record.
        record_audit(current, "created", "user", row["id"], {"role": "admin", "bootstrap": True}, row["username"], int(row["id"]))
        return {"token": token, "expires_at": expires_at, "user": public_user(row)}

    @app.post("/api/auth/login", response_model=schemas.AuthSessionOut)
    def login(payload: schemas.AuthCredentials, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        row = find_user(current, payload.username.strip())
        if row is None or not verify_password(payload.password, row["password_hash"]):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid username or password")
        token, expires_at = create_session(current, int(row["id"]))
        return {"token": token, "expires_at": expires_at, "user": public_user(row)}

    @app.get("/api/auth/me", response_model=schemas.UserOut)
    def auth_me(request: Request) -> dict[str, Any]:
        return public_user(request.state.user)

    @app.post("/api/auth/logout")
    def logout(request: Request) -> dict[str, bool]:
        revoke_token(_settings(app), _authorization_token(request))
        return {"ok": True}

    @app.get("/api/auth/users", response_model=list[schemas.UserOut])
    def get_users(request: Request, current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        _require_role(request, {"admin"})
        return list_users(current)

    @app.post("/api/auth/users", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
    def add_user(payload: schemas.UserCreate, request: Request, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        _require_role(request, {"admin"})
        try:
            row = create_user(current, payload.username.strip(), payload.password, payload.role)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username is already in use") from exc
        _record_request_audit(current, request, "created", "user", row.get("id"), {"role": payload.role})
        return public_user(row)

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
        request: Request,
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
        _record_request_audit(current, request, "created", "case", case_id, {"case_number": case_number}, _actor(actor, request))
        return _case_dict(current, row)

    @app.get("/api/cases/{case_id}", response_model=CaseOut)
    def get_case(case_id: int, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        return _case_dict(current, _case_or_404(current, case_id))

    @app.patch("/api/cases/{case_id}", response_model=CaseOut)
    @app.put("/api/cases/{case_id}", response_model=CaseOut)
    def update_case(
        case_id: int,
        payload: CaseUpdate,
        request: Request,
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
        _record_request_audit(current, request, "updated", "case", case_id, {"fields": sorted(changes)}, _actor(actor, request))
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
        request: Request,
        file: UploadFile = File(...),
        case_id: int | None = Form(default=None),
        source: str | None = Form(default=None),
        uploaded_by: str | None = Form(default=None),
        investigator_notes: str | None = Form(default=None),
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        _check_case_reference(current, case_id)
        original_name, stored_name, size, digests = await save_upload(current, file)
        digest = digests["sha256"]
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
                    INSERT INTO evidence (case_id, original_name, stored_name, media_type, size, md5, sha1, sha256, integrity_status, source, uploaded_by, investigator_notes, metadata_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
                    """,
                    (case_id, original_name, stored_name, file.content_type, size, digests["md5"], digests["sha1"], digest, source, uploaded_by, investigator_notes, json_dumps({"upload": "local", "hash_algorithms": ["MD5", "SHA-1", "SHA-256"]}), now, now),
                )
                evidence_id = int(cursor.lastrowid)
                row = row_dict(conn.execute("SELECT e.*, c.case_number FROM evidence e LEFT JOIN cases c ON c.id = e.case_id WHERE e.id = ?", (evidence_id,)).fetchone()) or {}
        except Exception:
            managed_file(current, stored_name).unlink(missing_ok=True)
            raise
        _record_request_audit(current, request, "uploaded", "evidence", evidence_id, {"sha256": digest, "size": size}, _actor(actor, request))
        with connection(current) as conn:
            conn.execute(
                "INSERT INTO custody_events (evidence_id, from_party, to_party, reason, event_timestamp, hash_at_handoff, actor, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (evidence_id, "local source", uploaded_by or _actor(actor, request), "Evidence ingested into the private FORENSIX vault", now, digest, _actor(actor, request), _user_id(request), now),
            )
        return _evidence_dict(row)

    @app.get("/api/evidence/{evidence_id}", response_model=EvidenceOut)
    def get_evidence_item(evidence_id: int, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT e.*, c.case_number FROM evidence e LEFT JOIN cases c ON c.id = e.case_id WHERE e.id = ?", (evidence_id,)).fetchone())
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        return _evidence_dict(row)

    @app.get("/api/evidence/{evidence_id}/preview", response_model=EvidencePreviewOut)
    def preview_evidence(evidence_id: int, request: Request, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
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
        _record_request_audit(current, request, "previewed", "evidence", evidence_id, {"kind": kind, "truncated": truncated})
        return {
            "evidence_id": evidence_id,
            "kind": kind,
            "content": content,
            "truncated": truncated,
            "size": size,
            "message": "Bounded UTF-8 preview only; evidence was not executed or rendered as HTML.",
        }

    @app.get("/api/evidence/{evidence_id}/download")
    def download_evidence(evidence_id: int, request: Request, current: Settings = Depends(lambda: _settings(app))) -> FileResponse:
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
        _record_request_audit(current, request, "downloaded", "evidence", evidence_id, {})
        return FileResponse(path, media_type=row["media_type"] or "application/octet-stream", filename=row["original_name"])

    @app.get("/api/evidence/{evidence_id}/hex", response_model=HexViewOut)
    def evidence_hex_view(
        evidence_id: int,
        offset: int = Query(default=0, ge=0),
        length: int = Query(default=256, ge=1, le=4096),
        current: Settings = Depends(lambda: _settings(app)),
    ) -> dict[str, Any]:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        path = managed_file(current, row["stored_name"])
        if not path.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence file is missing")
        total = path.stat().st_size
        if offset > total:
            raise HTTPException(status_code=status.HTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE, detail="offset is beyond evidence size")
        with path.open("rb") as source:
            source.seek(offset)
            data = source.read(length)
        hex_lines = []
        for index in range(0, len(data), 16):
            chunk = data[index:index + 16]
            hex_part = " ".join(f"{byte:02x}" for byte in chunk).ljust(47)
            ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
            hex_lines.append(f"{offset + index:08x}  {hex_part}  |{ascii_part}|")
        strings: list[str] = []
        for match in re.findall(rb"[ -~]{4,}", data):
            value = match.decode("ascii", errors="ignore")[:300]
            if value:
                strings.append(value)
        return {"evidence_id": evidence_id, "offset": offset, "length": len(data), "total_size": total, "hex_lines": hex_lines, "strings": strings[:200], "next_offset": offset + len(data) if offset + len(data) < total else None}

    @app.post("/api/evidence/{evidence_id}/verify", response_model=IntegrityOut)
    def verify_evidence(
        evidence_id: int,
        request: Request,
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
                _, observed_hashes = hash_file(path)
            else:
                observed_hashes = None
        except (OSError, ValueError):
            observed_hashes = None
        expected_md5 = row.get("md5")
        expected_sha1 = row.get("sha1")
        observed_md5 = observed_hashes.get("md5") if observed_hashes else None
        observed_sha1 = observed_hashes.get("sha1") if observed_hashes else None
        observed = observed_hashes.get("sha256") if observed_hashes else None
        verified = (
            observed is not None
            and observed.lower() == row["sha256"].lower()
            and (not expected_md5 or expected_md5.lower() == observed_md5.lower())
            and (not expected_sha1 or expected_sha1.lower() == observed_sha1.lower())
        )
        integrity_status = "verified" if verified else "failed"
        message = "SHA-256 matches the recorded evidence hash" if verified else "SHA-256 does not match or the evidence file is unavailable"
        with connection(current) as conn:
            conn.execute("UPDATE evidence SET integrity_status = ?, updated_at = ? WHERE id = ?", (integrity_status, checked_at, evidence_id))
            conn.execute(
                "INSERT INTO integrity_verifications (evidence_id, expected_md5, expected_sha1, expected_hash, observed_md5, observed_sha1, observed_hash, result, checked_at, actor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (evidence_id, expected_md5, expected_sha1, row["sha256"], observed_md5, observed_sha1, observed, integrity_status, checked_at, _actor(actor, request)),
            )
            if not verified:
                conn.execute(
                    "INSERT INTO integrity_alerts (evidence_id, alert_type, message, expected_hash, observed_hash, created_at) VALUES (?, 'integrity_drift', ?, ?, ?, ?)",
                    (evidence_id, message, row["sha256"], observed, checked_at),
                )
        _record_request_audit(current, request, "integrity_verified" if verified else "integrity_failed", "evidence", evidence_id, {"expected_hash": row["sha256"], "observed_hash": observed})
        return {"verified": verified, "status": integrity_status, "expected_md5": expected_md5, "expected_sha1": expected_sha1, "expected_hash": row["sha256"], "observed_md5": observed_md5, "observed_sha1": observed_sha1, "observed_hash": observed, "message": message, "checked_at": checked_at}

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

    @app.post("/api/evidence/{evidence_id}/rehash", response_model=IntegrityOut)
    def rehash_evidence(
        evidence_id: int,
        request: Request,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        """Run a bounded local re-hash and record drift as an integrity alert/job."""

        started_at = utc_now()
        result = verify_evidence(evidence_id, request, current, actor)
        finished_at = utc_now()
        with connection(current) as conn:
            conn.execute(
                "INSERT INTO analysis_jobs (evidence_id, integration_id, action, arguments_json, tool_version, status, output, error, started_at, finished_at) VALUES (?, 'integrity', 'rehash', '[]', 'FORENSIX hash service', ?, ?, ?, ?, ?)",
                (evidence_id, "completed" if result["verified"] else "failed", json_dumps(result), None if result["verified"] else result["message"], started_at, finished_at),
            )
        _record_request_audit(current, request, "rehash_completed", "evidence", evidence_id, {"status": result["status"]})
        return result

    @app.get("/api/evidence/{evidence_id}/integrity-alerts", response_model=list[IntegrityAlertOut])
    def integrity_alerts(evidence_id: int, current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        with connection(current) as conn:
            exists = conn.execute("SELECT 1 FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
            if exists is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
            rows = conn.execute("SELECT * FROM integrity_alerts WHERE evidence_id = ? ORDER BY id DESC", (evidence_id,)).fetchall()
        return [row_dict(row) or {} for row in rows]

    @app.get("/api/evidence/{evidence_id}/custody", response_model=list[CustodyOut])
    def get_custody(evidence_id: int, current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        with connection(current) as conn:
            exists = conn.execute("SELECT 1 FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
            if exists is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
            rows = conn.execute("SELECT * FROM custody_events WHERE evidence_id = ? ORDER BY event_timestamp ASC, id ASC", (evidence_id,)).fetchall()
        return [_custody_dict(row_dict(row) or {}) for row in rows]

    @app.post("/api/evidence/{evidence_id}/custody", response_model=CustodyOut, status_code=status.HTTP_201_CREATED)
    def add_custody(
        evidence_id: int,
        payload: CustodyCreate,
        request: Request,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        with connection(current) as conn:
            evidence = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
        if evidence is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        event_timestamp = payload.timestamp.isoformat() if payload.timestamp else utc_now()
        now = utc_now()
        username = _actor(actor, request)
        with connection(current) as conn:
            cursor = conn.execute(
                "INSERT INTO custody_events (evidence_id, from_party, to_party, reason, event_timestamp, hash_at_handoff, actor, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (evidence_id, payload.from_party.strip(), payload.to_party.strip(), payload.reason.strip(), event_timestamp, evidence["sha256"], username, _user_id(request), now),
            )
            row = row_dict(conn.execute("SELECT * FROM custody_events WHERE id = ?", (cursor.lastrowid,)).fetchone()) or {}
        _record_request_audit(current, request, "created", "custody_event", row.get("id"), {"evidence_id": evidence_id, "hash_at_handoff": evidence["sha256"]})
        return _custody_dict(row)

    @app.post("/api/evidence/{evidence_id}/network-analysis", response_model=NetworkAnalysisOut)
    def network_analysis(evidence_id: int, request: Request, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone())
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        suffix = Path(row["original_name"]).suffix.lower()
        media_type = (row.get("media_type") or "").lower()
        if suffix not in {".pcap", ".pcapng", ".cap"} and "pcap" not in media_type and "pcapng" not in media_type:
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="network analysis requires a PCAP, PCAPNG, or CAP evidence item")
        try:
            adapter = get_adapter("tshark-pcap")
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="TShark adapter is unavailable") from exc
        now = utc_now()
        with connection(current) as conn:
            cursor = conn.execute(
                "INSERT INTO analysis_jobs (evidence_id, integration_id, action, arguments_json, tool_version, status, output, error, progress, log, cancel_requested, created_at, updated_at, started_at, finished_at) VALUES (?, ?, 'analyze', '{}', ?, 'queued', '', NULL, 0, ?, 0, ?, ?, ?, NULL)",
                (
                    evidence_id,
                    adapter.name,
                    adapter.version,
                    "Queued by the network-analysis endpoint",
                    now,
                    now,
                    now,
                ),
            )
            job_id = int(cursor.lastrowid)
        _record_request_audit(current, request, "analysis_queued", "analysis_job", job_id, {"evidence_id": evidence_id, "adapter": adapter.name})
        return {"evidence_id": evidence_id, "job_id": job_id, "available": False, "status": "queued", "tool_version": adapter.version, "packet_count": 0, "protocols": {}, "endpoints": [], "dns_queries": [], "sample_packets": [], "message": "PCAP analysis queued for the local worker; no packet data has been claimed yet.", "analyzed_at": now}

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
        request: Request,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        _check_case_reference(current, payload.case_id)
        _check_evidence_reference(current, payload.evidence_id, payload.case_id)
        now = utc_now()
        with connection(current) as conn:
            cursor = conn.execute(
                """
                INSERT INTO timeline_events (case_id, evidence_id, event_timestamp, title, description, event_type, source, severity, confidence, timestamp_uncertain, raw_metadata_json, provenance_json, attack_techniques_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    payload.confidence,
                    int(payload.timestamp_uncertain),
                    json_dumps(payload.raw_metadata),
                    json_dumps({"source": "analyst", "parser": "manual", "parser_version": "n/a", "timestamp": now}),
                    json_dumps(normalize_techniques(payload.attack_techniques)),
                    now,
                ),
            )
            event_id = int(cursor.lastrowid)
            row = row_dict(conn.execute("SELECT * FROM timeline_events WHERE id = ?", (event_id,)).fetchone()) or {}
        _record_request_audit(current, request, "created", "timeline_event", event_id, {"case_id": payload.case_id}, _actor(actor, request))
        return _timeline_dict(row)

    @app.post("/api/timeline/import", response_model=TimelineImportOut)
    async def import_timeline(
        request: Request,
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
                        "attack_techniques": record.get("attack_techniques") or [],
                    }
                )
                if payload.timestamp.tzinfo is None:
                    payload.timestamp = payload.timestamp.replace(tzinfo=timezone.utc)
                _check_case_reference(current, payload.case_id)
                _check_evidence_reference(current, payload.evidence_id, payload.case_id)
                now = utc_now()
                with connection(current) as conn:
                    cursor = conn.execute(
                        "INSERT INTO timeline_events (case_id, evidence_id, event_timestamp, title, description, event_type, source, severity, confidence, timestamp_uncertain, raw_metadata_json, provenance_json, attack_techniques_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (payload.case_id, payload.evidence_id, payload.timestamp.isoformat(), payload.title, payload.description, payload.event_type, payload.source, payload.severity, payload.confidence, int(payload.timestamp_uncertain), json_dumps(payload.raw_metadata), json_dumps({"source": "timeline_import", "parser": "csv/json importer", "parser_version": "1", "timestamp": now}), json_dumps(normalize_techniques(payload.attack_techniques)), now),
                    )
                    event_ids.append(int(cursor.lastrowid))
            except (TypeError, ValueError, HTTPException, json.JSONDecodeError) as exc:
                detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
                rejected.append({"row": index, "error": detail})
        _record_request_audit(current, request, "timeline_imported", "timeline", None, {"filename": file.filename, "imported": len(event_ids), "rejected": len(rejected)}, _actor(actor, request))
        return {"imported_count": len(event_ids), "event_ids": event_ids, "rejected": rejected}

    @app.get("/api/findings", response_model=list[FindingOut])
    def get_findings(case_id: int | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        with connection(current) as conn:
            if case_id is None:
                rows = conn.execute("SELECT * FROM findings ORDER BY updated_at DESC, id DESC").fetchall()
            else:
                rows = conn.execute("SELECT * FROM findings WHERE case_id = ? ORDER BY updated_at DESC, id DESC", (case_id,)).fetchall()
        return [_finding_dict(current, row_dict(row) or {}) for row in rows]

    @app.get("/api/search", response_model=list[SearchResultOut])
    def global_search(
        q: str = Query(min_length=1, max_length=200),
        case_id: int | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
        current: Settings = Depends(lambda: _settings(app)),
    ) -> list[dict[str, Any]]:
        with connection(current) as conn:
            rebuild_search_index(conn)
            return search_index(conn, q, case_id, limit)

    @app.get("/api/notes", response_model=list[NoteOut])
    def get_notes(
        case_id: int | None = Query(default=None),
        target_type: str | None = Query(default=None),
        target_id: int | None = Query(default=None),
        current: Settings = Depends(lambda: _settings(app)),
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM notes WHERE 1 = 1"
        params: list[Any] = []
        if case_id is not None:
            query += " AND case_id = ?"
            params.append(case_id)
        if target_type is not None:
            query += " AND target_type = ?"
            params.append(target_type)
        if target_id is not None:
            query += " AND target_id = ?"
            params.append(target_id)
        query += " ORDER BY pinned DESC, updated_at DESC, id DESC"
        with connection(current) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [_note_dict(row_dict(row) or {}) for row in rows]

    @app.post("/api/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
    def create_note(
        payload: NoteCreate,
        request: Request,
        current: Settings = Depends(lambda: _settings(app)),
    ) -> dict[str, Any]:
        if "<script" in payload.markdown.lower() or "</script" in payload.markdown.lower():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="script markup is not allowed in notes")
        _check_case_reference(current, payload.case_id)
        now = utc_now()
        with connection(current) as conn:
            cursor = conn.execute(
                "INSERT INTO notes (case_id, target_type, target_id, offset, title, markdown, pinned, author_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (payload.case_id, payload.target_type, payload.target_id, payload.offset, payload.title.strip(), payload.markdown, int(payload.pinned), _user_id(request), now, now),
            )
            row = row_dict(conn.execute("SELECT * FROM notes WHERE id = ?", (cursor.lastrowid,)).fetchone()) or {}
        _record_request_audit(current, request, "created", "note", row.get("id"), {"target_type": payload.target_type, "target_id": payload.target_id})
        return _note_dict(row)

    @app.post("/api/findings", response_model=FindingOut, status_code=status.HTTP_201_CREATED)
    def create_finding(
        payload: FindingCreate,
        request: Request,
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
                INSERT INTO findings (case_id, title, description, severity, status, confidence, source, attack_techniques_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
                """,
                (payload.case_id, payload.title, payload.description, payload.severity, payload.confidence, payload.source, json_dumps(normalize_techniques(payload.attack_techniques)), now, now),
            )
            finding_id = int(cursor.lastrowid)
            for evidence_id in sorted(set(payload.evidence_ids)):
                conn.execute(
                    "INSERT INTO finding_evidence (finding_id, evidence_id, created_at) VALUES (?, ?, ?)",
                    (finding_id, evidence_id, now),
                )
            row = row_dict(conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()) or {}
        _record_request_audit(current, request, "created", "finding", finding_id, {"case_id": payload.case_id}, _actor(actor, request))
        return _finding_dict(current, row)

    @app.get("/api/audit-events", response_model=list[AuditOut])
    def get_audit_events(limit: int = Query(default=200, ge=1, le=1_000), current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        return list_audit(current, limit)

    @app.get("/api/audit-events/verify", response_model=AuditChainVerifyOut)
    def audit_chain_verify(current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        return verify_audit_chain(current)

    @app.get("/api/reports", response_model=list[ReportOut])
    def get_reports(case_id: int | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        return [_report_dict(row) for row in list_reports(current, case_id)]

    @app.post("/api/reports", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
    def generate_report(
        payload: ReportCreate,
        request: Request,
        current: Settings = Depends(lambda: _settings(app)),
        actor: str | None = Header(default=None, alias="X-Actor"),
    ) -> dict[str, Any]:
        try:
            row = create_report(current, payload.case_id, payload.name, payload.template)
        except LookupError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
        _record_request_audit(current, request, "generated", "report", row.get("id"), {"case_id": payload.case_id, "format": "pdf"}, _actor(actor, request))
        return _report_dict(row)

    @app.get("/api/reports/{report_id}/download")
    def download_report(report_id: int, request: Request, current: Settings = Depends(lambda: _settings(app))) -> FileResponse:
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
        _record_request_audit(current, request, "downloaded", "report", report_id, {})
        return FileResponse(path, media_type="application/pdf", filename=row["name"])

    @app.get("/api/reports/{report_id}/signature")
    def download_report_signature(report_id: int, current: Settings = Depends(lambda: _settings(app))) -> FileResponse:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone())
        if row is None or row.get("status") != "ready" or not row.get("signature_name"):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report signature not found")
        path = current.reports_dir / row["signature_name"]
        if not path.is_file():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report signature file is missing")
        return FileResponse(path, media_type="application/octet-stream", filename=row["signature_name"])

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
        request: Request,
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
        _record_request_audit(current, request, "integration_action", "integration", integration_id, {"action": payload.action, "evidence_id": payload.evidence_id, "available": result["available"]}, _actor(actor, request))
        return result

    @app.post("/api/analysis-jobs", response_model=AnalysisJobOut, status_code=status.HTTP_201_CREATED)
    def enqueue_analysis_job(
        payload: AnalysisJobCreate,
        request: Request,
        current: Settings = Depends(lambda: _settings(app)),
    ) -> dict[str, Any]:
        with connection(current) as conn:
            evidence = row_dict(conn.execute("SELECT * FROM evidence WHERE id = ?", (payload.evidence_id,)).fetchone())
        if evidence is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evidence not found")
        try:
            adapter = get_adapter(payload.adapter)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown analysis adapter") from exc
        if not adapter_supports(adapter, evidence["original_name"], evidence.get("media_type")):
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail=f"adapter {adapter.name} does not support this evidence type")
        now = utc_now()
        with connection(current) as conn:
            cursor = conn.execute(
                "INSERT INTO analysis_jobs (evidence_id, integration_id, action, arguments_json, tool_version, status, output, error, progress, log, cancel_requested, created_at, updated_at, started_at, finished_at) VALUES (?, ?, ?, ?, ?, 'queued', '', NULL, 0, ?, 0, ?, ?, ?, NULL)",
                (payload.evidence_id, adapter.name, payload.action, json_dumps(payload.options), adapter.version, "Queued by API", now, now, now),
            )
            row = row_dict(conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (cursor.lastrowid,)).fetchone()) or {}
        _record_request_audit(current, request, "analysis_queued", "analysis_job", row.get("id"), {"evidence_id": payload.evidence_id, "adapter": adapter.name})
        return _analysis_job_dict(row)

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
        return [_analysis_job_dict(row_dict(row) or {}) for row in rows]

    @app.get("/api/analysis-jobs/{job_id}", response_model=AnalysisJobOut)
    def get_analysis_job(job_id: int, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone())
        if row is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="analysis job not found")
        return _analysis_job_dict(row)

    @app.post("/api/analysis-jobs/{job_id}/cancel", response_model=AnalysisJobOut)
    def cancel_analysis_job(job_id: int, request: Request, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        now = utc_now()
        with connection(current) as conn:
            row = row_dict(conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone())
            if row is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="analysis job not found")
            if row["status"] in {"succeeded", "failed"}:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="analysis job is already finished")
            previous_log = str(row.get("log") or "")
            log = (previous_log + ("\n" if previous_log else "") + "Cancellation requested by API")[:20_000]
            conn.execute("UPDATE analysis_jobs SET cancel_requested = 1, log = ?, updated_at = ? WHERE id = ?", (log, now, job_id))
            updated = row_dict(conn.execute("SELECT * FROM analysis_jobs WHERE id = ?", (job_id,)).fetchone()) or {}
        _record_request_audit(current, request, "analysis_cancel_requested", "analysis_job", job_id, {})
        return _analysis_job_dict(updated)

    @app.post("/api/evidence/{evidence_id}/ioc-extraction", response_model=AnalysisJobOut, status_code=status.HTTP_201_CREATED)
    def queue_ioc_extraction(evidence_id: int, request: Request, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        row = _queue_adapter_job(current, evidence_id, "ioc-extract")
        _record_request_audit(current, request, "analysis_queued", "analysis_job", row.get("id"), {"evidence_id": evidence_id, "adapter": "ioc-extract"})
        return _analysis_job_dict(row)

    @app.post("/api/evidence/{evidence_id}/evtx-analysis", response_model=AnalysisJobOut, status_code=status.HTTP_201_CREATED)
    def queue_evtx_analysis(evidence_id: int, request: Request, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        row = _queue_adapter_job(current, evidence_id, "evtx-parser")
        _record_request_audit(current, request, "analysis_queued", "analysis_job", row.get("id"), {"evidence_id": evidence_id, "adapter": "evtx-parser"})
        return _analysis_job_dict(row)

    @app.post("/api/evidence/{evidence_id}/triage", response_model=AnalysisJobOut, status_code=status.HTTP_201_CREATED)
    def queue_file_triage(evidence_id: int, request: Request, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        row = _queue_adapter_job(current, evidence_id, "file-triage")
        _record_request_audit(current, request, "analysis_queued", "analysis_job", row.get("id"), {"evidence_id": evidence_id, "adapter": "file-triage"})
        return _analysis_job_dict(row)

    @app.post("/api/evidence/{evidence_id}/yara", response_model=AnalysisJobOut, status_code=status.HTTP_201_CREATED)
    def queue_yara_scan(evidence_id: int, payload: YaraScanCreate, request: Request, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        row = _queue_adapter_job(current, evidence_id, "yara-scan", {"rules": payload.rules})
        _record_request_audit(current, request, "analysis_queued", "analysis_job", row.get("id"), {"evidence_id": evidence_id, "adapter": "yara-scan"})
        return _analysis_job_dict(row)

    @app.get("/api/iocs", response_model=list[IOCOut])
    def get_iocs(case_id: int | None = Query(default=None), evidence_id: int | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> list[dict[str, Any]]:
        query = "SELECT * FROM iocs WHERE 1 = 1"
        params: list[Any] = []
        if case_id is not None:
            query += " AND case_id = ?"
            params.append(case_id)
        if evidence_id is not None:
            query += " AND evidence_id = ?"
            params.append(evidence_id)
        query += " ORDER BY id DESC LIMIT 2000"
        with connection(current) as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        result = []
        for row in rows:
            item = row_dict(row) or {}
            item["provenance"] = json_loads(item.pop("provenance_json", "{}"), {})
            result.append(item)
        return result

    @app.get("/api/attack/techniques", response_model=list[AttackTechniqueOut])
    def get_attack_techniques() -> list[dict[str, str]]:
        return list(TECHNIQUE_MAP.values())

    @app.get("/api/cases/{case_id}/attack-coverage", response_model=AttackCoverageOut)
    def attack_coverage(case_id: int, current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        _case_or_404(current, case_id)
        with connection(current) as conn:
            rows = [row_dict(row) or {} for row in conn.execute("SELECT attack_techniques_json FROM findings WHERE case_id = ? UNION ALL SELECT attack_techniques_json FROM timeline_events WHERE case_id = ?", (case_id, case_id)).fetchall()]
        for row in rows:
            row["attack_techniques"] = json_loads(row.pop("attack_techniques_json", "[]"), [])
        techniques = coverage_for_rows(rows)
        return {"case_id": case_id, "techniques": techniques, "covered_count": sum(1 for item in techniques if item["covered"]), "total_count": len(techniques), "methodology": "Coverage counts only explicit ATT&CK technique IDs recorded on findings and timeline events; no technique is inferred from evidence content."}

    @app.get("/api/cases/{case_id}/attack/stix")
    def attack_stix(case_id: int, current: Settings = Depends(lambda: _settings(app))) -> JSONResponse:
        coverage = attack_coverage(case_id, current)
        return JSONResponse(content=stix_bundle(case_id, [item for item in coverage["techniques"] if item["covered"]], utc_now()), media_type="application/stix+json")

    @app.get("/api/graph", response_model=GraphOut)
    def get_graph(case_id: int | None = Query(default=None), node_id: str | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        _check_case_reference(current, case_id)
        return _build_graph(current, case_id, node_id)

    @app.get("/api/network")
    def get_network(case_id: int | None = Query(default=None), current: Settings = Depends(lambda: _settings(app))) -> dict[str, Any]:
        graph = _build_graph(current, case_id)
        analysis_query = "SELECT j.* FROM analysis_jobs j LEFT JOIN evidence e ON e.id = j.evidence_id WHERE j.integration_id = 'tshark-pcap'"
        analysis_params: tuple[Any, ...] = ()
        if case_id is not None:
            analysis_query += " AND e.case_id = ?"
            analysis_params = (case_id,)
        analysis_query += " ORDER BY j.id DESC LIMIT 50"
        with connection(current) as conn:
            analysis_rows = conn.execute(analysis_query, analysis_params).fetchall()
        analyses = []
        for raw in analysis_rows:
            job = row_dict(raw) or {}
            parsed = json_loads(job.get("output"), {})
            analyses.append({"job_id": job.get("id"), "evidence_id": job.get("evidence_id"), "status": job.get("status"), "progress": job.get("progress", 0), "message": parsed.get("message") if isinstance(parsed, dict) else job.get("error"), "result": parsed if isinstance(parsed, dict) else {}})
        return {
            "nodes": [{"id": node["id"], "label": node["label"], "type": node["group"], "risk": "info"} for node in graph["nodes"]],
            "edges": [{"id": edge["id"], "source": edge["source"], "target": edge["target"], "label": edge["label"], "protocol": edge["relationship"]} for edge in graph["edges"]],
            "generated_at": graph["generated_at"],
            "methodology": graph["methodology"],
            "analyses": analyses,
        }

    return app


app = create_app()
