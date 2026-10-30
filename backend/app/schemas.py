"""Pydantic request and response models for the public API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class CaseCreate(APIModel):
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    status: str = Field(default="open", min_length=1, max_length=40)
    severity: str = Field(default="medium", min_length=1, max_length=20)
    assignee: str | None = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=30)

    @field_validator("title")
    @classmethod
    def title_must_not_be_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("title must not be blank")
        return value


class CaseUpdate(APIModel):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    status: str | None = Field(default=None, min_length=1, max_length=40)
    severity: str | None = Field(default=None, min_length=1, max_length=20)
    assignee: str | None = Field(default=None, max_length=200)
    tags: list[str] | None = Field(default=None, max_length=30)

    @field_validator("title", "status", "severity")
    @classmethod
    def optional_text_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("value must not be blank")
        return value


class CaseOut(APIModel):
    id: int
    case_number: str
    title: str
    description: str | None
    status: str
    severity: str
    assignee: str | None
    tags: list[str]
    created_at: str
    updated_at: str
    closed_at: str | None
    evidence_count: int = 0
    finding_count: int = 0


class EvidenceOut(APIModel):
    id: int
    name: str
    case_id: int | None
    case_number: str | None = None
    media_type: str | None
    size: int
    md5: str | None = None
    sha1: str | None = None
    sha256: str
    hash: str
    integrity_status: str
    source: str | None
    uploaded_by: str | None
    investigator_notes: str | None
    created_at: str
    updated_at: str
    metadata: dict[str, Any]
    download_url: str


class EvidencePreviewOut(APIModel):
    evidence_id: int
    kind: Literal["text", "json"]
    content: str
    truncated: bool
    size: int
    message: str


class VerificationHistoryOut(APIModel):
    id: int
    evidence_id: int
    expected_md5: str | None = None
    expected_sha1: str | None = None
    expected_hash: str
    observed_md5: str | None = None
    observed_sha1: str | None = None
    observed_hash: str | None
    result: str
    checked_at: str
    actor: str


class IntegrityOut(APIModel):
    verified: bool
    status: str
    expected_md5: str | None = None
    expected_sha1: str | None = None
    expected_hash: str | None
    observed_md5: str | None = None
    observed_sha1: str | None = None
    observed_hash: str | None
    message: str
    checked_at: str


class TimelineCreate(APIModel):
    case_id: int | None = None
    evidence_id: int | None = None
    timestamp: datetime
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    event_type: str | None = Field(default=None, max_length=100)
    source: str | None = Field(default=None, max_length=200)
    severity: str = Field(default="info", min_length=1, max_length=20)
    confidence: float | None = Field(default=None, ge=0, le=1)
    timestamp_uncertain: bool = False
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    attack_techniques: list[str] = Field(default_factory=list, max_length=20)


class TimelineOut(APIModel):
    id: int
    case_id: int | None
    evidence_id: int | None
    timestamp: str
    title: str
    description: str | None
    event_type: str | None
    source: str | None
    severity: str
    confidence: float | None = None
    timestamp_uncertain: bool
    raw_metadata: dict[str, Any]
    provenance: dict[str, Any] = Field(default_factory=dict)
    attack_techniques: list[str] = Field(default_factory=list)
    created_at: str


class TimelineImportOut(APIModel):
    imported_count: int
    event_ids: list[int]
    rejected: list[dict[str, Any]]


class FindingCreate(APIModel):
    case_id: int | None = None
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10_000)
    severity: str = Field(default="medium", min_length=1, max_length=20)
    confidence: float | None = Field(default=None, ge=0, le=1)
    source: str | None = Field(default=None, max_length=200)
    evidence_ids: list[int] = Field(default_factory=list, max_length=100)
    attack_techniques: list[str] = Field(default_factory=list, max_length=20)


class FindingOut(APIModel):
    id: int
    case_id: int | None
    title: str
    description: str | None
    severity: str
    status: str
    confidence: float | None
    source: str | None
    evidence_ids: list[int] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class ReportCreate(APIModel):
    case_id: int | None = None
    name: str | None = Field(default=None, max_length=200)
    template: Literal["executive", "technical"] = "technical"


class ReportOut(APIModel):
    id: int
    name: str
    case_id: int | None
    format: str
    status: str
    created_at: str
    size: int | None
    download_url: str | None
    error: str | None = None
    template: str = "technical"
    signer_fingerprint: str | None = None
    signature_url: str | None = None


class AuditOut(APIModel):
    id: int
    event_type: str
    entity_type: str
    entity_id: str | None
    actor: str
    user_id: int | None = None
    details: dict[str, Any]
    created_at: str
    prev_hash: str
    entry_hash: str


class AuditChainVerifyOut(APIModel):
    ok: bool
    checked_entries: int
    broken_entry_id: int | None = None
    reason: str | None = None


class CustodyCreate(APIModel):
    from_party: str = Field(min_length=1, max_length=200)
    to_party: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=10_000)
    timestamp: datetime | None = None


class CustodyOut(APIModel):
    id: int
    evidence_id: int
    from_party: str
    to_party: str
    reason: str
    event_timestamp: str
    hash_at_handoff: str
    actor: str
    user_id: int | None = None
    created_at: str


class IntegrityAlertOut(APIModel):
    id: int
    evidence_id: int
    alert_type: str
    message: str
    expected_hash: str | None
    observed_hash: str | None
    status: str
    created_at: str
    resolved_at: str | None


class AuthCredentials(APIModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=128)


class UserCreate(AuthCredentials):
    role: Literal["admin", "analyst", "reviewer"] = "analyst"


class UserOut(APIModel):
    id: int
    username: str
    role: Literal["admin", "analyst", "reviewer"]
    created_at: str
    disabled: bool = False


class AuthSessionOut(APIModel):
    token: str
    expires_at: str
    user: UserOut


class AuthStatusOut(APIModel):
    initialized: bool


class IntegrationAction(APIModel):
    action: Literal["version", "probe"] = "version"
    evidence_id: int | None = None


class IntegrationOut(APIModel):
    id: str
    name: str
    kind: str
    description: str
    available: bool
    configured: bool
    version: str | None
    message: str
    last_checked_at: str


class IntegrationActionOut(APIModel):
    integration_id: str
    action: str
    available: bool
    exit_code: int | None
    output: str
    error: str | None
    checked_at: str


class NetworkAnalysisOut(APIModel):
    evidence_id: int
    job_id: int | None = None
    available: bool
    status: str
    tool_version: str | None
    packet_count: int
    protocols: dict[str, int]
    endpoints: list[str]
    dns_queries: list[str]
    flows: list[dict[str, Any]] = Field(default_factory=list)
    http_hosts: list[str] = Field(default_factory=list)
    tls_sni: list[str] = Field(default_factory=list)
    top_talkers: list[dict[str, Any]] = Field(default_factory=list)
    sample_packets: list[dict[str, Any]]
    message: str
    analyzed_at: str


class AnalysisJobOut(APIModel):
    id: int
    evidence_id: int | None
    integration_id: str
    action: str
    arguments: list[str] | dict[str, Any]
    tool_version: str | None
    status: str
    output: str
    error: str | None
    progress: int = 0
    log: str = ""
    cancel_requested: bool = False
    created_at: str | None = None
    updated_at: str | None = None
    started_at: str
    finished_at: str | None


class AnalysisJobCreate(APIModel):
    evidence_id: int
    adapter: str = Field(default="tshark-pcap", min_length=1, max_length=100)
    action: Literal["analyze"] = "analyze"
    options: dict[str, Any] = Field(default_factory=dict)


class NoteCreate(APIModel):
    case_id: int | None = None
    target_type: Literal["evidence", "timeline", "case"]
    target_id: int
    offset: int | None = Field(default=None, ge=0)
    title: str = Field(min_length=1, max_length=200)
    markdown: str = Field(min_length=1, max_length=50_000)
    pinned: bool = False


class NoteOut(APIModel):
    id: int
    case_id: int | None
    target_type: str
    target_id: int
    offset: int | None
    title: str
    markdown: str
    pinned: bool
    author_id: int | None
    created_at: str
    updated_at: str


class SearchResultOut(APIModel):
    record_type: str
    record_id: int
    case_id: int | None
    title: str
    body: str
    source: str | None
    snippet: str


class HexViewOut(APIModel):
    evidence_id: int
    offset: int
    length: int
    total_size: int
    hex_lines: list[str]
    strings: list[str]
    next_offset: int | None


class YaraScanCreate(APIModel):
    rules: str = Field(min_length=1, max_length=100_000)


class IOCOut(APIModel):
    id: int
    case_id: int | None
    evidence_id: int | None
    ioc_type: str
    value: str
    defanged_value: str
    confidence: float
    source_record: str | None
    parser: str
    parser_version: str
    observed_at: str
    provenance: dict[str, Any]
    created_at: str


class AttackTechniqueOut(APIModel):
    id: str
    name: str
    tactic: str
    description: str


class AttackCoverageOut(APIModel):
    case_id: int
    techniques: list[dict[str, Any]]
    covered_count: int
    total_count: int
    methodology: str


class HealthOut(APIModel):
    status: str
    version: str
    services: dict[str, str]


class GraphNode(APIModel):
    id: str
    label: str
    group: str
    value: int = 1
    entity_type: str
    entity_id: int | None = None
    provenance: dict[str, Any]


class GraphEdge(APIModel):
    id: str
    source: str
    target: str
    label: str
    relationship: str
    provenance: dict[str, Any]


class GraphOut(APIModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    generated_at: str
    methodology: str
