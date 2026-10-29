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
    expected_hash: str
    observed_hash: str | None
    result: str
    checked_at: str
    actor: str


class IntegrityOut(APIModel):
    verified: bool
    status: str
    expected_hash: str | None
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
    timestamp_uncertain: bool = False
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


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
    timestamp_uncertain: bool
    raw_metadata: dict[str, Any]
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
    created_at: str
    updated_at: str


class ReportCreate(APIModel):
    case_id: int | None = None
    name: str | None = Field(default=None, max_length=200)


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


class AuditOut(APIModel):
    id: int
    event_type: str
    entity_type: str
    entity_id: str | None
    actor: str
    details: dict[str, Any]
    created_at: str


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
    available: bool
    status: str
    tool_version: str | None
    packet_count: int
    protocols: dict[str, int]
    endpoints: list[str]
    dns_queries: list[str]
    sample_packets: list[dict[str, Any]]
    message: str
    analyzed_at: str


class AnalysisJobOut(APIModel):
    id: int
    evidence_id: int | None
    integration_id: str
    action: str
    arguments: list[str]
    tool_version: str | None
    status: str
    output: str
    error: str | None
    started_at: str
    finished_at: str | None


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
