"""Append-only audit event recording."""

from __future__ import annotations

from typing import Any

from .config import Settings
from .database import connection, json_dumps, json_loads, row_dict, utc_now


def record_audit(
    settings: Settings,
    event_type: str,
    entity_type: str,
    entity_id: int | str | None,
    details: dict[str, Any] | None = None,
    actor: str = "system",
) -> None:
    with connection(settings) as conn:
        conn.execute(
            """
            INSERT INTO audit_events (event_type, entity_type, entity_id, actor, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (event_type, entity_type, str(entity_id) if entity_id is not None else None, actor, json_dumps(details or {}), utc_now()),
        )


def list_audit(settings: Settings, limit: int = 200) -> list[dict[str, Any]]:
    with connection(settings) as conn:
        rows = conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    result = []
    for row in rows:
        item = row_dict(row) or {}
        item["details"] = json_loads(item.pop("details_json", None), {})
        result.append(item)
    return result
