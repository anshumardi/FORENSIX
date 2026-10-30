"""Append-only audit event recording."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .config import Settings
from .database import connection, json_dumps, json_loads, row_dict, utc_now


def canonical_audit_payload(
    event_type: str,
    entity_type: str,
    entity_id: str | None,
    actor: str,
    user_id: int,
    details: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    return {
        "actor": actor,
        "created_at": created_at,
        "details": details,
        "entity_id": entity_id,
        "entity_type": entity_type,
        "event_type": event_type,
        "user_id": user_id,
    }


def entry_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def _row_hash(row: dict[str, Any], user_id: int) -> str:
    payload = canonical_audit_payload(
        row["event_type"],
        row["entity_type"],
        row.get("entity_id"),
        row["actor"],
        user_id,
        json_loads(row.get("details_json"), {}),
        row["created_at"],
    )
    return entry_hash(row.get("prev_hash") or "", payload)


def backfill_audit_chain(conn: Any, system_id: int) -> None:
    """Backfill hashes/user IDs for databases created before chained auditing."""

    previous = ""
    rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    for raw_row in rows:
        row = row_dict(raw_row) or {}
        user_id = int(row.get("user_id") or system_id)
        current = dict(row)
        current["user_id"] = user_id
        current["prev_hash"] = previous
        current_hash = _row_hash(current, user_id)
        if not row.get("entry_hash") or not row.get("prev_hash") or row.get("user_id") is None:
            conn.execute(
                "UPDATE audit_events SET user_id = ?, prev_hash = ?, entry_hash = ? WHERE id = ?",
                (user_id, previous, current_hash, row["id"]),
            )
        else:
            current_hash = row["entry_hash"]
        previous = current_hash


def record_audit(
    settings: Settings,
    event_type: str,
    entity_type: str,
    entity_id: int | str | None,
    details: dict[str, Any] | None = None,
    actor: str = "system",
    user_id: int | None = None,
) -> None:
    with connection(settings) as conn:
        if user_id is None:
            row = conn.execute("SELECT id FROM users WHERE username = 'system' LIMIT 1").fetchone()
            user_id = int(row[0]) if row is not None else None
        if user_id is None:
            raise RuntimeError("system audit identity is unavailable")
        created_at = utc_now()
        entity_id_value = str(entity_id) if entity_id is not None else None
        details_value = details or {}
        previous = conn.execute("SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = str(previous[0]) if previous and previous[0] else ""
        payload = canonical_audit_payload(event_type, entity_type, entity_id_value, actor, user_id, details_value, created_at)
        current_hash = entry_hash(prev_hash, payload)
        conn.execute(
            """
            INSERT INTO audit_events (event_type, entity_type, entity_id, actor, user_id, details_json, created_at, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (event_type, entity_type, entity_id_value, actor, user_id, json_dumps(details_value), created_at, prev_hash, current_hash),
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


def verify_audit_chain(settings: Settings) -> dict[str, Any]:
    with connection(settings) as conn:
        rows = [row_dict(row) or {} for row in conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()]
    previous = ""
    for index, row in enumerate(rows):
        if row.get("prev_hash") != previous:
            return {
                "ok": False,
                "checked_entries": index,
                "broken_entry_id": row.get("id"),
                "reason": "previous hash does not match the preceding audit entry",
            }
        user_id = row.get("user_id")
        if user_id is None:
            return {
                "ok": False,
                "checked_entries": index,
                "broken_entry_id": row.get("id"),
                "reason": "audit entry has no bound user ID",
            }
        expected = _row_hash(row, int(user_id))
        if row.get("entry_hash") != expected:
            return {
                "ok": False,
                "checked_entries": index,
                "broken_entry_id": row.get("id"),
                "reason": "entry hash does not match the canonical audit payload",
            }
        previous = str(row["entry_hash"])
    return {"ok": True, "checked_entries": len(rows), "broken_entry_id": None, "reason": None}
