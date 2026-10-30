"""Local password authentication and role/session helpers."""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt

from .config import Settings
from .database import connection, row_dict, utc_now

ROLES = {"admin", "analyst", "reviewer"}
SESSION_HOURS = 12


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def public_user(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
        "disabled": bool(row.get("disabled", 0)),
    }


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(settings: Settings, user_id: int) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    created_at = utc_now()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat()
    with connection(settings) as conn:
        conn.execute(
            "INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (user_id, _token_hash(token), created_at, expires_at),
        )
    return token, expires_at


def user_from_token(settings: Settings, token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    with connection(settings) as conn:
        row = row_dict(
            conn.execute(
                """
                SELECT u.* FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND u.disabled = 0 AND u.is_system = 0
                """,
                (_token_hash(token), utc_now()),
            ).fetchone()
        )
    return row


def revoke_token(settings: Settings, token: str | None) -> None:
    if not token:
        return
    with connection(settings) as conn:
        conn.execute("UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL", (utc_now(), _token_hash(token)))


def non_system_user_count(settings: Settings) -> int:
    with connection(settings) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM users WHERE is_system = 0").fetchone()[0])


def find_user(settings: Settings, username: str) -> dict[str, Any] | None:
    with connection(settings) as conn:
        return row_dict(conn.execute("SELECT * FROM users WHERE username = ? AND is_system = 0", (username,)).fetchone())


def create_user(settings: Settings, username: str, password: str, role: str) -> dict[str, Any]:
    if role not in ROLES:
        raise ValueError("role must be admin, analyst, or reviewer")
    now = utc_now()
    with connection(settings) as conn:
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, role, is_system, disabled, created_at) VALUES (?, ?, ?, 0, 0, ?)",
            (username, hash_password(password), role, now),
        )
        row = row_dict(conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone())
    return row or {}


def list_users(settings: Settings) -> list[dict[str, Any]]:
    with connection(settings) as conn:
        rows = conn.execute("SELECT * FROM users WHERE is_system = 0 ORDER BY id").fetchall()
    return [public_user(row_dict(row) or {}) for row in rows]
