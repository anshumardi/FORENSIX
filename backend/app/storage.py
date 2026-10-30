"""Private evidence storage with streaming writes and path validation."""

from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path

from fastapi import HTTPException, UploadFile, status

from .config import Settings
from .database import ensure_within_directory


CHUNK_SIZE = 1024 * 1024
PREVIEW_LIMIT = 512 * 1024
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def safe_original_name(filename: str | None) -> str:
    if not filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="an evidence filename is required")
    if "\x00" in filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="filename contains an invalid character")
    # Reject client-supplied paths rather than silently normalizing them. This makes
    # acquisition mistakes visible and keeps path traversal attempts auditable.
    if "/" in filename or "\\" in filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="path separators are not allowed in evidence filenames")
    basename = filename.strip()
    if not basename or basename in {".", ".."}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="filename is invalid")
    cleaned = _SAFE_NAME.sub("_", basename).strip(".")
    if not cleaned:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="filename is invalid")
    return cleaned[:255]


def managed_file(settings: Settings, stored_name: str) -> Path:
    if not stored_name or Path(stored_name).name != stored_name or "\x00" in stored_name:
        raise ValueError("invalid managed filename")
    return ensure_within_directory(settings.evidence_dir / stored_name, settings.evidence_dir)


def enforce_read_only_vault(settings: Settings) -> None:
    """Normalize managed evidence files to owner/group/other read-only mode."""

    for path in settings.evidence_dir.iterdir():
        if path.is_file():
            path.chmod(0o444)


async def save_upload(settings: Settings, upload: UploadFile) -> tuple[str, str, int, dict[str, str]]:
    """Stream an upload into a generated read-only name and return all content hashes."""

    original_name = safe_original_name(upload.filename)
    stored_name = f"{uuid.uuid4().hex}-{original_name}"
    destination = managed_file(settings, stored_name)
    digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    size = 0
    try:
        with destination.open("xb") as output:
            while True:
                chunk = await upload.read(CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > settings.max_upload_size_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail=f"evidence exceeds the {settings.max_upload_size_bytes} byte upload limit",
                    )
                for digest in digests.values():
                    digest.update(chunk)
                output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()
    destination.chmod(0o444)
    return original_name, stored_name, size, {name: digest.hexdigest() for name, digest in digests.items()}


def hash_file(path: Path) -> tuple[int, dict[str, str]]:
    digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_SIZE):
            size += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
    return size, {name: digest.hexdigest() for name, digest in digests.items()}


def sha256_file(path: Path) -> tuple[int, str]:
    """Backward-compatible SHA-256 helper for existing callers."""

    size, digests = hash_file(path)
    return size, digests["sha256"]


def safe_preview(path: Path, original_name: str, media_type: str | None) -> tuple[str, str, bool, int]:
    """Return a bounded, non-executable text/JSON preview.

    Preview eligibility is intentionally conservative. HTML, scripts, binaries, and
    unknown extensions are never decoded or sent to the browser by this helper.
    """

    suffix = Path(original_name).suffix.lower()
    json_like = suffix == ".json" or (media_type or "").lower().split(";", 1)[0] == "application/json"
    text_like = suffix in {".txt", ".log", ".csv", ".tsv", ".ndjson"} or (media_type or "").lower().startswith("text/")
    if not (json_like or text_like):
        raise ValueError("only text and JSON evidence can be previewed")
    if not path.is_file():
        raise FileNotFoundError(path)
    total_size = path.stat().st_size
    with path.open("rb") as source:
        raw = source.read(PREVIEW_LIMIT + 1)
    truncated = len(raw) > PREVIEW_LIMIT
    raw = raw[:PREVIEW_LIMIT]
    if b"\x00" in raw:
        raise ValueError("binary content is not previewable")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("evidence is not valid UTF-8 text") from exc
    if json_like:
        kind = "json"
        # Validate JSON without executing or evaluating any content. Keep the original
        # text so analysts can inspect the exact bounded bytes they acquired.
        import json

        json.loads(content)
    else:
        kind = "text"
    return kind, content, truncated, total_size
