"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """Paths and operational limits for one FORENSIX installation."""

    base_dir: Path
    database_path: Path
    evidence_dir: Path
    reports_dir: Path
    max_upload_size_bytes: int = 100 * 1024 * 1024
    seed_demo: bool = True
    cors_origins: tuple[str, ...] = ("http://localhost:3000", "http://127.0.0.1:3000")
    command_timeout_seconds: int = 20

    @classmethod
    def from_env(cls) -> "Settings":
        package_root = Path(__file__).resolve().parents[1]
        configured_base = os.getenv("FORENSIX_DATA_DIR")
        base_dir = Path(configured_base).expanduser().resolve() if configured_base else package_root / "data"
        database_path = Path(os.getenv("FORENSIX_DATABASE", str(base_dir / "forensix.sqlite3"))).expanduser().resolve()
        evidence_dir = Path(os.getenv("FORENSIX_EVIDENCE_DIR", str(base_dir / "evidence"))).expanduser().resolve()
        reports_dir = Path(os.getenv("FORENSIX_REPORTS_DIR", str(base_dir / "reports"))).expanduser().resolve()
        origins = tuple(
            origin.strip()
            for origin in os.getenv(
                "FORENSIX_CORS_ORIGINS",
                "http://localhost:3000,http://127.0.0.1:3000",
            ).split(",")
            if origin.strip()
        )
        return cls(
            base_dir=base_dir,
            database_path=database_path,
            evidence_dir=evidence_dir,
            reports_dir=reports_dir,
            max_upload_size_bytes=max(1, int(os.getenv("FORENSIX_MAX_UPLOAD_BYTES", str(100 * 1024 * 1024)))),
            seed_demo=_env_bool("FORENSIX_SEED_DEMO", True),
            cors_origins=origins,
            command_timeout_seconds=max(1, int(os.getenv("FORENSIX_COMMAND_TIMEOUT_SECONDS", "20"))),
        )

    def ensure_directories(self) -> None:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
