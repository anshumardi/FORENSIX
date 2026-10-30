from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture()
def client(tmp_path: Path):
    settings = Settings(
        base_dir=tmp_path,
        database_path=tmp_path / "forensix.sqlite3",
        evidence_dir=tmp_path / "evidence",
        reports_dir=tmp_path / "reports",
        max_upload_size_bytes=64,
        seed_demo=False,
    )
    application = create_app(settings)
    with TestClient(application) as test_client:
        bootstrap = test_client.post("/api/auth/bootstrap", json={"username": "test-admin", "password": "test-password-123"})
        assert bootstrap.status_code == 201, bootstrap.text
        test_client.headers.update({"Authorization": f"Bearer {bootstrap.json()['token']}"})
        yield test_client


@pytest.fixture()
def app_settings(client: TestClient) -> Settings:
    return client.app.state.settings
