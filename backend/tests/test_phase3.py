from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app import adapters, integrations, worker as worker_module
from app.adapters import AdapterContext, EvtxAdapter, FileTriageAdapter, YaraAdapter
from app.config import Settings


def test_tshark_parser_returns_flows_dns_http_tls_and_talkers(tmp_path: Path, monkeypatch):
    capture = tmp_path / "sample.pcap"
    capture.write_bytes(b"synthetic")
    packet_line = "\t".join(["1700000000.1", "TCP", "10.0.0.1", "1234", "", "10.0.0.2", "443", "", "", "", "portal.example", "120"])
    monkeypatch.setattr(integrations, "_configured_binary", lambda tool: "/usr/bin/tshark")

    def fake_run(binary, arguments, timeout):
        if arguments == ["--version"]:
            return SimpleNamespace(returncode=0, stdout="TShark 4.6", stderr="")
        return SimpleNamespace(returncode=0, stdout=packet_line, stderr="")

    monkeypatch.setattr(integrations, "_run", fake_run)
    result = integrations.analyze_pcap(Settings(tmp_path, tmp_path / "db", tmp_path / "evidence", tmp_path / "reports"), capture)
    assert result["flows"][0]["source"] == "10.0.0.1"
    assert result["tls_sni"] == ["portal.example"]
    assert result["top_talkers"][0]["address"] == "10.0.0.1"


def test_ioc_extraction_worker_persists_provenance(client: TestClient, app_settings: Settings, monkeypatch):
    monkeypatch.setattr(adapters, "ADAPTERS", (adapters.IOCExtractionAdapter(),))
    content = b"a@b.co http://x.co 192.0.2.10 0123456789abcdef0123456789abcdef"
    uploaded = client.post("/api/evidence", files={"file": ("ioc.txt", content, "text/plain")})
    job = client.post("/api/analysis-jobs", json={"evidence_id": uploaded.json()["id"], "adapter": "ioc-extract"})
    assert job.status_code == 201
    worker_module.run_worker(app_settings, once=True)
    iocs = client.get(f"/api/iocs?evidence_id={uploaded.json()['id']}")
    assert iocs.status_code == 200
    body = iocs.json()
    assert any(item["ioc_type"] == "email" and item["defanged_value"] == "a[at]b[.]co" for item in body)
    assert all(item["provenance"]["source_evidence_id"] == uploaded.json()["id"] for item in body)


def test_triage_and_yara_adapters_are_read_only_and_bounded(client: TestClient, app_settings: Settings, monkeypatch):
    monkeypatch.setattr(adapters, "ADAPTERS", (FileTriageAdapter(), YaraAdapter()))
    uploaded = client.post("/api/evidence", files={"file": ("fixture.bin", b"MZ synthetic marker SECRET", "application/octet-stream")})
    evidence_id = uploaded.json()["id"]
    triage = client.post("/api/analysis-jobs", json={"evidence_id": evidence_id, "adapter": "file-triage"})
    yara = client.post("/api/analysis-jobs", json={"evidence_id": evidence_id, "adapter": "yara-scan", "options": {"rules": 'rule Secret { strings: $s = "SECRET" condition: $s }'}})
    assert triage.status_code == 201 and yara.status_code == 201
    worker_module.run_worker(app_settings, once=True)
    worker_module.run_worker(app_settings, once=True)
    jobs = client.get(f"/api/analysis-jobs?evidence_id={evidence_id}").json()
    by_adapter = {job["integration_id"]: job for job in jobs}
    assert json.loads(by_adapter["file-triage"]["output"])["triage"]["magic"] == "PE/Windows"
    assert json.loads(by_adapter["yara-scan"]["output"])["matches"][0]["rule"] == "Secret"


def test_attack_tags_coverage_and_stix_export(client: TestClient):
    case = client.post("/api/cases", json={"title": "ATT&CK synthetic case"}).json()
    finding = client.post("/api/findings", json={"case_id": case["id"], "title": "Explicit command execution", "attack_techniques": ["T1059"]})
    assert finding.status_code == 201
    assert finding.json()["attack_techniques"] == ["T1059"]
    coverage = client.get(f"/api/cases/{case['id']}/attack-coverage")
    assert coverage.status_code == 200
    assert coverage.json()["covered_count"] >= 1
    stix = client.get(f"/api/cases/{case['id']}/attack/stix")
    assert stix.status_code == 200
    assert stix.headers["content-type"].startswith("application/stix+json")
    assert stix.json()["type"] == "bundle"
