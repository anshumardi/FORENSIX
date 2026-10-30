from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.report_signing import verify_report


def test_search_notes_hex_and_graph_pivot(client: TestClient, app_settings):
    case = client.post("/api/cases", json={"title": "Searchable synthetic investigation", "description": "local FTS fixture"}).json()
    uploaded = client.post(
        "/api/evidence",
        files={"file": ("binary.bin", b"HEADER\x00secret-string\xfftail", "application/octet-stream")},
        data={"case_id": str(case["id"])},
    )
    assert uploaded.status_code == 201
    evidence_id = uploaded.json()["id"]
    note = client.post("/api/notes", json={"case_id": case["id"], "target_type": "evidence", "target_id": evidence_id, "offset": 7, "title": "Offset review", "markdown": "**Synthetic** observation"})
    assert note.status_code == 201
    assert client.get(f"/api/notes?target_type=evidence&target_id={evidence_id}").json()[0]["markdown"] == "**Synthetic** observation"

    results = client.get("/api/search?q=secret-string")
    assert results.status_code == 200
    assert any(item["record_type"] == "note" for item in client.get("/api/search?q=Offset").json())

    view = client.get(f"/api/evidence/{evidence_id}/hex?offset=0&length=32")
    assert view.status_code == 200
    assert "secret-string" in view.json()["strings"]
    assert view.json()["hex_lines"][0].startswith("00000000")

    finding = client.post("/api/findings", json={"case_id": case["id"], "title": "Pivot finding", "evidence_ids": [evidence_id]})
    assert finding.status_code == 201
    graph = client.get(f"/api/graph?case_id={case['id']}").json()
    evidence_node = next(node for node in graph["nodes"] if node["entity_type"] == "evidence")
    pivot = client.get(f"/api/graph?case_id={case['id']}&node_id={evidence_node['id']}")
    assert pivot.status_code == 200
    assert evidence_node["id"] in {node["id"] for node in pivot.json()["nodes"]}
    assert all("provenance" in edge for edge in pivot.json()["edges"])


def test_signed_report_and_template(client: TestClient, app_settings):
    case = client.post("/api/cases", json={"title": "Signed synthetic report"}).json()
    response = client.post("/api/reports", json={"case_id": case["id"], "template": "executive", "name": "signed-report.pdf"})
    assert response.status_code == 201, response.text
    report = response.json()
    assert report["template"] == "executive"
    assert report["signer_fingerprint"]
    pdf = client.get(report["download_url"])
    signature = client.get(report["signature_url"])
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert signature.status_code == 200
    report_path = app_settings.reports_dir / "signed-report-test.pdf"
    report_path.write_bytes(pdf.content)
    signature_path = app_settings.reports_dir / "signed-report-test.pdf.sig"
    signature_path.write_bytes(signature.content)
    public_key = app_settings.base_dir / "keys" / "ed25519-public.pem"
    assert verify_report(report_path, signature_path, public_key) == report["signer_fingerprint"]
