"""Small local MITRE ATT&CK technique catalogue used for analyst tagging."""

from __future__ import annotations

import uuid
from typing import Any

TECHNIQUES: tuple[dict[str, str], ...] = (
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Use of command and scripting interpreters."},
    {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "description": "PowerShell command and script execution."},
    {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control", "description": "Application-layer communication over web protocols."},
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "description": "Phishing messages or attachments used for access."},
    {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "tactic": "Persistence", "description": "Persistence through startup locations."},
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access", "description": "Attempt to obtain operating system credentials."},
    {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery", "description": "Discovery of network connections and configuration."},
    {"id": "T1204", "name": "User Execution", "tactic": "Execution", "description": "User action enables execution of malicious content."},
)

TECHNIQUE_MAP = {item["id"]: item for item in TECHNIQUES}


def normalize_techniques(values: list[str]) -> list[str]:
    return sorted({value.strip().upper() for value in values if value.strip() and (value.strip().upper() in TECHNIQUE_MAP or value.strip().upper().startswith("T"))})[:20]


def coverage_for_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for row in rows:
        for technique in row.get("attack_techniques", []):
            counts[technique] = counts.get(technique, 0) + 1
    result = []
    for technique_id, definition in TECHNIQUE_MAP.items():
        result.append({**definition, "count": counts.get(technique_id, 0), "covered": counts.get(technique_id, 0) > 0})
    return result


def stix_bundle(case_id: int, techniques: list[dict[str, Any]], generated_at: str) -> dict[str, Any]:
    objects = []
    for item in techniques:
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, 'forensix:' + item['id'])}",
            "created": generated_at,
            "modified": generated_at,
            "name": item["name"],
            "description": item["description"],
            "external_references": [{"source_name": "mitre-attack", "external_id": item["id"]}],
            "x_forensix_case_id": case_id,
            "x_forensix_provenance": {"source": "local static ATT&CK catalogue", "timestamp": generated_at},
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
