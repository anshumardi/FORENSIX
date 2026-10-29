"""Optional forensic tool discovery and constrained subprocess actions."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Settings
from .database import utc_now


@dataclass(frozen=True)
class ToolDefinition:
    id: str
    name: str
    kind: str
    description: str
    env_name: str
    candidates: tuple[str, ...]


TOOLS = (
    ToolDefinition("tshark", "TShark", "packet_analysis", "Optional packet capture inspection", "FORENSIX_TSHARK_BIN", ("tshark",)),
    ToolDefinition(
        "sleuthkit",
        "The Sleuth Kit",
        "disk_forensics",
        "Optional disk image and filesystem tooling",
        "FORENSIX_SLEUTHKIT_BIN",
        ("mmls", "fls"),
    ),
    ToolDefinition(
        "volatility3",
        "Volatility 3",
        "memory_forensics",
        "Optional memory image analysis",
        "FORENSIX_VOLATILITY_BIN",
        ("vol", "vol.py"),
    ),
)


def _configured_binary(tool: ToolDefinition) -> str | None:
    configured = os.getenv(tool.env_name)
    if configured:
        path = Path(configured).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        return None
    for candidate in tool.candidates:
        located = shutil.which(candidate)
        if located:
            return located
    return None


def _definition(integration_id: str) -> ToolDefinition:
    for tool in TOOLS:
        if tool.id == integration_id:
            return tool
    raise KeyError(integration_id)


def integration_status(integration_id: str) -> dict[str, object]:
    tool = _definition(integration_id)
    binary = _configured_binary(tool)
    if binary is None:
        configured = bool(os.getenv(tool.env_name))
        message = f"{tool.name} is not available; install it or set {tool.env_name}"
        return {
            "id": tool.id,
            "name": tool.name,
            "kind": tool.kind,
            "description": tool.description,
            "available": False,
            "configured": configured,
            "version": None,
            "message": message,
            "last_checked_at": utc_now(),
        }
    result = _run(binary, ["--version"], 20)
    output = (result.stdout or result.stderr).strip().splitlines()
    return {
        "id": tool.id,
        "name": tool.name,
        "kind": tool.kind,
        "description": tool.description,
        "available": result.returncode == 0,
        "configured": True,
        "version": output[0][:300] if output else None,
        "message": "available" if result.returncode == 0 else (result.stderr.strip()[:500] or "version check failed"),
        "last_checked_at": utc_now(),
    }


def _run(binary: str, arguments: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    # The command and every argument are selected by this module; shell execution is never used.
    try:
        return subprocess.run(
            [binary, *arguments],
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        message = str(exc)
        return subprocess.CompletedProcess([binary, *arguments], 1, "", message)


def run_action(
    settings: Settings,
    integration_id: str,
    action: str,
    evidence_path: Path | None = None,
) -> dict[str, object]:
    tool = _definition(integration_id)
    binary = _configured_binary(tool)
    checked_at = utc_now()
    if binary is None:
        return {
            "integration_id": integration_id,
            "action": action,
            "available": False,
            "exit_code": None,
            "output": "",
            "error": f"{tool.name} is unavailable",
            "checked_at": checked_at,
        }
    if action == "version":
        arguments = ["--version"]
    elif action == "probe" and evidence_path is not None:
        # These probes are deliberately fixed and bounded; callers cannot provide arbitrary flags.
        arguments = {
            "tshark": ["-r", str(evidence_path), "-c", "1"],
            "sleuthkit": ["-i", str(evidence_path)],
            "volatility3": ["-f", str(evidence_path), "windows.info"],
        }[integration_id]
    else:
        return {
            "integration_id": integration_id,
            "action": action,
            "available": False,
            "exit_code": None,
            "output": "",
            "error": "probe requires an evidence item",
            "checked_at": checked_at,
        }
    result = _run(binary, arguments, settings.command_timeout_seconds)
    output = (result.stdout or "").strip()
    error = (result.stderr or "").strip() or None
    return {
        "integration_id": integration_id,
        "action": action,
        "available": result.returncode == 0,
        "exit_code": result.returncode,
        "output": output[:20_000],
        "error": error[:2_000] if error else None,
        "checked_at": checked_at,
    }


def analyze_pcap(settings: Settings, evidence_path: Path) -> dict[str, Any]:
    """Extract bounded packet metadata with TShark when it is installed.

    This intentionally asks TShark for fields only. It does not decrypt traffic,
    recover application content, or make attribution claims.
    """

    tool = _definition("tshark")
    binary = _configured_binary(tool)
    checked_at = utc_now()
    if binary is None:
        return {
            "available": False,
            "status": "unavailable",
            "tool_version": None,
            "packet_count": 0,
            "protocols": {},
            "endpoints": [],
            "dns_queries": [],
            "sample_packets": [],
            "message": "TShark is unavailable; install tshark or set FORENSIX_TSHARK_BIN.",
            "analyzed_at": checked_at,
        }
    version_result = _run(binary, ["--version"], settings.command_timeout_seconds)
    version_line = ((version_result.stdout or version_result.stderr).strip().splitlines() or [None])[0]
    arguments = [
        "-r",
        str(evidence_path),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
        "-e",
        "frame.time_epoch",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "udp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.dstport",
        "-e",
        "dns.qry.name",
        "-c",
        "1000",
        "-q",
    ]
    result = _run(binary, arguments, settings.command_timeout_seconds)
    if result.returncode != 0:
        return {
            "available": False,
            "status": "failed",
            "tool_version": version_line[:300] if version_line else None,
            "packet_count": 0,
            "protocols": {},
            "endpoints": [],
            "dns_queries": [],
            "sample_packets": [],
            "message": (result.stderr or "TShark could not read this capture")[:2_000],
            "analyzed_at": checked_at,
        }
    protocols: Counter[str] = Counter()
    endpoints: set[str] = set()
    dns_queries: set[str] = set()
    packets: list[dict[str, str | None]] = []
    for raw_line in (result.stdout or "").splitlines()[:1000]:
        fields = raw_line.split("\t")
        fields += [""] * (9 - len(fields))
        timestamp, protocol, source, tcp_source, udp_source, destination, tcp_destination, udp_destination, dns_name = fields[:9]
        protocol = protocol or "unknown"
        protocols[protocol] += 1
        if source:
            endpoints.add(source)
        if destination:
            endpoints.add(destination)
        if dns_name:
            dns_queries.add(dns_name)
        if len(packets) < 25:
            packets.append(
                {
                    "timestamp": timestamp or None,
                    "protocol": protocol,
                    "source": source or None,
                    "source_port": tcp_source or udp_source or None,
                    "destination": destination or None,
                    "destination_port": tcp_destination or udp_destination or None,
                    "dns_query": dns_name or None,
                }
            )
    return {
        "available": True,
        "status": "completed",
        "tool_version": version_line[:300] if version_line else None,
        "packet_count": sum(protocols.values()),
        "protocols": dict(protocols),
        "endpoints": sorted(endpoints)[:200],
        "dns_queries": sorted(dns_queries)[:200],
        "sample_packets": packets,
        "message": "Metadata extracted from up to 1,000 packets; encrypted payloads were not decrypted.",
        "analyzed_at": checked_at,
    }
