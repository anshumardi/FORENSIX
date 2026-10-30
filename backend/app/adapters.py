"""Registered, bounded analysis adapters used by the background worker."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from .config import Settings
from .integrations import analyze_pcap


class AnalysisAdapter(Protocol):
    name: str
    version: str
    supported_types: tuple[str, ...]

    def run(self, context: "AdapterContext") -> dict[str, Any]:
        """Read one managed evidence file and return bounded derived output."""


@dataclass
class AdapterContext:
    settings: Settings
    job_id: int
    evidence_id: int
    evidence_path: Path
    original_name: str
    media_type: str | None
    arguments: dict[str, Any]
    progress: Callable[[int, str], None]
    cancelled: Callable[[], bool]


@dataclass(frozen=True)
class TsharkPcapAdapter:
    name: str = "tshark-pcap"
    version: str = "1"
    supported_types: tuple[str, ...] = (".pcap", ".pcapng", ".cap")

    def run(self, context: AdapterContext) -> dict[str, Any]:
        if context.cancelled():
            return {"status": "cancelled", "message": "job cancellation was requested before analysis"}
        context.progress(15, "Starting bounded TShark metadata extraction")
        result = analyze_pcap(context.settings, context.evidence_path)
        context.progress(95, "TShark metadata extraction finished")
        result["provenance"] = _provenance(context, self.name, result.get("tool_version") or self.version)
        return result


def _provenance(context: AdapterContext, parser: str, version: str) -> dict[str, Any]:
    return {"source_evidence_id": context.evidence_id, "parser": parser, "parser_version": version, "timestamp": datetime.now(timezone.utc).isoformat()}


def _defang(value: str, ioc_type: str) -> str:
    if ioc_type == "url":
        value = re.sub(r"^https?://", lambda match: match.group(0).replace("http", "hxxp"), value, flags=re.IGNORECASE)
    if ioc_type in {"url", "domain", "ipv4", "ipv6", "email"}:
        value = value.replace(".", "[.]")
    if ioc_type == "email":
        value = value.replace("@", "[at]")
    return value


def _extract_iocs(text: str) -> list[dict[str, Any]]:
    patterns = {
        "url": re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE),
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"),
        "ipv4": re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
        "ipv6": re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![\w:])"),
        "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
        "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
        "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
        "domain": re.compile(r"\b(?=.{1,253}\b)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b"),
    }
    found: dict[tuple[str, str], dict[str, Any]] = {}
    for ioc_type, pattern in patterns.items():
        for match in pattern.finditer(text):
            value = match.group(0).rstrip(".,;:)")
            if ioc_type == "domain" and re.fullmatch(patterns["ipv4"], value):
                continue
            found[(ioc_type, value.lower() if ioc_type in {"domain", "email", "url"} else value)] = {
                "ioc_type": ioc_type,
                "value": value,
                "defanged_value": _defang(value, ioc_type),
                "confidence": 0.8 if ioc_type in {"ipv4", "ipv6", "hash", "md5", "sha1", "sha256"} else 0.65,
                "source_record": "bounded text extraction",
            }
    return list(found.values())[:2_000]


@dataclass(frozen=True)
class IOCExtractionAdapter:
    name: str = "ioc-extract"
    version: str = "1"
    supported_types: tuple[str, ...] = ("*",)

    def run(self, context: AdapterContext) -> dict[str, Any]:
        context.progress(10, "Reading bounded source for IOC extraction")
        raw = context.evidence_path.read_bytes()[:5 * 1024 * 1024]
        text = raw.decode("utf-8", errors="replace")
        if Path(context.original_name).suffix.lower() in {".pcap", ".pcapng", ".cap"}:
            packet_result = analyze_pcap(context.settings, context.evidence_path)
            text += "\n" + json.dumps(packet_result, ensure_ascii=False)
        iocs = _extract_iocs(text)
        context.progress(95, f"Extracted {len(iocs)} bounded IOC candidates")
        return {"available": True, "status": "completed", "iocs": iocs, "provenance": _provenance(context, self.name, self.version), "message": "IOC extraction is regex-based and requires analyst validation."}


@dataclass(frozen=True)
class EvtxAdapter:
    name: str = "evtx-parser"
    version: str = "1"
    supported_types: tuple[str, ...] = (".evtx",)

    def run(self, context: AdapterContext) -> dict[str, Any]:
        try:
            from Evtx.Evtx import Evtx
        except ImportError:
            return {"available": False, "status": "unavailable", "message": "python-evtx is not installed; no EVTX records were fabricated.", "provenance": _provenance(context, self.name, self.version)}
        events: list[dict[str, Any]] = []
        provenance = _provenance(context, self.name, self.version)
        with Evtx(str(context.evidence_path)) as log:
            for index, record in enumerate(log.records()):
                if index >= 2_000 or context.cancelled():
                    break
                xml = record.xml()
                timestamp_match = re.search(r"SystemTime=['\"]([^'\"]+)", xml)
                timestamp = timestamp_match.group(1) if timestamp_match else datetime.now(timezone.utc).isoformat()
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).isoformat()
                except ValueError:
                    timestamp = datetime.now(timezone.utc).isoformat()
                events.append({"timestamp": timestamp, "title": f"EVTX event {index + 1}", "description": xml[:4_000], "event_type": "evtx", "source": context.original_name, "severity": "info", "timestamp_uncertain": timestamp_match is None, "raw_metadata": {"record_index": index}, "confidence": 0.7, "provenance": provenance})
        return {"available": True, "status": "completed", "timeline_events": events, "provenance": provenance, "message": f"Parsed {len(events)} bounded EVTX records."}


def _entropy(path: Path) -> float:
    counts = [0] * 256
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            for byte in chunk:
                counts[byte] += 1
    if not total:
        return 0.0
    return round(-sum((count / total) * math.log2(count / total) for count in counts if count), 4)


@dataclass(frozen=True)
class FileTriageAdapter:
    name: str = "file-triage"
    version: str = "1"
    supported_types: tuple[str, ...] = ("*",)

    def run(self, context: AdapterContext) -> dict[str, Any]:
        context.progress(10, "Calculating bounded file entropy")
        path = context.evidence_path
        with path.open("rb") as source:
            head = source.read(16)
            sample = head + source.read(8 * 1024 * 1024)
        strings = [match.decode("ascii", errors="ignore")[:300] for match in re.findall(rb"[ -~]{4,}", sample)[:500]]
        magic = "unknown"
        if head.startswith(b"\x7fELF"): magic = "ELF"
        elif head.startswith(b"MZ"): magic = "PE/Windows"
        elif head.startswith(b"PK\x03\x04"): magic = "ZIP/container"
        elif head.startswith(b"\xd0\xcf\x11\xe0"): magic = "OLE compound"
        elif head.startswith(b"\x0a\x0d\x0d\x0a"): magic = "PCAPNG"
        elif head[:4] in {b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"}: magic = "PCAP"
        expected = {".exe": {"PE/Windows"}, ".dll": {"PE/Windows"}, ".pcap": {"PCAP"}, ".pcapng": {"PCAPNG"}, ".zip": {"ZIP/container"}}
        suffix = Path(context.original_name).suffix.lower()
        mismatch = bool(suffix in expected and magic not in expected[suffix])
        result = {"available": True, "status": "completed", "triage": {"size": path.stat().st_size, "entropy": _entropy(path), "magic": magic, "extension": suffix or None, "magic_extension_mismatch": mismatch, "strings": strings}, "provenance": _provenance(context, self.name, self.version), "message": "Triage is read-only; strings are bounded ASCII candidates and require review."}
        context.progress(95, "File triage finished")
        return result


@dataclass(frozen=True)
class YaraAdapter:
    name: str = "yara-scan"
    version: str = "1"
    supported_types: tuple[str, ...] = ("*",)

    def run(self, context: AdapterContext) -> dict[str, Any]:
        rules_source = str(context.arguments.get("rules", ""))
        if not rules_source or len(rules_source) > 100_000:
            return {"available": False, "status": "failed", "message": "YARA rules are required and limited to 100,000 characters.", "provenance": _provenance(context, self.name, self.version)}
        try:
            import yara
        except ImportError:
            return {"available": False, "status": "unavailable", "message": "yara-python is not installed; no scan was performed.", "provenance": _provenance(context, self.name, self.version)}
        try:
            compiled = yara.compile(source=rules_source)
            matches = compiled.match(filepath=str(context.evidence_path), timeout=10)
        except Exception as exc:
            return {"available": False, "status": "failed", "message": f"YARA rules could not be compiled or applied: {exc}", "provenance": _provenance(context, self.name, self.version)}
        return {"available": True, "status": "completed", "matches": [{"rule": match.rule, "namespace": match.namespace, "tags": list(match.tags)} for match in matches[:500]], "provenance": _provenance(context, self.name, self.version), "message": "YARA read the evidence file; it did not execute evidence content."}


ADAPTERS: tuple[AnalysisAdapter, ...] = (TsharkPcapAdapter(), IOCExtractionAdapter(), EvtxAdapter(), FileTriageAdapter(), YaraAdapter())


def list_adapters() -> list[dict[str, Any]]:
    return [{"name": adapter.name, "version": adapter.version, "supported_types": list(adapter.supported_types)} for adapter in ADAPTERS]


def get_adapter(name: str) -> AnalysisAdapter:
    for adapter in ADAPTERS:
        if adapter.name == name:
            return adapter
    raise KeyError(name)


def adapter_supports(adapter: AnalysisAdapter, original_name: str, media_type: str | None) -> bool:
    suffix = Path(original_name).suffix.lower()
    media = (media_type or "").lower()
    return "*" in adapter.supported_types or suffix in adapter.supported_types or any(token.lstrip(".") in media for token in adapter.supported_types)
