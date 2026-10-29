"""PDF report generation using ReportLab and private report storage."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

from .config import Settings
from .database import connection, ensure_within_directory, row_dict, utc_now
from .integrations import TOOLS, integration_status


def _report_path(settings: Settings, stored_name: str) -> Path:
    if Path(stored_name).name != stored_name or not stored_name:
        raise ValueError("invalid report filename")
    return ensure_within_directory(settings.reports_dir / stored_name, settings.reports_dir)


def _write_pdf(
    settings: Settings,
    stored_name: str,
    report_id: int,
    case: dict[str, Any] | None,
    evidence: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    audits: list[dict[str, Any]],
    tools: list[dict[str, Any]],
) -> int:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfbase.pdfmetrics import stringWidth
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise RuntimeError("ReportLab is required to generate PDF reports") from exc

    path = _report_path(settings, stored_name)
    pdf = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    y = height - 54

    def line(text: str, size: int = 10, bold: bool = False) -> None:
        nonlocal y
        if y < 54:
            pdf.showPage()
            y = height - 54
        font_name = "Helvetica-Bold" if bold else "Helvetica"
        pdf.setFont(font_name, size)
        # Keep generated documents readable even when user text is long.
        remaining = text
        while remaining:
            max_chars = max(20, int(width / max(stringWidth("M", font_name, size), 1)))
            segment, remaining = remaining[:max_chars], remaining[max_chars:]
            pdf.drawString(48, y, segment)
            y -= size + 5
            if remaining and y < 54:
                pdf.showPage()
                y = height - 54

    line("FORENSIX FORENSIC REPORT", 16, True)
    line(f"Report identifier: FRX-RPT-{report_id:06d}", 9)
    line(f"Generated: {utc_now()}", 9)
    if case:
        line(f"Case: {case['case_number']} — {case['title']}", 12, True)
        line(f"Status: {case['status']} | Severity: {case['severity']} | Assignee: {case.get('assignee') or 'Unassigned'}")
        line(f"Description: {case.get('description') or 'No description'}")
    else:
        line("All cases summary", 12, True)

    line("Evidence", 12, True)
    if evidence:
        for item in evidence:
            line(f"• {item['original_name']} | {item['size']} bytes | SHA-256 {item['sha256']} | {item['integrity_status']}")
    else:
        line("No evidence recorded.")

    line("Findings", 12, True)
    if findings:
        for finding in findings:
            line(f"• [{finding['severity']}] {finding['title']} (confidence: {finding.get('confidence') if finding.get('confidence') is not None else 'n/a'})")
            line(f"  {finding.get('description') or 'No description'}", 9)
    else:
        line("No findings recorded.")

    line("Timeline", 12, True)
    if timeline:
        for event in timeline:
            line(f"• {event['event_timestamp']} | {event['title']} | {event.get('source') or 'unspecified source'}")
    else:
        line("No timeline events recorded.")

    line("Analysis integrations", 12, True)
    for tool in tools:
        line(f"• {tool['name']}: {tool['version'] or 'unavailable'} — {tool['message']}")
    line("Audit trail", 12, True)
    if audits:
        for event in audits:
            line(f"• {event['created_at']} | {event['event_type']} | {event['entity_type']} {event.get('entity_id') or ''} | {event['actor']}", 9)
    else:
        line("No audit entries recorded.")

    line("Limitations and interpretation notes", 12, True)
    line("• Matching SHA-256 values support post-acquisition integrity checking; they do not independently prove authenticity or correct acquisition.", 9)
    line("• Observations, analyst interpretations, and unverified hypotheses must be distinguished during review; this report does not establish attribution.", 9)
    line("• Optional forensic tools are reported only when detected. Missing tools, unsupported formats, and encrypted content remain unresolved limitations.", 9)

    pdf.save()
    return path.stat().st_size


def create_report(settings: Settings, case_id: int | None, name: str | None) -> dict[str, Any]:
    stored_name = f"report-{uuid.uuid4().hex}.pdf"
    report_name = name or (f"{case_id}-forensic-report.pdf" if case_id else "forensix-case-summary.pdf")
    now = utc_now()
    with connection(settings) as conn:
        case = row_dict(conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()) if case_id else None
        if case_id is not None and case is None:
            raise LookupError("case not found")
        query = "SELECT * FROM evidence"
        params: tuple[Any, ...] = ()
        if case_id is not None:
            query += " WHERE case_id = ?"
            params = (case_id,)
        evidence = [row_dict(row) or {} for row in conn.execute(query, params).fetchall()]
        query = "SELECT * FROM findings"
        if case_id is not None:
            query += " WHERE case_id = ?"
        findings = [row_dict(row) or {} for row in conn.execute(query, params).fetchall()]
        query = "SELECT * FROM timeline_events"
        if case_id is not None:
            query += " WHERE case_id = ?"
        timeline = [row_dict(row) or {} for row in conn.execute(query, params).fetchall()]
        audits = [row_dict(row) or {} for row in conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 200").fetchall()]
        cursor = conn.execute(
            """
            INSERT INTO reports (case_id, name, format, status, stored_name, created_at)
            VALUES (?, ?, 'pdf', 'processing', ?, ?)
            """,
            (case_id, report_name, stored_name, now),
        )
        report_id = cursor.lastrowid

    try:
        tools = [integration_status(tool.id) for tool in TOOLS]
        size = _write_pdf(settings, stored_name, int(report_id), case, evidence, findings, timeline, audits, tools)
    except Exception as exc:
        with connection(settings) as conn:
            conn.execute("UPDATE reports SET status = 'failed', error = ? WHERE id = ?", (str(exc)[:2_000], report_id))
        _report_path(settings, stored_name).unlink(missing_ok=True)
        raise

    with connection(settings) as conn:
        row = conn.execute(
            "UPDATE reports SET status = 'ready', size = ? WHERE id = ? RETURNING *", (size, report_id)
        ).fetchone()
    return row_dict(row) or {}


def list_reports(settings: Settings, case_id: int | None = None) -> list[dict[str, Any]]:
    with connection(settings) as conn:
        if case_id is None:
            rows = conn.execute("SELECT * FROM reports ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM reports WHERE case_id = ? ORDER BY id DESC", (case_id,)).fetchall()
    return [row_dict(row) or {} for row in rows]


def report_file(settings: Settings, stored_name: str) -> Path:
    return _report_path(settings, stored_name)
