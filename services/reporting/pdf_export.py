"""PDF rendering for compliance evidence packs.

Uses ReportLab Platypus so the layout adapts to evidence size automatically
(SOC 2 packs grow with user count + detection-version count).
"""

from __future__ import annotations
import io
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# VIGIL palette mapped to ReportLab colors.
COLOR_BG = colors.HexColor("#0a0a0a")
COLOR_SURFACE = colors.HexColor("#1a1a1a")
COLOR_BORDER = colors.HexColor("#27272a")
COLOR_FG = colors.HexColor("#f4f4f5")
COLOR_FG_MUTED = colors.HexColor("#9ca3af")
COLOR_ACCENT = colors.HexColor("#dc2626")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    title = ParagraphStyle(
        "VigilTitle", parent=base["Heading1"],
        fontName="Helvetica-Bold", fontSize=20, leading=24,
        textColor=COLOR_FG, spaceBefore=0, spaceAfter=4,
    )
    subtitle = ParagraphStyle(
        "VigilSubtitle", parent=base["Heading2"],
        fontName="Helvetica", fontSize=11, leading=14,
        textColor=COLOR_FG_MUTED, spaceBefore=0, spaceAfter=12,
    )
    h2 = ParagraphStyle(
        "VigilH2", parent=base["Heading2"],
        fontName="Helvetica-Bold", fontSize=14, leading=18,
        textColor=COLOR_ACCENT, spaceBefore=18, spaceAfter=6,
    )
    body = ParagraphStyle(
        "VigilBody", parent=base["BodyText"],
        fontName="Helvetica", fontSize=10, leading=14,
        textColor=COLOR_FG, spaceBefore=0, spaceAfter=6,
    )
    label = ParagraphStyle(
        "VigilLabel", parent=base["BodyText"],
        fontName="Helvetica-Bold", fontSize=9, leading=11,
        textColor=COLOR_FG_MUTED, spaceBefore=0, spaceAfter=2,
    )
    return {
        "title": title, "subtitle": subtitle, "h2": h2,
        "body": body, "label": label,
    }


def _table_style(header_rows: int = 1) -> TableStyle:
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, header_rows - 1), COLOR_SURFACE),
        ("TEXTCOLOR", (0, 0), (-1, header_rows - 1), COLOR_FG_MUTED),
        ("FONTNAME", (0, 0), (-1, header_rows - 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, header_rows), (-1, -1), COLOR_FG),
        ("FONTNAME", (0, header_rows), (-1, -1), "Helvetica"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, COLOR_BORDER),
        ("BACKGROUND", (0, header_rows), (-1, -1), COLOR_BG),
    ])


def render_compliance_pdf(payload: dict[str, Any]) -> bytes:
    """Convert one of the compliance assembler payloads into a PDF."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        title=f"VIGIL — {payload.get('framework', 'Compliance')}",
    )
    styles = _styles()
    story: list = []

    framework = payload.get("framework", "Compliance Report")
    story.append(Paragraph(f"VIGIL — {framework}", styles["title"]))
    period_start = _fmt_date(payload.get("period_start"))
    period_end = _fmt_date(payload.get("period_end"))
    generated_at = _fmt_datetime(payload.get("generated_at"))
    tenant = payload.get("tenant_id", "—")
    story.append(Paragraph(
        f"Tenant: {tenant} &nbsp;&nbsp;|&nbsp;&nbsp; Period: {period_start} → {period_end}"
        f" &nbsp;&nbsp;|&nbsp;&nbsp; Generated: {generated_at}",
        styles["subtitle"],
    ))

    if "criteria" in payload and isinstance(payload["criteria"], list):
        for c in payload["criteria"]:
            heading = c.get("criterion") or c.get("requirement") or "Criterion"
            story.append(Paragraph(heading, styles["h2"]))
            ev = c.get("evidence")
            if isinstance(ev, list):
                story.append(_evidence_table(ev, styles))
            elif isinstance(ev, dict):
                story.append(_dict_table(ev, styles))
            else:
                story.append(Paragraph(str(ev), styles["body"]))
    elif "functions" in payload and isinstance(payload["functions"], dict):
        for fname, fbody in payload["functions"].items():
            story.append(Paragraph(fname, styles["h2"]))
            if isinstance(fbody, dict):
                story.append(_dict_table(fbody, styles))
            else:
                story.append(Paragraph(str(fbody), styles["body"]))

    doc.build(story, onFirstPage=_draw_chrome, onLaterPages=_draw_chrome)
    return buf.getvalue()


def render_executive_pdf(payload: dict[str, Any]) -> bytes:
    """Render the executive bundle (summary + trend) to PDF."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        title="VIGIL — Executive Summary",
    )
    styles = _styles()
    story: list = []

    story.append(Paragraph("VIGIL — Executive Summary", styles["title"]))
    story.append(Paragraph(
        f"Tenant: {payload.get('tenant_id', '—')} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Generated: {_fmt_datetime(payload.get('generated_at'))}",
        styles["subtitle"],
    ))

    summary = payload.get("summary") or {}
    if summary:
        story.append(Paragraph("Summary", styles["h2"]))
        rows = [
            ["Active Attacks",       str(summary.get("active_attacks", 0))],
            ["Resolved (7d)",        str(summary.get("attacks_resolved_7d", 0))],
            ["MTTR (7d)",            _fmt_seconds(summary.get("mttr_seconds_7d"))],
            ["SLA Breach Rate (7d)", _fmt_pct(summary.get("sla_breach_rate_7d"))],
            ["Coverage Score",       _fmt_pct(summary.get("coverage_score"))],
            ["Top Tactic",           summary.get("top_tactic") or "—"],
            ["Open Escalations",     str(summary.get("open_escalations", 0))],
            ["FP Rate (30d)",        _fmt_pct(summary.get("fp_rate_30d"))],
        ]
        t = Table(rows, colWidths=[2.6 * inch, 4.4 * inch])
        t.setStyle(_table_style(header_rows=0))
        story.append(t)

    trend = payload.get("trend") or {}
    if trend:
        story.append(Paragraph("Attack Volume — 30d", styles["h2"]))
        story.append(_volume_table(trend.get("attack_volume") or [], styles))

    doc.build(story, onFirstPage=_draw_chrome, onLaterPages=_draw_chrome)
    return buf.getvalue()


# ── helpers ───────────────────────────────────────────────────────────────


def _evidence_table(items: list[dict[str, Any]], styles) -> Any:
    if not items:
        return Paragraph("No evidence in this period.", styles["body"])

    keys: list[str] = []
    for it in items:
        for k in it.keys():
            if k not in keys:
                keys.append(k)

    headers = [_titleize(k) for k in keys]
    rows = [headers]
    for it in items:
        rows.append([_short(it.get(k)) for k in keys])

    avail = 7.0 * inch
    col_w = [avail / len(keys)] * len(keys)
    t = Table(rows, colWidths=col_w, repeatRows=1)
    t.setStyle(_table_style(header_rows=1))
    return t


def _dict_table(d: dict[str, Any], styles) -> Any:
    if not d:
        return Paragraph("—", styles["body"])
    rows = [[_titleize(k), _short(v)] for k, v in d.items()]
    t = Table(rows, colWidths=[2.6 * inch, 4.4 * inch])
    t.setStyle(_table_style(header_rows=0))
    return t


def _volume_table(points: list[dict[str, Any]], styles) -> Any:
    if not points:
        return Paragraph("—", styles["body"])
    nonzero = [p for p in points if (p.get("count") or 0) > 0]
    body = nonzero if nonzero else points[-7:]
    rows = [["Date", "Attacks"]]
    for p in body:
        rows.append([str(p.get("date", "—")), str(p.get("count", 0))])
    t = Table(rows, colWidths=[2.6 * inch, 1.4 * inch], repeatRows=1)
    t.setStyle(_table_style(header_rows=1))
    return t


def _draw_chrome(canvas, _doc) -> None:
    canvas.saveState()
    canvas.setFillColor(COLOR_BG)
    canvas.rect(0, 0, LETTER[0], LETTER[1], fill=1, stroke=0)
    # Footer.
    canvas.setFillColor(COLOR_FG_MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(0.6 * inch, 0.4 * inch, "VIGIL Platform — Confidential")
    canvas.drawRightString(LETTER[0] - 0.6 * inch, 0.4 * inch, f"Page {_doc.page}")
    canvas.restoreState()


def _short(value: Any, max_len: int = 60) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        import json
        s = json.dumps(value, default=str)
    else:
        s = str(value)
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def _titleize(key: str) -> str:
    return key.replace("_", " ").title()


def _fmt_date(value: Any) -> str:
    if not value:
        return "—"
    s = str(value)
    return s.split("T", 1)[0]


def _fmt_datetime(value: Any) -> str:
    if not value:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    s = str(value).replace("T", " ")
    if "." in s:
        s = s.split(".", 1)[0]
    return s.rstrip("Z").rstrip("+00:00").strip() + " UTC"


def _fmt_seconds(value: Any) -> str:
    if value is None:
        return "—"
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return "—"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def _fmt_pct(value: Any) -> str:
    if value is None:
        return "—"
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "—"
