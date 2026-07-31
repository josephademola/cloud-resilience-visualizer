"""
PDF report builder.

Takes the topology, the flat findings list, and the compliance view
(the same data the frontend already receives) and produces a PDF
byte string suitable for download.

Design notes:

- Uses reportlab's Platypus API rather than Canvas. Platypus handles
  text wrapping, page breaks, and flowable layout automatically; the
  Canvas API would mean positioning every character by hand for very
  little gain in a text-heavy report.

- The PDF is print-optimised, not screen-optimised. Light background,
  dark text, generous margins, black-and-white plus a small palette
  of accent colours for severity. This is deliberate — the dashboard
  is the interactive experience, the PDF is the artefact you hand to
  an auditor or attach to an email.

- Content organisation mirrors what a compliance auditor expects:
  cover page with summary counts, executive summary of framework
  scores, per-framework detail, then a full findings appendix.

- Returns bytes, does not touch disk. The API layer decides whether
  to stream to a client, write to a file, or attach to an email —
  this module is agnostic.
"""

from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from typing import Any

from reportlab.lib.colors import HexColor, black
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# ---- Colour palette (print-optimised) --------------------------------
_NAVY = HexColor("#1A2744")
_MUTED = HexColor("#5A6B85")
_BORDER = HexColor("#D0D6DF")
_ROW_ALT = HexColor("#F5F7FA")

_SEVERITY_COLOURS = {
    "critical": HexColor("#C62828"),
    "high":     HexColor("#EF6C00"),
    "medium":   HexColor("#F9A825"),
    "low":      HexColor("#546E7A"),
}


# ---- Paragraph styles ------------------------------------------------

def _styles() -> dict[str, ParagraphStyle]:
    """Return the paragraph styles used across the report."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=28,
            leading=34,
            textColor=_NAVY,
            spaceAfter=6,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontSize=14,
            leading=18,
            textColor=_MUTED,
            spaceAfter=24,
        ),
        "h1": ParagraphStyle(
            "H1",
            parent=base["Heading1"],
            fontSize=18,
            leading=22,
            textColor=_NAVY,
            spaceBefore=12,
            spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontSize=13,
            leading=17,
            textColor=_NAVY,
            spaceBefore=10,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=10,
            leading=14,
            textColor=black,
            spaceAfter=6,
        ),
        "muted": ParagraphStyle(
            "Muted",
            parent=base["Normal"],
            fontSize=9,
            leading=12,
            textColor=_MUTED,
            spaceAfter=4,
        ),
        "monospace": ParagraphStyle(
            "Mono",
            parent=base["Normal"],
            fontName="Courier",
            fontSize=9,
            leading=12,
            textColor=black,
            spaceAfter=4,
        ),
    }


# ---- Public entry point ---------------------------------------------

def build_pdf_report(
    topology: dict[str, Any],
    findings: list,
    compliance: dict[str, Any],
) -> bytes:
    """
    Generate a full PDF report from the assessment data.

    Returns the PDF file contents as bytes. Callers decide whether
    to stream over HTTP, write to disk, or attach to email.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="Cloud Resilience Report",
        author="Cloud Resilience Visualizer",
    )
    styles = _styles()

    story: list = []
    story.extend(_cover_page(topology, findings, styles))
    story.append(PageBreak())
    story.extend(_executive_summary(compliance, findings, styles))
    story.append(PageBreak())

    for framework in compliance["frameworks"]:
        story.extend(_framework_section(framework, styles))
        story.append(PageBreak())

    story.extend(_findings_appendix(findings, styles))

    doc.build(story)
    return buffer.getvalue()


# ---- Cover page ------------------------------------------------------

def _cover_page(topology, findings, styles) -> list:
    node_count = len(topology.get("nodes", []))
    finding_count = len(findings)
    affected_resources = len({f.resource_id for f in findings})
    generated_at = datetime.now(timezone.utc).strftime("%d %B %Y at %H:%M UTC")

    return [
        Spacer(1, 4 * cm),
        Paragraph("Cloud Resilience Report", styles["title"]),
        Paragraph("Cloud Security Posture Assessment", styles["subtitle"]),
        Spacer(1, 1 * cm),
        Paragraph(f"<b>Generated:</b> {generated_at}", styles["body"]),
        Paragraph(f"<b>Resources scanned:</b> {node_count}", styles["body"]),
        Paragraph(f"<b>Findings identified:</b> {finding_count}", styles["body"]),
        Paragraph(
            f"<b>Affected resources:</b> {affected_resources}",
            styles["body"],
        ),
        Spacer(1, 6 * cm),
        Paragraph(
            "This report is generated by the Cloud Resilience Visualizer, a "
            "Cloud Security Posture Management tool. Findings map to the EU "
            "NIS2 Directive, NCSC Cyber Assessment Framework, MITRE ATT&amp;CK, "
            "and UK Cyber Essentials.",
            styles["muted"],
        ),
    ]


# ---- Executive summary ----------------------------------------------

def _executive_summary(compliance, findings, styles) -> list:
    story: list = [Paragraph("Executive summary", styles["h1"])]

    # Severity breakdown
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    story.append(Paragraph("Findings by severity", styles["h2"]))
    severity_data = [["Severity", "Count"]]
    for level in ("critical", "high", "medium", "low"):
        severity_data.append([level.capitalize(), str(severity_counts[level])])

    severity_table = Table(severity_data, colWidths=[6 * cm, 3 * cm])
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), _ROW_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.5, _BORDER),
    ]))
    story.append(severity_table)
    story.append(Spacer(1, 0.6 * cm))

    # Framework overview
    story.append(Paragraph("Framework compliance overview", styles["h2"]))
    framework_data = [["Framework", "Result"]]
    for fw in compliance["frameworks"]:
        framework_data.append([
            fw["framework_full_name"],
            f"{fw['failing_count']} {fw['unit_label']}",
        ])

    framework_table = Table(framework_data, colWidths=[11 * cm, 5 * cm])
    framework_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), _ROW_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.5, _BORDER),
    ]))
    story.append(framework_table)

    return story


# ---- Per-framework section ------------------------------------------

def _framework_section(framework, styles) -> list:
    story: list = [
        Paragraph(framework["framework_full_name"], styles["h1"]),
        Paragraph(
            f"{framework['failing_count']} {framework['unit_label']}",
            styles["muted"],
        ),
        Spacer(1, 0.3 * cm),
    ]

    if not framework["failing_requirements"]:
        story.append(Paragraph(
            "No requirements failing in this framework.",
            styles["body"],
        ))
        return story

    # Table: Reference, Requirement, Findings
    table_data = [["Reference", "Requirement", "Findings"]]
    for req in framework["failing_requirements"]:
        finding_summaries = "<br/>".join(
            f"<font color='{_SEVERITY_COLOURS[f['severity']].hexval()}'>&#9632;</font> "
            f"<b>{f['severity']}</b> — {_escape_xml(f['resource_id'])}: {_escape_xml(f['title'])}"
            for f in req["findings"]
        )
        table_data.append([
            Paragraph(f"<font name='Courier'>{_escape_xml(req['reference_id'])}</font>", styles["body"]),
            Paragraph(_escape_xml(req["label"]), styles["body"]),
            Paragraph(finding_summaries, styles["body"]),
        ])

    table = Table(table_data, colWidths=[3.2 * cm, 5.5 * cm, 8.3 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), _ROW_ALT]),
        ("GRID", (0, 0), (-1, -1), 0.5, _BORDER),
    ]))
    story.append(table)

    return story


# ---- Findings appendix ----------------------------------------------

def _findings_appendix(findings, styles) -> list:
    story: list = [Paragraph("Findings detail", styles["h1"])]

    if not findings:
        story.append(Paragraph(
            "No findings were produced by this scan.",
            styles["body"],
        ))
        return story

    for i, finding in enumerate(findings):
        if i > 0:
            story.append(Spacer(1, 0.4 * cm))
        story.extend(_finding_block(finding, styles))

    return story


def _finding_block(finding, styles) -> list:
    severity = finding.severity.value
    colour = _SEVERITY_COLOURS[severity].hexval()

    return [
        Paragraph(
            f"<font color='{colour}'>&#9632;</font> "
            f"<b>{_escape_xml(finding.title)}</b>",
            styles["h2"],
        ),
        Paragraph(
            f"<b>Severity:</b> {severity} &nbsp;&nbsp; "
            f"<b>Resource:</b> <font name='Courier'>{_escape_xml(finding.resource_id)}</font> &nbsp;&nbsp; "
            f"<b>Finding type:</b> <font name='Courier'>{_escape_xml(finding.finding_type_id)}</font>",
            styles["muted"],
        ),
        Paragraph("<b>Description</b>", styles["body"]),
        Paragraph(_escape_xml(finding.description), styles["body"]),
        Paragraph("<b>Remediation</b>", styles["body"]),
        Paragraph(_escape_xml(finding.remediation), styles["body"]),
        Paragraph("<b>Framework references</b>", styles["body"]),
        Paragraph(
            "<br/>".join(
                f"<font name='Courier'>{_escape_xml(r.reference_id)}</font> — "
                f"{_escape_xml(r.framework)}: {_escape_xml(r.label)}"
                for r in finding.framework_references
            ),
            styles["body"],
        ),
    ]


# ---- Helpers ---------------------------------------------------------

def _escape_xml(text: str) -> str:
    """
    Escape special characters for reportlab's Paragraph parser, which
    interprets & < > as XML. Distinct from HTML escape — reportlab
    doesn't want &apos; or &quot;.
    """
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )