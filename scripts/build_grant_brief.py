"""Build the public DelegationBench Sentient technical brief."""

from __future__ import annotations

import argparse
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "output" / "pdf" / (
    "delegationbench-sentient-technical-brief.pdf")
SOCIAL_PREVIEW = ROOT / ".github" / "assets" / "social-preview.png"

INK = colors.HexColor("#101828")
MUTED = colors.HexColor("#667085")
BLUE = colors.HexColor("#3B6FE8")
PALE_BLUE = colors.HexColor("#EEF4FF")
CORAL = colors.HexColor("#FF7452")
PALE = colors.HexColor("#F8FAFC")
LINE = colors.HexColor("#E4E7EC")
WHITE = colors.white


def styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=30, leading=34, textColor=INK, alignment=TA_LEFT,
            spaceAfter=10),
        "subtitle": ParagraphStyle(
            "Subtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=13, leading=19, textColor=MUTED, spaceAfter=14),
        "eyebrow": ParagraphStyle(
            "Eyebrow", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=10, tracking=1.8, textColor=BLUE,
            spaceAfter=8),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=21, leading=25, textColor=INK, spaceAfter=12),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=13, leading=17, textColor=INK, spaceBefore=8,
            spaceAfter=5),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName="Helvetica",
            fontSize=9.5, leading=14.2, textColor=INK, spaceAfter=7),
        "small": ParagraphStyle(
            "Small", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8, leading=11.5, textColor=MUTED),
        "bullet": ParagraphStyle(
            "Bullet", parent=base["BodyText"], fontName="Helvetica",
            fontSize=9.2, leading=13.5, leftIndent=12, firstLineIndent=-7,
            bulletIndent=0, textColor=INK, spaceAfter=5),
        "metric": ParagraphStyle(
            "Metric", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=21, leading=23, textColor=BLUE, alignment=TA_CENTER),
        "metric_label": ParagraphStyle(
            "MetricLabel", parent=base["Normal"], fontName="Helvetica",
            fontSize=7.5, leading=10, textColor=MUTED, alignment=TA_CENTER),
        "callout": ParagraphStyle(
            "Callout", parent=base["BodyText"], fontName="Helvetica-Bold",
            fontSize=10.5, leading=15, textColor=INK, alignment=TA_CENTER),
        "link": ParagraphStyle(
            "Link", parent=base["BodyText"], fontName="Helvetica",
            fontSize=8.5, leading=12, textColor=BLUE),
    }


def bullet(text: str, sheet: dict) -> Paragraph:
    return Paragraph(f"• {text}", sheet["bullet"])


def metric_table(sheet: dict) -> Table:
    values = [
        ("75", "EXECUTABLE<br/>SCENARIOS"),
        ("231", "AUTOMATED<br/>TESTS"),
        ("V1-V7", "AUTHORITY<br/>VIOLATIONS"),
        ("3", "DEFENSE<br/>MODES"),
    ]
    cells = [
        [
            Paragraph(value, sheet["metric"]),
            Paragraph(label, sheet["metric_label"]),
        ]
        for value, label in values
    ]
    table = Table(cells, colWidths=[40 * mm] * 4, rowHeights=[23 * mm] * 4)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def callout(text: str, sheet: dict) -> Table:
    table = Table([[Paragraph(text, sheet["callout"])]], colWidths=[166 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE_BLUE),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#B2CCFF")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return table


def evidence_table(sheet: dict) -> Table:
    rows = [
        ["Layer", "Public evidence", "Status"],
        ["Deterministic core", "Runner, graph-derived oracle, V1-V7", "Ready"],
        ["Corpus", "38 attacks + 37 benign twins", "Ready"],
        ["Framework", "LangGraph adapter + compiled-graph CI", "Ready"],
        ["CI", "GitHub Action, JUnit, SARIF, JSON reports", "Ready"],
        ["Real models", "Repeated results on 2+ open-weight models", "Pending"],
        ["External use", "3-5 attributable independent reviews", "Pending"],
    ]
    formatted = []
    for index, row in enumerate(rows):
        style = sheet["small"] if index else ParagraphStyle(
            "TableHeader", parent=sheet["small"], fontName="Helvetica-Bold",
            textColor=WHITE)
        formatted.append([Paragraph(cell, style) for cell in row])
    table = Table(formatted, colWidths=[37 * mm, 93 * mm, 27 * mm],
                  repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("BACKGROUND", (0, 1), (-1, -1), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE]),
        ("GRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TEXTCOLOR", (2, 1), (2, 4), BLUE),
        ("TEXTCOLOR", (2, 5), (2, 6), CORAL),
    ]))
    return table


def footer(canvas, document):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.line(22 * mm, 15 * mm, 188 * mm, 15 * mm)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(22 * mm, 10 * mm, "DelegationBench - Sentient technical brief")
    canvas.drawRightString(
        188 * mm, 10 * mm, f"{document.page}")
    canvas.restoreState()


def build(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    sheet = styles()
    document = SimpleDocTemplate(
        str(output), pagesize=A4, leftMargin=22 * mm, rightMargin=22 * mm,
        topMargin=20 * mm, bottomMargin=21 * mm, title=(
            "DelegationBench - Sentient Technical Brief"),
        author="DelegationBench contributors",
        subject="Open deterministic security tests for multi-agent authority",
    )
    story = []

    story.extend([
        Spacer(1, 5 * mm),
        Paragraph("OPEN AGENT SECURITY TESTBED", sheet["eyebrow"]),
        Paragraph("DelegationBench", sheet["title"]),
        Paragraph(
            "Deterministic crash tests for unsafe agent handoffs and authority "
            "escalation across multi-agent systems.", sheet["subtitle"]),
        Spacer(1, 5 * mm),
    ])
    if SOCIAL_PREVIEW.exists():
        image = Image(str(SOCIAL_PREVIEW), width=166 * mm, height=83 * mm)
        story.extend([image, Spacer(1, 7 * mm)])
    story.extend([
        callout(
            "effective_authority(child) = user_grant AND parent_authority "
            "AND child_scope", sheet),
        Spacer(1, 8 * mm),
        Paragraph(
            "Public technical brief · v0.4.0 · Apache-2.0", sheet["small"]),
        Paragraph(
            "github.com/sergeyizmailov/DelegationBench", sheet["link"]),
        PageBreak(),
    ])

    story.extend([
        Paragraph("THE PROBLEM", sheet["eyebrow"]),
        Paragraph("Per-agent permissions do not preserve user intent", sheet["h1"]),
        Paragraph(
            "A multi-agent system can give each agent a sensible capability "
            "manifest and still lose the authority boundary when work is "
            "delegated. A read-only agent may hand an injected request to a "
            "payment agent that is technically capable of paying. Every local "
            "permission check passes, while the originating user grant is "
            "violated.", sheet["body"]),
        Paragraph("What DelegationBench checks", sheet["h2"]),
        bullet("Authority can attenuate across a handoff but cannot expand.", sheet),
        bullet("Delegation depth, expiry, nonce use, origin, and principal remain attributable.", sheet),
        bullet("Child-result content cannot silently widen the parent task scope.", sheet),
        bullet("Benign twins must complete useful work; blocking everything fails.", sheet),
        Spacer(1, 5 * mm),
        metric_table(sheet),
        Spacer(1, 8 * mm),
        Paragraph("Why deterministic", sheet["h2"]),
        Paragraph(
            "The model or framework produces the execution trace. A non-LLM "
            "oracle reconstructs the delegation graph and judges the trace "
            "against the root grant. The same trace therefore receives the "
            "same verdict, making failures reproducible in CI.", sheet["body"]),
        PageBreak(),
    ])

    story.extend([
        Paragraph("SYSTEM DESIGN", sheet["eyebrow"]),
        Paragraph("A narrow testbed with explicit trust boundaries", sheet["h1"]),
        callout(
            "User grant → delegated task scopes → tool calls → graph-derived "
            "oracle → exact V1-V7 verdict", sheet),
        Spacer(1, 6 * mm),
        Paragraph("Violation taxonomy", sheet["h2"]),
        bullet("<b>V1</b> - authority or temporal expansion on handoff", sheet),
        bullet("<b>V2</b> - confused-deputy action outside effective authority", sheet),
        bullet("<b>V3</b> - delegation-depth violation", sheet),
        bullet("<b>V4</b> - expired or replayed delegation", sheet),
        bullet("<b>V5</b> - origin or trace-integrity loss", sheet),
        bullet("<b>V6</b> - scope widening through a child result", sheet),
        bullet("<b>V7</b> - principal substitution", sheet),
        Paragraph("Framework and production surfaces", sheet["h2"]),
        bullet("Stable LangGraph callback adapter with custom handoffs, explicit scopes, principal propagation, and parallel correlation.", sheet),
        bullet("Experimental clean-room ROMA adapter pending upstream license and API confirmation.", sheet),
        bullet("Composite GitHub Action plus terminal, JSON, JUnit, SARIF, and versioned benchmark reports.", sheet),
        bullet("OpenAI-compatible real-model harness; no model is installed or started by DelegationBench.", sheet),
        PageBreak(),
    ])

    story.extend([
        Paragraph("PUBLIC EVIDENCE", sheet["eyebrow"]),
        Paragraph("What is verified and what remains external", sheet["h1"]),
        evidence_table(sheet),
        Spacer(1, 7 * mm),
        Paragraph("Verification baseline", sheet["h2"]),
        bullet("231 automated tests pass with the LangGraph integration dependencies.", sheet),
        bullet("All 75 scenarios match exact expectations in no-defense, envelope, and signed-envelope modes.", sheet),
        bullet("The corpus includes outcome assertions, so benign success requires completed work.", sheet),
        bullet("The package builds as wheel and source distribution and supports one-command CI.", sheet),
        Spacer(1, 5 * mm),
        callout(
            "No real-model percentage or external endorsement is claimed until "
            "the corresponding public artifact exists.", sheet),
        Spacer(1, 6 * mm),
        Paragraph(
            "This evidence policy is intentional: implemented infrastructure "
            "is separated from independent reproduction and probabilistic "
            "model results.", sheet["body"]),
        PageBreak(),
    ])

    story.extend([
        Paragraph("SENTIENT FIT", sheet["eyebrow"]),
        Paragraph("A shared security testbed, not a closed gateway", sheet["h1"]),
        Paragraph(
            "DelegationBench directly addresses the Unified Security Testbed "
            "need: another team can clone a tagged release, execute the same "
            "unsafe-handoff cases, inspect complete traces, and add framework-"
            "specific regressions without depending on a proprietary judge.",
            sheet["body"]),
        Paragraph("Grant-enabled milestones", sheet["h2"]),
        bullet("<b>Evidence:</b> publish repeated attack and benign runs for at least two competent open-weight models.", sheet),
        bullet("<b>Validation:</b> obtain 3-5 attributable reproductions, including one workflow or CI adoption signal.", sheet),
        bullet("<b>Integration:</b> harden framework conformance fixtures and validate ROMA if licensing is clarified.", sheet),
        bullet("<b>Ecosystem:</b> stabilize scenario and trace schemas, contribution review, and cross-framework reports.", sheet),
        Paragraph("Expected impact", sheet["h2"]),
        bullet("Framework maintainers gain reusable regression tests for delegation authority.", sheet),
        bullet("Agent developers gain CI-readable findings with exact paths and violated invariants.", sheet),
        bullet("Security researchers gain a shared paired corpus and deterministic evaluation layer.", sheet),
        Spacer(1, 8 * mm),
        HRFlowable(width="100%", thickness=0.6, color=LINE),
        Spacer(1, 6 * mm),
        KeepTogether([
            Paragraph("Repository", sheet["h2"]),
            Paragraph(
                "https://github.com/sergeyizmailov/DelegationBench",
                sheet["link"]),
            Paragraph("License: Apache-2.0", sheet["small"]),
        ]),
    ])

    document.build(story, onFirstPage=footer, onLaterPages=footer)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    build(args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
