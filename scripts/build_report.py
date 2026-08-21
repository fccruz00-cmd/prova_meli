from __future__ import annotations

import html
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "reports" / "forensic_report.md"
OUTPUT = ROOT / "output" / "pdf" / "forensic_report.pdf"
ML_YELLOW = colors.HexColor("#FFE600")
ML_BLUE = colors.HexColor("#3483FA")
DARK = colors.HexColor("#2D3277")
TEXT = colors.HexColor("#333333")
LIGHT = colors.HexColor("#F5F5F5")


def inline_markdown(value: str) -> str:
    escaped = html.escape(value, quote=False)
    escaped = re.sub(r"`([^`]+)`", r'<font name="Courier">\1</font>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)
    return escaped


styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CoverBrand", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=DARK, spaceAfter=8))
styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=29, leading=34, textColor=DARK, alignment=TA_LEFT, spaceAfter=14))
styles.add(ParagraphStyle(name="CoverSubtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=14, leading=20, textColor=TEXT, spaceAfter=24))
styles.add(ParagraphStyle(name="H1x", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=DARK, spaceBefore=14, spaceAfter=8, keepWithNext=1))
styles.add(ParagraphStyle(name="H2x", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12.5, leading=16, textColor=ML_BLUE, spaceBefore=10, spaceAfter=5, keepWithNext=1))
styles.add(ParagraphStyle(name="Bodyx", parent=styles["BodyText"], fontName="Helvetica", fontSize=9.3, leading=13.2, textColor=TEXT, spaceAfter=6))
styles.add(ParagraphStyle(name="Bulletx", parent=styles["BodyText"], fontName="Helvetica", fontSize=9.1, leading=12.8, leftIndent=13, firstLineIndent=-8, textColor=TEXT, spaceAfter=3))
styles.add(ParagraphStyle(name="Smallx", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.2, leading=9.2, textColor=TEXT))
styles.add(ParagraphStyle(name="Metric", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=DARK, alignment=TA_CENTER))
styles.add(ParagraphStyle(name="MetricLabel", parent=styles["Normal"], fontName="Helvetica", fontSize=7.5, leading=9, textColor=TEXT, alignment=TA_CENTER))


def footer(canvas, doc):
    canvas.saveState()
    width, _ = A4
    canvas.setStrokeColor(colors.HexColor("#DDDDDD"))
    canvas.line(18 * mm, 13 * mm, width - 18 * mm, 13 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(18 * mm, 8.5 * mm, "Confidencial - versão pública sanitizada")
    canvas.drawRightString(width - 18 * mm, 8.5 * mm, f"Página {doc.page}")
    canvas.restoreState()


def first_page(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(ML_YELLOW)
    canvas.rect(0, height - 58 * mm, width, 58 * mm, fill=1, stroke=0)
    canvas.setFillColor(DARK)
    canvas.rect(0, height - 60 * mm, width, 2 * mm, fill=1, stroke=0)
    canvas.restoreState()
    footer(canvas, doc)


def make_table(rows: list[list[str]], available_width: float) -> Table:
    count = len(rows[0])
    weights = []
    for col in range(count):
        maximum = max(len(row[col]) for row in rows)
        weights.append(min(maximum, 36) + 5)
    total = sum(weights)
    widths = [available_width * weight / total for weight in weights]
    cell_style = styles["Smallx"] if count >= 5 else styles["Bodyx"]
    data = [[Paragraph(inline_markdown(cell), cell_style) for cell in row] for row in rows]
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), ML_YELLOW),
                ("TEXTCOLOR", (0, 0), (-1, 0), DARK),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CCCCCC")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def cover() -> list:
    metric_data = [
        [Paragraph("61.961", styles["Metric"]), Paragraph("10.181", styles["Metric"]), Paragraph("10.173", styles["Metric"])],
        [Paragraph("requisições automatizadas", styles["MetricLabel"]), Paragraph("invoices no cluster", styles["MetricLabel"]), Paragraph("invoices com HTTP 200", styles["MetricLabel"])],
    ]
    metrics = Table(metric_data, colWidths=[52 * mm] * 3, rowHeights=[11 * mm, 10 * mm])
    metrics.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.white), ("BOX", (0, 0), (-1, -1), 0.7, ML_BLUE), ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D6E6FF")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    return [
        Spacer(1, 8 * mm),
        Paragraph("MERCADO LIVRE | DIGITAL FORENSICS", styles["CoverBrand"]),
        Spacer(1, 4 * mm),
        Paragraph("Relatório Forense", styles["CoverTitle"]),
        Spacer(1, 8 * mm),
        Paragraph("Potencial exploração IDOR no endpoint de busca de invoices", styles["CoverSubtitle"]),
        Spacer(1, 7 * mm),
        metrics,
        Spacer(1, 13 * mm),
        Table(
            [[Paragraph("CONCLUSÃO", styles["MetricLabel"]), Paragraph("Alta confiança de exploração automatizada compatível com IDOR; média confiança de divulgação de PII.", styles["Bodyx"])]],
            colWidths=[28 * mm, 128 * mm],
            style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFF8CC")), ("BOX", (0, 0), (-1, -1), 0.8, ML_YELLOW), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]),
        ),
        Spacer(1, 15 * mm),
        Paragraph("Janela observada: 2025-10-01 a 2025-12-31<br/>Data da análise: 2026-08-21<br/>Versão pública sanitizada", styles["Bodyx"]),
        PageBreak(),
    ]


def markdown_story() -> list:
    lines = SOURCE.read_text(encoding="utf-8").splitlines()
    story = []
    paragraph_buffer: list[str] = []

    def flush_paragraph():
        if paragraph_buffer:
            story.append(Paragraph(inline_markdown(" ".join(paragraph_buffer)), styles["Bodyx"]))
            paragraph_buffer.clear()

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        if i < 6 or line.startswith("# Relatório Forense"):
            i += 1
            continue
        if not line:
            flush_paragraph()
            i += 1
            continue
        if line.startswith("## "):
            flush_paragraph()
            title = line[3:]
            story.append(Paragraph(inline_markdown(title), styles["H1x"]))
            if title.startswith("6. Linha do tempo"):
                chart = ROOT / "results/public/charts/suspicious_daily_volume.png"
                if chart.exists():
                    story.extend([Image(str(chart), width=165 * mm, height=72 * mm), Spacer(1, 4 * mm)])
            i += 1
            continue
        if line.startswith("### "):
            flush_paragraph()
            story.append(Paragraph(inline_markdown(line[4:]), styles["H2x"]))
            i += 1
            continue
        if line.startswith("|"):
            flush_paragraph()
            table_lines = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1
            rows = [[cell.strip() for cell in item.strip("|").split("|")] for item in table_lines]
            rows = [row for row in rows if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in row)]
            story.extend([make_table(rows, 174 * mm), Spacer(1, 5 * mm)])
            continue
        if re.match(r"^[-*] ", line):
            flush_paragraph()
            story.append(Paragraph(inline_markdown(line[2:]), styles["Bulletx"], bulletText="-"))
            i += 1
            continue
        numbered = re.match(r"^(\d+)\. (.+)$", line)
        if numbered:
            flush_paragraph()
            story.append(Paragraph(inline_markdown(numbered.group(2)), styles["Bulletx"], bulletText=numbered.group(1) + "."))
            i += 1
            continue
        paragraph_buffer.append(line.strip())
        i += 1
    flush_paragraph()
    return story


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Relatório Forense - Potencial exploração IDOR em invoices",
        author="Digital Forensics",
        subject="Investigação técnica e impacto de negócio",
    )
    document.build(cover() + markdown_story(), onFirstPage=first_page, onLaterPages=footer)
    print(OUTPUT)


if __name__ == "__main__":
    main()
