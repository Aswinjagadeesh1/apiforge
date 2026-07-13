"""Report generation — Excel (pentest deliverable format) and JSON."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from apiforge.models import Finding

_SEVERITY_FILL = {
    "CRITICAL": "8B0000",
    "HIGH": "E63900",
    "MEDIUM": "E69500",
    "LOW": "E6C200",
    "INFO": "4A90A4",
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_COLUMNS = [
    ("Severity", 12),
    ("CVSS", 8),
    ("Check ID", 22),
    ("Title", 32),
    ("OWASP Category", 40),
    ("CWE", 10),
    ("Method", 9),
    ("Endpoint", 40),
    ("Description", 60),
    ("PoC Request", 45),
    ("PoC Response", 45),
    ("Remediation", 55),
]


class Reporter:
    def to_excel(
        self,
        findings: list[Finding],
        output_path: str | Path,
        target: str | None = None,
    ) -> None:
        wb = Workbook()

        # ---- Sheet 1: Executive Summary ----
        summary = wb.active
        summary.title = "Executive Summary"
        self._build_summary(summary, findings, target)

        # ---- Sheet 2: Findings (the detailed table) ----
        ws = wb.create_sheet("Findings")
        self._build_findings(ws, findings)

        wb.save(str(output_path))

    def _build_summary(self, ws, findings: list[Finding], target: str | None) -> None:
        # Title banner
        ws.merge_cells("A1:D1")
        title = ws.cell(row=1, column=1, value="APIForge — API Security Assessment")
        title.font = Font(bold=True, size=16, color="FFFFFF")
        title.alignment = Alignment(horizontal="center", vertical="center")
        title.fill = PatternFill("solid", fgColor="1F3A5F")
        ws.row_dimensions[1].height = 30

        # Metadata block
        meta = [
            ("Target", target or "N/A"),
            ("Scan Date", datetime.now().strftime("%Y-%m-%d %H:%M")),
            ("Total Findings", str(len(findings))),
            ("Standard", "OWASP API Security Top 10 (2023)"),
        ]
        row = 3
        for label, value in meta:
            lc = ws.cell(row=row, column=1, value=label)
            lc.font = Font(bold=True)
            ws.cell(row=row, column=2, value=value)
            row += 1

        # Severity breakdown
        row += 1
        hdr = ws.cell(row=row, column=1, value="Findings by Severity")
        hdr.font = Font(bold=True, size=12, color="FFFFFF")
        hdr.fill = PatternFill("solid", fgColor="1F3A5F")
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=2)
        row += 1

        sev_counts = Counter(f.severity.value for f in findings)
        for sev in _SEVERITY_ORDER:
            count = sev_counts.get(sev, 0)
            if count == 0:
                continue
            sc = ws.cell(row=row, column=1, value=sev)
            sc.fill = PatternFill("solid", fgColor=_SEVERITY_FILL.get(sev, "FFFFFF"))
            sc.font = Font(bold=True, color="FFFFFF")
            sc.alignment = Alignment(horizontal="center")
            ws.cell(row=row, column=2, value=count).alignment = Alignment(
                horizontal="center"
            )
            row += 1

        # OWASP category breakdown
        row += 1
        hdr2 = ws.cell(row=row, column=1, value="Findings by OWASP Category")
        hdr2.font = Font(bold=True, size=12, color="FFFFFF")
        hdr2.fill = PatternFill("solid", fgColor="1F3A5F")
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=2)
        row += 1

        cat_counts = Counter(f.owasp_category for f in findings)
        for cat, count in sorted(cat_counts.items()):
            ws.cell(row=row, column=1, value=cat).alignment = Alignment(wrap_text=True)
            ws.cell(row=row, column=2, value=count).alignment = Alignment(
                horizontal="center"
            )
            row += 1

        # Column widths
        ws.column_dimensions["A"].width = 42
        ws.column_dimensions["B"].width = 22
        ws.column_dimensions["C"].width = 12
        ws.column_dimensions["D"].width = 12

    def _build_findings(self, ws, findings: list[Finding]) -> None:
        header_fill = PatternFill("solid", fgColor="1F3A5F")
        header_font = Font(bold=True, color="FFFFFF", size=11)
        for col, (name, width) in enumerate(_COLUMNS, 1):
            cell = ws.cell(row=1, column=col, value=name)
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(
                horizontal="center", vertical="center", wrap_text=True
            )
            ws.column_dimensions[get_column_letter(col)].width = width

        ordered = sorted(findings, key=lambda f: (f.severity.rank, f.check_id))
        for row, f in enumerate(ordered, 2):
            values = [
                f.severity.value,
                f.cvss_score,
                f.check_id,
                f.title,
                f.owasp_category,
                f.cwe,
                f.method,
                f.endpoint,
                f.description,
                f.poc_request,
                f.poc_response,
                f.remediation,
            ]
            for col, value in enumerate(values, 1):
                cell = ws.cell(row=row, column=col, value=value)
                cell.alignment = Alignment(vertical="top", wrap_text=True)
            sev_cell = ws.cell(row=row, column=1)
            sev_cell.fill = PatternFill(
                "solid", fgColor=_SEVERITY_FILL.get(f.severity.value, "FFFFFF")
            )
            sev_cell.font = Font(bold=True, color="FFFFFF")

        ws.freeze_panes = "A2"

    def to_json(self, findings: list[Finding], output_path: str | Path) -> None:
        data = [f.model_dump() for f in findings]
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)


# ---- Word (.docx) export -------------------------------------------------
# Added as a separate function to keep the Reporter class edit minimal.

def write_word_report(findings, output_path, target=None):
    """Generate a professional .docx pentest report."""
    from collections import Counter
    from datetime import datetime

    from docx import Document
    from docx.shared import Pt, RGBColor, Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    _SEV_RGB = {
        "CRITICAL": RGBColor(0x8B, 0x00, 0x00),
        "HIGH": RGBColor(0xE6, 0x39, 0x00),
        "MEDIUM": RGBColor(0xE6, 0x95, 0x00),
        "LOW": RGBColor(0xE6, 0xC2, 0x00),
        "INFO": RGBColor(0x4A, 0x90, 0xA4),
    }
    _ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    doc = Document()

    # ---- Title page ----
    title = doc.add_heading("API Security Assessment", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub = doc.add_paragraph("Generated by APIForge — OWASP API Top 10 Scanner")
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph()

    meta = doc.add_paragraph()
    meta.add_run(f"Target: ").bold = True
    meta.add_run(f"{target or 'N/A'}\n")
    meta.add_run(f"Scan Date: ").bold = True
    meta.add_run(f"{datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    meta.add_run(f"Total Findings: ").bold = True
    meta.add_run(f"{len(findings)}\n")
    meta.add_run(f"Standard: ").bold = True
    meta.add_run("OWASP API Security Top 10 (2023)")

    # ---- Executive summary ----
    doc.add_heading("Executive Summary", level=1)

    sev_counts = Counter(f.severity.value for f in findings)
    doc.add_heading("Findings by Severity", level=2)
    t = doc.add_table(rows=1, cols=2)
    t.style = "Light Grid Accent 1"
    t.rows[0].cells[0].text = "Severity"
    t.rows[0].cells[1].text = "Count"
    for sev in _ORDER:
        c = sev_counts.get(sev, 0)
        if c == 0:
            continue
        row = t.add_row().cells
        run = row[0].paragraphs[0].add_run(sev)
        run.bold = True
        run.font.color.rgb = _SEV_RGB.get(sev, RGBColor(0, 0, 0))
        row[1].text = str(c)

    cat_counts = Counter(f.owasp_category for f in findings)
    doc.add_heading("Findings by OWASP Category", level=2)
    t2 = doc.add_table(rows=1, cols=2)
    t2.style = "Light Grid Accent 1"
    t2.rows[0].cells[0].text = "OWASP Category"
    t2.rows[0].cells[1].text = "Count"
    for cat, c in sorted(cat_counts.items()):
        row = t2.add_row().cells
        row[0].text = cat
        row[1].text = str(c)

    doc.add_page_break()

    # ---- Detailed findings ----
    doc.add_heading("Detailed Findings", level=1)
    ordered = sorted(findings, key=lambda f: (f.severity.rank, f.check_id))
    for i, f in enumerate(ordered, 1):
        h = doc.add_heading(f"{i}. {f.title}", level=2)

        sev_p = doc.add_paragraph()
        sev_run = sev_p.add_run(f"{f.severity.value}")
        sev_run.bold = True
        sev_run.font.color.rgb = _SEV_RGB.get(f.severity.value, RGBColor(0, 0, 0))
        sev_p.add_run(f"  |  CVSS {f.cvss_score}  |  {f.cwe}  |  {f.owasp_category}")

        meta_p = doc.add_paragraph()
        meta_p.add_run("Endpoint: ").bold = True
        meta_p.add_run(f"{f.method} {f.endpoint}")

        doc.add_paragraph().add_run("Description").bold = True
        doc.add_paragraph(f.description)

        doc.add_paragraph().add_run("Proof of Concept — Request").bold = True
        pr = doc.add_paragraph(f.poc_request)
        pr.style = "No Spacing"

        doc.add_paragraph().add_run("Proof of Concept — Response").bold = True
        rr = doc.add_paragraph(f.poc_response)
        rr.style = "No Spacing"

        doc.add_paragraph().add_run("Remediation").bold = True
        doc.add_paragraph(f.remediation)

        doc.add_paragraph("─" * 40)

    doc.save(str(output_path))
