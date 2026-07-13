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
