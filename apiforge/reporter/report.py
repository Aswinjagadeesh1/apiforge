"""Report generation — Excel (pentest deliverable format) and JSON."""
from __future__ import annotations

import json
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
    def to_excel(self, findings: list[Finding], output_path: str | Path) -> None:
        wb = Workbook()
        ws = wb.active
        ws.title = "Findings"

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
            # colour the severity cell
            sev_cell = ws.cell(row=row, column=1)
            sev_cell.fill = PatternFill(
                "solid", fgColor=_SEVERITY_FILL.get(f.severity.value, "FFFFFF")
            )
            sev_cell.font = Font(bold=True, color="FFFFFF")

        ws.freeze_panes = "A2"
        wb.save(str(output_path))

    def to_json(self, findings: list[Finding], output_path: str | Path) -> None:
        data = [f.model_dump() for f in findings]
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
