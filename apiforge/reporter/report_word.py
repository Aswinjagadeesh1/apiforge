"""apiforge/reporter/report_word.py

Nhance-format Word (.docx) report generator for APIForge.

Same name/signature as the old write_word_report() (findings, output_path,
target=None) plus an optional `meta` dict for per-engagement cover / submission
details. Consumes the real Finding model directly.

Section 4.2 embeds a NATIVE, editable Word column chart (right-click -> Edit
Data works) of vulnerability counts by severity.
"""
from __future__ import annotations

import io
import os
import re
import tempfile
import zipfile
from collections import Counter
from datetime import date

from apiforge.reporter.poc_render import render_poc

# ---- Nhance palette -------------------------------------------------------
_HDR_BLUE = "1F487C"
_SEV_HEX = {
    "CRITICAL": "C00000", "HIGH": "FF0000", "MEDIUM": "FFC000",
    "LOW": "00B050", "INFO": "00AFEF",
}
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
# chart categories: (label, hex) in fixed order
_CHART_SEV = [("Critical", "C00000"), ("High", "FF0000"), ("Medium", "FFC000"),
              ("Low", "00B050"), ("Information", "00AFEF")]

_SEV_LEGEND = [
    ("Critical (9.0 - 10.0)",
     "Exploitation is typically straightforward and can lead to root-level "
     "compromise of servers or infrastructure. No special credentials or victim "
     "knowledge is required. Requires management's immediate attention and action."),
    ("High (7.0 - 8.9)",
     "Harder to exploit, but successful exploitation can yield elevated privileges, "
     "significant data loss, or downtime. Requires management's immediate attention "
     "and action to meet minimum control standards."),
    ("Medium (4.0 - 6.9)",
     "An opportunity to improve the effectiveness of the control environment; "
     "requires management action in the near term."),
    ("Low (0.1 - 3.9)",
     "An opportunity to improve the efficiency of control processes."),
    ("Information (0.00)",
     "A finding worth noting that may contribute to or enable a further attack."),
]

_REPORT_FORMAT_FIELDS = [
    ("Title of the Vulnerability", "A short title describing the vulnerability."),
    ("Severity Level", "The risk level. Each vulnerability's title bar is colour "
     "coded for quick identification of its severity."),
    ("Affected Endpoint", "The API endpoint(s) affected by the vulnerability."),
    ("OWASP Category", "The OWASP API Security Top 10 (2023) category and CWE."),
    ("Description", "A brief description of the vulnerability."),
    ("Proof of Concept", "Evidence (annotated request/response) demonstrating the issue."),
    ("Remediation", "Recommended action to fix or mitigate the vulnerability."),
]

_OWASP_API_TOP10 = [
    ("API1:2023", "Broken Object Level Authorization"),
    ("API2:2023", "Broken Authentication"),
    ("API3:2023", "Broken Object Property Level Authorization"),
    ("API4:2023", "Unrestricted Resource Consumption"),
    ("API5:2023", "Broken Function Level Authorization"),
    ("API6:2023", "Unrestricted Access to Sensitive Business Flows"),
    ("API7:2023", "Server Side Request Forgery"),
    ("API8:2023", "Security Misconfiguration"),
    ("API9:2023", "Improper Inventory Management"),
    ("API10:2023", "Unsafe Consumption of APIs"),
]

_DEFAULT_META = {
    "report_title": "API Security Assessment Report",
    "is_reassessment": False,
    "vendor_name": "Company Name",
    "vendor_address": "Company Address",
    "vendor_contact": "",
    "test_type": "Grey Box Testing",
    "classification": "",
    "client_name": "",
    "scope_items": None,
    "assessment_period": date.today().strftime("%d-%m-%Y"),
    "submission": {
        "Date": "", "Classification": "", "Submitted To": "",
        "Designation": "", "Address": "", "E-Mail": "",
    },
    "preparation": [
        ("1", "", "", "Document Preparation"),
        ("2", "", "", "Document Review & Approval"),
        ("3", "", "", "Document Appraisal"),
        ("4", "", "", "Document Acceptance"),
    ],
}


# ======================= native editable chart injection ===================
def _embedded_xlsx(cats, vals):
    from openpyxl import Workbook
    wb = Workbook(); ws = wb.active; ws.title = "Sheet1"
    ws["A1"] = "Severity"; ws["B1"] = "Count"
    for i, (c, v) in enumerate(zip(cats, vals), 2):
        ws.cell(i, 1, c); ws.cell(i, 2, v)
    bio = io.BytesIO(); wb.save(bio); return bio.getvalue()


def _chart_xml(cats, vals):
    dpts = "".join(
        f'<c:dPt><c:idx val="{i}"/><c:invertIfNegative val="0"/><c:bubble3D val="0"/>'
        f'<c:spPr><a:solidFill><a:srgbClr val="{_CHART_SEV[i][1]}"/></a:solidFill></c:spPr></c:dPt>'
        for i in range(len(cats)))
    catpts = "".join(f'<c:pt idx="{i}"><c:v>{c}</c:v></c:pt>' for i, c in enumerate(cats))
    valpts = "".join(f'<c:pt idx="{i}"><c:v>{v}</c:v></c:pt>' for i, v in enumerate(vals))
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<c:chart>'
        '<c:title><c:tx><c:rich><a:bodyPr/><a:lstStyle/><a:p>'
        '<a:pPr><a:defRPr sz="1400" b="1"><a:solidFill><a:srgbClr val="1F487C"/></a:solidFill></a:defRPr></a:pPr>'
        '<a:r><a:rPr lang="en-US" sz="1400" b="1"><a:solidFill><a:srgbClr val="1F487C"/></a:solidFill></a:rPr>'
        '<a:t>Security Findings by Severity Level</a:t></a:r></a:p></c:rich></c:tx><c:overlay val="0"/></c:title>'
        '<c:autoTitleDeleted val="0"/>'
        '<c:plotArea><c:layout/>'
        '<c:barChart><c:barDir val="col"/><c:grouping val="clustered"/><c:varyColors val="1"/>'
        '<c:ser><c:idx val="0"/><c:order val="0"/>'
        '<c:tx><c:strRef><c:f>Sheet1!$B$1</c:f><c:strCache><c:ptCount val="1"/>'
        '<c:pt idx="0"><c:v>Count</c:v></c:pt></c:strCache></c:strRef></c:tx>'
        f'{dpts}'
        '<c:dLbls><c:spPr><a:noFill/></c:spPr><c:showLegendKey val="0"/><c:showVal val="1"/>'
        '<c:showCatName val="0"/><c:showSerName val="0"/><c:showPercent val="0"/><c:showBubbleSize val="0"/></c:dLbls>'
        f'<c:cat><c:strRef><c:f>Sheet1!$A$2:$A${len(cats)+1}</c:f>'
        f'<c:strCache><c:ptCount val="{len(cats)}"/>{catpts}</c:strCache></c:strRef></c:cat>'
        f'<c:val><c:numRef><c:f>Sheet1!$B$2:$B${len(vals)+1}</c:f>'
        f'<c:numCache><c:formatCode>General</c:formatCode><c:ptCount val="{len(vals)}"/>{valpts}</c:numCache></c:numRef></c:val>'
        '</c:ser>'
        '<c:gapWidth val="80"/><c:axId val="111111111"/><c:axId val="222222222"/></c:barChart>'
        '<c:catAx><c:axId val="111111111"/><c:scaling><c:orientation val="minMax"/></c:scaling>'
        '<c:delete val="0"/><c:axPos val="b"/><c:crossAx val="222222222"/></c:catAx>'
        '<c:valAx><c:axId val="222222222"/><c:scaling><c:orientation val="minMax"/></c:scaling>'
        '<c:delete val="0"/><c:axPos val="l"/><c:majorGridlines/>'
        '<c:title><c:tx><c:rich><a:bodyPr rot="-5400000" vert="horz"/><a:lstStyle/>'
        '<a:p><a:r><a:rPr lang="en-US"/><a:t>Count</a:t></a:r></a:p></c:rich></c:tx><c:overlay val="0"/></c:title>'
        '<c:crossAx val="111111111"/></c:valAx>'
        '</c:plotArea><c:plotVisOnly val="1"/><c:dispBlanksAs val="gap"/></c:chart>'
        '<c:externalData r:id="rId1"><c:autoUpdate val="0"/></c:externalData>'
        '</c:chartSpace>'
    )


def _chart_drawing(rid):
    return (
        '<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:drawing>'
        '<wp:inline distT="0" distB="0" distL="0" distR="0" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
        '<wp:extent cx="5486400" cy="3200400"/><wp:effectExtent l="0" t="0" r="0" b="0"/>'
        '<wp:docPr id="100" name="SeverityChart"/><wp:cNvGraphicFramePr/>'
        '<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
        '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart">'
        '<c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" '
        f'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:id="{rid}"/>'
        '</a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>'
    )


def _inject_severity_chart(path, counts):
    """Replace the [[SEVCHART]] marker paragraph with a native editable chart."""
    cats = [c for c, _ in _CHART_SEV]
    key = {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM",
           "Low": "LOW", "Information": "INFO"}
    vals = [counts.get(key[c], 0) for c in cats]

    with zipfile.ZipFile(path) as z:
        data = {n: z.read(n) for n in z.namelist()}

    rels = data["word/_rels/document.xml.rels"].decode()
    used = [int(x) for x in re.findall(r'Id="rId(\d+)"', rels)] or [0]
    rid = f"rId{max(used) + 1}"
    rels = rels.replace(
        "</Relationships>",
        f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/'
        f'officeDocument/2006/relationships/chart" Target="charts/chart1.xml"/></Relationships>')
    data["word/_rels/document.xml.rels"] = rels.encode()

    doc = data["word/document.xml"].decode()
    m = re.search(r'<w:p\b[^>]*>(?:(?!</w:p>).)*\[\[SEVCHART\]\](?:(?!</w:p>).)*</w:p>', doc, re.S)
    if not m:
        return  # marker missing — leave doc as-is
    doc = doc[:m.start()] + _chart_drawing(rid) + doc[m.end():]
    data["word/document.xml"] = doc.encode()

    data["word/charts/chart1.xml"] = _chart_xml(cats, vals).encode()
    data["word/charts/_rels/chart1.xml.rels"] = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/package" Target="../embeddings/Microsoft_Excel_Worksheet1.xlsx"/>'
        '</Relationships>').encode()
    data["word/embeddings/Microsoft_Excel_Worksheet1.xlsx"] = _embedded_xlsx(cats, vals)

    ct = data["[Content_Types].xml"].decode()
    ct = ct.replace("</Types>",
        '<Override PartName="/word/charts/chart1.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.drawingml.chart+xml"/>'
        '<Override PartName="/word/embeddings/Microsoft_Excel_Worksheet1.xlsx" ContentType='
        '"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"/></Types>')
    data["[Content_Types].xml"] = ct.encode()

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in data.items():
            z.writestr(n, b)


# ================================ report ===================================
def write_word_report(findings, output_path, target=None, meta=None):
    from docx import Document
    from docx.shared import Pt, RGBColor, Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement

    M = dict(_DEFAULT_META)
    if meta:
        M.update(meta)
    if not M.get("scope_items"):
        M["scope_items"] = [target or "In-scope APIs"]

    tmp = tempfile.mkdtemp(prefix="apiforge_poc_")
    doc = Document()
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10.5)

    def shade(cell, hex_color):
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), hex_color)
        tcPr.append(shd)

    def set_cell(cell, text, *, bold=False, color=None, white=False, fill=None, align=None, size=None):
        cell.text = ""
        p = cell.paragraphs[0]
        if align:
            p.alignment = align
        r = p.add_run(str(text)); r.bold = bold
        if size:
            r.font.size = Pt(size)
        if white:
            r.font.color.rgb = RGBColor.from_string("FFFFFF")
        elif color:
            r.font.color.rgb = RGBColor.from_string(color)
        if fill:
            shade(cell, fill)

    def new_table(cols):
        t = doc.add_table(rows=1, cols=cols); t.style = "Table Grid"; return t

    def header_row(table, labels):
        for c, lab in zip(table.rows[0].cells, labels):
            set_cell(c, lab, bold=True, white=True, fill=_HDR_BLUE, align=WD_ALIGN_PARAGRAPH.CENTER)

    def center(text, size, color=None, bold=True, italic=False):
        p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(text); r.bold = bold; r.italic = italic; r.font.size = Pt(size)
        if color:
            r.font.color.rgb = RGBColor.from_string(color)

    def h1(text):
        r = doc.add_heading(level=1).add_run(text); r.font.color.rgb = RGBColor.from_string(_HDR_BLUE)

    def h2(text):
        r = doc.add_heading(level=2).add_run(text); r.font.color.rgb = RGBColor.from_string(_HDR_BLUE)

    def field_label(text):
        p = doc.add_paragraph()
        r = p.add_run(text.upper()); r.bold = True; r.font.size = Pt(11)
        r.font.color.rgb = RGBColor.from_string(_HDR_BLUE)
        pPr = p._p.get_or_add_pPr(); pbdr = OxmlElement("w:pBdr"); b = OxmlElement("w:bottom")
        b.set(qn("w:val"), "single"); b.set(qn("w:sz"), "6"); b.set(qn("w:space"), "1")
        b.set(qn("w:color"), _HDR_BLUE); pbdr.append(b); pPr.append(pbdr)

    def value(text, color=None, bold=False):
        p = doc.add_paragraph(); r = p.add_run(text); r.bold = bold
        if color:
            r.font.color.rgb = RGBColor.from_string(color)

    def toc():
        p = doc.add_paragraph(); run = p.add_run()
        parts = [("fld", "begin"), ("instr", 'TOC \\o "1-2" \\h \\z \\u'),
                 ("fld", "separate"), ("txt", "Update this field in Word (F9)."), ("fld", "end")]
        for kind, val in parts:
            if kind == "instr":
                e = OxmlElement("w:instrText"); e.set(qn("xml:space"), "preserve"); e.text = val
            elif kind == "txt":
                e = OxmlElement("w:t"); e.text = val
            else:
                e = OxmlElement("w:fldChar"); e.set(qn("w:fldCharType"), val)
            run._r.append(e)

    ordered = sorted(findings, key=lambda f: (f.severity.rank, f.check_id))
    counts = Counter(f.severity.value for f in findings)

    # ---------- COVER ----------
    doc.add_paragraph("\n\n")
    center(M["report_title"], 26, _HDR_BLUE)
    center(target or M.get("client_name") or "", 15, bold=False)
    doc.add_paragraph("\n")
    center("Prepared by " + M["vendor_name"], 12, bold=True)
    center(M["vendor_address"], 10, bold=False, italic=True)
    if M["vendor_contact"]:
        center(M["vendor_contact"], 10, bold=False)
    doc.add_paragraph("\n")
    center(f'{M["test_type"]}', 10, italic=True, bold=False)
    center("Report auto-generated by APIForge", 9, italic=True, bold=False, color="888888")
    doc.add_page_break()

    # ---------- TOC ----------
    h1("Table of Contents"); toc(); doc.add_page_break()

    # ---------- 1 INTRODUCTION ----------
    h1("1. Introduction")
    h2("1.1 Summary")
    kind = "re-assessment" if M["is_reassessment"] else "assessment"
    value(f'This report presents the vulnerability {kind} for {target or "the in-scope APIs"}, '
          f'conducted as {M["test_type"]} against the OWASP API Security Top 10 (2023). Testing '
          f'assumed the perspective of a malicious user while taking due care not to harm the application.')
    h2("1.2 Aim")
    value(f'To assess the security posture of {target or "the in-scope APIs"} and provide '
          f'actionable remediation for each confirmed finding.')
    h2("1.3 Assessment Objective")
    value("Identify, verify and rate security flaws in the in-scope APIs against "
          "industry-standard benchmarks.")

    # ---------- 2 SCOPE ----------
    h1("2. Scope of Assessment")
    h2("2.1 Scope of Testing")
    t = new_table(2)
    header_row(t, ["S.No", "Scope of Testing"])
    for i, item in enumerate(M["scope_items"], 1):
        cells = t.add_row().cells
        set_cell(cells[0], i); set_cell(cells[1], str(item))

    h2("2.2 Document Submission Details")
    t = new_table(2)
    t._tbl.remove(t.rows[0]._tr)
    t.columns[0].width = Inches(2.0)
    for label, val in M["submission"].items():
        cells = t.add_row().cells
        set_cell(cells[0], label, bold=True, fill="E6E6E6")
        set_cell(cells[1], val)

    h2("2.3 Document Preparation")
    t = new_table(4)
    header_row(t, ["S.No", "Name", "Organization", "Responsibility"])
    for sno, name, org, resp in M["preparation"]:
        cells = t.add_row().cells
        set_cell(cells[0], sno); set_cell(cells[1], name)
        set_cell(cells[2], org); set_cell(cells[3], resp)

    # ---------- 3 TERMS ----------
    h1("3. Terms, Definitions and Legends")
    value("This section describes the format in which the identified vulnerabilities are "
          "reported in the later sections, and the colour-coded severity legend used "
          "throughout the report.")
    h2("3.1 Vulnerability Report Format")
    for name, desc in _REPORT_FORMAT_FIELDS:
        p = doc.add_paragraph()
        r = p.add_run(f"{name} - "); r.bold = True
        p.add_run(desc)

    h2("3.2 Severity Level of Vulnerability")
    value("The severity level of each vulnerability is colour coded for quick "
          "identification of the risk level, as follows:")
    t = new_table(2)
    header_row(t, ["Risk Exposure", "Description"])
    t.columns[0].width = Inches(1.9)
    for label, desc in _SEV_LEGEND:
        sev_key = "INFO" if label.upper().startswith("INFO") else label.split(" ")[0].upper()
        cells = t.add_row().cells
        set_cell(cells[0], label, bold=True, white=True, fill=_SEV_HEX.get(sev_key, "808080"))
        set_cell(cells[1], desc)

    # ---------- 4 EXECUTIVE SUMMARY ----------
    h1("4. Executive Summary of Vulnerabilities")
    h2("4.1 Vulnerabilities Ordered by Severity")
    t = new_table(5)
    header_row(t, ["S.No", "Vulnerability", "Severity", "CVSS", "OWASP"])
    for i, f in enumerate(ordered, 1):
        cells = t.add_row().cells
        set_cell(cells[0], i)
        set_cell(cells[1], f.title)
        set_cell(cells[2], f.severity.value, bold=True, white=True,
                 fill=_SEV_HEX.get(f.severity.value, "FFFFFF"), align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell(cells[3], f.cvss_score, align=WD_ALIGN_PARAGRAPH.CENTER)
        set_cell(cells[4], (f.owasp_category or "").split(" ")[0].split(":")[0] or f.owasp_category)

    h2("4.2 Total No. of Vulnerabilities and Severity Level")
    cmark = doc.add_paragraph(); cmark.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cmark.add_run("[[SEVCHART]]")           # replaced with a native chart after save
    present = [s for s in _SEV_ORDER if counts.get(s, 0)]
    t = new_table(len(present) + 1)
    header_row(t, ["Total"] + [s.title() for s in present])
    cells = t.add_row().cells
    set_cell(cells[0], len(findings), bold=True, align=WD_ALIGN_PARAGRAPH.CENTER)
    for j, sev in enumerate(present, 1):
        set_cell(cells[j], counts[sev], bold=True, white=True,
                 fill=_SEV_HEX[sev], align=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_page_break()

    # ---------- 5 FINDINGS ----------
    h1("5. Vulnerabilities List with Remediation")
    for i, f in enumerate(ordered, 1):
        h2(f"5.{i}  {f.title}")
        field_label("Severity"); value(f.severity.value, _SEV_HEX.get(f.severity.value), bold=True)
        if M["is_reassessment"]:
            status = getattr(f, "status", "Open")
            field_label("Status After Reassessment")
            value(status, "00B050" if str(status).lower() == "closed" else "FF0000", bold=True)
        field_label("Affected Endpoint"); value(f"{f.method} {f.endpoint}")
        field_label("OWASP Category"); value(f"{f.owasp_category}   (CVSS {f.cvss_score}, {f.cwe})")
        field_label("Description"); value(f.description)
        field_label("Proof of Concept")
        img_path = os.path.join(tmp, f"poc_{i}.png")
        render_poc(f.poc_request, f.poc_response, img_path,
                   highlight=getattr(f, "evidence", None),
                   caption=getattr(f, "evidence_caption", None))
        pic = doc.add_paragraph(); pic.alignment = WD_ALIGN_PARAGRAPH.CENTER
        pic.add_run().add_picture(img_path, width=Inches(6.3))
        cap = doc.add_paragraph(); cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cr = cap.add_run(f"Figure 5.{i}: annotated request/response evidence for {f.title}.")
        cr.italic = True; cr.font.size = Pt(9)
        field_label("Remediation"); value(f.remediation)
        doc.add_page_break()

    # ---------- Tools / Conclusion / Way Ahead ----------
    h1("Tools and References")
    for tool in ["APIForge (automated OWASP API pass)", "Postman", "Burp Suite", "jwt_tool", "curl"]:
        value("• " + tool)
    ch = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    h1("Conclusion")
    value(f'The assessment identified {len(findings)} finding(s), {ch} of Critical/High severity. '
          f'The most serious issues concern authentication and object-level authorization - the flaw '
          f'classes behind most real-world API breaches. Prioritise remediation of Critical/High items.')
    h1("Way Ahead")
    value("Remediate in severity order, then request a re-assessment to confirm closure. "
          "Adopt the OWASP API Security Top 10 as a recurring control baseline.")

    # ---------- Appendix ----------
    h1("Appendix A: OWASP API Top 10 (2023) Coverage")
    seen = {(f.owasp_category or "").split(":")[0].split(" ")[0] for f in findings}
    t = new_table(3)
    header_row(t, ["Category", "Name", "Findings in this report"])
    for cat, name in _OWASP_API_TOP10:
        cells = t.add_row().cells
        set_cell(cells[0], cat); set_cell(cells[1], name)
        hit = cat.split(":")[0] in seen
        set_cell(cells[2], "Yes" if hit else "-",
                 color=("00B050" if hit else None), bold=hit, align=WD_ALIGN_PARAGRAPH.CENTER)

    try:
        _upd = OxmlElement("w:updateFields"); _upd.set(qn("w:val"), "true")
        doc.settings.element.append(_upd)
    except Exception:
        pass

    doc.save(str(output_path))
    _inject_severity_chart(str(output_path), counts)   # swap marker for a native chart

    for fn in os.listdir(tmp):
        os.remove(os.path.join(tmp, fn))
    os.rmdir(tmp)
    return str(output_path)
