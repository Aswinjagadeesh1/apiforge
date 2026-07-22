"""apiforge/reporter/poc_render.py

Render a finding's raw request/response (the poc_request / poc_response
strings already on every Finding) into an annotated PoC image, with the
"smoking-gun" line boxed in red. Pure Python (Pillow) — no browser, no cloud.

The highlight can be supplied explicitly (a check sets finding.evidence) or
auto-derived by a small heuristic when none is given.
"""
from __future__ import annotations

import re
from PIL import Image, ImageDraw, ImageFont

_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
_MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
_SANS_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"

_BG = (255, 255, 255)
_HDR = (37, 47, 63)
_HDR_TXT = (255, 255, 255)
_BODY = (30, 34, 40)
_BORDER = (205, 210, 218)
_RED = (214, 40, 40)

_FS, _LH, _PAD, _W = 15, 22, 14, 980

# lines that look like leaked/injected evidence, used when no explicit
# evidence is provided by the check
_HEURISTIC = re.compile(
    r"(isadmin|is_admin|\"role\"|admin|password|secret|token|ssn|"
    r"credit|[\w.+-]+@[\w-]+\.[\w.]+|alg\"?\s*:\s*\"?none)",
    re.IGNORECASE,
)


def _font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def _wrap(text, font, draw, max_w):
    if text == "":
        return [""]
    out, cur = [], ""
    for ch in text:
        if draw.textlength(cur + ch, font=font) <= max_w:
            cur += ch
        else:
            out.append(cur)
            cur = ch
    out.append(cur)
    return out


def auto_highlight(response_lines):
    """Pick the most evidence-looking line if a check didn't set one."""
    for ln in response_lines:
        if _HEURISTIC.search(ln):
            return ln.strip()
    return None


def _panel(draw, x, y, title, lines, font, hdr_font, highlight):
    inner_w = _W - 2 * x
    draw.rectangle([x, y, x + inner_w, y + 28], fill=_HDR)
    draw.text((x + _PAD, y + 6), title, font=hdr_font, fill=_HDR_TXT)
    y += 28
    visual = []
    for ln in lines:
        hl = highlight is not None and highlight in ln
        for w in _wrap(ln, font, draw, inner_w - 2 * _PAD):
            visual.append((w, hl))
    body_h = len(visual) * _LH + 2 * _PAD
    draw.rectangle([x, y, x + inner_w, y + body_h], outline=_BORDER, width=1)
    y += _PAD
    hl_box, ty = None, y
    for txt, hl in visual:
        draw.text((x + _PAD, ty), txt, font=font, fill=_BODY)
        if hl and hl_box is None:
            hl_box = [x + _PAD - 4, ty - 3,
                      x + _PAD + draw.textlength(txt, font=font) + 6, ty + _LH - 4]
        ty += _LH
    return y + body_h - _PAD + _PAD, hl_box


def render_poc(poc_request, poc_response, out_path,
               highlight=None, caption=None,
               req_title="REQUEST  (attacker)",
               res_title="RESPONSE  (server)"):
    """Write an annotated PoC PNG. Returns out_path."""
    req_lines = (poc_request or "").splitlines() or [""]
    res_lines = (poc_response or "").splitlines() or [""]
    if highlight is None:
        highlight = auto_highlight(res_lines) or auto_highlight(req_lines)

    font, hdr, sans = _font(_MONO, _FS), _font(_MONO_B, _FS), _font(_SANS_B, _FS + 1)
    d0 = ImageDraw.Draw(Image.new("RGB", (_W, 10)))

    def panel_h(lines):
        n = sum(len(_wrap(ln, font, d0, _W - 2 * 20 - 2 * _PAD)) for ln in lines)
        return 28 + n * _LH + 2 * _PAD

    total = 20 + panel_h(req_lines) + 16 + panel_h(res_lines) + 12 + (34 if caption else 0) + 20
    img = Image.new("RGB", (_W, total), _BG)
    draw = ImageDraw.Draw(img)
    x = 20
    y, box1 = _panel(draw, x, 20, req_title, req_lines, font, hdr, highlight)
    y += 16
    y, box2 = _panel(draw, x, y, res_title, res_lines, font, hdr, highlight)
    hl_box = box2 or box1
    if hl_box:
        draw.rectangle(hl_box, outline=_RED, width=3)
    if caption:
        y += 14
        draw.text((x, y), "▸ " + caption, font=sans, fill=_RED)
    img.save(out_path)
    return out_path
