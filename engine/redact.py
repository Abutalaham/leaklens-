"""Redaction engine: produces new sanitised files. Originals are never modified."""
from __future__ import annotations

import io
import re
import textwrap

from PIL import Image, ImageDraw


def _merge(spans):
    spans = sorted(spans)
    out = []
    for s, e, label in spans:
        if out and s < out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e, label])
    return out


def redact_text(text: str, spans: list[tuple[int, int, str]], style: str = "label") -> str:
    """spans = [(start, end, TYPE)]. style: 'label' -> [REDACTED:TYPE], 'block' -> ████."""
    out, last = [], 0
    for s, e, label in _merge(spans):
        out.append(text[last:s])
        out.append("█" * max(4, min(e - s, 24)) if style == "block" else f"[REDACTED:{label}]")
        last = e
    out.append(text[last:])
    return "".join(out)


def sanitise_pdf(text: str, spans, style="label") -> bytes:
    """Rebuild the PDF as a text-only copy from the redacted text. Layout is not preserved, but
    nothing from the original file (hidden layers, metadata, images) can leak through."""
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    redacted = redact_text(text, spans, style)
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setTitle("Sanitised document")
    c.setAuthor("")
    c.setCreator("LeakLens")
    w, h = A4
    top, bottom, left = h - 40, 45, 36

    def new_page():
        c.setFont("Courier", 9)
        c.setFillGray(0.45)
        c.drawString(left, 24, "Sanitised by LeakLens (text-only copy)")
        c.setFillGray(0)
        c.setFont("Courier", 9)
        return top

    for page_text in redacted.split("\f"):
        y = new_page()
        for line in page_text.split("\n"):
            for seg in (textwrap.wrap(line, 96, break_long_words=True, replace_whitespace=False,
                                      drop_whitespace=False) or [""]):
                if y < bottom:
                    c.showPage()
                    y = new_page()
                c.drawString(left, y, seg.encode("latin-1", "replace").decode("latin-1"))
                y -= 12
        c.showPage()
    c.save()
    return buf.getvalue()


def sanitise_image(data: bytes, boxes: list[tuple[float, float, float, float]], fmt_hint: str = "png"):
    """Draw solid boxes over the selected regions and re-encode WITHOUT any metadata.
    Returns (bytes, extension)."""
    img = Image.open(io.BytesIO(data))
    img.load()
    rgb = img.convert("RGB")
    clean = Image.new("RGB", rgb.size)
    clean.paste(rgb)                      # fresh image: no EXIF / text chunks / XMP carried over
    d = ImageDraw.Draw(clean)
    pad = 3
    for x, y, w, h in boxes:
        d.rectangle([x - pad, y - pad, x + w + pad, y + h + pad], fill=(0, 0, 0))
    buf = io.BytesIO()
    if fmt_hint in ("jpg", "jpeg"):
        clean.save(buf, "JPEG", quality=95)
        return buf.getvalue(), "jpg"
    clean.save(buf, "PNG")
    return buf.getvalue(), "png"
