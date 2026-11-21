"""File validation and content extraction (text/code, PDF, images with OCR) + metadata findings."""
from __future__ import annotations

import io
import os
import re
from dataclasses import dataclass, field

from PIL import ExifTags, Image

import config

Image.MAX_IMAGE_PIXELS = config.MAX_IMAGE_PIXELS


class ScanError(Exception):
    """User-facing error (safe to show; never contains file content)."""


@dataclass
class Extracted:
    kind: str                                   # text | pdf | image
    text: str = ""
    pages: list = field(default_factory=list)   # [(start, end)] char spans per PDF page
    words: list = field(default_factory=list)   # image OCR: [{s, e, box:(x, y, w, h)}] in pixels
    size: tuple | None = None                   # image (w, h)
    metadata: list = field(default_factory=list)  # [{field, value, type}]
    warnings: list = field(default_factory=list)


def classify(filename: str, data: bytes) -> str:
    name = os.path.basename(filename or "").lower()
    ext = os.path.splitext(name)[1]
    if name == ".env" or name.startswith(".env."):
        ext = ".env"
    if ext in config.PDF_EXTS:
        if not data.startswith(b"%PDF"):
            raise ScanError("This file has a .pdf extension but is not a valid PDF.")
        return "pdf"
    if ext in config.IMAGE_EXTS:
        sig = (data[:8] == b"\x89PNG\r\n\x1a\n" or data[:3] == b"\xff\xd8\xff" or data[:2] == b"BM"
               or data[:4] in (b"II*\x00", b"MM\x00*") or (data[:4] == b"RIFF" and data[8:12] == b"WEBP"))
        if not sig:
            raise ScanError("This file has an image extension but is not a valid image.")
        return "image"
    if ext in config.TEXT_EXTS:
        return "text"
    allowed = ", ".join(sorted(config.TEXT_EXTS | config.PDF_EXTS | config.IMAGE_EXTS))
    raise ScanError(f"Unsupported file type '{ext or name}'. Supported: {allowed}")


def extract(filename: str, data: bytes) -> Extracted:
    if not data:
        raise ScanError("The file is empty.")
    if len(data) > config.MAX_UPLOAD_BYTES:
        raise ScanError(f"File is larger than {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
    kind = classify(filename, data)
    return {"text": _text, "pdf": _pdf, "image": _image}[kind](data)


# ------------------------------------------------------------------ text/code
def _text(data: bytes) -> Extracted:
    if b"\x00" in data[:8192] and not data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ScanError("This looks like a binary file, not text.")
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    ex = Extracted("text", text[: config.MAX_TEXT_CHARS])
    if len(text) > config.MAX_TEXT_CHARS:
        ex.warnings.append(f"Only the first {config.MAX_TEXT_CHARS:,} characters were scanned.")
    return ex


# ------------------------------------------------------------------------ PDF
def _pdf(data: bytes) -> Extracted:
    from pypdf import PdfReader
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted and not reader.decrypt(""):
            raise ScanError("The PDF is password-protected; remove the password first.")
        n = len(reader.pages)
        if n > config.MAX_PDF_PAGES:
            raise ScanError(f"PDF has {n} pages; the limit is {config.MAX_PDF_PAGES}.")
        parts = []
        for page in reader.pages:
            try:
                parts.append((page.extract_text() or "").replace("\r", ""))
            except Exception:
                parts.append("")
        meta = reader.metadata
    except ScanError:
        raise
    except Exception:
        raise ScanError("The PDF could not be read (it may be corrupted).")

    ex = Extracted("pdf")
    pos, chunks = 0, []
    for t in parts:
        ex.pages.append((pos, pos + len(t)))
        chunks.append(t)
        pos += len(t) + 1                     # form-feed separator
    ex.text = "\f".join(chunks)[: config.MAX_TEXT_CHARS]
    if not ex.text.strip():
        ex.warnings.append("No text layer found. Scanned PDFs are not supported in this version "
                           "(export pages as images to use OCR).")
    if meta:
        for key, typ in (("/Author", "METADATA_AUTHOR"), ("/Creator", "METADATA_SOFTWARE"),
                         ("/Producer", "METADATA_SOFTWARE"), ("/Title", "METADATA_DOCINFO"),
                         ("/Subject", "METADATA_DOCINFO"), ("/Keywords", "METADATA_DOCINFO")):
            v = str(meta.get(key) or "").strip()
            if v and v.lower() not in {"anonymous", "unspecified", "untitled", "none", "unknown"}:
                ex.metadata.append({"field": key.lstrip("/"), "value": v, "type": typ})
    return ex


# --------------------------------------------------------------------- images
_GPS_IFD, _EXIF_IFD = 0x8825, 0x8769


def _image_metadata(img: Image.Image) -> list:
    out = []
    try:
        exif = img.getexif()
    except Exception:
        exif = {}
    if exif:
        try:
            gps = exif.get_ifd(_GPS_IFD)
        except Exception:
            gps = {}
        if gps:
            out.append({"field": "GPS", "value": "coordinates present", "type": "METADATA_GPS"})
        for tag, typ in ((315, "METADATA_AUTHOR"), (33432, "METADATA_AUTHOR"), (271, "METADATA_DEVICE"),
                         (272, "METADATA_DEVICE"), (305, "METADATA_SOFTWARE"), (306, "METADATA_DEVICE")):
            v = exif.get(tag)
            if v:
                out.append({"field": ExifTags.TAGS.get(tag, str(tag)), "value": str(v).strip(), "type": typ})
    for k, v in (img.info or {}).items():
        if k in ("Author", "Artist", "Copyright") and isinstance(v, str) and v.strip():
            out.append({"field": k, "value": v.strip(), "type": "METADATA_AUTHOR"})
        elif k in ("Software", "Comment", "Description", "Title") and isinstance(v, str) and v.strip():
            out.append({"field": k, "value": v.strip()[:200],
                        "type": "METADATA_SOFTWARE" if k == "Software" else "METADATA_DOCINFO"})
    return out


def ocr_available() -> bool:
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def _image(data: bytes) -> Extracted:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
    except Exception:
        raise ScanError("The image could not be read (it may be corrupted or too large).")
    ex = Extracted("image", size=img.size, metadata=_image_metadata(img))
    if not ocr_available():
        ex.warnings.append("Tesseract OCR is not installed, so only image metadata was scanned. "
                           "Install Tesseract to read text inside screenshots.")
        return ex
    import pytesseract
    gray = img.convert("L")
    scale = 2 if min(gray.size) < 1000 else 1
    if scale > 1:
        gray = gray.resize((gray.width * scale, gray.height * scale), Image.LANCZOS)
    try:
        d = pytesseract.image_to_data(gray, output_type=pytesseract.Output.DICT, timeout=40,
                                      config="--psm 6")
    except Exception:
        ex.warnings.append("OCR failed or timed out; only metadata was scanned.")
        return ex
    lines: dict = {}
    for i, w in enumerate(d["text"]):
        if not w.strip() or float(d["conf"][i]) < 30:
            continue
        key = (d["block_num"][i], d["par_num"][i], d["line_num"][i])
        lines.setdefault(key, []).append((w, d["left"][i], d["top"][i], d["width"][i], d["height"][i]))
    text, pos = [], 0
    for key in sorted(lines):
        for j, (w, x, y, bw, bh) in enumerate(lines[key]):
            if j:
                text.append(" ")
                pos += 1
            ex.words.append({"s": pos, "e": pos + len(w),
                             "box": (x / scale, y / scale, bw / scale, bh / scale)})
            text.append(w)
            pos += len(w)
        text.append("\n")
        pos += 1
    ex.text = "".join(text)
    if not ex.text.strip():
        ex.warnings.append("OCR found no readable text in this image.")
    return ex


def page_of(ex: Extracted, offset: int):
    """(page number 1-based, line number within page) for a PDF offset."""
    for i, (a, b) in enumerate(ex.pages):
        if a <= offset <= b:
            return i + 1, ex.text.count("\n", a, offset) + 1
    return None, None
