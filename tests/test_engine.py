import io

from PIL import Image

from engine import extract, redact, service
from engine.detector import Detector

from .conftest import rnd


def test_redact_text_labels_and_merge():
    out = redact.redact_text("a=SECRET b=OTHER", [(2, 8, "X"), (7, 8, "X"), (11, 16, "Y")])
    assert out == "a=[REDACTED:X] b=[REDACTED:Y]"
    assert "█" in redact.redact_text("pw=hunter22", [(3, 11, "X")], "block")


def test_text_roundtrip_removes_secret_and_rescan_clean(fake):
    src = f'DB_PASSWORD = "{fake["pw"]}"\ngh = "{fake["gh"]}"\nname = "ok"\n'.encode()
    ex, fs = service.analyse("cfg.py", src)
    ids = {f["id"] for f in fs if f["status"] == "active"}
    out, name, applied = service.apply_redaction("text", "cfg.py", src, ex, fs, ids)
    assert fake["pw"].encode() not in out and fake["gh"].encode() not in out
    assert b'name = "ok"' in out and name == "sanitised_cfg.py"
    assert service.rescan(name, out)["active"] == 0


def test_validation_rejects_bad_files():
    import pytest
    for name, data in (("x.exe", b"MZ"), ("x.pdf", b"not a pdf"), ("x.png", b"nope"), ("x.txt", b"\x00\x01\x02" * 50),
                       ("x.txt", b"")):
        with pytest.raises(extract.ScanError):
            extract.extract(name, data)


def test_pdf_extract_redact_and_metadata(fake):
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    c.setAuthor("Asha Nair")
    c.drawString(60, 700, f"Token: {fake['gh']}")
    c.drawString(60, 680, f"Mail {fake['email']}")
    c.showPage(); c.save()
    data = buf.getvalue()
    ex, fs = service.analyse("r.pdf", data)
    types = {f["type"] for f in fs}
    assert {"GITHUB_TOKEN", "EMAIL", "METADATA_AUTHOR"} <= types
    ids = {f["id"] for f in fs if f["status"] == "active" and not f.get("metadata")}
    out, name, _ = service.apply_redaction("pdf", "r.pdf", data, ex, fs, ids)
    ex2 = extract.extract(name, out)
    assert fake["gh"] not in ex2.text and fake["email"] not in ex2.text
    assert not ex2.metadata or all(m["field"] not in ("Author",) for m in ex2.metadata)
    assert "Asha" not in str(ex2.metadata)


def test_image_metadata_stripped_and_boxes_drawn():
    img = Image.new("RGB", (200, 100), "white")
    exif = Image.Exif()
    exif[315] = "Asha Nair"
    exif[0x8825] = {1: "N", 2: (12.0, 58.0, 0.0), 3: "E", 4: (77.0, 35.0, 0.0)}
    buf = io.BytesIO(); img.save(buf, "JPEG", exif=exif)
    ex = extract.extract("p.jpg", buf.getvalue())
    assert {m["type"] for m in ex.metadata} >= {"METADATA_GPS", "METADATA_AUTHOR"}
    out, ext = redact.sanitise_image(buf.getvalue(), [(10, 10, 50, 20)], "jpg")
    clean = Image.open(io.BytesIO(out))
    assert not clean.getexif() and clean.getpixel((20, 20))[0] < 30 and clean.getpixel((150, 80))[0] > 240


def test_ocr_screenshot_end_to_end():
    import pytest
    if not extract.ocr_available():
        pytest.skip("tesseract not installed")
    from PIL import ImageDraw, ImageFont
    try:
        font = ImageFont.truetype("DejaVuSansMono.ttf", 28)
    except OSError:
        font = ImageFont.load_default(size=28)
    img = Image.new("RGB", (900, 140), "white")
    ImageDraw.Draw(img).text((20, 40), "Contact: asha.nair7@quartzmail.net", fill="black", font=font)
    buf = io.BytesIO(); img.save(buf, "PNG")
    ex, fs = service.analyse("s.png", buf.getvalue())
    em = [f for f in fs if f["type"] == "EMAIL"]
    assert em and em[0]["boxes"]
    out, _, _ = service.apply_redaction("image", "s.png", buf.getvalue(), ex, fs, {em[0]["id"]})
    assert not [f for f in service.rescan("s.png", out).get("remaining", []) if f["type"] == "EMAIL"]


def test_ml_never_decides_alone_above_medium():
    d = Detector()
    if not d.use_ml:
        return
    for f in d.scan_text("Wifi password: " + rnd(18)):
        if f["source"] == "ml":
            assert f["level"] != "high" and f["score"] <= 45


def test_overall_score_explained():
    ex, fs = service.analyse("a.txt", b"nothing here")
    assert service.summary(fs)["overall"]["score"] == 0
