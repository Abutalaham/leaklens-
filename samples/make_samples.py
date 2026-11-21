"""Generate demo files containing FAKE secrets/PII (random values; nothing real).
    python samples/make_samples.py
"""
import random
import string
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine.rules import verhoeff_check_digit  # noqa: E402

OUT = Path(__file__).resolve().parent
r = random.Random(2026)
AL = string.ascii_letters + string.digits


def rnd(n, alphabet=AL):
    return "".join(r.choice(alphabet) for _ in range(n))


def aadhaar():
    base = "".join(str(r.randint(2, 9)) if i == 0 else str(r.randint(0, 9)) for i in range(11))
    n = base + verhoeff_check_digit(base)
    return f"{n[:4]} {n[4:8]} {n[8:]}"


GH, AWS, DBPW = "ghp_" + rnd(36), "AKIA" + rnd(16, string.ascii_uppercase + string.digits), rnd(18)
EMAIL, AAD = "meera.rao42@quartzmail.net", aadhaar()


def code():
    (OUT / "demo_app.py").write_text(f'''"""Demo service config (all values are fake)."""
import os

# --- real-looking values that should be flagged ---
DB_PASSWORD = "{DBPW}"
GITHUB_TOKEN = "{GH}"
AWS_ACCESS_KEY_ID = "{AWS}"
DATABASE_URL = "postgres://appuser:{rnd(14)}@db.internal.example-corp.net:5432/orders"
ADMIN_CONTACT = "{EMAIL}"

# --- things that should NOT be treated as real secrets ---
API_KEY = "your_api_key_here"                      # placeholder
SECRET = os.getenv("APP_SECRET")                   # read from environment
password_label = "Enter your password"             # UI text
token_type = "Bearer"                              # config keyword
SUPPORT_EMAIL = "user@example.com"                 # documentation address

def connect():
    password = os.environ["DB_PASSWORD"]
    return password
''', encoding="utf-8")


def notes():
    (OUT / "demo_notes.txt").write_text(f"""Onboarding notes (fake data)
Contact: {EMAIL}
Mobile: +91 98765 43210
Aadhaar: {AAD}
Wifi password: {rnd(16)}
Example config for the docs:  password = "changeme"
""", encoding="utf-8")


def pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    c = canvas.Canvas(str(OUT / "demo_report.pdf"), pagesize=A4)
    c.setAuthor("Meera Rao")
    c.setTitle("Quarterly infra review")
    c.setFont("Helvetica", 12)
    y = 780
    for line in ["Quarterly infrastructure review (fake data)",
                 f"Owner: {EMAIL}   Phone: +91 91234 56789",
                 f"Deploy token: {GH}",
                 "Policy reminder: never email passwords. See the security handbook.",
                 "Example only: api_key = \"<YOUR_API_KEY>\""]:
        c.drawString(50, y, line)
        y -= 24
    c.showPage()
    c.drawString(50, 780, f"Page 2 - billing contact: finance.team@quartzmail.net")
    c.save()


def screenshot():
    try:
        font = ImageFont.truetype("DejaVuSansMono.ttf", 26)
    except OSError:
        font = ImageFont.load_default(size=26)
    img = Image.new("RGB", (1100, 330), "white")
    d = ImageDraw.Draw(img)
    lines = ["# .env", f"API_TOKEN = {GH}", f"Contact: {EMAIL}", "Hello world, nothing secret here"]
    for i, t in enumerate(lines):
        d.text((30, 30 + i * 60), t, fill="black", font=font)
    exif = Image.Exif()
    exif[271], exif[272], exif[315] = "FakeCam", "X100", "Meera Rao"
    exif[0x8825] = {1: "N", 2: (12.0, 58.0, 0.0), 3: "E", 4: (77.0, 35.0, 0.0)}
    img.save(OUT / "demo_screenshot.jpg", "JPEG", quality=95, exif=exif)


if __name__ == "__main__":
    code(); notes(); pdf(); screenshot()
    print("samples written to", OUT)
