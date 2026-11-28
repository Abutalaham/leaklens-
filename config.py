"""LeakLens configuration. Scoring values are illustrative design choices, not
empirically validated risk measurements. Override any base score by creating
instance/scoring.json, e.g. {"EMAIL": 30, "GENERIC_CREDENTIAL": 65}."""
import json
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
_ENV_FILE = BASE_DIR / ".env"
if _ENV_FILE.is_file():
    for _line in _ENV_FILE.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

INSTANCE_DIR = BASE_DIR / "instance"
TMP_DIR = INSTANCE_DIR / "tmp"
DB_PATH = INSTANCE_DIR / "leaklens.db"
MODEL_PATH = BASE_DIR / "models" / "leaklens_model.joblib"
THRESHOLDS_PATH = BASE_DIR / "models" / "thresholds.json"
EVAL_PATH = BASE_DIR / "evaluation" / "metrics.json"

# ---- security & sessions ----
INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
_KEY_FILE = INSTANCE_DIR / "secret_key"
if os.environ.get("SECRET_KEY"):
    SECRET_KEY = os.environ["SECRET_KEY"]
elif _KEY_FILE.exists():
    SECRET_KEY = _KEY_FILE.read_text(encoding="utf-8").strip()
else:
    SECRET_KEY = secrets.token_hex(32)
    try:
        _KEY_FILE.write_text(SECRET_KEY, encoding="utf-8")
    except OSError:
        pass

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_LIFETIME_HOURS = 12
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()

# ---- rate limiting ----
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300  # 5 minutes

# ---- upload limits (free-tier friendly: small, CPU only) ----
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_TEXT_CHARS = 2_000_000
MAX_IMAGE_PIXELS = 40_000_000
MAX_PDF_PAGES = 200
MAX_FINDINGS = 2000
UPLOAD_TTL_SECONDS = 30 * 60          # temp files are deleted after this

TEXT_EXTS = {".txt", ".py", ".js", ".java", ".md", ".json", ".yaml", ".yml", ".env",
             ".ini", ".cfg", ".conf", ".log", ".csv", ".sh", ".ts", ".properties",
             ".xml", ".html", ".toml"}
IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}
PDF_EXTS = {".pdf"}

# ---- risk levels ----
HIGH_AT = 70
MEDIUM_AT = 40

# ---- ML defaults (overridden by models/thresholds.json after tuning) ----
DEFAULT_ML = {"discover": 0.90, "benign": 0.15, "boost": 0.80}

# ---- illustrative base scores per finding type ----
BASE_SCORES = {
    "PRIVATE_KEY": 95, "AWS_ACCESS_KEY": 80, "AWS_SECRET_KEY": 85, "GITHUB_TOKEN": 80,
    "GOOGLE_API_KEY": 75, "SLACK_TOKEN": 80, "STRIPE_KEY": 85, "SENDGRID_KEY": 80,
    "OPENAI_STYLE_KEY": 80, "NPM_TOKEN": 80, "HUGGINGFACE_TOKEN": 75, "JWT": 55,
    "AUTH_HEADER": 65, "CONNECTION_STRING": 75, "GENERIC_CREDENTIAL": 60,
    "TWILIO_KEY": 80, "DISCORD_TOKEN": 75, "GITLAB_PAT": 80, "SUPABASE_KEY": 80,
    "POSTMAN_KEY": 75, "DIGITALOCEAN_TOKEN": 80, "HEROKU_KEY": 80,
    "CREDIT_CARD": 70, "AADHAAR": 65, "SSN": 65, "PAN": 55,
    "EMAIL": 25, "PHONE": 25, "IP_ADDRESS": 15, "INTERNAL_IP": 20,
    "SUSPECTED_SENSITIVE": 40,
    "METADATA_GPS": 50, "METADATA_AUTHOR": 25, "METADATA_DEVICE": 15,
    "METADATA_SOFTWARE": 10, "METADATA_DOCINFO": 10,
}
try:
    BASE_SCORES.update(json.loads((INSTANCE_DIR / "scoring.json").read_text()))
except (OSError, ValueError):
    pass
