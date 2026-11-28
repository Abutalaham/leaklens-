"""SQLite store for user authentication, scan summaries, audit logs, and encrypted vault.
Supports Scrypt + AES-256-GCM encryption, portable .leaklens vaults, and RFC 6238 TOTP 2FA."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import shutil
import sqlite3
import struct
import time
import uuid
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.security import check_password_hash, generate_password_hash

import config


def _db():
    config.INSTANCE_DIR.mkdir(exist_ok=True)
    con = sqlite3.connect(config.DB_PATH)
    con.row_factory = sqlite3.Row

    # Scans table
    con.execute("""CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY, created REAL, filename TEXT, kind TEXT, size INTEGER,
        score INTEGER, level TEXT, high INTEGER, medium INTEGER, low INTEGER, redacted INTEGER DEFAULT 0,
        user_id TEXT, findings_json TEXT)""")

    try:
        con.execute("ALTER TABLE scans ADD COLUMN user_id TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        con.execute("ALTER TABLE scans ADD COLUMN findings_json TEXT")
    except sqlite3.OperationalError:
        pass

    # Users table
    con.execute("""CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        status TEXT NOT NULL DEFAULT 'active',
        created_at REAL NOT NULL,
        last_login REAL,
        totp_secret TEXT,
        totp_enabled INTEGER DEFAULT 0,
        recovery_codes TEXT
    )""")

    try:
        con.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        con.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        con.execute("ALTER TABLE users ADD COLUMN recovery_codes TEXT")
    except sqlite3.OperationalError:
        pass

    # Rate limiting table
    con.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        username TEXT,
        timestamp REAL NOT NULL,
        success INTEGER NOT NULL
    )""")

    # 2FA Temporary Login Tokens table
    con.execute("""CREATE TABLE IF NOT EXISTS twofa_temp_tokens (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at REAL NOT NULL,
        used INTEGER DEFAULT 0
    )""")

    # Password resets table
    con.execute("""CREATE TABLE IF NOT EXISTS password_resets (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at REAL NOT NULL,
        used INTEGER DEFAULT 0
    )""")

    # Vault table (encrypted credentials)
    con.execute("""CREATE TABLE IF NOT EXISTS user_vault (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        key_name TEXT NOT NULL,
        provider TEXT,
        masked_preview TEXT NOT NULL,
        encrypted_value TEXT NOT NULL,
        created_at REAL NOT NULL
    )""")

    # Audit logs
    con.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        action TEXT NOT NULL,
        ip_address TEXT,
        timestamp REAL NOT NULL,
        details TEXT
    )""")

    # Human feedback on findings (false positives / missed secrets). Notes must not contain raw secrets.
    con.execute("""CREATE TABLE IF NOT EXISTS feedback (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        scan_id TEXT,
        finding_id TEXT,
        finding_type TEXT,
        provider TEXT,
        kind TEXT NOT NULL,
        note TEXT,
        created_at REAL NOT NULL
    )""")

    # API Tokens (Personal Access Tokens - PATs)
    con.execute("""CREATE TABLE IF NOT EXISTS api_tokens (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        token_prefix TEXT NOT NULL,
        token_last4 TEXT NOT NULL,
        scopes TEXT NOT NULL DEFAULT 'read,scan',
        created_at REAL NOT NULL,
        expires_at REAL,
        last_used REAL,
        status TEXT NOT NULL DEFAULT 'active'
    )""")

    # External OAuth / Identity Provider mappings (e.g., Google 'sub')
    con.execute("""CREATE TABLE IF NOT EXISTS user_identities (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_sub TEXT NOT NULL,
        email TEXT,
        email_verified INTEGER DEFAULT 0,
        created_at REAL NOT NULL,
        UNIQUE(provider, provider_sub)
    )""")

    # Short-lived single-use tokens for password-verified account linking
    con.execute("""CREATE TABLE IF NOT EXISTS oauth_link_tokens (
        token TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        provider_sub TEXT NOT NULL,
        email TEXT NOT NULL,
        email_verified INTEGER DEFAULT 0,
        expires_at REAL NOT NULL,
        used INTEGER DEFAULT 0
    )""")

    return con


# ----------------------------------------------------------------- Authentication
def create_user(username: str, email: str, password: str, role: str = "user") -> dict:
    username = username.strip().lower()
    email = email.strip().lower()
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not username or not email:
        raise ValueError("Username and email are required.")

    user_id = uuid.uuid4().hex
    pwhash = generate_password_hash(password)
    now = time.time()

    with _db() as con:
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, status, created_at, totp_enabled) VALUES (?,?,?,?,?,?,?,0)",
            (user_id, username, email, pwhash, role, "active", now),
        )
    return get_user_by_id(user_id)


def get_user_by_id(user_id: str) -> Optional[dict]:
    with _db() as con:
        row = con.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_user_by_username_or_email(ident: str) -> Optional[dict]:
    ident = (ident or "").strip().lower()
    with _db() as con:
        row = con.execute(
            "SELECT * FROM users WHERE username=? OR email=?", (ident, ident)
        ).fetchone()
        return dict(row) if row else None


def verify_user_password(user: dict, password: str) -> bool:
    if not user or not user.get("password_hash"):
        return False
    return check_password_hash(user["password_hash"], password)


def update_last_login(user_id: str):
    with _db() as con:
        con.execute("UPDATE users SET last_login=? WHERE id=?", (time.time(), user_id))


def update_user_password(user_id: str, new_password: str):
    if len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    pwhash = generate_password_hash(new_password)
    with _db() as con:
        con.execute("UPDATE users SET password_hash=? WHERE id=?", (pwhash, user_id))


def update_user_profile(user_id: str, username: str, email: str):
    username = username.strip().lower()
    email = email.strip().lower()
    with _db() as con:
        con.execute(
            "UPDATE users SET username=?, email=? WHERE id=?", (username, email, user_id)
        )


def list_users() -> list[dict]:
    with _db() as con:
        rows = con.execute(
            "SELECT id, username, email, role, status, created_at, last_login, totp_enabled FROM users ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def update_user_status(user_id: str, status: str):
    if status not in ("active", "disabled"):
        raise ValueError("Invalid status.")
    with _db() as con:
        con.execute("UPDATE users SET status=? WHERE id=?", (status, user_id))


def delete_user(user_id: str):
    with _db() as con:
        con.execute("DELETE FROM users WHERE id=?", (user_id,))
        con.execute("DELETE FROM user_identities WHERE user_id=?", (user_id,))
        con.execute("DELETE FROM scans WHERE user_id=?", (user_id,))
        con.execute("DELETE FROM user_vault WHERE user_id=?", (user_id,))
        con.execute("DELETE FROM twofa_temp_tokens WHERE user_id=?", (user_id,))


# ----------------------------------------------------------------- External Identity Linking
def get_user_by_identity(provider: str, provider_sub: str) -> Optional[dict]:
    provider = (provider or "").strip().lower()
    provider_sub = (provider_sub or "").strip()
    if not provider or not provider_sub:
        return None
    with _db() as con:
        row = con.execute(
            """SELECT u.* FROM users u
               JOIN user_identities ui ON ui.user_id = u.id
               WHERE ui.provider=? AND ui.provider_sub=?""",
            (provider, provider_sub),
        ).fetchone()
        return dict(row) if row else None


def link_user_identity(
    user_id: str, provider: str, provider_sub: str, email: Optional[str], email_verified: bool
) -> dict:
    provider = (provider or "").strip().lower()
    provider_sub = (provider_sub or "").strip()
    clean_email = (email or "").strip().lower() or None
    if not user_id or not provider or not provider_sub:
        raise ValueError("Invalid identity linking parameters.")
    ident_id = uuid.uuid4().hex
    now = time.time()
    with _db() as con:
        existing = con.execute(
            "SELECT user_id FROM user_identities WHERE provider=? AND provider_sub=?",
            (provider, provider_sub),
        ).fetchone()
        if existing:
            if existing["user_id"] != user_id:
                raise ValueError("This external identity is already linked to another account.")
            return {"id": ident_id, "user_id": user_id, "provider": provider, "provider_sub": provider_sub}
        con.execute(
            """INSERT INTO user_identities (id, user_id, provider, provider_sub, email, email_verified, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (ident_id, user_id, provider, provider_sub, clean_email, 1 if email_verified else 0, now),
        )
    return {"id": ident_id, "user_id": user_id, "provider": provider, "provider_sub": provider_sub}


def _unique_username(con: sqlite3.Connection, seed: str) -> str:
    base = re.sub(r"[^a-z0-9_]", "_", (seed or "user").strip().lower()).strip("_")
    if len(base) < 3:
        base = f"user_{base or 'll'}"
    base = base[:24]
    candidate = base
    suffix = 1
    while con.execute("SELECT 1 FROM users WHERE username=?", (candidate,)).fetchone():
        suffix += 1
        candidate = f"{base[:20]}_{suffix}"
    return candidate


def create_google_user(email: str, name: str, provider_sub: str, email_verified: bool) -> dict:
    email = (email or "").strip().lower()
    provider_sub = (provider_sub or "").strip()
    if not email or not provider_sub or not email_verified:
        raise ValueError("Verified email and Google subject are required.")

    user_id = uuid.uuid4().hex
    ident_id = uuid.uuid4().hex
    # Non-loginable random password hash; user can set a password later via profile/reset.
    pwhash = generate_password_hash(secrets.token_urlsafe(48))
    now = time.time()
    seed = name or email.split("@")[0]

    with _db() as con:
        if con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise ValueError("An account with this email already exists.")
        if con.execute("SELECT 1 FROM user_identities WHERE provider='google' AND provider_sub=?", (provider_sub,)).fetchone():
            raise ValueError("This Google account is already linked.")
        username = _unique_username(con, seed)
        con.execute(
            "INSERT INTO users (id, username, email, password_hash, role, status, created_at, totp_enabled) VALUES (?,?,?,?,?,?,?,0)",
            (user_id, username, email, pwhash, "user", "active", now),
        )
        con.execute(
            """INSERT INTO user_identities (id, user_id, provider, provider_sub, email, email_verified, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (ident_id, user_id, "google", provider_sub, email, 1, now),
        )
    return get_user_by_id(user_id)


def create_oauth_link_token(provider: str, provider_sub: str, email: str, email_verified: bool) -> str:
    token = secrets.token_urlsafe(32)
    expires = time.time() + 300  # 5 minutes
    with _db() as con:
        con.execute(
            """INSERT INTO oauth_link_tokens (token, provider, provider_sub, email, email_verified, expires_at, used)
               VALUES (?,?,?,?,?,?,0)""",
            (token, provider, provider_sub, email.strip().lower(), 1 if email_verified else 0, expires),
        )
    return token


def consume_oauth_link_token(token: str) -> Optional[dict]:
    with _db() as con:
        row = con.execute(
            "SELECT * FROM oauth_link_tokens WHERE token=?", (token,)
        ).fetchone()
        if not row or row["used"] or time.time() > row["expires_at"]:
            return None
        con.execute("UPDATE oauth_link_tokens SET used=1 WHERE token=?", (token,))
        return dict(row)


# ----------------------------------------------------------------- Rate limiting
def record_login_attempt(ip: str, username: str, success: bool):
    with _db() as con:
        con.execute(
            "INSERT INTO login_attempts (ip, username, timestamp, success) VALUES (?,?,?,?)",
            (ip or "unknown", username or "", time.time(), 1 if success else 0),
        )


def is_rate_limited(ip: str, username: str) -> bool:
    cutoff = time.time() - config.LOGIN_LOCKOUT_SECONDS
    with _db() as con:
        row = con.execute(
            "SELECT COUNT(*) as cnt FROM login_attempts WHERE (ip=? OR username=?) AND timestamp > ? AND success=0",
            (ip or "unknown", username or "", cutoff),
        ).fetchone()
        return bool(row and row["cnt"] >= config.LOGIN_MAX_ATTEMPTS)


# ----------------------------------------------------------------- TOTP 2FA (RFC 6238)
def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").rstrip("=")


def generate_recovery_codes(count: int = 8) -> tuple[list[str], list[str]]:
    plain = [f"{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}" for _ in range(count)]
    hashed = [hashlib.sha256(c.replace("-", "").strip().lower().encode("utf-8")).hexdigest() for c in plain]
    return plain, hashed


def get_totp_token(secret_b32: str, intervals_no: int) -> int:
    pad = (8 - len(secret_b32) % 8) % 8
    key = base64.b32decode(secret_b32 + "=" * pad, casefold=True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    return (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000


def verify_totp(secret_b32: str, token_str: str, window: int = 1) -> bool:
    try:
        tok = str(token_str).strip()
        if len(tok) != 6 or not tok.isdigit():
            return False
        cur = int(time.time() // 30)
        return any(f"{get_totp_token(secret_b32, cur + i):06d}" == tok for i in range(-window, window + 1))
    except Exception:
        return False


def verify_recovery_code(user_id: str, code_str: str) -> bool:
    clean = code_str.replace("-", "").strip().lower()
    chash = hashlib.sha256(clean.encode("utf-8")).hexdigest()
    user = get_user_by_id(user_id)
    if not user or not user.get("recovery_codes"):
        return False
    try:
        codes = json.loads(user["recovery_codes"])
    except Exception:
        return False
    if chash in codes:
        codes.remove(chash)
        with _db() as con:
            con.execute("UPDATE users SET recovery_codes=? WHERE id=?", (json.dumps(codes), user_id))
        return True
    return False


def enable_2fa(user_id: str, secret: str, hashed_recovery_codes: list[str]):
    with _db() as con:
        con.execute(
            "UPDATE users SET totp_secret=?, totp_enabled=1, recovery_codes=? WHERE id=?",
            (secret, json.dumps(hashed_recovery_codes), user_id),
        )


def disable_2fa(user_id: str):
    with _db() as con:
        con.execute(
            "UPDATE users SET totp_secret=NULL, totp_enabled=0, recovery_codes=NULL WHERE id=?",
            (user_id,),
        )


def create_2fa_temp_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = time.time() + 300  # 5 minutes validity
    with _db() as con:
        con.execute(
            "INSERT INTO twofa_temp_tokens (token, user_id, expires_at, used) VALUES (?,?,?,0)",
            (token, user_id, expires),
        )
    return token


def verify_2fa_temp_token(token: str) -> Optional[str]:
    with _db() as con:
        row = con.execute(
            "SELECT user_id, expires_at, used FROM twofa_temp_tokens WHERE token=?", (token,)
        ).fetchone()
        if not row or row["used"] or time.time() > row["expires_at"]:
            return None
        con.execute("UPDATE twofa_temp_tokens SET used=1 WHERE token=?", (token,))
        return row["user_id"]


# ----------------------------------------------------------------- Password reset
def create_password_reset(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = time.time() + 3600  # 1 hour
    with _db() as con:
        con.execute(
            "INSERT INTO password_resets (token, user_id, expires_at, used) VALUES (?,?,?,0)",
            (token, user_id, expires),
        )
    return token


def verify_reset_token(token: str) -> Optional[str]:
    with _db() as con:
        row = con.execute(
            "SELECT user_id, expires_at, used FROM password_resets WHERE token=?", (token,)
        ).fetchone()
        if not row or row["used"] or time.time() > row["expires_at"]:
            return None
        return row["user_id"]


def use_password_reset(token: str, new_password: str) -> bool:
    user_id = verify_reset_token(token)
    if not user_id:
        return False
    update_user_password(user_id, new_password)
    with _db() as con:
        con.execute("UPDATE password_resets SET used=1 WHERE token=?", (token,))
    return True


# ----------------------------------------------------------------- Audit logs
def record_audit(user_id: Optional[str], action: str, ip: str, details: str = ""):
    with _db() as con:
        con.execute(
            "INSERT INTO audit_logs (user_id, action, ip_address, timestamp, details) VALUES (?,?,?,?,?)",
            (user_id, action, ip or "127.0.0.1", time.time(), details[:500]),
        )


def get_audit_logs(limit: int = 50) -> list[dict]:
    with _db() as con:
        rows = con.execute(
            """SELECT a.*, u.username FROM audit_logs a
               LEFT JOIN users u ON a.user_id = u.id
               ORDER BY a.timestamp DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ----------------------------------------------------------------- Scan records
def _safe_history_findings(findings: list[dict]) -> list[dict]:
    return [{
        "id": finding.get("id"),
        "type": finding.get("type"),
        "label": finding.get("label"),
        "category": finding.get("category"),
        "provider": finding.get("provider", "Generic"),
        "level": finding.get("level"),
        "status": finding.get("status"),
        "line": finding.get("line"),
        "preview": finding.get("preview"),
        "key": finding.get("key"),
        "blast_radius": finding.get("blast_radius") or "",
    } for finding in findings]


def _decode_history_findings(raw_findings: Optional[str]) -> tuple[list[dict], bool]:
    if raw_findings is None:
        return [], False
    try:
        findings = json.loads(raw_findings)
    except (TypeError, ValueError):
        return [], False
    valid_findings = isinstance(findings, list) and all(isinstance(finding, dict) for finding in findings)
    return (findings, True) if valid_findings else ([], False)


def _history_finding_counts(findings: list[dict], redacted: int, *,
                            data_available: bool) -> dict:
    if not data_available:
        return {
            "total": None,
            "active_total": None,
            "active_high": None,
            "active_medium": None,
            "active_low": None,
            "redacted": redacted,
            "placeholder": None,
            "likely_benign": None,
            "unclassified": None,
            "status_available": False,
        }

    recognized_statuses = {"active", "placeholder", "likely_benign", "redacted"}
    statuses_valid = all(finding.get("status") in recognized_statuses for finding in findings)
    redacted_count = sum(1 for finding in findings if finding.get("status") == "redacted")
    status_available = statuses_valid and redacted_count == redacted
    total = len(findings)
    if not status_available:
        return {
            "total": total,
            "active_total": None,
            "active_high": None,
            "active_medium": None,
            "active_low": None,
            "redacted": redacted,
            "placeholder": None,
            "likely_benign": None,
            "unclassified": None,
            "status_available": False,
        }

    active = [finding for finding in findings if finding["status"] == "active"]
    active_high = sum(1 for finding in active if finding.get("level") == "high")
    active_medium = sum(1 for finding in active if finding.get("level") == "medium")
    active_low = sum(1 for finding in active if finding.get("level") == "low")
    placeholder = sum(1 for finding in findings if finding["status"] == "placeholder")
    likely_benign = sum(1 for finding in findings if finding["status"] == "likely_benign")
    redacted_count = sum(1 for finding in findings if finding["status"] == "redacted")
    unclassified = total - active_high - active_medium - active_low - placeholder - likely_benign - redacted_count
    return {
        "total": total,
        "active_total": len(active),
        "active_high": active_high,
        "active_medium": active_medium,
        "active_low": active_low,
        "redacted": redacted_count,
        "placeholder": placeholder,
        "likely_benign": likely_benign,
        "unclassified": unclassified,
        "status_available": True,
    }


def record_scan(scan_id: str, filename: str, kind: str, size: int, summ: dict,
                user_id: Optional[str] = None, findings: Optional[list] = None):
    safe_findings = _safe_history_findings(findings or [])
    f_json = json.dumps(safe_findings)

    with _db() as con:
        con.execute(
            """INSERT OR REPLACE INTO scans
               (id, created, filename, kind, size, score, level, high, medium, low, redacted, user_id, findings_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?)""",
            (scan_id, time.time(), filename, kind, size, summ["overall"]["score"],
             summ["overall"]["level"], summ["high"], summ["medium"], summ["low"],
             user_id, f_json),
        )


def record_redaction(scan_id: str, redacted_ids: list[str], findings: list[dict]):
    selected_ids = {str(finding_id) for finding_id in redacted_ids}
    stored_findings = _safe_history_findings(findings)
    recorded_ids = set()
    for finding in stored_findings:
        if finding.get("id") in selected_ids:
            finding["status"] = "redacted"
            recorded_ids.add(finding["id"])
    if recorded_ids != selected_ids:
        raise ValueError("Redacted finding IDs do not match the stored scan findings.")

    with _db() as con:
        con.execute(
            "UPDATE scans SET redacted=?, findings_json=? WHERE id=?",
            (len(recorded_ids), json.dumps(stored_findings), scan_id),
        )


def get_scan(scan_id: str) -> Optional[dict]:
    with _db() as con:
        row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None


def delete_scan_record(scan_id: str):
    with _db() as con:
        con.execute("DELETE FROM scans WHERE id=?", (scan_id,))


def history(limit: int = 30) -> list[dict]:
    with _db() as con:
        return [dict(r) for r in con.execute("SELECT * FROM scans ORDER BY created DESC LIMIT ?", (limit,))]


def user_history(user_id: str, limit: int = 50, risk_level: Optional[str] = None,
                 kind: Optional[str] = None, search: Optional[str] = None) -> list[dict]:
    query = "SELECT * FROM scans WHERE user_id=?"
    params = [user_id]
    if risk_level:
        query += " AND level=?"
        params.append(risk_level)
    if kind:
        query += " AND kind=?"
        params.append(kind)
    if search:
        query += " AND filename LIKE ?"
        params.append(f"%{search}%")
    query += " ORDER BY created DESC LIMIT ?"
    params.append(limit)

    with _db() as con:
        rows = con.execute(query, tuple(params)).fetchall()
        res = []
        for r in rows:
            d = dict(r)
            if d.get("findings_json"):
                try:
                    d["findings"] = json.loads(d["findings_json"])
                except Exception:
                    d["findings"] = []
            else:
                d["findings"] = []
            res.append(d)
        return res


def user_history_page(user_id: str, *, risk_level: Optional[str] = None,
                      file_format: Optional[str] = None, search: Optional[str] = None,
                      days: int = 0, sort: str = "newest", page: int = 1,
                      per_page: int = 10) -> dict:
    filters = ["user_id=?"]
    params: list = [user_id]
    if risk_level:
        filters.append("LOWER(level)=?")
        params.append(risk_level.lower())
    if file_format:
        filters.append("LOWER(filename) LIKE ?")
        params.append(f"%.{file_format.lower()}")
    if search:
        filters.append("instr(LOWER(filename), LOWER(?)) > 0")
        params.append(search)
    if days:
        filters.append("created>=?")
        params.append(int(time.time()) - days * 86400)

    where = " AND ".join(filters)
    order_by = {
        "newest": "created DESC",
        "oldest": "created ASC",
        "highest": "score DESC, created DESC",
        "lowest": "score ASC, created DESC",
        "filename": "filename COLLATE NOCASE ASC, created DESC",
    }.get(sort, "created DESC")

    with _db() as con:
        summary = con.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN LOWER(level)='high' THEN 1 ELSE 0 END) AS high_risk,
                      SUM(CASE WHEN redacted>0 THEN 1 ELSE 0 END) AS sanitised
               FROM scans WHERE user_id=?""",
            (user_id,),
        ).fetchone()
        total = con.execute(f"SELECT COUNT(*) FROM scans WHERE {where}", tuple(params)).fetchone()[0]
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, pages)
        rows = con.execute(
            f"""SELECT id, created, filename, kind, size, score, level, high, medium, low, redacted,
                       findings_json
                FROM scans WHERE {where}
                ORDER BY {order_by}, id ASC LIMIT ? OFFSET ?""",
            tuple(params + [per_page, (page - 1) * per_page]),
        ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        raw_findings = item.pop("findings_json", None)
        findings, data_available = _decode_history_findings(raw_findings)
        item["finding_counts"] = _history_finding_counts(
            findings, item["redacted"], data_available=data_available,
        )
        items.append(item)
    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
        "summary": {
            "total": summary["total"] or 0,
            "high_risk": summary["high_risk"] or 0,
            "sanitised": summary["sanitised"] or 0,
        },
    }


def user_history_detail(user_id: str, scan_id: str) -> Optional[dict]:
    with _db() as con:
        row = con.execute(
            """SELECT id, created, filename, kind, size, score, level, high, medium, low,
                      redacted, findings_json
               FROM scans WHERE id=? AND user_id=?""",
            (scan_id, user_id),
        ).fetchone()
    if not row:
        return None
    result = dict(row)
    raw_findings = result.pop("findings_json", None)
    result["findings"], data_available = _decode_history_findings(raw_findings)
    result["finding_counts"] = _history_finding_counts(
        result["findings"], result["redacted"], data_available=data_available,
    )
    return result


def user_dashboard_stats(user_id: str, days: int = 0) -> dict:
    with _db() as con:
        rows = con.execute("SELECT * FROM scans WHERE user_id=?", (user_id,)).fetchall()
        total_files = len(rows)
        high = sum(r["high"] for r in rows)
        medium = sum(r["medium"] for r in rows)
        low = sum(r["low"] for r in rows)
        sanitised = sum(1 for r in rows if r["redacted"] > 0)
        total_findings = high + medium + low

        active_findings = 0
        for r in rows:
            raw = r["findings_json"]
            if not raw:
                continue
            try:
                findings = json.loads(raw)
            except (TypeError, ValueError):
                continue
            active_findings += sum(1 for f in findings if f.get("status") in (None, "", "active"))

        cutoff = int(time.time()) - (days * 86400) if days else None
        trend_rows = [r for r in rows if cutoff is None or r["created"] >= cutoff]
        period_files = len(trend_rows)
        period_high = sum(r["high"] for r in trend_rows)
        period_medium = sum(r["medium"] for r in trend_rows)
        period_low = sum(r["low"] for r in trend_rows)
        period_findings = period_high + period_medium + period_low

        if cutoff is None:
            recent = con.execute(
                """SELECT strftime('%Y-%m-%d', datetime(created, 'unixepoch')) as day,
                          SUM(high) as h, SUM(medium) as m, SUM(low) as l, COUNT(*) as files
                   FROM scans WHERE user_id=?
                   GROUP BY day ORDER BY day DESC LIMIT 14""",
                (user_id,),
            ).fetchall()
        else:
            recent = con.execute(
                """SELECT strftime('%Y-%m-%d', datetime(created, 'unixepoch')) as day,
                          SUM(high) as h, SUM(medium) as m, SUM(low) as l, COUNT(*) as files
                   FROM scans WHERE user_id=? AND created>=?
                   GROUP BY day ORDER BY day DESC LIMIT ?""",
                (user_id, cutoff, days),
            ).fetchall()

        providers: dict[str, int] = {}
        categories: dict[str, int] = {}
        for r in rows:
            raw = r["findings_json"]
            if not raw:
                continue
            try:
                items = json.loads(raw)
            except (TypeError, ValueError):
                continue
            for f in items:
                if f.get("status") not in (None, "", "active"):
                    continue
                prov = (f.get("provider") or "Generic").strip() or "Generic"
                cat = (f.get("category") or "General").strip() or "General"
                providers[prov] = providers.get(prov, 0) + 1
                categories[cat] = categories.get(cat, 0) + 1

        def _ranked(counter: dict, key: str) -> list[dict]:
            ranked = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0].lower()))
            return [{key: name, "count": count} for name, count in ranked[:12]]

        return {
            "total_files": total_files,
            "total_findings": total_findings,
            "active_findings": active_findings,
            "high": high,
            "medium": medium,
            "low": low,
            "sanitised": sanitised,
            "period_files": period_files,
            "period_findings": period_findings,
            "period_high": period_high,
            "period_medium": period_medium,
            "period_low": period_low,
            "trends": [dict(r) for r in reversed(recent)],
            "providers": _ranked(providers, "provider"),
            "categories": _ranked(categories, "category"),
        }


def clear_user_history(user_id: str):
    with _db() as con:
        con.execute("DELETE FROM scans WHERE user_id=?", (user_id,))


def clear_history():
    with _db() as con:
        con.execute("DELETE FROM scans")


# ----------------------------------------------------------------- Admin stats
def admin_system_stats() -> dict:
    with _db() as con:
        user_rows = con.execute("SELECT status, role, COUNT(*) as cnt FROM users GROUP BY status, role").fetchall()
        total_users = sum(r["cnt"] for r in user_rows)
        active_users = sum(r["cnt"] for r in user_rows if r["status"] == "active")
        disabled_users = sum(r["cnt"] for r in user_rows if r["status"] == "disabled")

        scan_row = con.execute(
            """SELECT COUNT(*) as total_scans,
                      COALESCE(SUM(high), 0) as total_high,
                      COALESCE(SUM(medium), 0) as total_medium,
                      COALESCE(SUM(low), 0) as total_low,
                      COALESCE(SUM(redacted), 0) as total_redactions
               FROM scans"""
        ).fetchone()

        db_size_bytes = config.DB_PATH.stat().st_size if config.DB_PATH.exists() else 0
        tmp_size_bytes = 0
        tmp_count = 0
        if config.TMP_DIR.exists():
            for item in config.TMP_DIR.rglob("*"):
                if item.is_file():
                    try:
                        tmp_size_bytes += item.stat().st_size
                        tmp_count += 1
                    except OSError:
                        pass

        return {
            "users": {
                "total": total_users,
                "active": active_users,
                "disabled": disabled_users,
            },
            "scans": {
                "total": scan_row["total_scans"] if scan_row else 0,
                "high": scan_row["total_high"] if scan_row else 0,
                "medium": scan_row["total_medium"] if scan_row else 0,
                "low": scan_row["total_low"] if scan_row else 0,
                "redactions": scan_row["total_redactions"] if scan_row else 0,
            },
            "storage": {
                "db_mb": round(db_size_bytes / (1024 * 1024), 2),
                "tmp_mb": round(tmp_size_bytes / (1024 * 1024), 2),
                "tmp_items": tmp_count,
            },
        }


# ----------------------------------------------------------------- Vault (Scrypt + AES-256-GCM)
def _scrypt_key(secret: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        secret.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        maxmem=0,
        dklen=32,
    )


def _encrypt_vault_value(user_id: str, plaintext: str) -> str:
    salt = secrets.token_bytes(16)
    key = _scrypt_key(f"{config.SECRET_KEY}:{user_id}", salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # Standard 96-bit GCM nonce
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Binary format: \x02 + salt(16) + nonce(12) + ct_with_tag
    payload = b"\x02" + salt + nonce + ct
    return base64.b64encode(payload).decode("ascii")


def _decrypt_vault_value(user_id: str, encoded: str) -> str:
    raw = base64.b64decode(encoded.encode("ascii"))
    if raw.startswith(b"\x02"):
        salt = raw[1:17]
        nonce = raw[17:29]
        ct = raw[29:]
        key = _scrypt_key(f"{config.SECRET_KEY}:{user_id}", salt)
        aesgcm = AESGCM(key)
        try:
            pt = aesgcm.decrypt(nonce, ct, None)
            return pt.decode("utf-8")
        except Exception:
            raise ValueError("Decryption failed. Authentication tag mismatch or corrupted ciphertext.")
    else:
        # Legacy backward-compatibility fallback
        salt, tag, ct = raw[:16], raw[16:32], raw[32:]
        key = hashlib.pbkdf2_hmac("sha256", f"{config.SECRET_KEY}:{user_id}".encode("utf-8"), salt, 100000, dklen=32)
        expected_tag = hmac.new(key, salt + ct, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            raise ValueError("Invalid vault ciphertext integrity tag.")
        keystream = bytearray()
        counter = 0
        while len(keystream) < len(ct):
            keystream.extend(hmac.new(key, counter.to_bytes(4, "big"), hashlib.sha256).digest())
            counter += 1
        pt = bytes(b ^ k for b, k in zip(ct, keystream[:len(ct)]))
        return pt.decode("utf-8")


def vault_add_item(user_id: str, key_name: str, provider: str, masked_preview: str, raw_value: str) -> dict:
    item_id = uuid.uuid4().hex
    enc = _encrypt_vault_value(user_id, raw_value)
    now = time.time()
    with _db() as con:
        con.execute(
            "INSERT INTO user_vault (id, user_id, key_name, provider, masked_preview, encrypted_value, created_at) VALUES (?,?,?,?,?,?,?)",
            (item_id, user_id, key_name.strip(), provider.strip(), masked_preview.strip(), enc, now),
        )
    return {"id": item_id, "key_name": key_name, "provider": provider, "masked_preview": masked_preview, "created_at": now}


def vault_list_items(user_id: str) -> list[dict]:
    with _db() as con:
        rows = con.execute(
            "SELECT id, key_name, provider, masked_preview, created_at FROM user_vault WHERE user_id=? ORDER BY created_at DESC",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def vault_get_all_raw(user_id: str) -> list[dict]:
    with _db() as con:
        rows = con.execute(
            "SELECT id, key_name, provider, masked_preview, encrypted_value FROM user_vault WHERE user_id=?",
            (user_id,),
        ).fetchall()
        items = []
        for r in rows:
            try:
                decrypted = _decrypt_vault_value(user_id, r["encrypted_value"])
            except Exception as exc:
                raise ValueError("A saved vault item could not be decrypted; export was stopped.") from exc
            items.append({
                "id": r["id"],
                "key_name": r["key_name"],
                "provider": r["provider"],
                "masked_preview": r["masked_preview"],
                "value": decrypted,
            })
        return items


def vault_delete_item(user_id: str, item_id: str):
    with _db() as con:
        con.execute("DELETE FROM user_vault WHERE id=? AND user_id=?", (item_id, user_id))


# ----------------------------------------------------------------- Portable .leaklens Vault
_VAULT_MAGIC = b"LEAKLENS_VAULT\x01"
_PORTABLE_VAULT_MAX_ITEMS = 500
_PORTABLE_VAULT_MAX_VALUE_LENGTH = 16_384


def export_portable_vault(user_id: str, export_password: str) -> bytes:
    if not isinstance(export_password, str) or len(export_password) < 8:
        raise ValueError("Export password must be at least 8 characters long.")
    raw_items = vault_get_all_raw(user_id)
    if len(raw_items) > _PORTABLE_VAULT_MAX_ITEMS:
        raise ValueError("Vault contains too many entries for a portable export.")
    for item in raw_items:
        if (not isinstance(item["key_name"], str)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", item["key_name"])
                or not isinstance(item["provider"], str) or len(item["provider"]) > 64
                or any(ord(char) < 32 for char in item["provider"])
                or not isinstance(item["value"], str) or not item["value"]
                or len(item["value"]) > _PORTABLE_VAULT_MAX_VALUE_LENGTH):
            raise ValueError("A saved vault item is invalid for portable export.")
    payload_data = {
        "format": "leaklens-portable-vault",
        "version": 1,
        "exported_at": time.time(),
        "item_count": len(raw_items),
        "items": [
            {
                "key_name": it["key_name"],
                "provider": it["provider"],
                "masked_preview": it["masked_preview"],
                "value": it["value"],
            }
            for it in raw_items
        ],
    }
    raw_bytes = json.dumps(payload_data).encode("utf-8")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _scrypt_key(export_password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, raw_bytes, None)
    return _VAULT_MAGIC + salt + nonce + ct


def import_portable_vault(user_id: str, import_password: str, file_bytes: bytes) -> dict:
    if not isinstance(import_password, str) or not import_password:
        raise ValueError("Vault password is required.")
    if not isinstance(file_bytes, bytes) or len(file_bytes) > config.MAX_UPLOAD_BYTES:
        raise ValueError("Vault file is invalid or exceeds the supported size.")
    if not file_bytes.startswith(_VAULT_MAGIC):
        raise ValueError("Invalid .leaklens vault file header signature.")
    magic_len = len(_VAULT_MAGIC)
    if len(file_bytes) < magic_len + 16 + 12 + 16:
        raise ValueError("Invalid .leaklens vault file.")
    salt = file_bytes[magic_len : magic_len + 16]
    nonce = file_bytes[magic_len + 16 : magic_len + 28]
    ct = file_bytes[magic_len + 28 :]

    key = _scrypt_key(import_password, salt)
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception:
        raise ValueError("Decryption failed. Incorrect password or corrupted vault file.")

    try:
        data = json.loads(pt.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Vault payload is malformed.") from exc
    if (not isinstance(data, dict) or data.get("format") != "leaklens-portable-vault"
            or type(data.get("version")) is not int or data.get("version") != 1):
        raise ValueError("Unsupported .leaklens vault format.")
    items = data.get("items")
    if (not isinstance(items, list) or len(items) > _PORTABLE_VAULT_MAX_ITEMS
            or type(data.get("item_count")) is not int or data.get("item_count") != len(items)):
        raise ValueError("Vault payload has an invalid item list.")

    validated_items = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Vault payload contains an invalid entry.")
        key_name = item.get("key_name")
        provider = item.get("provider", "Generic")
        value = item.get("value")
        if (not isinstance(key_name, str) or not key_name.strip() or len(key_name) > 128
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key_name.strip())
                or not isinstance(provider, str) or len(provider) > 64
                or any(ord(char) < 32 for char in provider)
                or not isinstance(value, str) or not value
                or len(value) > _PORTABLE_VAULT_MAX_VALUE_LENGTH):
            raise ValueError("Vault payload contains an invalid entry.")
        validated_items.append((key_name.strip(), provider.strip() or "Generic", value))

    now = time.time()
    encrypted_items = [
        (uuid.uuid4().hex, user_id, key_name, provider, "••••",
         _encrypt_vault_value(user_id, value), now)
        for key_name, provider, value in validated_items
    ]
    with _db() as con:
        con.executemany(
            """INSERT INTO user_vault
               (id, user_id, key_name, provider, masked_preview, encrypted_value, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            encrypted_items,
        )
    return {"success": True, "imported_count": len(encrypted_items)}


# ----------------------------------------------------------------- API Tokens (PATs)
def create_api_token(user_id: str, name: str, expires_days: Optional[int] = 30, scopes: str = "read,scan") -> tuple[dict, str]:
    token_id = uuid.uuid4().hex
    raw_token = f"pat_{secrets.token_hex(20)}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    token_prefix = raw_token[:8]
    token_last4 = raw_token[-4:]
    now = time.time()
    expires_at = (now + (expires_days * 86400)) if expires_days and expires_days > 0 else None

    with _db() as con:
        con.execute(
            """INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, token_last4, scopes, created_at, expires_at, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')""",
            (token_id, user_id, (name or "Default Token").strip(), token_hash, token_prefix, token_last4, scopes, now, expires_at),
        )

    meta = {
        "id": token_id,
        "user_id": user_id,
        "name": (name or "Default Token").strip(),
        "token_prefix": token_prefix,
        "token_last4": token_last4,
        "scopes": scopes,
        "created_at": now,
        "expires_at": expires_at,
        "status": "active",
    }
    return meta, raw_token


def verify_api_token(raw_token: str) -> Optional[dict]:
    if not raw_token or not raw_token.startswith("pat_"):
        return None
    token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
    now = time.time()
    with _db() as con:
        row = con.execute(
            """SELECT t.*, u.username, u.email, u.role, u.status as user_status
               FROM api_tokens t
               JOIN users u ON t.user_id = u.id
               WHERE t.token_hash = ? AND t.status = 'active'
                 AND (t.expires_at IS NULL OR t.expires_at > ?)""",
            (token_hash, now),
        ).fetchone()
        if not row:
            return None
        token_info = dict(row)
        if token_info["user_status"] != "active":
            return None
        con.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?", (now, token_info["id"]))
        token_info["last_used"] = now
        return token_info


def list_user_api_tokens(user_id: str) -> list[dict]:
    with _db() as con:
        rows = con.execute(
            """SELECT id, user_id, name, token_prefix, token_last4, scopes, created_at, expires_at, last_used, status
               FROM api_tokens
               WHERE user_id = ?
               ORDER BY created_at DESC""",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def revoke_api_token(user_id: str, token_id: str) -> bool:
    with _db() as con:
        cur = con.execute(
            "UPDATE api_tokens SET status = 'revoked' WHERE id = ? AND user_id = ?",
            (token_id, user_id),
        )
        return cur.rowcount > 0


def delete_api_token(user_id: str, token_id: str) -> bool:
    with _db() as con:
        cur = con.execute(
            "DELETE FROM api_tokens WHERE id = ? AND user_id = ?",
            (token_id, user_id),
        )
        return cur.rowcount > 0


# ----------------------------------------------------------------- Finding feedback
_FEEDBACK_KINDS = {"false_positive", "false_negative"}
_RAW_SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{8,}|gho_[A-Za-z0-9]{8,}|github_pat_|AKIA[0-9A-Z]{12,}"
    r"|sk_live_[A-Za-z0-9]|sk-[A-Za-z0-9]{16,}|xox[baprs]-|-----BEGIN )",
    re.I,
)


def add_feedback(user_id: str, kind: str, scan_id: Optional[str] = None,
                 finding_id: Optional[str] = None, finding_type: Optional[str] = None,
                 provider: Optional[str] = None, note: str = "") -> dict:
    """Store a false-positive or missed-secret report. Rejects notes that contain raw secrets."""
    kind = (kind or "").strip().lower()
    if kind not in _FEEDBACK_KINDS:
        raise ValueError("kind must be false_positive or false_negative.")
    note = (note or "").strip()
    if len(note) > 2000:
        raise ValueError("Note is too long (2000 characters maximum).")
    if kind == "false_negative" and len(note) < 8:
        raise ValueError("Describe the missed secret in at least 8 characters, without pasting the raw value.")
    if _RAW_SECRET.search(note):
        raise ValueError("Do not include the raw secret in feedback. Name the finding type and location only.")
    if scan_id:
        scan = get_scan(scan_id)
        if scan and scan.get("user_id") and scan["user_id"] != user_id:
            raise ValueError("That scan belongs to another account.")

    def _clip(value: Optional[str], n: int) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text[:n] or None

    row_id = uuid.uuid4().hex
    now = time.time()
    with _db() as con:
        con.execute(
            """INSERT INTO feedback
               (id, user_id, scan_id, finding_id, finding_type, provider, kind, note, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (row_id, user_id, _clip(scan_id, 64), _clip(finding_id, 32),
             _clip(finding_type, 64), _clip(provider, 64), kind, note, now),
        )
    return {
        "id": row_id, "user_id": user_id, "scan_id": _clip(scan_id, 64),
        "finding_id": _clip(finding_id, 32), "finding_type": _clip(finding_type, 64),
        "provider": _clip(provider, 64), "kind": kind, "note": note, "created_at": now,
    }


def list_feedback(user_id: Optional[str] = None, limit: int = 100) -> list[dict]:
    limit = max(1, min(int(limit), 500))
    with _db() as con:
        if user_id:
            rows = con.execute(
                "SELECT * FROM feedback WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM feedback ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


# ----------------------------------------------------------------- Cleanup
def sweep_tmp(ttl: Optional[int] = None):
    ttl = config.UPLOAD_TTL_SECONDS if ttl is None else ttl
    if not config.TMP_DIR.exists():
        return
    now = time.time()
    for d in config.TMP_DIR.iterdir():
        try:
            if d.is_dir() and now - d.stat().st_mtime > ttl:
                shutil.rmtree(d, ignore_errors=True)
        except OSError:
            pass
