"""LeakLens - privacy-aware file scanner and developer security platform.
Flask backend supporting hybrid secret detection, user authentication,
role-based dashboards, safe team setup, and IDE Guard scanning."""
from __future__ import annotations

import argparse
import io
import json
import logging
import os
import re
import secrets
import shutil
import sys
import time
import uuid
import zipfile
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

from flask import (Flask, abort, jsonify, render_template, request,
                   send_file, session)

import config
from engine import catalog, extract, redact, sarif, service, store

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_BYTES + 64 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = config.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = config.SESSION_COOKIE_SAMESITE
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=config.SESSION_LIFETIME_HOURS)

log = logging.getLogger("leaklens")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

ID_RX = re.compile(r"[0-9a-f]{32}")
ENV_VAR_RX = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
VAULT_PROVIDERS = {"Generic", "AWS", "GitHub", "Stripe", "Google Cloud", "OpenAI", "Twilio"}
MIME = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "bmp": "image/bmp",
        "tif": "image/tiff", "tiff": "image/tiff", "webp": "image/webp"}
SAMPLE_FILES = {
    "python": "demo_app.py",
    "pdf": "demo_report.pdf",
    "screenshot": "demo_screenshot.jpg",
    "notes": "demo_notes.txt",
}


# ----------------------------------------------------------------- security & helpers
def safe_name(name: str) -> str:
    name = os.path.basename((name or "upload").replace("\\", "/"))
    name = re.sub(r"[^\w.\- ]", "_", name).strip() or "upload"
    return name[:100]


def scan_dir(scan_id: str):
    if not ID_RX.fullmatch(scan_id or ""):
        abort(404)
    d = config.TMP_DIR / scan_id
    if not d.is_dir():
        abort(404, description="Scan not found or expired. Please scan the file again.")
    return d


def load_state(scan_id: str):
    d = scan_dir(scan_id)
    return d, json.loads((d / "state.json").read_text(encoding="utf-8"))


def can_access_scan(scan_id: str, state: dict) -> bool:
    user = get_current_user()
    record = store.get_scan(scan_id)
    owner_id = (record or {}).get("user_id") or state.get("user_id")
    return not owner_id or bool(user and (user["id"] == owner_id or user["role"] == "admin"))


def err(msg: str, code: int = 400):
    return jsonify({"error": msg}), code


def get_current_user() -> Optional[dict]:
    # 1. Check Bearer token in Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header[7:].strip()
        if raw_token.startswith("pat_"):
            token_info = store.verify_api_token(raw_token)
            if token_info:
                user = store.get_user_by_id(token_info["user_id"])
                if user and user.get("status") == "active":
                    user["auth_method"] = "pat"
                    user["token_info"] = token_info
                    return user

    # 2. Check session
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = store.get_user_by_id(user_id)
    if not user or user.get("status") != "active":
        session.clear()
        return None
    user["auth_method"] = "session"
    return user


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            return err("Authentication required. Please log in or provide a valid Bearer token.", 401)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or user.get("role") != "admin":
            return err("Administrator privileges required.", 403)
        return f(*args, **kwargs)
    return decorated


def get_or_create_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]


def verify_csrf():
    if app.config.get("TESTING"):
        return True
    # If authenticated via Bearer token, CSRF is not required
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer pat_"):
        return True
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        header_token = request.headers.get("X-CSRF-Token")
        session_token = session.get("csrf_token")
        if not header_token or not session_token or not secrets.compare_digest(header_token, session_token):
            # For API uploads and login/register, allow requests without CSRF if session is new
            if request.path in ("/api/auth/login", "/api/auth/register", "/api/scan", "/api/ide/scan", "/api/auth/2fa/verify-login", "/api/v1/scan"):
                return True
            return False
    return True


@app.before_request
def check_csrf_protection():
    if not verify_csrf():
        return err("Invalid or missing CSRF token. Please refresh the page.", 403)


@app.after_request
def apply_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' blob: data:; "
        "style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(413)
def too_big(_):
    return err(f"File is larger than {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB.", 413)


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/") or request.path.startswith("/report/"):
        return err(getattr(e, "description", "Not found"), 404)
    return "Not found", 404


@app.errorhandler(Exception)
def crash(e):
    if hasattr(e, "code") and isinstance(e.code, int):
        return err(getattr(e, "description", "Error"), e.code)
    log.error("unhandled error: %s", type(e).__name__)
    return err("Something went wrong while processing the request.", 500)


# ------------------------------------------------------------------ views & status
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/status")
def status():
    from engine import ml
    u = get_current_user()
    return jsonify({
        "ocr": extract.ocr_available(),
        "ml": ml.load_classifier() is not None,
        "ttl_minutes": config.UPLOAD_TTL_SECONDS // 60,
        "max_mb": config.MAX_UPLOAD_BYTES // (1024 * 1024),
        "extensions": sorted(config.TEXT_EXTS | config.PDF_EXTS | config.IMAGE_EXTS),
        "authenticated": u is not None,
        "user": {"id": u["id"], "username": u["username"], "role": u["role"]} if u else None,
        "csrf_token": get_or_create_csrf_token(),
    })


@app.get("/api/samples/<sample_id>")
def sample_file(sample_id: str):
    filename = SAMPLE_FILES.get(sample_id)
    if filename is None:
        return err("Sample not found.", 404)
    path = config.BASE_DIR / "samples" / filename
    if not path.is_file():
        abort(404, description="Sample file not found.")
    return send_file(path, as_attachment=False, download_name=filename)


# ------------------------------------------------------------------ auth routes
@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""

    if not username or not email or not password:
        return err("Username, email, and password are required.")
    if len(password) < 8:
        return err("Password must be at least 8 characters long.")
    if store.get_user_by_username_or_email(username) or store.get_user_by_username_or_email(email):
        return err("An account with that username or email already exists.")

    try:
        user = store.create_user(username, email, password, role="user")
        session["user_id"] = user["id"]
        session.permanent = True
        store.record_audit(user["id"], "user_registered", request.remote_addr, f"Username: {username}")
        return jsonify({
            "success": True,
            "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]},
            "csrf_token": get_or_create_csrf_token(),
        })
    except ValueError as e:
        return err(str(e))


@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    ident = (body.get("username") or "").strip()
    password = body.get("password") or ""
    ip = request.remote_addr or "127.0.0.1"

    if not ident or not password:
        return err("Username/email and password are required.")

    if store.is_rate_limited(ip, ident):
        store.record_audit(None, "login_rate_limited", ip, f"Target: {ident}")
        return err(f"Too many failed login attempts. Please wait {config.LOGIN_LOCKOUT_SECONDS // 60} minutes.", 429)

    user = store.get_user_by_username_or_email(ident)
    if not user or not store.verify_user_password(user, password):
        store.record_login_attempt(ip, ident, success=False)
        return err("Invalid username/email or password.", 401)

    if user.get("status") == "disabled":
        store.record_login_attempt(ip, ident, success=False)
        return err("This account has been disabled. Please contact an administrator.", 403)

    store.record_login_attempt(ip, ident, success=True)

    # 2FA Enforcement check
    if user.get("totp_enabled"):
        temp_token = store.create_2fa_temp_token(user["id"])
        store.record_audit(user["id"], "2fa_challenge_issued", ip)
        return jsonify({
            "requires_2fa": True,
            "temp_token": temp_token,
            "username": user["username"],
        })

    store.update_last_login(user["id"])
    session["user_id"] = user["id"]
    session.permanent = True
    store.record_audit(user["id"], "user_logged_in", ip, f"User: {user['username']}")

    return jsonify({
        "success": True,
        "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]},
        "csrf_token": get_or_create_csrf_token(),
    })


@app.post("/api/auth/2fa/verify-login")
def verify_2fa_login():
    body = request.get_json(silent=True) or {}
    temp_token = (body.get("temp_token") or "").strip()
    code = (body.get("code") or "").strip()

    if not temp_token or not code:
        return err("Missing temporary session token or 2FA code.")

    user_id = store.verify_2fa_temp_token(temp_token)
    if not user_id:
        return err("Invalid or expired 2FA session token. Please log in again.", 401)

    user = store.get_user_by_id(user_id)
    if not user or user.get("status") == "disabled":
        return err("Account invalid or disabled.", 403)

    # Validate TOTP token or recovery code
    valid = store.verify_totp(user.get("totp_secret", ""), code) or store.verify_recovery_code(user_id, code)
    if not valid:
        store.record_audit(user_id, "2fa_login_failed", request.remote_addr, "Invalid code entered")
        return err("Invalid authentication or recovery code.", 401)

    store.update_last_login(user_id)
    session["user_id"] = user_id
    session.permanent = True
    store.record_audit(user_id, "user_2fa_logged_in", request.remote_addr, f"User: {user['username']}")

    return jsonify({
        "success": True,
        "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]},
        "csrf_token": get_or_create_csrf_token(),
    })


@app.get("/api/auth/2fa/status")
@login_required
def twofa_status():
    user = get_current_user()
    return jsonify({"enabled": bool(user.get("totp_enabled"))})


@app.post("/api/auth/2fa/setup")
@login_required
def twofa_setup():
    user = get_current_user()
    secret = store.generate_totp_secret()
    plain_codes, hashed_codes = store.generate_recovery_codes()

    session["pending_2fa_secret"] = secret
    session["pending_2fa_codes"] = hashed_codes

    uri = f"otpauth://totp/LeakLens:{user['username']}?secret={secret}&issuer=LeakLens"
    return jsonify({
        "secret": secret,
        "otpauth_uri": uri,
        "recovery_codes": plain_codes,
    })


@app.post("/api/auth/2fa/enable")
@login_required
def twofa_enable():
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    code = (body.get("code") or "").strip()

    secret = session.get("pending_2fa_secret")
    hashed_codes = session.get("pending_2fa_codes")

    if not secret or not store.verify_totp(secret, code):
        return err("Invalid verification code. Please check your authenticator and try again.", 400)

    store.enable_2fa(user["id"], secret, hashed_codes)
    session.pop("pending_2fa_secret", None)
    session.pop("pending_2fa_codes", None)
    store.record_audit(user["id"], "2fa_enabled", request.remote_addr)

    return jsonify({"success": True, "message": "Two-factor authentication successfully enabled."})


@app.post("/api/auth/2fa/disable")
@login_required
def twofa_disable():
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    password = body.get("password") or ""

    if not store.verify_user_password(user, password):
        return err("Incorrect password. Cannot disable 2FA.", 400)

    store.disable_2fa(user["id"])
    store.record_audit(user["id"], "2fa_disabled", request.remote_addr)
    return jsonify({"success": True, "message": "Two-factor authentication disabled."})


@app.post("/api/auth/logout")
def logout():
    user = get_current_user()
    if user:
        store.record_audit(user["id"], "user_logged_out", request.remote_addr, f"User: {user['username']}")
    session.clear()
    return jsonify({"success": True, "csrf_token": get_or_create_csrf_token()})


@app.get("/api/auth/me")
def auth_me():
    user = get_current_user()
    if not user:
        return jsonify({"authenticated": False, "csrf_token": get_or_create_csrf_token()})
    return jsonify({
        "authenticated": True,
        "user": {"id": user["id"], "username": user["username"], "email": user["email"], "role": user["role"]},
        "csrf_token": get_or_create_csrf_token(),
    })


@app.post("/api/auth/profile")
@login_required
def update_profile():
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    email = (body.get("email") or "").strip()

    if not username or not email:
        return err("Username and email are required.")

    # Check for duplicate if changed
    existing = store.get_user_by_username_or_email(username)
    if existing and existing["id"] != user["id"]:
        return err("That username is already taken.")
    existing_email = store.get_user_by_username_or_email(email)
    if existing_email and existing_email["id"] != user["id"]:
        return err("That email is already registered.")

    store.update_user_profile(user["id"], username, email)
    store.record_audit(user["id"], "profile_updated", request.remote_addr, f"New username: {username}")
    return jsonify({"success": True, "user": {"id": user["id"], "username": username, "email": email, "role": user["role"]}})


@app.post("/api/auth/password")
@login_required
def change_password():
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    old_pw = body.get("current_password") or ""
    new_pw = body.get("new_password") or ""

    if not store.verify_user_password(user, old_pw):
        return err("Incorrect current password.", 400)
    if len(new_pw) < 8:
        return err("New password must be at least 8 characters long.")

    store.update_user_password(user["id"], new_pw)
    store.record_audit(user["id"], "password_changed", request.remote_addr)
    return jsonify({"success": True})


@app.post("/api/auth/forgot-password")
def forgot_password():
    body = request.get_json(silent=True) or {}
    ident = (body.get("email_or_username") or "").strip()
    user = store.get_user_by_username_or_email(ident)
    if not user:
        # Don't reveal user existence
        return jsonify({"success": True, "message": "If an account exists, a reset token was generated."})

    token = store.create_password_reset(user["id"])
    store.record_audit(user["id"], "password_reset_requested", request.remote_addr)
    # Free-tier/Local system: Return reset token directly for local dev/testing
    return jsonify({
        "success": True,
        "message": "Password reset token generated (valid for 1 hour).",
        "reset_token": token,
    })


@app.post("/api/auth/reset-password")
def reset_password():
    body = request.get_json(silent=True) or {}
    token = (body.get("token") or "").strip()
    new_password = body.get("new_password") or ""
    if not token or not new_password:
        return err("Token and new password are required.")
    if len(new_password) < 8:
        return err("New password must be at least 8 characters long.")

    success = store.use_password_reset(token, new_password)
    if not success:
        return err("Invalid or expired password reset token.", 400)
    return jsonify({"success": True, "message": "Password has been successfully reset. You may now log in."})


# ------------------------------------------------------------------- scan & redact
@app.post("/api/scan")
def scan():
    store.sweep_tmp()
    user = get_current_user()
    f = request.files.get("file")
    if not f or not f.filename:
        return err("Choose a file to scan.")
    name = safe_name(f.filename)
    data = f.read()
    t0 = time.time()
    try:
        ex, findings = service.analyse(name, data)
    except extract.ScanError as e:
        return err(str(e))
    if len(findings) > config.MAX_FINDINGS:
        findings = findings[: config.MAX_FINDINGS]
        ex.warnings.append(f"Only the first {config.MAX_FINDINGS} findings are shown.")

    scan_id = uuid.uuid4().hex
    d = config.TMP_DIR / scan_id
    d.mkdir(parents=True)
    (d / "original.bin").write_bytes(data)
    internal = [{k: v for k, v in x.items() if k != "_value"} for x in findings]
    state = {
        "filename": name, "kind": ex.kind, "size": len(data), "created": time.time(),
        "text": ex.text, "pages": ex.pages, "words": ex.words, "img_size": ex.size,
        "warnings": ex.warnings, "findings": internal, "user_id": user["id"] if user else None,
    }
    (d / "state.json").write_text(json.dumps(state), encoding="utf-8")

    summ = service.summary(internal)
    store.record_scan(scan_id, name, ex.kind, len(data), summ,
                      user_id=user["id"] if user else None, findings=internal)
    if user:
        store.record_audit(user["id"], "file_scanned", request.remote_addr, f"{name} ({ex.kind}) findings={len(internal)}")
    log.info("scan %s kind=%s findings=%d active=%d %.1fs", scan_id[:8], ex.kind, len(internal),
             summ["active"], time.time() - t0)

    return jsonify({
        "scan_id": scan_id, "filename": name, "kind": ex.kind, "size": len(data), "summary": summ,
        "findings": service.public(internal), "warnings": ex.warnings,
        "masked_text": service.masked_text(ex.text, internal) if ex.kind != "image" else None,
        "pages": ex.pages if ex.kind == "pdf" else None,
        "image": {"w": ex.size[0], "h": ex.size[1], "url": f"/api/original/{scan_id}"} if ex.kind == "image" else None,
        "ocr_text_chars": len(ex.text) if ex.kind == "image" else None,
    })


@app.get("/api/original/<scan_id>")
def original(scan_id):
    d, st = load_state(scan_id)
    if not can_access_scan(scan_id, st):
        abort(403, description="Access denied to this scan.")
    if st["kind"] != "image":
        abort(404)
    ext = os.path.splitext(st["filename"])[1].lower().lstrip(".")
    return send_file(d / "original.bin", mimetype=MIME.get(ext, "application/octet-stream"))


@app.post("/api/redact")
def redact():
    body = request.get_json(silent=True) or {}
    scan_id = str(body.get("scan_id", ""))
    d, st = load_state(scan_id)
    user = get_current_user()
    if not can_access_scan(scan_id, st):
        return err("Unauthorized to redact this scan.", 403)

    ids = {str(i) for i in body.get("finding_ids", [])}
    style = body.get("style") if body.get("style") in ("label", "block") else "label"
    data = (d / "original.bin").read_bytes()
    ex = extract.Extracted(st["kind"], st["text"], [tuple(p) for p in st["pages"]], st["words"],
                           tuple(st["img_size"]) if st["img_size"] else None)
    findings = st["findings"]
    out_bytes, out_name, applied = service.apply_redaction(st["kind"], st["filename"], data, ex, findings, ids, style)
    (d / "out").mkdir(exist_ok=True)
    for old in (d / "out").glob("sanitised_*"):
        try:
            old.unlink()
        except OSError:
            pass
    (d / "out" / out_name).write_bytes(out_bytes)

    verify = service.rescan(out_name, out_bytes)
    report = {
        "filename": st["filename"], "kind": st["kind"],
        "scanned_at": datetime.fromtimestamp(st["created"]).isoformat(timespec="seconds"),
        "summary": service.summary(findings), "findings": service.public(findings),
        "action": {"style": style, "redacted_ids": [f["id"] for f in applied], "redacted_count": len(applied),
                   "output_file": out_name,
                   "metadata_stripped": st["kind"] in ("pdf", "image") or False,
                   "note": ("PDF output is a text-only rebuild: layout and images are not preserved." if st["kind"] == "pdf" else
                            "Image metadata (EXIF/GPS/text chunks) is always stripped from the sanitised copy." if st["kind"] == "image" else "")},
        "verification": verify, "warnings": st["warnings"],
    }
    (d / "out" / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (d / "out" / "report.html").write_text(render_template("report.html", r=report), encoding="utf-8")
    store.record_redaction(d.name, [finding["id"] for finding in applied], findings)
    if user:
        store.record_audit(user["id"], "file_redacted", request.remote_addr, f"{st['filename']} redacted={len(applied)}")
    log.info("redact %s applied=%d remaining=%s", d.name[:8], len(applied), verify.get("active"))

    return jsonify({
        "output_file": out_name, "redacted_count": len(applied), "verification": verify,
        "downloads": {"sanitised": f"/api/download/{d.name}/sanitised",
                      "report_html": f"/api/download/{d.name}/report_html",
                      "report_json": f"/api/download/{d.name}/report_json",
                      "sarif": f"/api/download/{d.name}/sarif"}
    })


@app.get("/api/download/<scan_id>/sarif")
def download_sarif_direct(scan_id):
    return download(scan_id, "sarif")


@app.get("/api/download/<scan_id>/<what>")
def download(scan_id, what):
    d, st = load_state(scan_id)
    if not can_access_scan(scan_id, st):
        abort(403, description="Access denied to this download.")

    if what in ("sarif", "report_sarif"):
        sarif_data = sarif.generate_sarif(st["filename"], st.get("findings", []), scan_id=scan_id)
        base = os.path.splitext(os.path.basename(st["filename"]))[0] or "scan"
        buf = io.BytesIO(json.dumps(sarif_data, indent=2).encode("utf-8"))
        return send_file(buf, mimetype="application/sarif+json", as_attachment=True, download_name=f"leaklens_{base}.sarif")

    out = d / "out"
    if not out.is_dir():
        abort(404, description="Nothing to download yet. Redact first.")
    if what == "sanitised":
        files = list(out.glob("sanitised_*"))
        if not files:
            abort(404)
        return send_file(files[0], as_attachment=True, download_name=files[0].name)
    if what in ("report_html", "report_json"):
        ext = "html" if what == "report_html" else "json"
        return send_file(out / f"report.{ext}", as_attachment=True, download_name=f"leaklens_report.{ext}")
    abort(404)


@app.get("/report/<scan_id>")
def report_view(scan_id):
    d, st = load_state(scan_id)
    if not can_access_scan(scan_id, st):
        abort(403, description="Access denied to this report.")
    p = d / "out" / "report.html"
    if not p.exists():
        abort(404, description="No report yet. Redact first.")
    return send_file(p, mimetype="text/html")


@app.delete("/api/scan/<scan_id>")
def delete_scan(scan_id):
    d, st = load_state(scan_id)
    if not can_access_scan(scan_id, st):
        return err("Unauthorized to delete this scan.", 403)
    store.delete_scan_record(scan_id)
    shutil.rmtree(d)
    return jsonify({"deleted": True})


# ---------------------------------------------------------- user dashboard & history
@app.get("/api/user/stats")
@login_required
def user_stats():
    user = get_current_user()
    try:
        days = int(request.args.get("days", "0"))
    except (TypeError, ValueError):
        days = 0
    if days not in (7, 30, 90):
        days = 0
    return jsonify(store.user_dashboard_stats(user["id"], days=days))


@app.get("/api/user/history")
@login_required
def user_history_api():
    user = get_current_user()
    if "page" in request.args:
        risk = request.args.get("risk", "").lower()
        file_format = request.args.get("format", "").lower()
        sort = request.args.get("sort", "newest")
        try:
            page = int(request.args.get("page", "1"))
            per_page = int(request.args.get("per_page", "10"))
            days = int(request.args.get("days", "0"))
        except ValueError:
            return err("History page, page size, and date range must be integers.", 400)
        if risk and risk not in ("high", "medium", "low"):
            return err("Invalid risk filter.", 400)
        if file_format and file_format not in {
            ext.lstrip(".").lower() for ext in config.TEXT_EXTS | config.PDF_EXTS | config.IMAGE_EXTS
        }:
            return err("Unsupported file format filter.", 400)
        if sort not in ("newest", "oldest", "highest", "lowest", "filename"):
            return err("Invalid history sort order.", 400)
        if page < 1 or per_page not in (10, 20, 50) or days not in (0, 7, 30, 90):
            return err("Invalid history page, page size, or date range.", 400)
        result = store.user_history_page(
            user["id"], risk_level=risk or None, file_format=file_format or None,
            search=request.args.get("q", "")[:100] or None, days=days, sort=sort,
            page=page, per_page=per_page,
        )
        for item in result["items"]:
            out_dir = config.TMP_DIR / item["id"] / "out"
            item["report_available"] = (out_dir / "report.html").is_file()
            item["sanitised_available"] = out_dir.is_dir() and any(out_dir.glob("sanitised_*"))
        return jsonify(result)

    risk = request.args.get("risk")
    kind = request.args.get("kind")
    search = request.args.get("q")
    items = store.user_history(user["id"], limit=100, risk_level=risk, kind=kind, search=search)
    return jsonify(items)


@app.get("/api/user/history/<scan_id>")
@login_required
def user_history_detail_api(scan_id):
    user = get_current_user()
    item = store.user_history_detail(user["id"], scan_id)
    if not item:
        abort(404, description="Scan not found.")
    out_dir = config.TMP_DIR / scan_id / "out" if ID_RX.fullmatch(scan_id or "") else None
    item["report_available"] = bool(out_dir and (out_dir / "report.html").is_file())
    item["sanitised_available"] = bool(out_dir and out_dir.is_dir() and any(out_dir.glob("sanitised_*")))
    return jsonify(item)


@app.post("/api/feedback")
@login_required
def submit_feedback():
    """Report a false positive or a secret the scanner missed. Raw secrets are rejected."""
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    try:
        row = store.add_feedback(
            user["id"],
            body.get("kind") or "",
            scan_id=body.get("scan_id"),
            finding_id=body.get("finding_id"),
            finding_type=body.get("finding_type"),
            provider=body.get("provider"),
            note=body.get("note") or "",
        )
    except ValueError as e:
        return err(str(e))
    store.record_audit(user["id"], "feedback_submitted", request.remote_addr, row["kind"])
    return jsonify({"success": True, "feedback": row})


@app.get("/api/feedback")
@login_required
def list_my_feedback():
    user = get_current_user()
    return jsonify(store.list_feedback(user["id"]))


@app.get("/api/admin/feedback")
@admin_required
def admin_feedback():
    return jsonify(store.list_feedback(limit=200))


@app.delete("/api/user/history")
@login_required
def clear_user_history_api():
    user = get_current_user()
    store.clear_user_history(user["id"])
    store.record_audit(user["id"], "user_history_cleared", request.remote_addr)
    return jsonify({"cleared": True})


@app.get("/api/history")
@login_required
def history():
    user = get_current_user()
    return jsonify(store.user_history(user["id"], limit=30))


@app.delete("/api/history")
@login_required
def clear_history():
    user = get_current_user()
    store.clear_user_history(user["id"])
    return jsonify({"cleared": True})


# ---------------------------------------------------------- admin dashboard
@app.get("/api/admin/stats")
@admin_required
def admin_stats():
    stats_data = store.admin_system_stats()
    from engine import ml
    stats_data["system"] = {
        "ml_loaded": ml.load_classifier() is not None,
        "ocr_available": extract.ocr_available(),
        "scoring_policy": config.BASE_SCORES,
    }
    return jsonify(stats_data)


@app.get("/api/admin/users")
@admin_required
def admin_users():
    return jsonify(store.list_users())


@app.post("/api/admin/users/<user_id>/status")
@admin_required
def admin_toggle_user(user_id):
    current = get_current_user()
    if current["id"] == user_id:
        return err("Cannot disable your own administrator account.")
    body = request.get_json(silent=True) or {}
    status_val = body.get("status")
    try:
        store.update_user_status(user_id, status_val)
        store.record_audit(current["id"], "admin_user_status_changed", request.remote_addr, f"User {user_id} set to {status_val}")
        return jsonify({"success": True})
    except ValueError as e:
        return err(str(e))


@app.delete("/api/admin/users/<user_id>")
@admin_required
def admin_delete_user(user_id):
    current = get_current_user()
    if current["id"] == user_id:
        return err("Cannot delete your own account.")
    store.delete_user(user_id)
    store.record_audit(current["id"], "admin_user_deleted", request.remote_addr, f"Deleted user {user_id}")
    return jsonify({"success": True})


@app.get("/api/admin/audit")
@admin_required
def admin_audit():
    return jsonify(store.get_audit_logs(limit=100))


@app.get("/api/admin/policies")
@admin_required
def admin_get_policies():
    return jsonify(config.BASE_SCORES)


@app.post("/api/admin/policies")
@admin_required
def admin_save_policies():
    current = get_current_user()
    body = request.get_json(silent=True) or {}
    for k, v in body.items():
        if k in config.BASE_SCORES and isinstance(v, (int, float)):
            config.BASE_SCORES[k] = int(v)
    try:
        (config.INSTANCE_DIR / "scoring.json").write_text(json.dumps(config.BASE_SCORES, indent=2), encoding="utf-8")
        store.record_audit(current["id"], "scoring_policies_updated", request.remote_addr)
        return jsonify({"success": True, "policies": config.BASE_SCORES})
    except OSError:
        return err("Failed to persist scoring policy.")


# ---------------------------------------------------------- safe team setup
def _team_env_name(value) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not ENV_VAR_RX.fullmatch(value):
        return None
    return value.upper()


def _render_team_env_example(variable_names) -> str:
    names = set()
    for name in variable_names:
        normalized = _team_env_name(name)
        if normalized:
            names.add(normalized)
    names = sorted(names)
    lines = [
        "# LeakLens Environment Configuration",
        "# Share placeholders only; never commit real credentials.",
        "",
    ]
    if names:
        lines.extend(f"{name}=your_{name.lower()}_here" for name in names)
    else:
        lines.extend([
            "# No scan-specific variables detected yet.",
            "# Scan a project file to generate a tailored template.",
        ])
    return "\n".join(lines) + "\n"


def _team_template_names(env_example) -> set[str]:
    if not isinstance(env_example, str):
        raise ValueError("Environment template must be text.")
    if len(env_example) > 1_000_000:
        raise ValueError("Environment template is too large.")
    names = set()
    for line in env_example.splitlines():
        match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]{0,127})\s*=", line)
        if match:
            names.add(match.group(1))
    return names


@app.post("/api/team/env-example")
def generate_env_example():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return err("Request body must be a JSON object.")
    scan_id = body.get("scan_id")
    if scan_id is not None:
        if not isinstance(scan_id, str) or not scan_id:
            return err("Invalid scan identifier.")
        _, state = load_state(scan_id)
        if not can_access_scan(scan_id, state):
            return err("Unauthorized to use this scan.", 403)
        raw_findings = state.get("findings", [])
    else:
        raw_findings = body.get("findings", [])
    if not isinstance(raw_findings, list) or any(not isinstance(finding, dict) for finding in raw_findings):
        return err("Findings must be a list of scan findings.")

    env_names = set()
    for finding in raw_findings:
        if finding.get("status") not in ("active", "likely_benign"):
            continue
        name = _team_env_name(finding.get("key")) or _team_env_name(finding.get("type"))
        if name:
            env_names.add(name)
    return jsonify({
        "env_example": _render_team_env_example(env_names),
        "variables": sorted(env_names),
        "safe_template": True,
    })


@app.post("/api/team/package")
def generate_team_package():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return err("Request body must be a JSON object.")
    project = body.get("project_name", "project")
    if not isinstance(project, str):
        return err("Project name must be text.")
    try:
        env_names = _team_template_names(body.get("env_example", ""))
    except ValueError as exc:
        return err(str(exc), 413 if "too large" in str(exc).lower() else 400)
    env_content = _render_team_env_example(env_names)
    project_name = safe_name(project)

    readme_content = f"""# {project_name} — Safe Team Setup Guide
Prepared with LeakLens Privacy Guard.

## Getting Started
1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Populate the environment variables in `.env` using your local developer credentials.
3. NEVER commit `.env` or any production secrets to version control.
4. Verify your `.gitignore` contains:
   ```
   .env
   .env.local
   *.bin
   *.key
   instance/
   ```

## Secrets Management Policy
- Always read credentials via `os.environ.get(...)` (Python) or `process.env.*` (JavaScript/TypeScript).
- Use local secret vaults or authorized team secrets managers (Doppler, 1Password, AWS Secrets Manager) instead of sharing credentials in chat.
"""

    install_guide = """# Installation Guide

1. Create and activate a local virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
   ```
2. Install project requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Run test verification before committing any code:
   ```bash
   python -m pytest
   ```
"""

    security_checklist = """# Team Developer Security Checklist

- [ ] Ensure `.env` is listed in `.gitignore`.
- [ ] No hardcoded passwords, API keys, or private tokens in source code.
- [ ] Run LeakLens pre-commit hook before pushing code.
- [ ] Rotate credentials immediately if any key is ever accidentally leaked.
- [ ] Keep production credentials separate from local development environments.
"""

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(".env.example", env_content)
        z.writestr("README-TEAM-SETUP.md", readme_content)
        z.writestr("INSTALLATION-GUIDE.md", install_guide)
        z.writestr("SECURITY-CHECKLIST.md", security_checklist)
    buf.seek(0)

    user = get_current_user()
    if user:
        store.record_audit(user["id"], "team_package_downloaded", request.remote_addr, f"Project: {project_name}")

    return send_file(
        buf,
        as_attachment=True,
        download_name=f"leaklens_team_setup_{project_name}.zip",
        mimetype="application/zip",
    )


# ---------------------------------------------------------- local vault (encrypted)
@app.get("/api/vault")
@login_required
def get_vault():
    user = get_current_user()
    return jsonify(store.vault_list_items(user["id"]))


@app.post("/api/vault")
@login_required
def add_vault_item():
    user = get_current_user()
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return err("Request body must be a JSON object.")
    key_name = body.get("key_name", "")
    provider = body.get("provider", "Generic")
    raw_val = body.get("raw_value", "")
    if not isinstance(key_name, str) or not isinstance(provider, str) or not isinstance(raw_val, str):
        return err("Variable name, category, and secret must be text.")
    key_name = key_name.strip()
    provider = provider.strip()
    if not key_name or not raw_val:
        return err("Key name and secret value are required.")
    if (not ENV_VAR_RX.fullmatch(key_name) or provider not in VAULT_PROVIDERS
            or len(raw_val) > 16_384):
        return err("Use a valid variable name, supported category, and a secret of at most 16 KB.")

    # Server generates masked preview; raw value is encrypted in store
    masked = service.mask_value(raw_val)
    item = store.vault_add_item(user["id"], key_name, provider, masked, raw_val)
    store.record_audit(user["id"], "vault_item_added", request.remote_addr, f"Key: {key_name}")
    return jsonify(item)


@app.delete("/api/vault/<item_id>")
@login_required
def delete_vault_item(item_id):
    user = get_current_user()
    store.vault_delete_item(user["id"], item_id)
    store.record_audit(user["id"], "vault_item_deleted", request.remote_addr, f"Item: {item_id}")
    return jsonify({"deleted": True})


@app.post("/api/vault/export")
@login_required
def export_vault():
    user = get_current_user()
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return err("Request body must be a JSON object.")
    export_pw = body.get("password", "")
    if not isinstance(export_pw, str) or len(export_pw) < 8:
        return err("Vault export password must be at least 8 characters long.")

    try:
        vault_bytes = store.export_portable_vault(user["id"], export_pw)
        store.record_audit(user["id"], "portable_vault_exported", request.remote_addr)
        return send_file(
            io.BytesIO(vault_bytes),
            as_attachment=True,
            download_name=f"leaklens_vault_{user['username']}.leaklens",
            mimetype="application/octet-stream",
        )
    except ValueError as e:
        return err(str(e))


@app.post("/api/vault/import")
@login_required
def import_vault():
    user = get_current_user()
    f = request.files.get("file")
    password = request.form.get("password") or ""

    if not f or not f.filename:
        return err("Please select a .leaklens vault file to import.")
    if not f.filename.lower().endswith(".leaklens"):
        return err("Choose a .leaklens vault file.")
    if not password:
        return err("Vault password is required for decryption.")

    file_bytes = f.stream.read(config.MAX_UPLOAD_BYTES + 1)
    if len(file_bytes) > config.MAX_UPLOAD_BYTES:
        return err(f"Vault file exceeds the {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.", 413)
    try:
        res = store.import_portable_vault(user["id"], password, file_bytes)
        store.record_audit(user["id"], "portable_vault_imported", request.remote_addr, f"Items: {res['imported_count']}")
        return jsonify(res)
    except ValueError as e:
        return err(str(e))


# ---------------------------------------------------------- Personal Access Tokens (PATs)
@app.post("/api/tokens")
@login_required
def create_token_api():
    user = get_current_user()
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "API Token").strip()
    try:
        expires_days = int(body.get("expires_days", 30))
    except (ValueError, TypeError):
        expires_days = 30
    scopes = (body.get("scopes") or "read,scan").strip()
    meta, raw_token = store.create_api_token(user["id"], name, expires_days, scopes)
    store.record_audit(user["id"], "pat_token_created", request.remote_addr, f"Token: {name} ({meta['token_prefix']}...)")
    return jsonify({"success": True, "token": meta, "raw_token": raw_token})


@app.get("/api/tokens")
@login_required
def list_tokens_api():
    user = get_current_user()
    return jsonify(store.list_user_api_tokens(user["id"]))


@app.delete("/api/tokens/<token_id>")
@login_required
def revoke_token_api(token_id):
    user = get_current_user()
    ok = store.revoke_api_token(user["id"], token_id)
    if not ok:
        return err("Token not found or already revoked.", 404)
    store.record_audit(user["id"], "pat_token_revoked", request.remote_addr, f"Token ID: {token_id}")
    return jsonify({"success": True})


# ---------------------------------------------------------- Headless REST API v1
@app.post("/api/v1/scan")
def api_v1_scan():
    """Headless scan endpoint for CLI, CI/CD pipelines, and automated security tools.
    Supports Personal Access Tokens (Authorization: Bearer pat_...) and Session auth.
    Accepts multipart file or JSON payload (text/code).
    Returns JSON summary or SARIF 2.1.0 format based on format query or Accept header."""
    user = get_current_user()
    store.sweep_tmp()

    # Determine input data: multipart file or JSON body
    if "file" in request.files:
        f = request.files["file"]
        if not f or not f.filename:
            return err("Choose a file to scan.")
        filename = safe_name(f.filename)
        data = f.read()
    else:
        body = request.get_json(silent=True) or {}
        text = body.get("text")
        if text is None:
            return err("Provide a 'file' in multipart upload or 'text' in JSON payload.")
        filename = safe_name(body.get("filename") or "code.txt")
        data = text.encode("utf-8")

    if len(data) > config.MAX_UPLOAD_BYTES:
        return err(f"File exceeds maximum upload size of {config.MAX_UPLOAD_BYTES // (1024 * 1024)} MB.", 413)

    try:
        ex, findings = service.analyse(filename, data)
    except extract.ScanError as e:
        return err(str(e))

    internal = [{k: v for k, v in x.items() if k != "_value"} for x in findings]
    scan_id = uuid.uuid4().hex
    summ = service.summary(internal)

    # Persist in DB and store for state/download if requested
    d = config.TMP_DIR / scan_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "original.bin").write_bytes(data)
    state = {
        "filename": filename, "kind": ex.kind, "size": len(data), "created": time.time(),
        "text": ex.text, "pages": ex.pages, "words": ex.words, "img_size": ex.size,
        "warnings": ex.warnings, "findings": internal, "user_id": user["id"] if user else None,
    }
    (d / "state.json").write_text(json.dumps(state), encoding="utf-8")

    store.record_scan(scan_id, filename, ex.kind, len(data), summ,
                      user_id=user["id"] if user else None, findings=internal)
    if user:
        store.record_audit(user["id"], "headless_scan", request.remote_addr, f"{filename} findings={len(internal)}")

    fmt = (request.args.get("format") or "").lower()
    accept = request.headers.get("Accept", "").lower()

    if fmt == "sarif" or "application/sarif+json" in accept:
        sarif_log = sarif.generate_sarif(filename, internal, scan_id=scan_id)
        return jsonify(sarif_log)

    return jsonify({
        "scan_id": scan_id,
        "filename": filename,
        "kind": ex.kind,
        "size": len(data),
        "summary": summ,
        "findings": service.public(internal),
        "warnings": ex.warnings,
        "masked_text": service.masked_text(ex.text, internal) if ex.kind != "image" else None,
        "downloads": {
            "sarif": f"/api/download/{scan_id}/sarif",
        },
    })


# ---------------------------------------------------------- IDE Guard API
@app.post("/api/ide/scan")
def ide_scan():
    """In-memory scan for IDE extensions and pre-commit hooks.
    Creates zero temporary files on disk and never logs raw values."""
    body = request.get_json(silent=True) or {}
    filename = safe_name(body.get("filename") or "code.py")
    content = body.get("content") or ""

    if not content:
        return jsonify({"filename": filename, "diagnostics": [], "summary": {"total": 0, "active": 0}})

    try:
        ex, findings = service.analyse(filename, content.encode("utf-8"))
    except extract.ScanError as e:
        return err(str(e))

    diagnostics = []
    for f in findings:
        var_name = f.get("key") or f.get("type", "SECRET").upper()
        env_var = re.sub(r"[^\w]", "_", var_name).upper()
        if not env_var.isidentifier():
            env_var = f"ENV_{env_var}"

        if filename.endswith((".js", ".ts", ".jsx", ".tsx")):
            suggested = f"process.env.{env_var}"
        elif filename.endswith(".py"):
            suggested = f"os.environ.get('{env_var}')"
        elif filename.endswith((".java", ".properties")):
            suggested = f"System.getenv(\"{env_var}\")"
        else:
            suggested = f"${env_var}"

        level = f.get("level", "medium")
        severity = "error" if level == "high" else "warning" if level == "medium" else "information"

        diagnostics.append({
            "line": f.get("line", 1),
            "col": f.get("col", 1),
            "end_line": f.get("end_line", f.get("line", 1)),
            "end_col": f.get("end_col", f.get("col", 1) + 10),
            "severity": severity,
            "message": f"LeakLens: Potential {f.get('label')} detected ({level.upper()} risk).",
            "preview": f.get("preview"),
            "provider": f.get("provider", "Generic"),
            "confidence": f.get("confidence", "Medium"),
            "status": f.get("status"),
            "why": f.get("why"),
            "remediation": f.get("action"),
            "blast_radius": f.get("blast_radius", ""),
            "suggested_fix": suggested,
            "env_var": env_var,
            "type": f.get("type"),
        })

    return jsonify({
        "filename": filename,
        "diagnostics": diagnostics,
        "summary": service.summary(findings),
    })


# ---------------------------------------------------------- evaluation
@app.get("/api/evaluation")
def evaluation():
    try:
        return jsonify(json.loads(config.EVAL_PATH.read_text()))
    except (OSError, ValueError):
        return err("No evaluation yet. Run: python -m training.train", 404)


# ---------------------------------------------------------- CLI & Entry Point
def cli_create_admin(username, email, password):
    if len(password) < 8:
        print("Error: Password must be at least 8 characters long.", file=sys.stderr)
        return 1
    try:
        user = store.create_user(username, email, password, role="admin")
        print(f"[SUCCESS] Created administrator account: {user['username']} ({user['email']})")
        return 0
    except Exception as e:
        print(f"[ERROR] Failed to create admin: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LeakLens Privacy Guard")
    subparsers = parser.add_subparsers(dest="command")

    admin_parser = subparsers.add_parser("create-admin", help="Create an initial administrator account securely")
    admin_parser.add_argument("--username", required=True, help="Admin username")
    admin_parser.add_argument("--email", required=True, help="Admin email")
    admin_parser.add_argument("--password", required=True, help="Admin password (min 8 chars)")

    args = parser.parse_args()

    if args.command == "create-admin":
        sys.exit(cli_create_admin(args.username, args.email, args.password))
    else:
        config.TMP_DIR.mkdir(parents=True, exist_ok=True)
        app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
