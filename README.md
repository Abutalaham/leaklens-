# LeakLens — Full-Stack Privacy Leak Detection & Developer Security Platform

Privacy-aware scanner with a **hybrid detector** (rules + mathematical checksums + context checks + a local char n-gram Logistic Regression model), **explainable risk scores**, **in-place redaction with rescan verification**, **user & admin dashboards**, **safe team developer handoff**, and **real-time IDE Guard**.

Runs **100% locally on CPU**, requires **zero paid APIs**, **zero GPU**, and **no internet connection at runtime**.

---

## 🚀 Quick Start (Local Setup)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```
*(Optional: For screenshot OCR, install [Tesseract OCR](https://github.com/tesseract-ocr/tesseract) and ensure it is on your PATH).*

### 2. Create an Initial Administrator Account
Use the secure CLI command to create your first admin (no plaintext default passwords!):
```bash
python app.py create-admin --username admin --email admin@leaklens.local --password YourSecurePassword123
```

### 3. Launch the Application
```bash
python app.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your web browser.

---

## 🌟 Key Capabilities & Upgraded Features

### 1. Hybrid Detection Engine
* **Deterministic Rules & Providers:** Detects AWS Access & Secret keys, GitHub tokens, Google API keys, Stripe live keys, Slack tokens, SendGrid tokens, OpenAI-style `sk-` keys, npm tokens, Hugging Face tokens, Twilio keys, Discord bot tokens, GitLab PATs, Postman keys, DigitalOcean tokens, JWTs, private keys, database connection strings, and authorization headers.
* **Algorithmic Validation:** Employs the **Luhn algorithm** for payment cards, the **Verhoeff algorithm** for Indian Aadhaar, and format validators for US SSNs and Indian PANs.
* **Context Filtering:** Filters out harmless placeholder values (`your_api_key_here`, `example.com`), environment variable reads (`os.environ.get(...)`), and sample test fixtures to avoid false alerts.
* **Local ML Model (TF-IDF + Logistic Regression):** Evaluates character 3–5 grams to discover secrets assigned to unfamiliar variable names. ML findings are capped at medium risk and never decide severity alone.

### 2. Complete Authentication & Role-Based Access Control
* **Secure Registration & Login:** Password hashing using standard Scrypt (`werkzeug.security`), secure session management with `HttpOnly` and `SameSite=Lax` cookies.
* **Brute-Force Rate Limiting:** Locks out excessive failed login attempts per IP/username.
* **User Isolation:** Users can view, redact, and manage only their own scan history and reports.
* **Self-Service Password Reset:** Safe local reset token workflow (tokens expire in 1 hour).
* **Profile Settings:** Update username, email, and password.

### 3. User Dashboard & Risk Analytics
* **Summary Cards:** Total files scanned, total detected findings, breakdown by High, Medium, and Low risk, and total sanitized files.
* **Visual Trend Chart:** Responsive SVG bar chart visualizing findings and scan volume over time.
* **Search & Filters:** Filter scan history by date, severity level, format, or filename keyword.
* **Instant Privacy Purge:** Delete individual scan files or purge all user history with one click.

### 4. Administrator Control Center (`/admin`)
* **Role-Protected Backend:** Only authenticated administrators (`role == 'admin'`) can access admin routes.
* **Aggregate Telemetry:** Total registered users, active vs. disabled accounts, total system scans, and storage consumption.
* **Account Management:** Enable, disable, or remove accounts according to data retention policies.
* **Scoring Policy Editor:** Adjust base risk weights dynamically (persisted to `instance/scoring.json`).
* **Zero Secret Exposure:** Admins **never** see raw passwords, API keys, or private uploaded files.

### 5. Safe Team Developer Handoff
* **Secret Inventory:** Extracts detected environment variables, providers, and risk levels without exposing raw values.
* **`.env.example` Generator:** Automatically builds clean `.env.example` templates populated with placeholder assignments only.
* **Team Setup Package (ZIP):** Generates a downloadable ZIP containing:
  - `.env.example`
  - `README-TEAM-SETUP.md`
  - `INSTALLATION-GUIDE.md`
  - `SECURITY-CHECKLIST.md`
* **Local Encrypted Vault:** Owner-controlled local credential vault encrypted with authenticated PBKDF2/HMAC keys.

### 6. LeakLens IDE Guard & Git Pre-Commit Hook
* **VS Code Extension (`ide-extension/`):**
  - Real-time in-editor diagnostics and highlighting on save.
  - One-click **QuickFix**: Replaces hardcoded literals with `os.environ.get('VAR')` (Python) or `process.env.VAR` (JS/TS).
  - Automatically ignores `node_modules`, `.git`, `.venv`, and build artifacts.
* **In-Memory Backend Endpoint (`/api/ide/scan`):**
  - Scans code in-memory with zero disk persistence.
* **Git Pre-Commit Hook (`scripts/leaklens-pre-commit.py`):**
  - Install via `python scripts/install-hook.py`.
  - Blocks `git commit` if active high or medium risk credentials are staged.

---

## 🧪 Testing & Verification

Run the full automated test suite (all tests run locally in seconds):
```bash
python -m pytest tests -q
```
*Current test suite: **33 passed, 1 skipped** (optional OCR)*

Covered test suites:
- `tests/test_rules.py`: Regex matching, checksums, and entropy.
- `tests/test_context.py`: Placeholders, docs, test fixtures, benign assignments.
- `tests/test_risk.py`: Additive explainable risk scoring.
- `tests/test_ml.py`: TF-IDF classifier inference and threshold tuning.
- `tests/test_extract.py`: Text, PDF, and image extraction.
- `tests/test_redact.py`: Code, PDF, and image redaction.
- `tests/test_app.py`: Scan, redact, download, and file lifecycle APIs.
- `tests/test_auth_and_features.py`: Registration, login, rate limiting, password reset, user data isolation, admin authorization, safe team setup, and in-memory IDE scanning.

---

## 📁 Project Directory Structure

```
leaklens/
├── app.py                      # Flask REST API, web views, and CLI commands
├── config.py                   # System limits, thresholds, and security configuration
├── requirements.txt            # Minimal free-tier Python dependencies
├── pytest.ini                  # Pytest configuration
├── engine/                     # Core detection & processing engine
│   ├── catalog.py              # Finding catalog, explanations, and remediation actions
│   ├── context.py              # Heuristics for placeholders and benign code contexts
│   ├── detector.py             # Hybrid detector coordinating rules, context, and ML
│   ├── extract.py              # File extractors (Text, PDF, OCR, Image metadata)
│   ├── ml.py                   # Local char n-gram Logistic Regression model loader
│   ├── redact.py               # Redaction and sanitisation logic
│   ├── risk.py                 # Additive explainable risk scoring system
│   ├── rules.py                # Regex rules, Shannon entropy, Luhn & Verhoeff checksums
│   ├── service.py              # High-level scan and redaction orchestration
│   └── store.py                # SQLite database (auth, scans, audit logs, encrypted vault)
├── ide-extension/              # LeakLens IDE Guard (VS Code Extension)
│   ├── package.json            # VS Code extension manifest
│   ├── tsconfig.json           # TypeScript configuration
│   ├── README.md               # IDE Guard installation and setup guide
│   └── src/
│       └── extension.ts        # In-editor diagnostics and QuickFix provider
├── scripts/                    # Developer tooling
│   ├── leaklens-pre-commit.py  # Local Git pre-commit security hook
│   └── install-hook.py         # One-click hook installer
├── templates/                  # Frontend HTML templates
│   ├── index.html              # Modern unified cybersecurity dashboard
│   └── report.html             # Standalone downloadable audit report
├── static/                     # Frontend styling & client logic
│   ├── style.css               # Responsive cybersecurity SaaS theme (Dark/Light)
│   └── app.js                  # Frontend controllers and interactive views
├── models/                     # Shipped local model & thresholds
├── samples/                    # Synthetic demo files for testing
├── evaluation/                 # Metrics & evaluation report (EVALUATION.md)
└── tests/                      # Automated Pytest suite (33 tests)
```

---

## 🛡️ Privacy & Security Architecture

1. **Local-Only Processing:** All file uploads live in `instance/tmp/<id>/` and are permanently deleted after 30 minutes (or immediately via the manual "Delete temporary files" button).
2. **Server-Side Secret Masking:** Raw secrets are **never** transmitted to the browser, stored in history tables, or written to server logs.
3. **Robust Cryptography:** Uses Scrypt for password hashing and PBKDF2 + HMAC-SHA256 for local vault encryption.
4. **Defense in Depth:** Enforces Content Security Policy (`CSP`), `nosniff`, `SameSite=Lax` cookies, and parameter sanitization.
5. **No Telemetry / No Tracking:** Zero external network calls or tracking scripts.

---

## 📖 Known Limitations

- **OCR Accuracy:** OCR on long random strings can experience character confusion (e.g., `0`/`O`). Bounding box redaction covers whole OCR words.
- **Text-Only PDF Redaction:** PDF redaction rebuilds a secure text-only document via `reportlab` to ensure nothing hidden remains in unflattened streams.
- **Model Training:** The model is trained on synthetic snippets; real-world obfuscated code may require user review. Rotating credentials remains the primary remediation for leaked secrets.
# leaklens-
