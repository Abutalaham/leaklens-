# LeakLens — Implementation Gap Matrix & Specification Audit

This matrix provides an objective, code-verified comparison between the **LeakLens Master Specification** and the current implementation as of November 21, 2026.

---

## 1. Executive Summary

| Status Category | Count | Key Highlights |
|---|---|---|
| **1. IMPLEMENTED AND VERIFIED** | 16 | Core hybrid detection (Rules + Context + ML), in-place redaction, rescan verification, PDF/image extraction, Scrypt password hashing, session cookies, rate limiting, basic user dashboard, basic admin dashboard. |
| **2. IMPLEMENTED BUT NEEDS VERIFICATION** | 3 | IDE extension TypeScript source, Pre-commit hook, Team setup package generation. |
| **3. PARTIALLY IMPLEMENTED** | 8 | User/Admin dashboards (need advanced metrics/filters), Vault (lacks portable format), IDE Guard (simulator exists, extension lacks packaging/VSIX build). |
| **4. NOT IMPLEMENTED** | 14 | 2FA (TOTP), Portable `.leaklens` vault file format, Standalone CLI (`leaklens scan`), SARIF export, REST API v1 with Personal Access Tokens (PATs), Blast-radius analysis, GitHub repo scanning, Classroom mode & Instructor roles. |
| **5. CONFLICTS WITH EXISTING ARCHITECTURE** | 1 | SQLite vs suggested multi-user Postgres (retaining SQLite with WAL mode is strongly recommended for local free-tier compliance). |
| **6. REQUIRES SECURITY IMPROVEMENT** | 3 | Vault cryptographic cipher upgrade (HMAC-stream to AES-256-GCM), TOTP 2FA enforcement, PAT token hashing and scoping. |

---

## 2. Detailed Requirement Gap Matrix

### Feature Group P0: Core Security, Identity & High-Priority Platform Features

| Feature Name | Spec Ref | Existing Files / Modules | Current Implementation | Missing Functionality | Tests Available | Priority | Recommended Action | Classification |
|---|---|---|---|---|---|---|---|---|
| **Multi-Factor Auth (2FA / TOTP)** | P0.1 | `app.py`, `engine/store.py` | RFC 6238 TOTP engine, secret generation, otpauth URI, 8 single-use recovery codes, login challenge enforcement. | None for Phase 1. Optional: native QR code canvas rendering in browser without CDN. | `test_phase1_p0.py::test_totp_2fa_full_lifecycle` | P0 | Verified working. Ready for production. | **IMPLEMENTED AND VERIFIED** |
| **Cryptographic Portable Vault (`.leaklens`)** | P0.2 | `engine/store.py`, `app.py` | Scrypt KDF + AES-256-GCM authenticated encryption for database vault items and standalone portable `.leaklens` files. | None. Export (`/api/vault/export`) and Import (`/api/vault/import`) working. | `test_phase1_p0.py::test_aes_gcm_vault_encryption`, `test_phase1_p0.py::test_portable_leaklens_vault_export_and_import` | P0 | Verified working with Scrypt and AES-256-GCM. | **IMPLEMENTED AND VERIFIED** |
| **Advanced User Dashboard** | P0.3 | `templates/index.html`, `static/app.js`, `app.py` | Basic summary cards, history list, and daily trend bar chart. | Scan-level drilldown modals, category distribution donuts, MTTR/sanitization tracking, filterable table by tag/provider. | `test_auth_and_features.py::test_user_data_isolation` | P0 | Enhance `/api/user/stats` to aggregate by provider, risk category, and time-to-sanitize; expand UI charts. | **PARTIALLY IMPLEMENTED** |
| **Advanced Admin Dashboard** | P0.4 | `templates/index.html`, `static/app.js`, `app.py` | Aggregate user counts, active/disabled toggle, disk stats, audit list, policy editor. | Granular role assignment (user, auditor, instructor, admin), user-level quota enforcement, audit log search/export. | `test_auth_and_features.py::test_admin_authorization` | P0 | Add audit log CSV/JSON export and user quota controls while maintaining privacy. | **PARTIALLY IMPLEMENTED** |
| **VS Code Extension (Installable)** | P0.5 | `ide-extension/*`, `app.py` | TypeScript extension source with diagnostics provider, in-memory scan API (`/api/ide/scan`), `leaklens.scanWorkspace` batch command, compiled `.vsix` (`leaklens-ide-guard.vsix`). | Support for custom threshold overrides via `.leaklensrc` within extension. | `test_auth_and_features.py::test_ide_guard_in_memory_scan` | P0 | ✅ Phase 3 complete: VSIX built and packaged, workspace scan command implemented. | **IMPLEMENTED AND VERIFIED** |

---

### Feature Group P1: Developer Tooling, Automation & Intelligence

| Feature Name | Spec Ref | Existing Files / Modules | Current Implementation | Missing Functionality | Tests Available | Priority | Recommended Action | Classification |
|---|---|---|---|---|---|---|---|---|
| **Standalone LeakLens CLI** | P1.1 | `cli.py` | Full CLI with recursive directory scanning, single-file scan, custom threshold (`high`, `medium`, `low`), multiple formats (`text`, `json`, `sarif`), remote server scanning, and vault import/export. | None for Phase 2. Optional: colorama for non-ANSI Windows terminals. | `test_phase2_p1.py::test_cli_standalone_scan_exit_codes`, `test_phase2_p1.py::test_cli_vault_export_and_import` | P1 | Fully verified and operational. | **IMPLEMENTED AND VERIFIED** |
| **Git Pre-Commit Hook** | P1.2 | `scripts/leaklens-pre-commit.py`, `scripts/install-hook.py` | Working staged file scanner calling `git show :<file>` and `service.analyse`. Bug fixed (config.TEXT_EXTS vs extract.TEXT_EXTS). 6 automated tests cover allow, block, and unstaged scenarios. | Support for custom threshold overrides via `.leaklensrc`, diff hunk line matching. | `tests/test_hooks.py` (6 tests: all passing) | P1 | ✅ Phase 3 complete: bug fixed, automated tests added and passing. | **IMPLEMENTED AND VERIFIED** |
| **SARIF 2.1.0 Export** | P1.3 | `engine/sarif.py`, `app.py`, `cli.py` | Full OASIS SARIF 2.1.0 exporter mapping findings into rule descriptors and result locations with masked preview/snippets. Direct download via `/api/download/<scan_id>/sarif`. | None. Fully compliant with SARIF 2.1.0 standard schema. | `test_phase2_p1.py::test_sarif_generation_and_schema_compliance`, `test_phase2_p1.py::test_api_v1_headless_scan_and_sarif_export` | P1 | Fully verified and operational. | **IMPLEMENTED AND VERIFIED** |
| **REST API v1 & Personal Access Tokens (PATs)** | P1.4 | `app.py`, `engine/store.py` | Database table `api_tokens` with SHA-256 hashed storage, token generation, revocation, and Bearer token middleware (`Authorization: Bearer pat_...`). Headless `/api/v1/scan` endpoint. | None. Supports expiration, prefix/last4 masking, and CSRF bypass for Bearer tokens. | `test_phase2_p1.py::test_pat_token_generation_and_hashing`, `test_phase2_p1.py::test_pat_api_endpoints_and_bearer_auth`, `test_phase2_p1.py::test_api_v1_headless_scan_and_sarif_export` | P1 | Fully verified and operational. | **IMPLEMENTED AND VERIFIED** |
| **OpenAPI / Swagger Spec** | P1.5 | None | None | OpenAPI 3.0 / Swagger UI definition (`/docs` or `/api/spec.json`). | None | P1 | Add lightweight OpenAPI 3.0 JSON specification route. | **NOT IMPLEMENTED** |
| **Blast-Radius Explanation** | P1.6 | `engine/catalog.py`, `engine/risk.py` | General advice ("Revoke or rotate it now", risk explanation). | Specific blast-radius assessment (e.g. AWS IAM permissions potentially affected, financial impact of Stripe live key). | `test_rules.py::test_explanations_present` | P1 | Enrich finding metadata with concrete blast-radius scope descriptors per provider. | **PARTIALLY IMPLEMENTED** |
| **Human Feedback & Model Retraining** | P1.7 | `training/train.py`, `training/dataset.py` | Offline dataset generator and training script. | Web UI button to report false-positives/negatives, review queue, safe incremental retraining pipeline. | Offline training verified | P1 | Add user feedback store (`feedback` table) and exportable false-positive fine-tuning script. | **NOT IMPLEMENTED** |
| **Public GitHub Repository Scanner** | P1.8 | None | None | Remote repository URL cloning (shallow clone in temp sandbox), branch scanning, commit history scanning. | None | P1 | Implement `/api/scan/github` using shallow git clone with strict URL sanitization and size caps. | **NOT IMPLEMENTED** |

---

### Feature Group P2: Collaborative & Educational Capabilities

| Feature Name | Spec Ref | Existing Files / Modules | Current Implementation | Missing Functionality | Tests Available | Priority | Recommended Action | Classification |
|---|---|---|---|---|---|---|---|---|
| **Classroom Mode & Instructor Role** | P2.1 | `engine/store.py` | Roles supported: `user` and `admin`. | `instructor` role, course/cohort grouping, assignment submission scanning, student progress tracking. | None | P2 | Add `instructor` role, cohort tables, and classroom dashboard. | **NOT IMPLEMENTED** |
| **Anonymous Security Leaderboard** | P2.2 | None | None | Gamified student/team hygiene scoring, zero-knowledge handles, streaks. | None | P2 | Add opt-in cohort leaderboard route with aggregated hygiene percentiles. | **NOT IMPLEMENTED** |
| **Public Demo Sandbox** | P2.3 | `templates/index.html`, `app.py` | Unauthenticated scanning supported on home/scan view. | Rate-limited sandbox banner, sample file pre-loader, ephemeral session indicator. | `test_app.py::test_full_workflow_text` | P2 | Add one-click sample file loader in Web UI for quick demonstrations without file picking. | **PARTIALLY IMPLEMENTED** |

---

## 3. Database Architecture Note (Conflict Audit)

- **Spec proposal:** Multi-tenant PostgreSQL or centralized enterprise DB.
- **Current architecture:** Local SQLite database at `instance/leaklens.db` with WAL mode and multi-table structure (`users`, `scans`, `login_attempts`, `password_resets`, `user_vault`, `audit_logs`).
- **Audit Verdict:** Retaining SQLite is **strictly aligned with Free-Tier & Local Processing constraints**. It requires zero database servers, runs cross-platform without Docker/network setup, and easily handles student/developer workloads. No migration is necessary.
