"""Phase 2 Tests: Headless Tooling (PAT Tokens, Standalone CLI & SARIF 2.1.0 Export).

Verifies:
1. Personal Access Tokens (PATs) generation, SHA-256 storage, Bearer auth, expiration, and revocation.
2. OASIS SARIF 2.1.0 schema compliance, rule descriptors, masked snippets, and downloads.
3. Headless REST API v1 (`/api/v1/scan`) JSON & SARIF output.
4. Standalone CLI scanning (`cli.py`), exit codes (0 on clean, 1 on leaks), and vault export/import.
"""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

import pytest

import cli
from engine import sarif, store


def test_pat_token_generation_and_hashing(client):
    # Create user
    user = store.create_user("pat_user", "pat_user@example.com", "Password123!")
    
    # Generate PAT
    meta, raw_token = store.create_api_token(user["id"], name="CI Runner Token", expires_days=30)
    assert raw_token.startswith("pat_")
    assert len(raw_token) > 20
    assert meta["name"] == "CI Runner Token"
    assert meta["token_prefix"] == raw_token[:8]
    assert meta["token_last4"] == raw_token[-4:]
    assert meta["status"] == "active"
    assert meta["expires_at"] is not None

    # Verify raw token is NEVER stored directly in the database
    with store._db() as con:
        row = con.execute("SELECT * FROM api_tokens WHERE id=?", (meta["id"],)).fetchone()
        assert row is not None
        assert row["token_hash"] != raw_token
        # It must be SHA-256 hex (64 chars)
        assert len(row["token_hash"]) == 64

    # Verify token lookup
    verified = store.verify_api_token(raw_token)
    assert verified is not None
    assert verified["user_id"] == user["id"]
    assert verified["username"] == "pat_user"
    assert verified["last_used"] is not None

    # Invalid token check
    assert store.verify_api_token("pat_invalidtoken123456789") is None
    assert store.verify_api_token("bad_prefix") is None


def test_pat_api_endpoints_and_bearer_auth(client):
    # Register and log in
    client.post("/api/auth/register", json={
        "username": "pat_tester",
        "email": "pat_tester@example.com",
        "password": "Password123!"
    })

    # Create PAT via API
    r_create = client.post("/api/tokens", json={
        "name": "GitHub Actions",
        "expires_days": 60,
        "scopes": "read,scan"
    })
    assert r_create.status_code == 200
    create_data = r_create.get_json()
    assert create_data["success"] is True
    raw_token = create_data["raw_token"]
    token_id = create_data["token"]["id"]
    assert raw_token.startswith("pat_")

    # List tokens via session
    r_list = client.get("/api/tokens")
    assert r_list.status_code == 200
    tokens = r_list.get_json()
    assert len(tokens) == 1
    assert tokens[0]["name"] == "GitHub Actions"

    # Log out session
    client.post("/api/auth/logout")

    # Unauthorized access without session or Bearer
    r_unauth = client.get("/api/tokens")
    assert r_unauth.status_code == 401

    # Authorized access with Bearer PAT token
    r_bearer = client.get("/api/tokens", headers={"Authorization": f"Bearer {raw_token}"})
    assert r_bearer.status_code == 200
    assert len(r_bearer.get_json()) == 1

    # Revoke token via Bearer auth
    r_del = client.delete(f"/api/tokens/{token_id}", headers={"Authorization": f"Bearer {raw_token}"})
    assert r_del.status_code == 200

    # Token should no longer authenticate
    r_revoked = client.get("/api/tokens", headers={"Authorization": f"Bearer {raw_token}"})
    assert r_revoked.status_code == 401


def test_sarif_generation_and_schema_compliance():
    sample_findings = [
        {
            "id": "f1",
            "type": "AWS_KEY",
            "label": "AWS Access Key",
            "category": "Cloud Provider",
            "provider": "AWS",
            "confidence": "High",
            "line": 15,
            "col": 12,
            "end_line": 15,
            "end_col": 32,
            "score": 90,
            "level": "high",
            "status": "active",
            "source": "rule",
            "preview": "AKIA••••••••••••••••",
            "context": "aws_key = 'AKIA████████████████'",
            "why": "Grants programmatic access to AWS cloud resources.",
            "action": "Rotate the credential in AWS IAM immediately."
        },
        {
            "id": "f2",
            "type": "GENERIC_API_KEY",
            "label": "API Key",
            "category": "Credential",
            "provider": "Generic",
            "confidence": "Medium",
            "line": 28,
            "col": 10,
            "end_line": 28,
            "end_col": 30,
            "score": 60,
            "level": "medium",
            "status": "active",
            "source": "rule",
            "preview": "api_••••••••",
            "context": "secret = 'api_████████'",
            "why": "Possible third-party API token.",
            "action": "Store in environment variables."
        }
    ]

    sarif_log = sarif.generate_sarif("config/settings.py", sample_findings, scan_id="test_scan_001")

    # Validate OASIS SARIF 2.1.0 root structure
    assert sarif_log["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    assert sarif_log["version"] == "2.1.0"
    assert len(sarif_log["runs"]) == 1

    run = sarif_log["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "LeakLens"
    assert driver["version"] == "2.0.0"
    assert len(driver["rules"]) == 2

    # Check rule descriptors
    rule_ids = {r["id"] for r in driver["rules"]}
    assert "LL-AWS-KEY" in rule_ids
    assert "LL-GENERIC-API-KEY" in rule_ids

    # Check results mapping
    results = run["results"]
    assert len(results) == 2
    r_aws = next(r for r in results if r["ruleId"] == "LL-AWS-KEY")
    assert r_aws["level"] == "error"
    assert "AKIA••••" in r_aws["message"]["text"]
    loc = r_aws["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "config/settings.py"
    assert loc["region"]["startLine"] == 15
    assert loc["region"]["startColumn"] == 12
    assert "AKIA████" in loc["region"]["snippet"]["text"]

    # Verify no raw unmasked values leaked into JSON
    raw_json = json.dumps(sarif_log)
    assert "AKIA1234" not in raw_json


def test_api_v1_headless_scan_and_sarif_export(client, fake):
    # Register user & create PAT
    client.post("/api/auth/register", json={
        "username": "headless_dev",
        "email": "dev@example.com",
        "password": "Password123!"
    })
    r_pat = client.post("/api/tokens", json={"name": "CLI PAT"})
    pat = r_pat.get_json()["raw_token"]

    dirty_code = (
        f"# Server initialization\n"
        f"aws_token = '{fake['aws']}'\n"
        f"stripe_key = '{fake['stripe']}'\n"
        f"app_port = 8080\n"
    )

    # 1. Headless scan with JSON format output
    r_json = client.post(
        "/api/v1/scan",
        json={"filename": "service.py", "text": dirty_code},
        headers={"Authorization": f"Bearer {pat}"}
    )
    assert r_json.status_code == 200
    res = r_json.get_json()
    assert res["filename"] == "service.py"
    assert res["summary"]["active"] >= 2
    assert res["summary"]["high"] >= 1
    scan_id = res["scan_id"]
    assert "sarif" in res["downloads"]

    # 2. Headless scan with SARIF format output
    r_sarif = client.post(
        "/api/v1/scan?format=sarif",
        json={"filename": "service.py", "text": dirty_code},
        headers={"Authorization": f"Bearer {pat}"}
    )
    assert r_sarif.status_code == 200
    sarif_data = r_sarif.get_json()
    assert sarif_data["version"] == "2.1.0"
    results = sarif_data["runs"][0]["results"]
    assert len(results) >= 2

    # 3. Download SARIF via `/api/download/<scan_id>/sarif`
    r_down = client.get(f"/api/download/{scan_id}/sarif", headers={"Authorization": f"Bearer {pat}"})
    assert r_down.status_code == 200
    assert "application/sarif+json" in r_down.headers.get("Content-Type", "")
    down_sarif = json.loads(r_down.data.decode("utf-8"))
    assert down_sarif["version"] == "2.1.0"


def test_cli_standalone_scan_exit_codes(tmp_path, fake):
    # Create clean file
    clean_file = tmp_path / "clean.py"
    clean_file.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    # Create dirty file with active secrets
    dirty_file = tmp_path / "dirty.py"
    dirty_file.write_text(f"API_SECRET = '{fake['aws']}'\n", encoding="utf-8")

    # 1. Scan clean file (should exit with 0)
    args_clean = argparse.Namespace(
        path=str(clean_file),
        format="text",
        threshold="high",
        output=None,
        server=None,
        pat=None,
    )
    code_clean = cli.run_scan(args_clean)
    assert code_clean == 0

    # 2. Scan dirty file with threshold 'high' (should exit with 1)
    args_dirty = argparse.Namespace(
        path=str(dirty_file),
        format="text",
        threshold="high",
        output=None,
        server=None,
        pat=None,
    )
    code_dirty = cli.run_scan(args_dirty)
    assert code_dirty == 1

    # 3. Scan with SARIF output file
    sarif_out = tmp_path / "report.sarif"
    args_sarif = argparse.Namespace(
        path=str(dirty_file),
        format="sarif",
        threshold="high",
        output=str(sarif_out),
        server=None,
        pat=None,
    )
    code_sarif = cli.run_scan(args_sarif)
    assert code_sarif == 1
    assert sarif_out.exists()
    sarif_content = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_content["version"] == "2.1.0"
    assert len(sarif_content["runs"][0]["results"]) >= 1


def test_cli_vault_export_and_import(client, tmp_path):
    # Setup user in db
    user = store.create_user("cli_vault_user", "cli_vault@example.com", "Password123!")
    store.vault_add_item(user["id"], "GITHUB_TOKEN", "GitHub", "ghp_••••", "ghp_1234567890abcdef1234567890abcdef")

    vault_file = tmp_path / "cli_backup.leaklens"

    # Export via CLI
    args_exp = argparse.Namespace(
        output_file=str(vault_file),
        password="CliVaultPassword123!",
        username="cli_vault_user",
    )
    res_exp = cli.run_vault_export(args_exp)
    assert res_exp == 0
    assert vault_file.exists()
    assert vault_file.read_bytes().startswith(b"LEAKLENS_VAULT\x01")

    # Create target user for import
    importer = store.create_user("cli_importer", "cli_importer@example.com", "Password123!")
    args_imp = argparse.Namespace(
        input_file=str(vault_file),
        password="CliVaultPassword123!",
        username="cli_importer",
    )
    res_imp = cli.run_vault_import(args_imp)
    assert res_imp == 0

    # Verify credentials imported into target user
    imported_items = store.vault_list_items(importer["id"])
    assert len(imported_items) == 1
    assert imported_items[0]["key_name"] == "GITHUB_TOKEN"
