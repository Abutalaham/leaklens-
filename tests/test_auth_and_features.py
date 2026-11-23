import io
import json
import zipfile
import pytest

from engine import store


def test_auth_registration_and_login(client):
    # Registration
    r = client.post("/api/auth/register", json={
        "username": "alice",
        "email": "alice@example.com",
        "password": "Password123"
    })
    assert r.status_code == 200
    j = r.get_json()
    assert j["success"] is True
    assert j["user"]["username"] == "alice"

    # Current user check
    me = client.get("/api/auth/me").get_json()
    assert me["authenticated"] is True
    assert me["user"]["username"] == "alice"

    # Logout
    r_out = client.post("/api/auth/logout")
    assert r_out.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is False

    # Login
    r_in = client.post("/api/auth/login", json={
        "username": "alice",
        "password": "Password123"
    })
    assert r_in.status_code == 200
    assert r_in.get_json()["success"] is True

    # Bad login
    r_bad = client.post("/api/auth/login", json={
        "username": "alice",
        "password": "WrongPassword"
    })
    assert r_bad.status_code == 401


def test_password_reset_workflow(client):
    # Register user
    client.post("/api/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "BobPassword123"
    })
    client.post("/api/auth/logout")

    # Request reset
    req = client.post("/api/auth/forgot-password", json={"email_or_username": "bob@example.com"}).get_json()
    token = req.get("reset_token")
    assert token is not None

    # Reset password with token
    reset = client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": "NewBobPassword123"
    }).get_json()
    assert reset["success"] is True

    # Re-login with new password
    login_new = client.post("/api/auth/login", json={
        "username": "bob",
        "password": "NewBobPassword123"
    })
    assert login_new.status_code == 200


def test_user_data_isolation(client):
    # User 1 registers and uploads file
    client.post("/api/auth/register", json={"username": "user1", "email": "u1@example.com", "password": "Password123"})
    src = b'MY_KEY = "ghp_drfXArg153cyIJvv2dkivJvSpka5BXf4Myea"\n'
    r1 = client.post("/api/scan", data={"file": (io.BytesIO(src), "u1_secrets.py")}, content_type="multipart/form-data")
    assert r1.status_code == 200
    scan_id1 = r1.get_json()["scan_id"]
    finding_ids = [finding["id"] for finding in r1.get_json()["findings"]]
    redact_response = client.post("/api/redact", json={"scan_id": scan_id1, "finding_ids": finding_ids})
    assert redact_response.status_code == 200

    # User 1 history has 1 scan
    h1 = client.get("/api/user/history").get_json()
    assert any(s["id"] == scan_id1 for s in h1)

    # User 2 registers
    client.post("/api/auth/logout")
    client.post("/api/auth/register", json={"username": "user2", "email": "u2@example.com", "password": "Password123"})

    # User 2 history must NOT contain User 1's scan
    h2 = client.get("/api/user/history").get_json()
    assert not any(s["id"] == scan_id1 for s in h2)
    paged = client.get("/api/user/history?page=1&per_page=10").get_json()
    assert paged["total"] == 0
    assert client.get(f"/api/user/history/{scan_id1}").status_code == 404

    # User 2 cannot view, download, or delete User 1's scan.
    assert client.get(f"/report/{scan_id1}").status_code == 403
    assert client.get(f"/api/download/{scan_id1}/sanitised").status_code == 403
    assert client.get(f"/api/download/{scan_id1}/report_json").status_code == 403
    del_r = client.delete(f"/api/scan/{scan_id1}")
    assert del_r.status_code == 403


def test_guest_history_cannot_read_or_clear_user_records(client, fake):
    client.post("/api/auth/register", json={
        "username": "private_history",
        "email": "private_history@example.com",
        "password": "Password123",
    })
    source = f"API_KEY = \"{fake['gh']}\"\n".encode()
    scan = client.post(
        "/api/scan",
        data={"file": (io.BytesIO(source), "private.py")},
        content_type="multipart/form-data",
    )
    scan_id = scan.get_json()["scan_id"]
    client.post("/api/auth/logout")

    assert client.get("/api/history").status_code == 401
    assert client.get("/api/user/history?page=1").status_code == 401
    assert client.delete("/api/history").status_code == 401
    assert client.delete("/api/user/history").status_code == 401

    client.post("/api/auth/login", json={"username": "private_history", "password": "Password123"})
    assert any(item["id"] == scan_id for item in client.get("/api/user/history").get_json())


def test_history_filtering_sorting_and_pagination_are_user_scoped(client):
    from engine import store

    client.post("/api/auth/register", json={
        "username": "history_page",
        "email": "history_page@example.com",
        "password": "Password123",
    })
    user_id = client.get("/api/auth/me").get_json()["user"]["id"]
    for index in range(12):
        level = "high" if index % 2 == 0 else "low"
        store.record_scan(
            f"{index:032x}",
            f"project_{index:02}.py",
            "text",
            120,
            {
                "overall": {"score": 80 if level == "high" else 10, "level": level},
                "high": 1 if level == "high" else 0,
                "medium": 0,
                "low": 1 if level == "low" else 0,
            },
            user_id=user_id,
            findings=[{"type": "TEST", "level": level, "preview": "••••"}],
        )
    first_page = client.get("/api/user/history?page=1&per_page=10").get_json()
    second_page = client.get("/api/user/history?page=2&per_page=10").get_json()
    assert first_page["total"] == 12 and first_page["pages"] == 2 and len(first_page["items"]) == 10
    assert second_page["page"] == 2 and len(second_page["items"]) == 2
    assert not {item["id"] for item in first_page["items"]} & {item["id"] for item in second_page["items"]}

    result = client.get(
        "/api/user/history?page=1&per_page=10&risk=high&format=py&q=project_&days=7&sort=highest"
    ).get_json()
    assert result["total"] == 6
    assert len(result["items"]) == 6
    assert result["summary"] == {"total": 12, "high_risk": 6, "sanitised": 0}
    assert all(item["level"] == "high" for item in result["items"])

    client.post("/api/auth/logout")
    client.post("/api/auth/register", json={
        "username": "history_other",
        "email": "history_other@example.com",
        "password": "Password123",
    })
    other = client.get("/api/user/history?page=1&per_page=10").get_json()
    assert other["total"] == 0


def test_history_finding_counts_match_detail_and_latest_redaction(client):
    client.post("/api/auth/register", json={
        "username": "history_counts",
        "email": "history_counts@example.com",
        "password": "Password123",
    })
    user_id = client.get("/api/auth/me").get_json()["user"]["id"]
    scan_id = "a" * 32
    findings = [
        {"id": "high", "type": "TEST_HIGH", "level": "high", "status": "active"},
        {"id": "medium", "type": "TEST_MEDIUM", "level": "medium", "status": "active"},
        {"id": "low", "type": "TEST_LOW", "level": "low", "status": "active"},
        {"id": "placeholder", "type": "PLACEHOLDER", "level": "low", "status": "placeholder"},
        {"id": "benign", "type": "BENIGN", "level": "low", "status": "likely_benign"},
    ]
    store.record_scan(
        scan_id, "counts.py", "text", 100,
        {"overall": {"score": 40, "level": "high"}, "high": 1, "medium": 1, "low": 1},
        user_id=user_id,
        findings=findings,
    )

    def assert_counts(expected):
        page = client.get("/api/user/history?page=1&per_page=10").get_json()
        detail = client.get(f"/api/user/history/{scan_id}").get_json()
        assert page["items"][0]["finding_counts"] == expected
        assert detail["finding_counts"] == expected
        assert expected["total"] == sum(expected[key] for key in (
            "active_high", "active_medium", "active_low", "redacted",
            "placeholder", "likely_benign", "unclassified",
        ))

    store.record_redaction(scan_id, ["high"], findings)
    assert_counts({
        "total": 5, "active_total": 2, "active_high": 0, "active_medium": 1,
        "active_low": 1, "redacted": 1, "placeholder": 1,
        "likely_benign": 1, "unclassified": 0, "status_available": True,
    })

    store.record_redaction(scan_id, ["medium"], findings)
    assert_counts({
        "total": 5, "active_total": 2, "active_high": 1, "active_medium": 0,
        "active_low": 1, "redacted": 1, "placeholder": 1,
        "likely_benign": 1, "unclassified": 0, "status_available": True,
    })


def test_legacy_history_redaction_counts_do_not_guess_active_findings(client):
    client.post("/api/auth/register", json={
        "username": "legacy_counts",
        "email": "legacy_counts@example.com",
        "password": "Password123",
    })
    user_id = client.get("/api/auth/me").get_json()["user"]["id"]
    scan_id = "b" * 32
    store.record_scan(
        scan_id, "legacy.py", "text", 100,
        {"overall": {"score": 40, "level": "high"}, "high": 1, "medium": 0, "low": 0},
        user_id=user_id,
    )
    with store._db() as con:
        con.execute("UPDATE scans SET redacted=1, findings_json=NULL WHERE id=?", (scan_id,))

    counts = client.get(f"/api/user/history/{scan_id}").get_json()["finding_counts"]
    assert counts["total"] is None
    assert counts["active_high"] is None
    assert counts["redacted"] == 1
    assert counts["status_available"] is False

    empty_scan_id = "c" * 32
    store.record_scan(
        empty_scan_id, "empty.py", "text", 0,
        {"overall": {"score": 0, "level": "low"}, "high": 0, "medium": 0, "low": 0},
        user_id=user_id,
    )
    empty_counts = client.get(f"/api/user/history/{empty_scan_id}").get_json()["finding_counts"]
    assert empty_counts["total"] == 0
    assert empty_counts["active_total"] == 0
    assert empty_counts["status_available"] is True

    with store._db() as con:
        con.execute("UPDATE scans SET findings_json=NULL WHERE id=?", (empty_scan_id,))
    legacy_empty_counts = client.get(f"/api/user/history/{empty_scan_id}").get_json()["finding_counts"]
    assert legacy_empty_counts["total"] is None
    assert legacy_empty_counts["status_available"] is False


def test_dashboard_stats_are_authenticated_and_user_scoped(client, fake):
    assert client.get("/api/user/stats?days=30").status_code == 401

    client.post("/api/auth/register", json={
        "username": "dashboard_one",
        "email": "dashboard_one@example.com",
        "password": "Password123",
    })
    source = f'MY_KEY = "{fake["gh"]}"\n'.encode()
    scan = client.post(
        "/api/scan",
        data={"file": (io.BytesIO(source), "dashboard.py")},
        content_type="multipart/form-data",
    )
    assert scan.status_code == 200
    own_stats = client.get("/api/user/stats?days=30").get_json()
    assert own_stats["total_files"] == 1
    assert own_stats["period_files"] == 1

    client.post("/api/auth/logout")
    client.post("/api/auth/register", json={
        "username": "dashboard_two",
        "email": "dashboard_two@example.com",
        "password": "Password123",
    })
    other_stats = client.get("/api/user/stats?days=30").get_json()
    assert other_stats["total_files"] == 0
    assert other_stats["period_files"] == 0


def test_admin_authorization(client):
    # Create non-admin and verify 403 on admin routes
    client.post("/api/auth/register", json={"username": "norman", "email": "norman@example.com", "password": "Password123"})
    r_stats = client.get("/api/admin/stats")
    assert r_stats.status_code == 403

    # Create admin directly in store and login as admin
    store.create_user("superadmin", "superadmin@example.com", "AdminPassword123", role="admin")
    client.post("/api/auth/logout")
    r_login = client.post("/api/auth/login", json={"username": "superadmin", "password": "AdminPassword123"})
    assert r_login.status_code == 200

    # Admin access succeeds
    r_admin_stats = client.get("/api/admin/stats")
    assert r_admin_stats.status_code == 200
    j_stats = r_admin_stats.get_json()
    assert "users" in j_stats
    assert "storage" in j_stats

    # Admin can list users
    r_users = client.get("/api/admin/users")
    assert r_users.status_code == 200
    assert any(u["username"] == "norman" for u in r_users.get_json())


def test_safe_team_setup_endpoints(client):
    # Generate .env.example
    findings = [
        {"key": "DB_PASSWORD", "type": "GENERIC_CREDENTIAL", "status": "active", "value": "example-secret-value"},
        {"key": None, "type": "AWS_ACCESS_KEY", "status": "active"},
    ]
    r_env = client.post("/api/team/env-example", json={"findings": findings})
    assert r_env.status_code == 200
    j = r_env.get_json()
    assert "DB_PASSWORD=your_db_password_here" in j["env_example"]
    assert "AWS_ACCESS_KEY=your_aws_access_key_here" in j["env_example"]
    assert "example-secret-value" not in j["env_example"]

    # Generate team package ZIP
    r_pkg = client.post("/api/team/package", json={
        "project_name": "TestProject",
        "env_example": "DB_PASSWORD=caller-supplied-value\nEXTRA_TOKEN=another-private-value\n"
    })
    assert r_pkg.status_code == 200
    assert r_pkg.mimetype == "application/zip"
    buf = io.BytesIO(r_pkg.data)
    with zipfile.ZipFile(buf, "r") as z:
        namelist = z.namelist()
        assert ".env.example" in namelist
        assert "README-TEAM-SETUP.md" in namelist
        assert "INSTALLATION-GUIDE.md" in namelist
        env_content = z.read(".env.example").decode("utf-8")
        assert "DB_PASSWORD=your_db_password_here" in env_content
        assert "EXTRA_TOKEN=your_extra_token_here" in env_content
        assert "caller-supplied-value" not in env_content
        assert "another-private-value" not in env_content


def test_vault_rejects_non_text_fields_and_remains_private(client):
    assert client.get("/api/vault").status_code == 401
    client.post("/api/auth/register", json={
        "username": "vault_validation_user",
        "email": "vault_validation@example.com",
        "password": "Password123"
    })

    bad_key = client.post("/api/vault", json={
        "key_name": ["NOT", "TEXT"],
        "provider": "Generic",
        "raw_value": "example-value"
    })
    assert bad_key.status_code == 400
    assert client.get("/api/vault").get_json() == []

    bad_provider = client.post("/api/vault", json={
        "key_name": "VALID_NAME",
        "provider": {"name": "Generic"},
        "raw_value": "example-value"
    })
    assert bad_provider.status_code == 400
    assert client.get("/api/vault").get_json() == []


def test_logout_returns_fresh_csrf_token(client):
    client.post("/api/auth/register", json={
        "username": "csrf_logout_user",
        "email": "csrf_logout@example.com",
        "password": "Password123"
    })
    previous_token = client.get("/api/auth/me").get_json()["csrf_token"]
    response = client.post("/api/auth/logout")

    assert response.status_code == 200
    next_token = response.get_json()["csrf_token"]
    assert next_token
    assert next_token != previous_token
    assert client.get("/api/auth/me").get_json()["csrf_token"] == next_token


def test_ide_guard_in_memory_scan(client):
    code = 'DATABASE_PASSWORD = "SuperSecretPassword123!"\n'
    r = client.post("/api/ide/scan", json={"filename": "db.py", "content": code})
    assert r.status_code == 200
    j = r.get_json()
    assert len(j["diagnostics"]) >= 1
    d = j["diagnostics"][0]
    assert d["line"] == 1
    assert "DATABASE_PASSWORD" in d["message"] or "credential" in d["message"].lower()
    assert "os.environ.get" in d["suggested_fix"]
    assert "SuperSecretPassword123!" not in str(d["preview"])   # preview is masked


def test_encrypted_vault(client):
    client.post("/api/auth/register", json={"username": "vaultuser", "email": "vault@example.com", "password": "Password123"})
    add = client.post("/api/vault", json={
        "key_name": "STRIPE_KEY",
        "provider": "Stripe",
        "raw_value": "sk_live_1234567890abcdef123456"
    })
    assert add.status_code == 200
    item = add.get_json()
    assert "sk_" in item["masked_preview"]
    assert "••••" in item["masked_preview"]

    # List items
    items = client.get("/api/vault").get_json()
    assert len(items) == 1
    assert items[0]["key_name"] == "STRIPE_KEY"

    # Delete item
    del_r = client.delete(f"/api/vault/{item['id']}")
    assert del_r.status_code == 200
    assert len(client.get("/api/vault").get_json()) == 0
