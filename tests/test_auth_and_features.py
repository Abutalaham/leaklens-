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

    # User 1 history has 1 scan
    h1 = client.get("/api/user/history").get_json()
    assert any(s["id"] == scan_id1 for s in h1)

    # User 2 registers
    client.post("/api/auth/logout")
    client.post("/api/auth/register", json={"username": "user2", "email": "u2@example.com", "password": "Password123"})

    # User 2 history must NOT contain User 1's scan
    h2 = client.get("/api/user/history").get_json()
    assert not any(s["id"] == scan_id1 for s in h2)

    # User 2 cannot delete User 1's scan
    del_r = client.delete(f"/api/scan/{scan_id1}")
    assert del_r.status_code == 403


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
        {"key": "DB_PASSWORD", "type": "GENERIC_CREDENTIAL", "status": "active"},
        {"key": None, "type": "AWS_ACCESS_KEY", "status": "active"},
    ]
    r_env = client.post("/api/team/env-example", json={"findings": findings})
    assert r_env.status_code == 200
    j = r_env.get_json()
    assert "DB_PASSWORD=your_db_password_here" in j["env_example"]
    assert "AWS_ACCESS_KEY=your_aws_access_key_here" in j["env_example"]

    # Generate team package ZIP
    r_pkg = client.post("/api/team/package", json={
        "project_name": "TestProject",
        "env_example": j["env_example"]
    })
    assert r_pkg.status_code == 200
    assert r_pkg.mimetype == "application/zip"
    buf = io.BytesIO(r_pkg.data)
    with zipfile.ZipFile(buf, "r") as z:
        namelist = z.namelist()
        assert ".env.example" in namelist
        assert "README-TEAM-SETUP.md" in namelist
        assert "INSTALLATION-GUIDE.md" in namelist


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
