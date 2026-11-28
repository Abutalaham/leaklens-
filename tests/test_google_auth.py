import pytest

import app as leaklens_app
import config
from engine import store


TEST_CLIENT_ID = "1234567890-testclient.apps.googleusercontent.com"


@pytest.fixture(autouse=True)
def google_client_id(monkeypatch):
    monkeypatch.setattr(config, "GOOGLE_CLIENT_ID", TEST_CLIENT_ID)


def _mock_google_verify(monkeypatch, payload=None, exc=None):
    def fake_verify(token, request, audience):
        if exc is not None:
            raise exc
        assert audience == TEST_CLIENT_ID
        return payload

    monkeypatch.setattr(leaklens_app.google_id_token, "verify_oauth2_token", fake_verify)


def test_google_new_registration_and_existing_login(client, monkeypatch):
    _mock_google_verify(monkeypatch, payload={
        "iss": "https://accounts.google.com",
        "aud": TEST_CLIENT_ID,
        "sub": "google-sub-1001",
        "email": "newdev@example.com",
        "email_verified": True,
        "name": "New Dev",
    })

    # 1. First sign-in registers a new user with default 'user' role
    r1 = client.post("/api/auth/google", json={"credential": "valid-id-token"})
    assert r1.status_code == 200
    d1 = r1.get_json()
    assert d1["success"] is True
    assert d1["created"] is True
    assert d1["user"]["email"] == "newdev@example.com"
    assert d1["user"]["role"] == "user"

    # Session is active
    me = client.get("/api/auth/me").get_json()
    assert me["authenticated"] is True
    assert me["user"]["id"] == d1["user"]["id"]

    # 2. Logout
    out = client.post("/api/auth/logout")
    assert out.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is False

    # 3. Second sign-in logs into the same account without creating a duplicate
    r2 = client.post("/api/auth/google", json={"credential": "valid-id-token"})
    assert r2.status_code == 200
    d2 = r2.get_json()
    assert d2["created"] is False
    assert d2["user"]["id"] == d1["user"]["id"]


def test_google_invalid_and_expired_token(client, monkeypatch):
    _mock_google_verify(monkeypatch, exc=ValueError("Token expired"))
    r = client.post("/api/auth/google", json={"credential": "expired-token"})
    assert r.status_code == 401

    # Cancellation / empty credential
    r_empty = client.post("/api/auth/google", json={"credential": ""})
    assert r_empty.status_code == 400


def test_google_wrong_audience_and_invalid_issuer(client, monkeypatch):
    _mock_google_verify(monkeypatch, payload={
        "iss": "https://accounts.google.com",
        "aud": "wrong-client-id.apps.googleusercontent.com",
        "sub": "google-sub-2002",
        "email": "aud@example.com",
        "email_verified": True,
    })
    assert client.post("/api/auth/google", json={"credential": "tok"}).status_code == 401

    _mock_google_verify(monkeypatch, payload={
        "iss": "https://evil.example.com",
        "aud": TEST_CLIENT_ID,
        "sub": "google-sub-2002",
        "email": "iss@example.com",
        "email_verified": True,
    })
    assert client.post("/api/auth/google", json={"credential": "tok"}).status_code == 401


def test_google_unverified_email_rejected(client, monkeypatch):
    _mock_google_verify(monkeypatch, payload={
        "iss": "https://accounts.google.com",
        "aud": TEST_CLIENT_ID,
        "sub": "google-sub-3003",
        "email": "unverified@example.com",
        "email_verified": False,
    })
    r = client.post("/api/auth/google", json={"credential": "tok"})
    assert r.status_code == 403
    assert store.get_user_by_username_or_email("unverified@example.com") is None


def test_google_existing_email_conflict_and_password_link(client, monkeypatch):
    # Pre-existing traditional account
    reg = client.post("/api/auth/register", json={
        "username": "existinguser",
        "email": "conflict@example.com",
        "password": "StrongPassword123",
    })
    assert reg.status_code == 200
    existing_id = reg.get_json()["user"]["id"]
    client.post("/api/auth/logout")

    _mock_google_verify(monkeypatch, payload={
        "iss": "https://accounts.google.com",
        "aud": TEST_CLIENT_ID,
        "sub": "google-sub-4004",
        "email": "conflict@example.com",
        "email_verified": True,
    })

    # Must NOT silently link or create duplicate
    r_conflict = client.post("/api/auth/google", json={"credential": "tok"})
    assert r_conflict.status_code == 409
    body = r_conflict.get_json()
    assert body["requires_link"] is True
    link_token = body["link_token"]

    # Wrong password must fail
    r_bad_pw = client.post("/api/auth/google/link", json={
        "link_token": link_token,
        "password": "WrongPassword",
    })
    assert r_bad_pw.status_code == 401

    # Re-issue link token (since previous single-use token was consumed) and link with correct password
    r_conflict2 = client.post("/api/auth/google", json={"credential": "tok"})
    link_token2 = r_conflict2.get_json()["link_token"]
    r_link = client.post("/api/auth/google/link", json={
        "link_token": link_token2,
        "password": "StrongPassword123",
    })
    assert r_link.status_code == 200
    assert r_link.get_json()["user"]["id"] == existing_id

    # Subsequent Google login goes directly to existing account
    client.post("/api/auth/logout")
    r_direct = client.post("/api/auth/google", json={"credential": "tok"})
    assert r_direct.status_code == 200
    assert r_direct.get_json()["user"]["id"] == existing_id


def test_google_duplicate_provider_identity_blocked(client):
    u1 = store.create_user("dup1", "dup1@example.com", "Password123")
    u2 = store.create_user("dup2", "dup2@example.com", "Password123")
    store.link_user_identity(u1["id"], "google", "sub-shared-999", "dup1@example.com", True)
    with pytest.raises(ValueError):
        store.link_user_identity(u2["id"], "google", "sub-shared-999", "dup2@example.com", True)


def test_google_2fa_enforcement_preserved(client, monkeypatch):
    reg = client.post("/api/auth/register", json={
        "username": "twofa_google",
        "email": "twofa@example.com",
        "password": "Password123",
    })
    user_id = reg.get_json()["user"]["id"]
    secret = store.generate_totp_secret()
    _, hashed_codes = store.generate_recovery_codes()
    store.enable_2fa(user_id, secret, hashed_codes)
    store.link_user_identity(user_id, "google", "google-sub-2fa", "twofa@example.com", True)
    client.post("/api/auth/logout")

    _mock_google_verify(monkeypatch, payload={
        "iss": "https://accounts.google.com",
        "aud": TEST_CLIENT_ID,
        "sub": "google-sub-2fa",
        "email": "twofa@example.com",
        "email_verified": True,
    })

    r = client.post("/api/auth/google", json={"credential": "tok"})
    assert r.status_code == 200
    data = r.get_json()
    assert data["requires_2fa"] is True
    assert data["temp_token"]
    assert client.get("/api/auth/me").get_json()["authenticated"] is False

    # Complete 2FA challenge with current TOTP
    import time
    code = f"{store.get_totp_token(secret, int(time.time() // 30)):06d}"
    r2 = client.post("/api/auth/2fa/verify-login", json={
        "temp_token": data["temp_token"],
        "code": code,
    })
    assert r2.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is True


def test_google_csrf_and_rate_limiting(client, monkeypatch):
    _mock_google_verify(monkeypatch, exc=ValueError("bad token"))

    # CSRF check when TESTING is False
    monkeypatch.setitem(leaklens_app.app.config, "TESTING", False)
    r_csrf = client.post("/api/auth/google", json={"credential": "bad"})
    assert r_csrf.status_code == 403

    # Fetch CSRF token and test rate limiting
    csrf = client.get("/api/status").get_json()["csrf_token"]
    for _ in range(config.LOGIN_MAX_ATTEMPTS):
        r_fail = client.post(
            "/api/auth/google",
            json={"credential": "bad"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r_fail.status_code == 401

    r_limited = client.post(
        "/api/auth/google",
        json={"credential": "bad"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r_limited.status_code == 429
