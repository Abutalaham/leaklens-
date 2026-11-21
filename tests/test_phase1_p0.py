import io
import time
from engine import store


def test_aes_gcm_vault_encryption():
    user_id = "test_user_crypto_123"
    raw_secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    enc = store._encrypt_vault_value(user_id, raw_secret)
    assert enc != raw_secret
    
    # Decrypt
    dec = store._decrypt_vault_value(user_id, enc)
    assert dec == raw_secret

    # Tamper test: Corrupt ciphertext and ensure tag mismatch failure
    import base64
    raw_bytes = bytearray(base64.b64decode(enc))
    raw_bytes[-1] ^= 0xFF  # Flip bit in GCM tag/ciphertext
    tampered_enc = base64.b64encode(raw_bytes).decode("ascii")

    try:
        store._decrypt_vault_value(user_id, tampered_enc)
        assert False, "Decryption should have failed on tampered ciphertext"
    except ValueError as e:
        assert "Authentication tag mismatch" in str(e) or "Decryption failed" in str(e)


def test_portable_leaklens_vault_export_and_import(client):
    # Register user and add vault items
    client.post("/api/auth/register", json={
        "username": "vault_exporter",
        "email": "exporter@example.com",
        "password": "Password123"
    })
    client.post("/api/vault", json={
        "key_name": "GITHUB_API_KEY",
        "provider": "GitHub",
        "raw_value": "ghp_abcdef1234567890abcdef1234567890"
    })
    client.post("/api/vault", json={
        "key_name": "STRIPE_KEY",
        "provider": "Stripe",
        "raw_value": "sk_live_abcdef1234567890abcdef"
    })

    # Export vault
    r_exp = client.post("/api/vault/export", json={"password": "ExportPassword123"})
    assert r_exp.status_code == 200
    assert r_exp.data.startswith(b"LEAKLENS_VAULT\x01")
    vault_blob = r_exp.data

    # Log in as a different user to import
    client.post("/api/auth/logout")
    client.post("/api/auth/register", json={
        "username": "vault_importer",
        "email": "importer@example.com",
        "password": "Password123"
    })

    # Verify importer starts with empty vault
    items_before = client.get("/api/vault").get_json()
    assert len(items_before) == 0

    # Import with wrong password should fail
    r_bad_imp = client.post(
        "/api/vault/import",
        data={"file": (io.BytesIO(vault_blob), "backup.leaklens"), "password": "WrongPassword!"},
        content_type="multipart/form-data"
    )
    assert r_bad_imp.status_code == 400

    # Import with correct password
    r_imp = client.post(
        "/api/vault/import",
        data={"file": (io.BytesIO(vault_blob), "backup.leaklens"), "password": "ExportPassword123"},
        content_type="multipart/form-data"
    )
    assert r_imp.status_code == 200
    assert r_imp.get_json()["imported_count"] == 2

    # Verify imported items appear in importer's vault
    items_after = client.get("/api/vault").get_json()
    assert len(items_after) == 2
    keys = {it["key_name"] for it in items_after}
    assert "GITHUB_API_KEY" in keys
    assert "STRIPE_KEY" in keys


def test_totp_2fa_full_lifecycle(client):
    # Register user
    client.post("/api/auth/register", json={
        "username": "twofa_user",
        "email": "twofa@example.com",
        "password": "TwofaPassword123"
    })

    # Check 2FA initial status
    status1 = client.get("/api/auth/2fa/status").get_json()
    assert status1["enabled"] is False

    # Setup 2FA
    setup = client.post("/api/auth/2fa/setup").get_json()
    secret = setup["secret"]
    recovery_codes = setup["recovery_codes"]
    assert len(secret) >= 16
    assert len(recovery_codes) == 8
    assert "otpauth://" in setup["otpauth_uri"]

    # Generate current valid token
    cur_step = int(time.time() // 30)
    valid_token = f"{store.get_totp_token(secret, cur_step):06d}"

    # Invalid code enable attempt
    r_bad = client.post("/api/auth/2fa/enable", json={"code": "000000" if valid_token != "000000" else "111111"})
    assert r_bad.status_code == 400

    # Valid code enable attempt
    r_ok = client.post("/api/auth/2fa/enable", json={"code": valid_token})
    assert r_ok.status_code == 200
    assert client.get("/api/auth/2fa/status").get_json()["enabled"] is True

    # Logout
    client.post("/api/auth/logout")

    # Primary Login -> Must require 2FA
    r_login = client.post("/api/auth/login", json={
        "username": "twofa_user",
        "password": "TwofaPassword123"
    })
    assert r_login.status_code == 200
    j_login = r_login.get_json()
    assert j_login.get("requires_2fa") is True
    temp_token = j_login["temp_token"]

    # Verify session is NOT yet logged in
    assert client.get("/api/auth/me").get_json()["authenticated"] is False

    # Bad 2FA code verification
    r_verify_bad = client.post("/api/auth/2fa/verify-login", json={
        "temp_token": temp_token,
        "code": "123456"
    })
    assert r_verify_bad.status_code == 401

    # Need new temp_token or re-login if single-use
    r_login2 = client.post("/api/auth/login", json={
        "username": "twofa_user",
        "password": "TwofaPassword123"
    }).get_json()
    temp_token2 = r_login2["temp_token"]

    # Valid 2FA verification
    cur_valid_token = f"{store.get_totp_token(secret, int(time.time() // 30)):06d}"
    r_verify_ok = client.post("/api/auth/2fa/verify-login", json={
        "temp_token": temp_token2,
        "code": cur_valid_token
    })
    assert r_verify_ok.status_code == 200
    assert r_verify_ok.get_json()["success"] is True

    # Verify session is now authenticated
    me = client.get("/api/auth/me").get_json()
    assert me["authenticated"] is True
    assert me["user"]["username"] == "twofa_user"

    # Logout and test Recovery Code login
    client.post("/api/auth/logout")
    r_login3 = client.post("/api/auth/login", json={
        "username": "twofa_user",
        "password": "TwofaPassword123"
    }).get_json()
    temp_token3 = r_login3["temp_token"]

    used_code = recovery_codes[0]
    r_rec_ok = client.post("/api/auth/2fa/verify-login", json={
        "temp_token": temp_token3,
        "code": used_code
    })
    assert r_rec_ok.status_code == 200
    assert client.get("/api/auth/me").get_json()["authenticated"] is True

    # Recovery code must be single use!
    client.post("/api/auth/logout")
    r_login4 = client.post("/api/auth/login", json={
        "username": "twofa_user",
        "password": "TwofaPassword123"
    }).get_json()
    r_rec_reuse = client.post("/api/auth/2fa/verify-login", json={
        "temp_token": r_login4["temp_token"],
        "code": used_code
    })
    assert r_rec_reuse.status_code == 401

    # Disable 2FA
    r_login5 = client.post("/api/auth/login", json={
        "username": "twofa_user",
        "password": "TwofaPassword123"
    }).get_json()
    client.post("/api/auth/2fa/verify-login", json={
        "temp_token": r_login5["temp_token"],
        "code": recovery_codes[1]
    })
    r_dis = client.post("/api/auth/2fa/disable", json={"password": "TwofaPassword123"})
    assert r_dis.status_code == 200
    assert client.get("/api/auth/2fa/status").get_json()["enabled"] is False

    # Next login requires NO 2FA
    client.post("/api/auth/logout")
    r_final = client.post("/api/auth/login", json={
        "username": "twofa_user",
        "password": "TwofaPassword123"
    }).get_json()
    assert r_final.get("requires_2fa") is None
    assert r_final["success"] is True
