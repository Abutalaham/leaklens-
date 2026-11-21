import string

from engine.detector import Detector, mask_value
from engine.rules import find_candidates, luhn_valid, verhoeff_check_digit, verhoeff_valid

from .conftest import rnd

D = Detector(use_ml=False)


def types(text):
    return {f["type"]: f for f in D.scan_text(text)}


def test_validators():
    assert luhn_valid("4539148803436467") and not luhn_valid("4539148803436468")
    assert verhoeff_valid("2363")                       # published Verhoeff example
    base = "23456789123"
    assert verhoeff_valid(base + verhoeff_check_digit(base))


def test_provider_tokens(fake):
    t = types(f'a = "{fake["gh"]}"\nb = "{fake["aws"]}"\nc = "{fake["stripe"]}"')
    assert {"GITHUB_TOKEN", "AWS_ACCESS_KEY", "STRIPE_KEY"} <= set(t)
    assert all(f["level"] == "high" for f in t.values())


def test_private_key_block():
    body = "\n".join(rnd(64, string.ascii_letters + string.digits + "+/") for _ in range(3))
    text = f"x\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\ny"
    f = D.scan_text(text)
    assert f[0]["type"] == "PRIVATE_KEY" and f[0]["score"] >= 90 and f[0]["end_line"] == 6


def test_generic_credential_and_bracket_syntax(fake):
    for line in (f'DB_PASSWORD = "{fake["pw"]}"', f'config["secret_key"] = "{fake["pw"]}"',
                 f'{{"password": "{fake["pw"]}"}}', f"API_SECRET={fake['pw']}"):
        f = [x for x in D.scan_text(line) if x["type"] == "GENERIC_CREDENTIAL"]
        assert f and f[0]["status"] == "active", line


def test_placeholders_are_not_treated_as_real_secrets():
    for line in ('api_key = "your_api_key_here"', 'password = "changeme"', 'token = "<YOUR_TOKEN>"',
                 'email = "user@example.com"', 'k = "AKIAIOSFODNN7EXAMPLE"'):
        f = D.scan_text(line)
        assert f and all(x["status"] == "placeholder" and x["level"] == "low" for x in f), line


def test_non_secrets_are_dismissed():
    for line in ('password = os.getenv("DB_PASSWORD")', 'password_label = "Enter your password"',
                 'token_type = "Bearer"', "tokens = text.split()", 'key_path = "/etc/ssl/private/key.pem"'):
        assert all(x["status"] != "active" for x in D.scan_text(line)), line


def test_pii_validation():
    base = "23456789123"
    aad = base + verhoeff_check_digit(base)
    text = f"Aadhaar: {aad[:4]} {aad[4:8]} {aad[8:]}\nCard: 4539 1488 0343 6467\nbad: 4539 1488 0343 6468\nPAN ABCPE1234F"
    t = {f["type"] for f in D.scan_text(text) if f["status"] == "active"}
    assert {"AADHAAR", "CREDIT_CARD", "PAN"} <= t
    assert sum(1 for f in D.scan_text(text) if f["type"] == "CREDIT_CARD") == 1   # Luhn-invalid ignored


def test_email_edge_cases():
    assert not [f for f in D.scan_text("git clone git@github.com:o/r.git") if f["type"] == "EMAIL"]
    assert not [f for f in D.scan_text("icon@2x.png") if f["type"] == "EMAIL"]
    assert D.scan_text("mail rahul.k@quartzmail.net now")[0]["type"] == "EMAIL"


def test_email_inside_connection_string_is_not_double_reported(fake):
    f = D.scan_text(f"u = postgres://admin:{fake['pw']}@db.quartzmail.net/app")
    assert [x["type"] for x in f] == ["CONNECTION_STRING"]


def test_bare_phone_needs_context():
    assert not D.scan_text("order 9876543210 shipped")
    assert D.scan_text("Mobile: 9876543210")[0]["type"] == "PHONE"


def test_findings_never_contain_raw_value_in_public_fields(fake):
    from engine.service import public
    fs = D.scan_text(f'password = "{fake["pw"]}"')
    pub = str(public(fs))
    assert fake["pw"] not in pub and "_value" not in pub
    assert fake["pw"] not in fs[0]["context"]
    assert mask_value(fake["pw"]).count("•") > 0


def test_explanations_present(fake):
    f = D.scan_text(f'github_token = "{fake["gh"]}"')[0]
    assert f["reasons"][0]["signal"] == "base" and f["action"] and f["why"]
    assert sum(r["delta"] for r in f["reasons"]) >= f["score"] - 5
