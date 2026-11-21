"""Synthetic labelled dataset (SENSITIVE / NON_SENSITIVE). Every value is randomly generated;
no real credentials or personal data are used.

Honest-evaluation design: the TEST split also draws from variable names and syntax templates that
never appear in TRAIN, so it measures some generalisation rather than memorisation. It is still
synthetic, so real-world performance will differ."""
from __future__ import annotations

import random
import string

from engine.rules import verhoeff_check_digit

KEYS_TRAIN = ["password", "passwd", "pwd", "db_password", "secret_key", "api_key", "auth_token", "access_token",
              "client_secret", "DB_PASS", "SECRET", "private_key", "apikey", "token", "bearer_token", "DB_PASSWORD",
              "API_SECRET", "jwt_secret", "redis_password", "admin_pass"]
KEYS_TEST_EXTRA = ["admin_login", "conn_secret", "signing_salt", "webhook_key", "smtp_pass", "session_secret",
                   "encryption_key", "pin_code", "license_key", "vault_token", "root_credential", "ftp_pw"]
SYNTAX_TRAIN = ['{k} = "{v}"', "{k} = '{v}'", 'const {k} = "{v}";', '{k}: "{v}"', "{K}={v}", '"{k}": "{v}",',
                'self.{k} = "{v}"', "export {K}={v}", "{k}: {v}", 'let {k} = "{v}";']
SYNTAX_TEST_EXTRA = ['private static final String {K} = "{v}";', 'var {k} = "{v}"', 'config["{k}"] = "{v}"',
                     'let {k}: string = "{v}";', '{k} := "{v}"', "set {K}={v}", 'os.environ["{K}"] = "{v}"']
NAMES = ["rahul", "meera", "ana", "kofi", "li", "sven", "priya", "tomas", "aisha", "diego", "nora", "arjun"]
SURN = ["mehta", "okafor", "silva", "chen", "novak", "rao", "haddad", "ivanov", "kim", "dubois"]
DOMAINS = ["quartzmail.net", "northwind-labs.io", "brightcrest.co", "lumenworks.org", "ostrava-tech.cz"]
PW_WORDS = ["Maple", "Tiger", "Orbit", "Cobalt", "Falcon", "Jungle", "Pixel", "Harbor", "Ember", "Lotus"]

PLACEHOLDERS = ["your_password_here", "<YOUR_API_KEY>", "xxxxxxxx", "changeme", "REPLACE_ME", "your-api-key-here",
                "example-placeholder", "dummy-token", "****", "TODO", "<password>", "insert_token_here", "sample_secret",
                "{{ SECRET }}", "your_token_goes_here", "fake-key-123", "AKIAIOSFODNN7EXAMPLE", "<YOUR_SECRET>"]
REFERENCES = ['os.getenv("{K}")', "process.env.{K}", "${{{K}}}", 'config.get("{k}")', 'os.environ["{K}"]',
              "settings.{K}", 'System.getenv("{K}")', "secrets.{k}", "getpass.getpass()", "input_value"]
BENIGN_VALUES = ["Bearer", "refresh", "/etc/ssl/private/server.pem", "oauth2", "db-credentials", "basic", "jwt",
                 "Enter your password", "Password must be at least 8 characters", "Please type your secret code",
                 "./keys/id_rsa.pem", "required", "Your token has expired, please log in again", "3600", "hidden"]
BENIGN_KEYS = ["token_type", "password_label", "password_field", "secret_name", "key_path", "auth_method",
               "password_prompt", "token_expiry", "api_key_header", "password_min_length", "secret_file"]
CODE = ["def add(a, b):\n    return a + b", "for i in range(10):\n    print(i)", "import os, sys", "class User:\n    pass",
        "total_tokens = len(tokens)", "tokens = text.split()", "if not password:\n    raise ValueError('password required')",
        "const total = items.reduce((a, b) => a + b, 0);", "public static void main(String[] args) {",
        "logger.info('user logged in')", "return render_template('index.html')", "x = [n * 2 for n in range(5)]",
        "password_input = document.getElementById('password')", "<input type=\"password\" name=\"pwd\" placeholder=\"Password\">",
        "token = tokenizer.encode(text)", "api_key = config['api_key']", "const apiKey = process.env.API_KEY;",
        "response = requests.get(url, timeout=10)", "@app.route('/login', methods=['POST'])", "SELECT id, name FROM users;",
        "try:\n    run()\nexcept Exception as e:\n    log(e)", "version = '2.4.1'", "while queue:\n    node = queue.pop()"]
DOCS = ["Set the API key in your environment before running the app.", "Never commit passwords to the repository.",
        "Passwords must be at least 12 characters long.", "Contact the support team through the help portal.",
        "This function returns the access token expiry in seconds.", "See the README for installation instructions.",
        "The secret manager rotates credentials every 30 days.", "Use a strong, unique passphrase for each account.",
        "Authentication is handled by the identity provider.", "Meeting notes: discuss the release schedule on Friday."]
COMMENTS_SENS = ["# production credentials", "// TODO: move this to the vault", "# staging db login", "# temp, delete before commit",
                 "// admin access", "# DO NOT SHARE"]
COMMENTS_SAFE = ["# example only", "# replace with your own key", "# loaded from env", "// sample configuration",
                 "# placeholder values", "// see docs"]


def _alnum(r, n, extra=""):
    return "".join(r.choice(string.ascii_letters + string.digits + extra) for _ in range(n))


def _secret_value(r):
    k = r.random()
    if k < 0.20:
        return _alnum(r, r.randint(16, 40))
    if k < 0.32:
        return "".join(r.choice("0123456789abcdef") for _ in range(r.choice([32, 40, 64])))
    if k < 0.44:
        return r.choice(["ghp_", "sk-", "xoxb-", "SG.", "AKIA"]) + _alnum(r, r.randint(20, 36))
    if k < 0.56:
        return _alnum(r, r.randint(20, 40), "+/")
    if k < 0.90:
        return r.choice(PW_WORDS) + r.choice("#@$!_-") + str(r.randint(10, 9999)) + r.choice(["", "x", "!", "Q"])
    return "-".join(r.choice(["blue", "tiger", "moon", "river", "stone"]) for _ in range(2)) + "-" + str(r.randint(100, 99999))


def _email(r):
    return f"{r.choice(NAMES)}.{r.choice(SURN)}{r.choice(['', str(r.randint(2, 99))])}@{r.choice(DOMAINS)}"


def _luhn_card(r):
    body = [4] + [r.randint(0, 9) for _ in range(14)]
    s = 0
    for i, d in enumerate(reversed(body)):
        d = d * 2 if i % 2 == 0 else d
        s += d - 9 if d > 9 else d
    return "".join(map(str, body)) + str((10 - s % 10) % 10)


def _aadhaar(r):
    base = str(r.randint(2, 9)) + "".join(str(r.randint(0, 9)) for _ in range(10))
    n = base + verhoeff_check_digit(base)
    return f"{n[:4]} {n[4:8]} {n[8:]}"


def _fmt(r, tmpl, k, v):
    return tmpl.format(k=k, K=k.upper(), v=v)


def _pools(r, split):
    keys = KEYS_TRAIN + (KEYS_TEST_EXTRA if split == "test" and r.random() < 0.4 else [])
    syn = SYNTAX_TRAIN + (SYNTAX_TEST_EXTRA if split == "test" and r.random() < 0.4 else [])
    return keys, syn


def sensitive(r, split):
    keys, syn = _pools(r, split)
    kind = r.random()
    if kind < 0.55:
        s = _fmt(r, r.choice(syn), r.choice(keys), _secret_value(r))
    elif kind < 0.65:
        s = f'headers = {{"Authorization": "Bearer {_alnum(r, r.randint(24, 40), "-_.")}"}}'
    elif kind < 0.72:
        s = f"postgres://{r.choice(NAMES)}:{_secret_value(r)}@db.{r.choice(DOMAINS)}:5432/app"
    elif kind < 0.80:
        s = r.choice(["Email: ", "contact = ", "Reach me at ", "From: ", "owner: "]) + _email(r)
    elif kind < 0.86:
        s = r.choice(["Phone: ", "Mobile: ", "Call me on ", "tel: "]) + r.choice(
            [f"+91 {r.randint(6, 9)}{r.randint(1000, 9999)} {r.randint(10000, 99999)}",
             f"({r.randint(200, 999)}) {r.randint(200, 999)}-{r.randint(1000, 9999)}",
             f"+44 7{r.randint(100, 999)} {r.randint(100000, 999999)}"])
    elif kind < 0.90:
        s = "Aadhaar: " + _aadhaar(r)
    elif kind < 0.94:
        s = "Card: " + _luhn_card(r)
    elif kind < 0.97:
        s = r.choice(["Login with username ", "Wifi password: ", "The admin password is ", "Use pass: "]) + _secret_value(r)
    else:
        s = "PAN: " + "".join(r.choice(string.ascii_uppercase) for _ in range(3)) + "P" + r.choice(string.ascii_uppercase) \
            + str(r.randint(1000, 9999)) + r.choice(string.ascii_uppercase)
    if r.random() < 0.25:
        s = r.choice(COMMENTS_SENS) + "\n" + s
    return s


def non_sensitive(r, split):
    keys, syn = _pools(r, split)
    kind = r.random()
    if kind < 0.20:
        s = _fmt(r, r.choice(syn), r.choice(keys), r.choice(PLACEHOLDERS))
    elif kind < 0.34:
        k = r.choice(keys)
        ref = r.choice(REFERENCES).format(k=k, K=k.upper())
        s = r.choice(["{k} = {v}", "{k} := {v}", "const {k} = {v};", "{K} = {v}"]).format(k=k, K=k.upper(), v=ref)
    elif kind < 0.50:
        s = _fmt(r, r.choice(["{k} = \"{v}\"", "{k}: \"{v}\"", "const {k} = '{v}';"]), r.choice(BENIGN_KEYS), r.choice(BENIGN_VALUES))
    elif kind < 0.55:
        s = _fmt(r, r.choice(syn), r.choice(keys), r.choice(BENIGN_VALUES))
    elif kind < 0.70:
        s = r.choice(CODE)
    elif kind < 0.78:
        s = r.choice(DOCS)
    elif kind < 0.86:
        s = r.choice(["commit = \"{}\"", "uuid = \"{}\"", "checksum = \"sha256:{}\"", "build_id: {}"]).format(
            r.choice(["".join(r.choice("0123456789abcdef") for _ in range(40)),
                      f"{_alnum(r, 8).lower()}-{_alnum(r, 4).lower()}-{_alnum(r, 4).lower()}-{_alnum(r, 12).lower()}"]))
    elif kind < 0.92:
        s = r.choice(["Email: ", "contact = ", "Reach us at ", "owner: "]) + r.choice(
            ["user@example.com", "name@example.org", "support@example.net", "your.name@example.com", "test@test.com"])
    elif kind < 0.96:
        s = r.choice(["Phone: ", "Call: ", "tel: "]) + r.choice(["555-0100", "(555) 555-0123", "+1 555 0100 000", "1234567890"])
    else:
        s = r.choice(["Order #", "timestamp = ", "ticket id "]) + str(r.randint(10**9, 10**12))
    if r.random() < 0.25:
        s = r.choice(COMMENTS_SAFE) + "\n" + s
    return s


def generate(n: int, seed: int, split: str = "train", pos_frac: float = 0.45):
    r = random.Random(seed)
    rows = []
    for _ in range(n):
        if r.random() < pos_frac:
            rows.append((sensitive(r, split), "SENSITIVE"))
        else:
            rows.append((non_sensitive(r, split), "NON_SENSITIVE"))
    return rows
