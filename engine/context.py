"""Context-aware checks: is a candidate a placeholder, or structurally not a secret?"""
from __future__ import annotations

import re

from .rules import Candidate, entropy

PLACEHOLDER_WORDS = (
    "example", "placeholder", "dummy", "sample", "changeme", "change_me", "change-me", "your_", "your-",
    "yourkey", "<your", "insert", "replace", "redacted", "fake", "mock", "todo", "fixme", "xxxx", "****",
    "not_a_real", "notreal", "secret_here", "password_here", "key_here", "token_here", "lorem",
)
GENERIC_WORDS = {"password", "passwd", "secret", "token", "apikey", "api_key", "username", "user", "pass",
                 "key", "value", "string", "none", "null", "empty", "admin", "default"}
KNOWN_SAMPLES = {
    "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "4111111111111111", "4242424242424242", "5555555555554444", "378282246310005", "6011111111111117",
    "4111 1111 1111 1111", "4111-1111-1111-1111", "123-45-6789", "078-05-1120", "ABCDE1234F", "ABCDE1234A",
}
PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "test.com", "domain.com", "yourdomain.com",
                       "mydomain.com", "email.com", "sample.com", "localhost", "company.com", "acme.com"}
PLACEHOLDER_LOCALS = {"user", "username", "name", "email", "you", "your.name", "yourname", "someone", "foo",
                      "bar", "test", "john.doe", "jane.doe", "johndoe", "janedoe", "firstname.lastname", "me"}
ROLE_LOCALS = {"support", "info", "contact", "hello", "noreply", "no-reply", "admin", "sales", "help",
               "team", "office", "security", "webmaster", "postmaster"}

ENUM_VALUES = {"bearer", "basic", "oauth", "oauth2", "jwt", "refresh", "access", "true", "false", "none", "null",
               "required", "optional", "string", "hidden", "text", "number", "digest", "token", "password"}
BENIGN_KEY_SUFFIX = {"type", "path", "file", "name", "label", "prompt", "field", "placeholder", "hint", "length",
                     "len", "count", "min", "max", "expiry", "expires", "ttl", "header", "endpoint", "policy",
                     "mode", "method", "format", "scope", "version", "algorithm", "alg", "env", "var", "regex",
                     "pattern", "title", "message", "msg", "text", "error", "help", "link", "required"}

DOC_HINT = re.compile(r"(?i)\b(e\.g\.?|for example|example|sample|dummy|placeholder|replace|fake|mock|demo|"
                      r"your (?:own )?(?:api|key|token|password|secret))\b")
TEST_FILE = re.compile(r"(?i)(^|[_\-.])(test|tests|mock|fixture|example|sample|demo)([_\-.]|$)")

_REF_PREFIX = ("${", "$(", "{{", "%(", "<%", "$", "os.environ", "os.getenv", "getenv", "process.env",
               "env(", "env.", "config.", "settings.", "secrets.", "System.getenv", "ENV[")


def placeholder_reason(c: Candidate) -> str | None:
    v = c.value
    vl = v.lower()
    if v in KNOWN_SAMPLES:
        return "well-known documentation/test value"
    if c.type == "EMAIL":
        local, domain = vl.rsplit("@", 1)
        if domain in PLACEHOLDER_DOMAINS or domain.rsplit(".", 1)[-1] in {"example", "test", "invalid", "localhost"}:
            return f"reserved or example domain '{domain}'"
        if local in PLACEHOLDER_LOCALS:
            return f"generic example name '{local}'"
        return None
    if c.type == "PHONE":
        digits = re.sub(r"\D", "", v)
        if re.search(r"555[ \-.]?01\d\d", v) or len(set(digits)) <= 2 or digits[-10:] in {"1234567890", "0123456789", "9876543210"}:
            return "fictional or sequential phone number"
        return None
    if c.type in ("IP_ADDRESS", "INTERNAL_IP"):
        if v.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
            return "reserved documentation IP range"
        return None
    for w in PLACEHOLDER_WORDS:
        if w in vl:
            return f"value contains '{w.strip('_-<')}'"
    if re.fullmatch(r"[<\[{(].*[>\]})]", v):
        return "wrapped in template markers"
    if len(v) >= 4 and len(set(v)) <= 2:
        return "repeated characters"
    if vl in GENERIC_WORDS or (c.key and vl == c.key.lower()):
        return "value is just a generic word"
    if vl in {"1234567890", "12345678", "abcdefgh", "abcd1234", "qwertyuiop"}:
        return "sequential / keyboard-pattern value"
    return None


def _key_tokens(key: str) -> list[str]:
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key)
    return [t for t in re.split(r"[_.\-]+", key.lower()) if t]


def benign_reason(c: Candidate) -> str | None:
    """Structural reasons a credential-named assignment is NOT a secret."""
    if c.type != "GENERIC_CREDENTIAL":
        return None
    v = c.value.strip()
    if v.startswith(_REF_PREFIX) or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", v):
        return "value is read from the environment/config, not hardcoded"
    if re.search(r"[()\[\]]", v) and not re.search(r"\s", v) and c.meta.get("unquoted"):
        return "value is a code expression, not a literal"
    if len(v.split()) >= 3 and re.fullmatch(r"[A-Za-z][A-Za-z0-9 ',.!?:\-]+", v):
        return "value reads like natural-language text (UI label or message)"
    if v.startswith(("/", "./", "~/", "../")) or re.search(r"\.(pem|key|json|txt|crt|cer|p12|pfx|env)$", v, re.I):
        return "value is a file path"
    if v.lower() in ENUM_VALUES:
        return "value is a mode/type keyword"
    toks = _key_tokens(c.key or "")
    if toks and toks[-1] in BENIGN_KEY_SUFFIX:
        return f"variable name ends in '{toks[-1]}', which suggests configuration metadata"
    if (c.meta.get("unquoted") and re.fullmatch(r"[A-Za-z_]+", v)
            and ("_" in v or v.islower() or v.isupper() or entropy(v) < 3.6)):
        return "unquoted value looks like a variable name"
    return None


def doc_hint(line: str, prev_line: str, value: str) -> str | None:
    """Nearby words such as 'example' that suggest documentation rather than live data."""
    here = line.replace(value, " ") if value else line
    here = re.sub(r"""(["'])(?:(?!\1).)*\1|\S+://\S+""", " ", here)   # ignore quoted strings and URLs
    for s in (here, prev_line if prev_line.lstrip().startswith(("#", "//", "*", "/*", "<!--")) else ""):
        m = DOC_HINT.search(s)
        if m:
            return m.group(1).lower()
    return None


def test_file_hint(filename: str) -> bool:
    return bool(filename) and bool(TEST_FILE.search(filename.rsplit("/", 1)[-1]))
