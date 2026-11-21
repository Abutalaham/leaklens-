"""Deterministic detection rules (regex + checksum validators).

Pure functions. Matched values are returned to the caller but never logged.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field


@dataclass
class Candidate:
    type: str
    start: int
    end: int
    value: str
    key: str | None = None      # variable/field name that holds the value, if any
    validated: bool = False     # passed a checksum / structural validation
    strong: bool = False        # provider-specific, unambiguous format
    meta: dict = field(default_factory=dict)


# ---------------------------------------------------------------- validators
def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def luhn_valid(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(num: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


# ------------------------------------------------------------------ patterns
KW = r"(?:pass(?:word|wd|phrase|code)?|pwd|secret|token|api[_\-]?key|apikey|auth|credential|private[_\-]?key|access[_\-]?key|client[_\-]?secret|bearer)"

PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
    r"(?:[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)?")

PROVIDERS = [
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[abprs]-[0-9A-Za-z\-]{10,72}\b")),
    ("STRIPE_KEY", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,99}\b")),
    ("SENDGRID_KEY", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("OPENAI_STYLE_KEY", re.compile(r"\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_\-]{32,}\b")),
    ("NPM_TOKEN", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("HUGGINGFACE_TOKEN", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("TWILIO_KEY", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("GITLAB_PAT", re.compile(r"\bglpat-[0-9a-zA-Z_\-]{20,22}\b")),
    ("POSTMAN_KEY", re.compile(r"\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b")),
    ("DIGITALOCEAN_TOKEN", re.compile(r"\bdop_v1_[0-9a-fA-F]{64}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
]
AWS_SECRET = re.compile(r"""(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key["']?\s*[:=]\s*["']?(?P<val>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])""")
AUTH_HEADER = re.compile(r"(?i)\b(?:Bearer|Basic)[ \t]+(?P<val>[A-Za-z0-9_\-\.=+/]{20,})")
CONN_STRING = re.compile(r"""\b[a-z][a-z0-9+.\-]{1,15}://[^\s:/@'"<>]+:(?P<val>[^\s@'"/<>]+)@[^\s'"<>]+""", re.I)
GENERIC_Q = re.compile(
    rf"""(?P<key>(?:[A-Za-z_][\w.\-]*?)?{KW}[\w.\-]*)["']?\]?[ \t]*(?::=|=>|[:=])[ \t]*(?P<q>["'])(?P<val>[^"'\r\n]{{4,200}})(?P=q)""", re.I)
GENERIC_UNQ = re.compile(
    rf"""(?im)^[ \t]*(?:export[ \t]+)?(?P<key>[\w.\-]*?{KW}[\w.\-]*)[ \t]*[:=][ \t]*(?P<val>[^\s"'#][^\s#]{{3,199}})[ \t]*(?:#.*)?$""")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b")
_BAD_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "py", "ico", "html", "json"}
PHONE_INTL = re.compile(r"(?<![\w.+])(?:\+|00)\d{1,3}[ \-.]?\(?\d{1,5}\)?(?:[ \-.]?\d{2,5}){2,3}(?!\d)")
PHONE_US = re.compile(r"(?<![\d\-])\(?\d{3}\)?[ \-.]\d{3}[ \-.]\d{4}(?![\d\-])")
PHONE_IN_SPACED = re.compile(r"(?<!\d)[6-9]\d{4}[ \-]\d{5}(?!\d)")
PHONE_BARE = re.compile(r"(?<![\d.])[6-9]\d{9}(?![\d.])")
PHONE_CTX = re.compile(r"(?i)\b(?:phone|mobile|mob|tel|telephone|contact|call|whatsapp|cell)\b")
CARD = re.compile(r"(?<![\d\-.])\d(?:[ \-]?\d){12,18}(?![\d\-]|\.\d)")
CARD_CTX = re.compile(r"(?i)\b(?:card|visa|mastercard|amex|cc|credit|debit|cvv)\b")
AADHAAR = re.compile(r"(?<![\d\-])[2-9]\d{3}([ \-]?)\d{4}\1\d{4}(?![\d\-])")
AADHAAR_CTX = re.compile(r"(?i)\b(?:aadhaar|aadhar|uidai|uid)\b")
PAN = re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")
SSN = re.compile(r"(?<![\d\-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d\-])")
IPV4 = re.compile(r"(?<![\d.\w])(?:\d{1,3}\.){3}\d{1,3}(?![\d\w]|\.\d)")


def _card_ok(digits: str) -> bool:
    if not 13 <= len(digits) <= 19 or len(set(digits)) < 3 or not luhn_valid(digits):
        return False
    d2, d4 = int(digits[:2]), int(digits[:4])
    return (digits[0] == "4" or 51 <= d2 <= 55 or 2221 <= d4 <= 2720 or d2 in (34, 37, 35, 65, 36, 38)
            or d4 == 6011 or digits[:2] == "30")


def _line_of(text: str, pos: int) -> str:
    a = text.rfind("\n", 0, pos) + 1
    b = text.find("\n", pos)
    return text[a:] if b < 0 else text[a:b]


_PRIORITY = {"PRIVATE_KEY": 0, "AWS_SECRET_KEY": 1, "CONNECTION_STRING": 2, "AUTH_HEADER": 2,
             "GENERIC_CREDENTIAL": 3, "CREDIT_CARD": 4, "AADHAAR": 4, "SSN": 4, "PAN": 4,
             "EMAIL": 5, "PHONE": 6, "IP_ADDRESS": 7, "INTERNAL_IP": 7}


def _prio(c: Candidate) -> int:
    return _PRIORITY.get(c.type, 1)  # provider tokens sit at 1


def find_candidates(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    add = out.append

    for m in PRIVATE_KEY.finditer(text):
        add(Candidate("PRIVATE_KEY", m.start(), m.end(), m.group(), strong=True))
    for t, rx in PROVIDERS:
        for m in rx.finditer(text):
            add(Candidate(t, m.start(), m.end(), m.group(), strong=True))
    for m in AWS_SECRET.finditer(text):
        add(Candidate("AWS_SECRET_KEY", m.start("val"), m.end("val"), m.group("val"), strong=True))
    for m in AUTH_HEADER.finditer(text):
        add(Candidate("AUTH_HEADER", m.start("val"), m.end("val"), m.group("val"), key="Authorization"))
    for m in CONN_STRING.finditer(text):
        add(Candidate("CONNECTION_STRING", m.start("val"), m.end("val"), m.group("val"), strong=True))
    for m in GENERIC_Q.finditer(text):
        add(Candidate("GENERIC_CREDENTIAL", m.start("val"), m.end("val"), m.group("val"), key=m.group("key")))
    for m in GENERIC_UNQ.finditer(text):
        val = m.group("val").rstrip(";,")
        add(Candidate("GENERIC_CREDENTIAL", m.start("val"), m.start("val") + len(val), val,
                      key=m.group("key"), meta={"unquoted": True}))

    for m in CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if _card_ok(digits):
            ctx = bool(CARD_CTX.search(_line_of(text, m.start())))
            add(Candidate("CREDIT_CARD", m.start(), m.end(), m.group(), validated=True, meta={"ctx": ctx}))
    for m in AADHAAR.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        sep = bool(m.group(1))
        ctx = bool(AADHAAR_CTX.search(_line_of(text, m.start())))
        if verhoeff_valid(digits) and (sep or ctx):
            add(Candidate("AADHAAR", m.start(), m.end(), m.group(), validated=True, meta={"ctx": ctx}))
    for m in PAN.finditer(text):
        add(Candidate("PAN", m.start(), m.end(), m.group(), validated=True))
    for m in SSN.finditer(text):
        add(Candidate("SSN", m.start(), m.end(), m.group(), validated=True))

    for m in EMAIL.finditer(text):
        v = m.group()
        local, domain = v.rsplit("@", 1)
        if domain.rsplit(".", 1)[-1].lower() in _BAD_TLDS or local.lower() == "git":
            continue
        add(Candidate("EMAIL", m.start(), m.end(), v))

    for rx in (PHONE_INTL, PHONE_US, PHONE_IN_SPACED):
        for m in rx.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if 9 <= len(digits) <= 15:
                add(Candidate("PHONE", m.start(), m.end(), m.group()))
    for m in PHONE_BARE.finditer(text):
        if PHONE_CTX.search(_line_of(text, m.start())):
            add(Candidate("PHONE", m.start(), m.end(), m.group(), meta={"ctx": True}))

    for m in IPV4.finditer(text):
        parts = [int(p) for p in m.group().split(".")]
        if any(p > 255 for p in parts) or parts[0] in (0, 127, 255) or (parts[0] >= 224):
            continue
        line = _line_of(text, m.start()).lower()
        if "version" in line or re.search(r"\bv\d", line[max(0, m.start() - 3):]):
            continue
        priv = (parts[0] == 10 or (parts[0] == 192 and parts[1] == 168)
                or (parts[0] == 172 and 16 <= parts[1] <= 31))
        add(Candidate("INTERNAL_IP" if priv else "IP_ADDRESS", m.start(), m.end(), m.group()))

    return _resolve(out)


def _resolve(cands: list[Candidate]) -> list[Candidate]:
    """Drop lower-priority candidates that overlap a higher-priority one;
    carry the variable name over so the explanation can mention it."""
    cands.sort(key=lambda c: (_prio(c), -(c.end - c.start), c.start))
    kept: list[Candidate] = []
    for c in cands:
        clash = next((k for k in kept if c.start < k.end and k.start < c.end), None)
        if clash is None:
            kept.append(c)
        elif c.key and not clash.key:
            clash.key = c.key
    kept.sort(key=lambda c: c.start)
    return kept


# ------------------------------------------------------------ OCR tolerance
# OCR often inserts a stray space inside long tokens or after a dot in an email. For images only,
# re-check provider tokens on whitespace-collapsed lines and allow ". " inside email local parts.
EMAIL_OCR = re.compile(r"\b[A-Za-z0-9_%+\-]+(?:\. ?[A-Za-z0-9_%+\-]+)*@[A-Za-z0-9\-]+(?:\. ?[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b")


def find_ocr_candidates(text: str) -> list[Candidate]:
    out: list[Candidate] = []
    pos = 0
    for line in text.split("\n"):
        idx = [i for i, ch in enumerate(line) if not ch.isspace()]
        if len(idx) != len(line):                       # only lines that actually contain whitespace
            compact = "".join(line[i] for i in idx)
            for t, rx in PROVIDERS:
                for m in rx.finditer(compact):
                    a, b = pos + idx[m.start()], pos + idx[m.end() - 1] + 1
                    out.append(Candidate(t, a, b, text[a:b], strong=True))
        for m in EMAIL_OCR.finditer(line):
            v = m.group()
            if v.rsplit("@", 1)[0].lower() != "git" and v.rsplit(".", 1)[-1].lower() not in _BAD_TLDS:
                out.append(Candidate("EMAIL", pos + m.start(), pos + m.end(), v.replace(" ", "")))
        pos += len(line) + 1
    return out
