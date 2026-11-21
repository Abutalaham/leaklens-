"""Transparent, additive risk scoring. Every adjustment is recorded as a reason so
the dashboard can show the evidence behind the final level."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import config
from . import catalog
from .context import ROLE_LOCALS
from .rules import Candidate, entropy

ML_ADJUSTABLE_SKIP = {"PRIVATE_KEY", "METADATA_GPS"}


@dataclass
class Assessment:
    score: int
    level: str
    status: str            # active | placeholder | likely_benign
    reasons: list = field(default_factory=list)   # [{signal, delta, text}]


def level_for(score: int) -> str:
    return "high" if score >= config.HIGH_AT else "medium" if score >= config.MEDIUM_AT else "low"


def assess(c: Candidate, *, placeholder: str | None, benign: str | None, hint: str | None,
           test_file: bool, ml_prob: float | None, ml_cfg: dict, use_context: bool = True) -> Assessment:
    base = catalog.info(c.type)["base"]
    score = base
    reasons = [{"signal": "base", "delta": base,
                "text": f"{catalog.info(c.type)['label']} (base score {base})"}]

    def add(signal, delta, text):
        nonlocal score
        score += delta
        reasons.append({"signal": signal, "delta": delta, "text": text})

    ent = entropy(c.value) if c.type not in ("EMAIL", "PHONE") else 0.0
    if c.strong and c.type not in ("PRIVATE_KEY",):
        add("format", 0, "Matches a provider-specific format")
    if c.key and c.type != "GENERIC_CREDENTIAL" and re.search(r"(?i)pass|secret|token|key|auth|cred", c.key):
        add("key_name", 5, f"Assigned to credential-named variable '{c.key}'")
    elif c.key and c.type == "GENERIC_CREDENTIAL":
        add("key_name", 0, f"Variable name '{c.key}' suggests a credential")
    if c.validated:
        add("checksum", 10, "Passes the identifier's checksum/structure validation")
    if c.meta.get("ctx"):
        add("keyword", 5, "A nearby keyword (e.g. phone/card/Aadhaar) supports this reading")
    if c.type in ("GENERIC_CREDENTIAL", "AUTH_HEADER") or c.strong:
        if len(c.value) >= 12 and ent >= 3.5:
            add("entropy", 10, f"High-entropy value ({ent:.1f} bits/char) looks randomly generated")
        elif len(c.value) < 8:
            add("entropy", -5, "Short value; weaker evidence of a real secret")
    if c.type == "EMAIL" and c.value.split("@")[0].lower() in ROLE_LOCALS:
        add("role_mailbox", -10, "Shared/role mailbox, lower privacy impact than a personal address")

    status = "active"
    if use_context:
        if ml_prob is not None and c.type not in ML_ADJUSTABLE_SKIP and not (c.strong and c.type != "GENERIC_CREDENTIAL"):
            if ml_prob >= ml_cfg["boost"]:
                add("ml", 10, f"ML classifier agrees the snippet is sensitive (p={ml_prob:.2f})")
            elif ml_prob <= 0.25:
                add("ml", -10, f"ML classifier leans non-sensitive (p={ml_prob:.2f})")
        if hint:
            add("doc_context", -15, f"Nearby text says '{hint}', suggesting documentation")
        if test_file:
            add("test_file", -10, "File name suggests test/example/demo content")
        if placeholder:
            status = "placeholder"
            add("placeholder", 0, f"Looks like a placeholder: {placeholder}")
            score = min(score, 15)
        elif benign:
            status = "likely_benign"
            add("benign", 0, f"Probably not a secret: {benign}")
            score = min(score, 10)
        elif (ml_prob is not None and c.type == "GENERIC_CREDENTIAL" and ml_prob < ml_cfg["benign"]
              and ent < 3.5 and not c.validated):
            status = "likely_benign"
            add("ml_gate", 0, f"ML classifier strongly considers this non-sensitive (p={ml_prob:.2f}) "
                              f"and the value is low-entropy")
            score = min(score, 10)

    score = max(0, min(100, int(round(score))))
    return Assessment(score, level_for(score), status, reasons)


def overall(findings: list[dict]) -> dict:
    """Overall file risk = highest active finding score, +5 per extra high-risk finding (cap +15)."""
    active = [f for f in findings if f["status"] == "active"]
    if not active:
        return {"score": 0, "level": "low", "explanation": "No active findings."}
    top = max(f["score"] for f in active)
    extra = min(15, 5 * max(0, sum(1 for f in active if f["level"] == "high") - 1))
    s = min(100, top + extra)
    text = f"Highest active finding scores {top}"
    if extra:
        text += f", plus {extra} for additional high-risk findings"
    return {"score": s, "level": level_for(s), "explanation": text + "."}
