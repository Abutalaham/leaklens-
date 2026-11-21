"""Hybrid detector: rules -> context checks -> ML adjustment/discovery -> explainable findings."""
from __future__ import annotations

import bisect
import re

from . import catalog, context, ml, risk
from .rules import Candidate, _resolve, find_candidates, find_ocr_candidates

_VALUE_RX = [re.compile(r"""["']([^"'\r\n]{6,200})["']\s*[;,)\]}]*\s*$"""),
             re.compile(r"""[:=]\s*([^\s"'][^\s]{5,199})\s*$"""),
             re.compile(r"""\b(?:is|are)[ :]+([^\s]{6,100})[.,;]?\s*$""", re.I)]
_PREFILTER = re.compile(r"[=:]|\b(?:is|are)\b")


def mask_value(v: str) -> str:
    v = v.replace("\n", " ")
    if len(v) < 8:
        return "•" * len(v)
    return v[:3] + "•" * min(len(v) - 3, 16)


def extract_value(line: str):
    """Best-effort value span in a line, for ML-discovered findings."""
    for rx in _VALUE_RX:
        m = rx.search(line)
        if m:
            v = m.group(1)
            if len(v.split()) >= 3:           # prose, not a value
                continue
            if not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)) and len(v) < 12:
                continue
            return m.start(1), m.end(1)
    return None


class Detector:
    def __init__(self, classifier=None, use_ml=True, use_context=True, ml_cfg=None):
        self.use_context = use_context
        self.use_ml = use_ml
        self.ml_cfg = ml_cfg or ml.load_thresholds()
        self.clf = classifier if classifier is not None else (ml.load_classifier() if use_ml else None)
        if self.clf is None:
            self.use_ml = False

    # ------------------------------------------------------------------
    def scan_text(self, text: str, filename: str = "", ocr: bool = False) -> list[dict]:
        """Return findings as dicts. Raw values stay under key '_value' (server-side only).
        ocr=True adds OCR-tolerant matching (stray spaces inside tokens/emails)."""
        cands = find_candidates(text)
        if ocr:
            cands = _resolve(cands + find_ocr_candidates(text))
        lines = text.split("\n")
        starts = [0]
        for ln in lines[:-1]:
            starts.append(starts[-1] + len(ln) + 1)

        def line_no(pos):
            return bisect.bisect_right(starts, pos) - 1

        # one batched ML call for every candidate line + discovery lines
        cand_lines = {line_no(c.start) for c in cands}
        discover = []
        if self.use_ml:
            for i, ln in enumerate(lines):
                if i not in cand_lines and 8 <= len(ln.strip()) <= 300 and _PREFILTER.search(ln):
                    ev = extract_value(ln)
                    if ev:
                        discover.append((i, ev))
                if len(discover) >= 5000:
                    break
        need = sorted(cand_lines | {i for i, _ in discover}) if self.use_ml else []
        probs = dict(zip(need, self.clf.prob_sensitive([ml.snippet_for(lines, i) for i in need]))) if need else {}

        findings = []
        for c in cands:
            li = line_no(c.start)
            prev = lines[li - 1] if li else ""
            a = risk.assess(
                c,
                placeholder=context.placeholder_reason(c) if self.use_context else None,
                benign=context.benign_reason(c) if self.use_context else None,
                hint=context.doc_hint(lines[li], prev, c.value) if self.use_context else None,
                test_file=context.test_file_hint(filename) if self.use_context else False,
                ml_prob=probs.get(li) if (self.use_ml and self.use_context) else None,
                ml_cfg=self.ml_cfg, use_context=self.use_context)
            findings.append(self._finding(c, a, starts, li, "rule" if probs.get(li) is None else "rule+ml",
                                          probs.get(li)))

        for li, (a0, b0) in discover:
            p = probs.get(li)
            if p is None or p < self.ml_cfg["discover"]:
                continue
            ln = lines[li]
            c = Candidate("SUSPECTED_SENSITIVE", starts[li] + a0, starts[li] + b0, ln[a0:b0],
                          key=None, meta={"unquoted": True})
            if context.placeholder_reason(c) or context.doc_hint(ln, lines[li - 1] if li else "", c.value):
                continue
            a = risk.assess(c, placeholder=None, benign=None, hint=None, test_file=False,
                            ml_prob=None, ml_cfg=self.ml_cfg)
            if p >= 0.97:
                a.score += 5
                a.reasons.append({"signal": "ml", "delta": 5, "text": f"ML classifier is very confident (p={p:.2f})"})
            a.reasons.append({"signal": "ml_only", "delta": 0,
                              "text": f"No deterministic rule matched; flagged by ML classifier alone (p={p:.2f}). "
                                      f"ML-only findings are capped at medium risk."})
            a.score = min(a.score, config_cap())
            a.level = risk.level_for(a.score)
            findings.append(self._finding(c, a, starts, li, "ml", p))

        findings.sort(key=lambda f: f["start"])
        masked = list(text)
        for f in findings:
            for k in range(f["start"], f["end"]):
                if masked[k] != "\n":
                    masked[k] = "█"
        masked_text = "".join(masked)
        mlines = masked_text.split("\n")
        for n, f in enumerate(findings, 1):
            f["id"] = f"f{n}"
            f["context"] = mlines[f["line"] - 1].strip()[:240]
        return findings

    # ------------------------------------------------------------------
    @staticmethod
    def _finding(c: Candidate, a: risk.Assessment, starts, li, source, p):
        info = catalog.info(c.type)
        end_line = bisect.bisect_right(starts, max(c.start, c.end - 1)) - 1
        end_col = max(1, c.end - starts[end_line] + 1)
        if c.validated or c.strong:
            confidence = "High"
        elif source == "ml" or a.score >= 50:
            confidence = "Medium"
        else:
            confidence = "Low" if a.status != "active" else "Medium"

        return {
            "type": c.type, "label": info["label"], "category": info["category"],
            "provider": info.get("provider", "Generic"), "confidence": confidence,
            "start": c.start, "end": c.end, "line": li + 1, "col": c.start - starts[li] + 1,
            "end_line": end_line + 1, "end_col": end_col, "score": a.score, "level": a.level, "status": a.status,
            "source": source, "ml_prob": None if p is None else round(p, 3),
            "reasons": a.reasons, "why": info["why"], "action": info["action"],
            "blast_radius": info.get("blast_radius", ""),
            "preview": mask_value(c.value), "key": c.key, "_value": c.value,
        }

    def flagged(self, text: str, filename: str = "") -> bool:
        """True if any ACTIVE finding exists (used by the evaluation)."""
        return any(f["status"] == "active" for f in self.scan_text(text, filename))


def config_cap() -> int:
    import config
    return config.MEDIUM_AT + 5
