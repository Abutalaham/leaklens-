"""Orchestration: file -> extraction -> detection -> findings (with locations) -> redaction -> rescan.

Raw secret values never leave this module: findings returned to the web layer carry only masked
previews, and nothing here logs content."""
from __future__ import annotations

import os

from . import catalog, extract, redact, risk
from .detector import Detector, mask_value

_detector = None


def get_detector() -> Detector:
    global _detector
    if _detector is None:
        _detector = Detector()
    return _detector


def _metadata_findings(ex: extract.Extracted) -> list[dict]:
    out = []
    for m in ex.metadata:
        info = catalog.info(m["type"])
        score = info["base"]
        reasons = [{"signal": "base", "delta": score, "text": f"{info['label']} (base score {score})"},
                   {"signal": "metadata", "delta": 0, "text": f"Embedded field '{m['field']}'"}]
        out.append({
            "type": m["type"], "label": info["label"], "category": "Metadata",
            "provider": "Metadata", "confidence": "High",
            "start": None, "end": None, "line": None, "col": None, "end_line": None, "end_col": None, "page": None, "score": score,
            "level": risk.level_for(score), "status": "active", "source": "metadata", "ml_prob": None,
            "reasons": reasons, "why": info["why"], "action": info["action"],
            "blast_radius": info.get("blast_radius", ""),
            "preview": f"{m['field']}: " + ("present" if m["type"] == "METADATA_GPS" else mask_value(m["value"])),
            "key": m["field"], "context": "", "metadata": True,
        })
    return out


def analyse(filename: str, data: bytes) -> tuple[extract.Extracted, list[dict]]:
    """Return (extracted, findings). Internal findings keep '_value' (server-side only)."""
    ex = extract.extract(filename, data)
    findings = get_detector().scan_text(ex.text, filename, ocr=(ex.kind == "image")) if ex.text else []
    for f in findings:
        if ex.kind == "pdf":
            f["page"], f["page_line"] = extract.page_of(ex, f["start"])
        elif ex.kind == "image":
            boxes = [w["box"] for w in ex.words if w["s"] < f["end"] and w["e"] > f["start"]]
            W, H = ex.size
            f["boxes"] = [[x, y, w, h] for x, y, w, h in boxes]
            f["boxes_pct"] = [[x / W * 100, y / H * 100, w / W * 100, h / H * 100] for x, y, w, h in boxes]
    meta = _metadata_findings(ex)
    findings = findings + meta
    for n, f in enumerate(findings, 1):
        f["id"] = f"f{n}"
    return ex, findings


def public(findings: list[dict]) -> list[dict]:
    """Strip anything secret before sending to the browser."""
    return [{k: v for k, v in f.items() if k not in ("_value", "boxes")} for f in findings]


def masked_text(text: str, findings: list[dict]) -> str:
    chars = list(text)
    for f in findings:
        if f.get("start") is None:
            continue
        for k in range(f["start"], f["end"]):
            if chars[k] != "\n":
                chars[k] = "█"
    return "".join(chars)


def summary(findings: list[dict]) -> dict:
    act = [f for f in findings if f["status"] == "active"]
    return {
        "total": len(findings), "active": len(act),
        "high": sum(1 for f in act if f["level"] == "high"),
        "medium": sum(1 for f in act if f["level"] == "medium"),
        "low": sum(1 for f in act if f["level"] == "low"),
        "placeholder": sum(1 for f in findings if f["status"] == "placeholder"),
        "likely_benign": sum(1 for f in findings if f["status"] == "likely_benign"),
        "overall": risk.overall(findings),
    }


def apply_redaction(kind: str, filename: str, data: bytes, ex: extract.Extracted, findings: list[dict],
                    selected_ids: set, style: str = "label"):
    """Return (sanitised_bytes, output_filename, applied_findings)."""
    chosen = [f for f in findings if f["id"] in selected_ids and not f.get("metadata")]
    base = os.path.splitext(os.path.basename(filename))[0] or "file"
    if kind == "text":
        spans = [(f["start"], f["end"], f["type"]) for f in chosen]
        ext = os.path.splitext(filename)[1] or ".txt"
        return redact.redact_text(ex.text, spans, style).encode("utf-8"), f"sanitised_{base}{ext}", chosen
    if kind == "pdf":
        spans = [(f["start"], f["end"], f["type"]) for f in chosen]
        return redact.sanitise_pdf(ex.text, spans, style), f"sanitised_{base}.pdf", chosen
    boxes = [tuple(b) for f in chosen for b in f.get("boxes", [])]
    hint = os.path.splitext(filename)[1].lower().lstrip(".")
    out, ext = redact.sanitise_image(data, boxes, hint)
    return out, f"sanitised_{base}.{ext}", chosen


def rescan(filename: str, data: bytes) -> dict:
    """Scan the sanitised output again to verify what is left."""
    try:
        _, findings = analyse(filename, data)
    except extract.ScanError as e:
        return {"error": str(e)}
    non_meta = [f for f in findings if not f.get("metadata")]
    s = summary(non_meta)
    s["metadata_remaining"] = sum(1 for f in findings if f.get("metadata"))
    s["remaining"] = [{"id": f["id"], "type": f["type"], "label": f["label"], "level": f["level"],
                       "line": f.get("line"), "page": f.get("page")} for f in non_meta if f["status"] == "active"]
    return s
