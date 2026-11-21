"""OASIS SARIF 2.1.0 (Static Analysis Results Interchange Format) exporter for LeakLens.

Converts LeakLens findings into standard SARIF 2.1.0 format consumable by GitHub Advanced Security,
VS Code SARIF Viewer, GitLab, CI/CD security pipelines, and automated policy scanners.
Raw credentials and secrets are NEVER exposed in SARIF outputs; only masked previews and context snippets are emitted.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def sarif_level_for(level: str) -> str:
    """Map LeakLens risk level to SARIF 2.1.0 level (error, warning, note, none)."""
    lvl = (level or "").lower()
    if lvl == "high":
        return "error"
    if lvl == "medium":
        return "warning"
    if lvl == "low":
        return "note"
    return "note"


def build_rule_descriptor(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Create a SARIF reportingDescriptor for a given finding type."""
    ftype = finding.get("type", "SUSPECTED_SENSITIVE")
    rule_id = f"LL-{ftype.replace('_', '-')}"
    label = finding.get("label", ftype)
    why = finding.get("why", f"Detected potential security or privacy leak of type {label}.")
    action = finding.get("action", "Rotate the exposed credential immediately and replace with environment variables.")
    blast = (finding.get("blast_radius") or "").strip()
    level = sarif_level_for(finding.get("level", "medium"))
    precision = "very-high" if finding.get("confidence") == "High" else "high" if finding.get("confidence") == "Medium" else "medium"

    return {
        "id": rule_id,
        "name": label,
        "shortDescription": {
            "text": label,
        },
        "fullDescription": {
            "text": why,
        },
        "help": {
            "text": action if not blast else f"{action} Blast radius: {blast}",
            "markdown": (
                f"### Remediation\n\n{action}\n\n**Risk Impact:** {why}"
                + (f"\n\n**Potential blast radius:** {blast}" if blast else "")
            ),
        },
        "defaultConfiguration": {
            "level": level,
        },
        "properties": {
            "category": finding.get("category", "Security"),
            "provider": finding.get("provider", "Generic"),
            "precision": precision,
            **({"blastRadius": blast} if blast else {}),
            "tags": ["security", "privacy", "secret-detection", finding.get("category", "Security").lower()],
        },
    }


def build_sarif_result(filename: str, finding: Dict[str, Any], rule_indices: Dict[str, int]) -> Dict[str, Any]:
    """Convert an individual finding into a SARIF 2.1.0 result object."""
    ftype = finding.get("type", "SUSPECTED_SENSITIVE")
    rule_id = f"LL-{ftype.replace('_', '-')}"
    level = sarif_level_for(finding.get("level", "medium"))
    preview = finding.get("preview", "••••")
    label = finding.get("label", ftype)
    rule_idx = rule_indices.get(rule_id, 0)

    start_line = max(1, finding.get("line") or 1)
    start_col = max(1, finding.get("col") or 1)
    end_line = max(start_line, finding.get("end_line") or start_line)
    end_col = max(start_col + 1, finding.get("end_col") or (start_col + 4))

    # Masked snippet for context
    snippet_text = finding.get("context", "")

    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_idx,
        "level": level,
        "message": {
            "text": f"Potential leak of {label}: {preview}",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": filename.replace("\\", "/"),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": start_line,
                        "startColumn": start_col,
                        "endLine": end_line,
                        "endColumn": end_col,
                        "snippet": {
                            "text": snippet_text,
                        },
                    },
                },
            }
        ],
        "properties": {
            "score": finding.get("score", 0),
            "status": finding.get("status", "active"),
            "source": finding.get("source", "rule"),
            "confidence": finding.get("confidence", "Medium"),
            "maskedPreview": preview,
        },
    }

    # If finding has reasons/explanations, attach them
    if finding.get("reasons"):
        result["properties"]["reasons"] = [r.get("text", "") for r in finding["reasons"] if isinstance(r, dict)]

    return result


def generate_sarif(filename: str, findings: List[Dict[str, Any]], scan_id: str = "", active_only: bool = True) -> Dict[str, Any]:
    """Generate a SARIF 2.1.0 document from a list of findings for a single file."""
    return generate_sarif_multi({filename: findings}, scan_id=scan_id, active_only=active_only)


def generate_sarif_multi(file_findings: Dict[str, List[Dict[str, Any]]], scan_id: str = "", active_only: bool = True) -> Dict[str, Any]:
    """Generate a SARIF 2.1.0 document from multiple files and their findings."""
    rules_dict: Dict[str, Dict[str, Any]] = {}
    rule_indices: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    # First collect unique rules
    for _, flist in file_findings.items():
        for f in flist:
            if active_only and f.get("status") != "active":
                continue
            ftype = f.get("type", "SUSPECTED_SENSITIVE")
            rule_id = f"LL-{ftype.replace('_', '-')}"
            if rule_id not in rules_dict:
                rule_indices[rule_id] = len(rules_dict)
                rules_dict[rule_id] = build_rule_descriptor(f)

    # Then compile results
    for filename, flist in file_findings.items():
        for f in flist:
            if active_only and f.get("status") != "active":
                continue
            results.append(build_sarif_result(filename, f, rule_indices))

    sarif_log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LeakLens",
                        "fullName": "LeakLens AI-Powered Privacy Leak Detection & Prevention System",
                        "version": "2.0.0",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/leaklens/leaklens",
                        "rules": list(rules_dict.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "scanId": scan_id or None,
                        },
                    }
                ],
                "results": results,
            }
        ],
    }

    return sarif_log
