#!/usr/bin/env python3
"""LeakLens Standalone CLI Tool.

Enables automated privacy leak detection, hardcoded secret scanning, and SARIF 2.1.0
export for developer terminal workflows, pre-commit hooks, and CI/CD pipelines.

Usage:
    python cli.py scan <path> [--format text|json|sarif] [--threshold high|medium|low] [--output <file>]
    python cli.py scan <path> --server http://127.0.0.1:5000 --pat pat_xxx
    python cli.py vault export <output_file> --password <password> [--username <user>]
    python cli.py vault import <input_file> --password <password> [--username <user>]
    python cli.py --version
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Tuple

import config
from engine import extract, sarif, service, store

VERSION = "2.0.0"

# Directories to skip when scanning a directory recursively
IGNORED_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
    ".pytest_cache", ".hypothesis", ".idea", ".vscode", "dist", "build",
    "instance", ".system_generated", "tmp"
}

# Binary and non-target file extensions to skip in bulk directory scans
SKIPPED_EXTS = {
    ".pyc", ".pyo", ".pyd", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".leaklens", ".db", ".sqlite", ".sqlite3", ".woff", ".woff2", ".ttf",
    ".eot", ".zip", ".tar", ".gz", ".7z", ".rar", ".lock"
}


def is_ignored(path: Path) -> bool:
    for part in path.parts:
        if part in IGNORED_DIRS or (part.startswith(".") and part != "." and part != ".."):
            return True
    if path.suffix.lower() in SKIPPED_EXTS:
        return True
    return False


def scan_local_file(filepath: Path) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
    """Scan an individual local file using the LeakLens hybrid detection engine."""
    try:
        data = filepath.read_bytes()
    except Exception as e:
        return str(filepath), [], {"error": str(e)}

    if len(data) > config.MAX_UPLOAD_BYTES:
        return str(filepath), [], {"error": "File exceeds max scan size limit."}

    rel_name = str(filepath).replace("\\", "/")
    try:
        ex, findings = service.analyse(filepath.name, data)
        # Filter server-side raw secrets
        safe_findings = [{k: v for k, v in f.items() if k != "_value"} for f in findings]
        summ = service.summary(safe_findings)
        return rel_name, safe_findings, summ
    except extract.ScanError as e:
        return rel_name, [], {"error": str(e)}
    except Exception as e:
        return rel_name, [], {"error": f"Analysis failed: {e}"}


def scan_local_target(target_path: Path) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, Any]]:
    """Recursively scan a directory or a single file."""
    if not target_path.exists():
        print(f"[ERROR] Target path does not exist: {target_path}", file=sys.stderr)
        sys.exit(2)

    file_findings: Dict[str, List[Dict[str, Any]]] = {}
    total_files = 0
    total_findings = 0
    active_high = 0
    active_medium = 0
    active_low = 0

    if target_path.is_file():
        files_to_scan = [target_path]
    else:
        files_to_scan = []
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
            for f in files:
                p = Path(root) / f
                if not is_ignored(p):
                    files_to_scan.append(p)

    for fp in files_to_scan:
        rel_name, findings, summ = scan_local_file(fp)
        total_files += 1
        if findings:
            file_findings[rel_name] = findings
            act = [f for f in findings if f.get("status") == "active"]
            total_findings += len(act)
            active_high += sum(1 for f in act if f.get("level") == "high")
            active_medium += sum(1 for f in act if f.get("level") == "medium")
            active_low += sum(1 for f in act if f.get("level") == "low")

    overall_summary = {
        "files_scanned": total_files,
        "total_active_findings": total_findings,
        "high": active_high,
        "medium": active_medium,
        "low": active_low,
    }

    return file_findings, overall_summary


def scan_remote_target(target_path: Path, server_url: str, pat: str, fmt: str) -> Tuple[Any, Dict[str, Any]]:
    """Perform a headless scan against a remote LeakLens server."""
    if not target_path.is_file():
        print("[ERROR] Remote server scanning currently supports single file uploads. For full directories, run CLI locally.", file=sys.stderr)
        sys.exit(2)

    url = f"{server_url.rstrip('/')}/api/v1/scan?format={fmt}"
    try:
        content = target_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}", file=sys.stderr)
        sys.exit(2)

    payload = json.dumps({"filename": target_path.name, "text": content}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    if pat:
        req.add_header("Authorization", f"Bearer {pat}")

    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode("utf-8")
            data = json.loads(body)
            if fmt == "sarif":
                # Extract summary from SARIF results
                results = data.get("runs", [{}])[0].get("results", [])
                high = sum(1 for r in results if r.get("level") == "error")
                medium = sum(1 for r in results if r.get("level") == "warning")
                low = sum(1 for r in results if r.get("level") == "note")
                summary = {"files_scanned": 1, "total_active_findings": len(results), "high": high, "medium": medium, "low": low}
            else:
                s = data.get("summary", {})
                summary = {"files_scanned": 1, "total_active_findings": s.get("active", 0), "high": s.get("high", 0), "medium": s.get("medium", 0), "low": s.get("low", 0)}
            return data, summary
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        print(f"[ERROR] Remote scan failed (HTTP {e.code}): {err_msg}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Connection to LeakLens server failed: {e}", file=sys.stderr)
        sys.exit(1)


def format_text_output(target_name: str, file_findings: Dict[str, List[Dict[str, Any]]], summary: Dict[str, Any], threshold: str) -> str:
    """Format scan results into human-readable terminal output."""
    lines = []
    lines.append("=" * 68)
    lines.append(f"  LeakLens Scanner v{VERSION} — Hybrid Secret & Privacy Guard")
    lines.append("=" * 68)
    lines.append(f"Target:         {target_name}")
    lines.append(f"Files Scanned:  {summary['files_scanned']}")
    lines.append(f"Findings:       {summary['total_active_findings']} active "
                 f"(High: {summary['high']}, Medium: {summary['medium']}, Low: {summary['low']})")
    lines.append(f"Fail Threshold: {threshold.upper()}")
    lines.append("-" * 68)

    if not file_findings or summary["total_active_findings"] == 0:
        lines.append("✔ No privacy leaks or hardcoded credentials detected.")
        lines.append("-" * 68)
        lines.append("[PASSED] Scan completed cleanly.")
        return "\n".join(lines)

    for filename, findings in file_findings.items():
        active = [f for f in findings if f.get("status") == "active"]
        if not active:
            continue
        lines.append(f"\n📁 {filename} ({len(active)} finding{'s' if len(active) > 1 else ''}):")
        for f in active:
            lvl = f.get("level", "medium").upper()
            line_num = f.get("line") or 1
            col_num = f.get("col") or 1
            label = f.get("label", f.get("type"))
            provider = f.get("provider", "Generic")
            preview = f.get("preview", "••••")
            action = f.get("action", "Rotate immediately and store in environment variables.")

            lines.append(f"  [{lvl:6s}] Line {line_num}:{col_num} — {label} ({provider})")
            lines.append(f"           Preview:      {preview}")
            lines.append(f"           Remediation:  {action}")
            blast = f.get("blast_radius")
            if blast:
                lines.append(f"           Blast radius: {blast}")

    lines.append("\n" + "-" * 68)

    # Determine failure condition based on threshold
    fail = False
    if threshold == "high" and summary["high"] > 0:
        fail = True
    elif threshold == "medium" and (summary["high"] > 0 or summary["medium"] > 0):
        fail = True
    elif threshold == "low" and summary["total_active_findings"] > 0:
        fail = True

    if fail:
        lines.append(f"[FAILED] Found active findings meeting or exceeding threshold '{threshold.upper()}'.")
    else:
        lines.append(f"[PASSED] No findings exceeded the failure threshold '{threshold.upper()}'.")

    return "\n".join(lines)


def run_scan(args: argparse.Namespace) -> int:
    target_path = Path(args.path).resolve()
    threshold = (args.threshold or "high").lower()
    fmt = (args.format or "text").lower()

    if args.server:
        raw_data, summary = scan_remote_target(target_path, args.server, args.pat, fmt)
        if fmt == "sarif" or fmt == "json":
            out_str = json.dumps(raw_data, indent=2)
        else:
            file_findings = {}
            if isinstance(raw_data, dict) and "findings" in raw_data:
                file_findings[target_path.name] = raw_data["findings"]
            out_str = format_text_output(str(target_path), file_findings, summary, threshold)
    else:
        file_findings, summary = scan_local_target(target_path)
        if fmt == "sarif":
            sarif_log = sarif.generate_sarif_multi(file_findings)
            out_str = json.dumps(sarif_log, indent=2)
        elif fmt == "json":
            json_report = {
                "version": VERSION,
                "target": str(target_path),
                "summary": summary,
                "results": file_findings,
            }
            out_str = json.dumps(json_report, indent=2)
        else:
            out_str = format_text_output(str(target_path), file_findings, summary, threshold)

    if args.output:
        out_p = Path(args.output).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(out_str, encoding="utf-8")
        print(f"[INFO] Report saved to: {out_p}")
    else:
        print(out_str)

    # Exit code determination
    if threshold == "high" and summary["high"] > 0:
        return 1
    if threshold == "medium" and (summary["high"] > 0 or summary["medium"] > 0):
        return 1
    if threshold == "low" and summary["total_active_findings"] > 0:
        return 1
    return 0


def run_vault_export(args: argparse.Namespace) -> int:
    out_file = Path(args.output_file).resolve()
    password = args.password
    if len(password) < 8:
        print("[ERROR] Password must be at least 8 characters long.", file=sys.stderr)
        return 1

    # Locate user
    username = args.username or "admin"
    user = store.get_user_by_username_or_email(username)
    if not user:
        # Fall back to first available user
        with store._db() as con:
            row = con.execute("SELECT * FROM users WHERE status='active' LIMIT 1").fetchone()
            if row:
                user = dict(row)

    if not user:
        print(f"[ERROR] No user account found in database to export vault for. Specify --username.", file=sys.stderr)
        return 1

    try:
        vault_bytes = store.export_portable_vault(user["id"], password)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_bytes(vault_bytes)
        print(f"[SUCCESS] Exported encrypted .leaklens vault for user '{user['username']}' to: {out_file}")
        return 0
    except Exception as e:
        print(f"[ERROR] Vault export failed: {e}", file=sys.stderr)
        return 1


def run_vault_import(args: argparse.Namespace) -> int:
    in_file = Path(args.input_file).resolve()
    password = args.password
    if not in_file.exists():
        print(f"[ERROR] Input vault file does not exist: {in_file}", file=sys.stderr)
        return 1

    username = args.username or "admin"
    user = store.get_user_by_username_or_email(username)
    if not user:
        with store._db() as con:
            row = con.execute("SELECT * FROM users WHERE status='active' LIMIT 1").fetchone()
            if row:
                user = dict(row)

    if not user:
        print("[ERROR] No active user account found in database to import vault into. Specify --username.", file=sys.stderr)
        return 1

    try:
        file_bytes = in_file.read_bytes()
        res = store.import_portable_vault(user["id"], password, file_bytes)
        print(f"[SUCCESS] Successfully imported {res['imported_count']} vault items into user '{user['username']}'.")
        return 0
    except Exception as e:
        print(f"[ERROR] Vault import failed: {e}", file=sys.stderr)
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="leaklens",
        description="LeakLens CLI — AI-Powered Privacy Leak Detection & Security Platform",
    )
    parser.add_argument("--version", action="version", version=f"LeakLens {VERSION}")

    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a directory or file for secrets and privacy leaks")
    scan_parser.add_argument("path", help="Path to file or directory to scan")
    scan_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                             help="Report format: text (default), json, or sarif (OASIS SARIF 2.1.0)")
    scan_parser.add_argument("--threshold", choices=["high", "medium", "low"], default="high",
                             help="Failure exit threshold: high (default), medium, or low")
    scan_parser.add_argument("-o", "--output", help="Write report to output file instead of stdout")
    scan_parser.add_argument("--server", help="Remote LeakLens server URL (e.g. http://127.0.0.1:5000)")
    scan_parser.add_argument("--pat", help="Personal Access Token for authenticating to remote server")

    # vault commands
    vault_parser = subparsers.add_parser("vault", help="Encrypted .leaklens vault operations")
    vault_sub = vault_parser.add_subparsers(dest="vault_command")

    v_export = vault_sub.add_parser("export", help="Export local encrypted vault to a portable .leaklens file")
    v_export.add_argument("output_file", help="Path to save exported .leaklens file")
    v_export.add_argument("--password", required=True, help="Password for Scrypt + AES-256-GCM encryption")
    v_export.add_argument("--username", help="User account whose vault to export")

    v_import = vault_sub.add_parser("import", help="Import a portable .leaklens vault file into local store")
    v_import.add_argument("input_file", help="Path to .leaklens file to import")
    v_import.add_argument("--password", required=True, help="Password for decryption")
    v_import.add_argument("--username", help="User account to import credentials into")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(run_scan(args))
    elif args.command == "vault":
        if args.vault_command == "export":
            sys.exit(run_vault_export(args))
        elif args.vault_command == "import":
            sys.exit(run_vault_import(args))
        else:
            vault_parser.print_help()
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
