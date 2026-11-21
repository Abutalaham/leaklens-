#!/usr/bin/env python3
"""LeakLens Pre-Commit Hook.
Scans staged files for credentials, API tokens, and PII before allowing git commit.
Runs 100% locally and exits with code 1 if active high/medium risks are found."""
import os
import subprocess
import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import config
from engine import extract, service


def get_staged_files() -> list[str]:
    try:
        out = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return [f.strip() for f in out.splitlines() if f.strip()]
    except Exception:
        return []


def get_staged_content(rel_path: str) -> bytes:
    try:
        return subprocess.check_output(
            ["git", "show", f":{rel_path}"],
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return b""


def main() -> int:
    files = get_staged_files()
    if not files:
        return 0

    print("[LeakLens Pre-Commit Guard] Inspecting staged files for secret leaks...")
    total_leaks = 0
    blocked_files = []

    for path in files:
        ext = os.path.splitext(path)[1].lower()
        if ext not in (config.TEXT_EXTS | config.PDF_EXTS | config.IMAGE_EXTS):
            continue

        data = get_staged_content(path)
        if not data:
            continue

        try:
            ex, findings = service.analyse(os.path.basename(path), data)
            active_threats = [f for f in findings if f.get("status") == "active" and f.get("level") in ("high", "medium")]
            if active_threats:
                total_leaks += len(active_threats)
                blocked_files.append((path, active_threats))
        except Exception:
            continue

    if total_leaks > 0:
        print("\n\033[91m[LEAKLENS SECURITY ALERT] Commit blocked! Active secrets detected:\033[0m")
        for path, threats in blocked_files:
            print(f"\n  File: \033[1m{path}\033[0m")
            for t in threats:
                print(f"    - Line {t.get('line', '?')}: {t.get('label')} [{t.get('level', '').upper()} RISK]")
                print(f"      Masked: {t.get('preview')}")
                print(f"      Action: {t.get('action')}")

        print("\n\033[93mRemediation:\033[0m Move secrets to a local .env file or use 'LeakLens Safe Team Setup'.")
        print("To bypass this check in an emergency (not recommended): git commit --no-verify\n")
        return 1

    print("\033[92m[LeakLens Pre-Commit Guard] Staged files clean. Commit allowed.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
