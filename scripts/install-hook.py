#!/usr/bin/env python3
"""Installs the LeakLens Git pre-commit hook into .git/hooks/pre-commit."""
import os
import shutil
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GIT_DIR = ROOT / ".git"
HOOK_SRC = ROOT / "scripts" / "leaklens-pre-commit.py"
HOOK_DEST = GIT_DIR / "hooks" / "pre-commit"


def install():
    if not GIT_DIR.exists():
        # Check parent if nested git
        if (ROOT.parent / ".git").exists():
            dest = ROOT.parent / ".git" / "hooks" / "pre-commit"
        else:
            print("Error: No .git directory found. Please run within a git repository.", file=sys.stderr)
            return 1
    else:
        dest = HOOK_DEST

    dest.parent.mkdir(parents=True, exist_ok=True)
    
    script_content = f"""#!/usr/bin/env bash
python "{HOOK_SRC.as_posix()}"
"""
    dest.write_text(script_content, encoding="utf-8")
    
    # Make executable on Unix
    try:
        dest.chmod(dest.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass

    print(f"[SUCCESS] LeakLens pre-commit hook installed to: {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(install())
