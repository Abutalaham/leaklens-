"""Automated tests for scripts/leaklens-pre-commit.py.

Creates a real temporary git repository, stages files with and without secrets,
runs the pre-commit hook script, and asserts correct exit codes and output.
All secrets used here are fake / synthetically generated and never stored in the repo.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOK_SCRIPT = ROOT / "scripts" / "leaklens-pre-commit.py"
PYTHON = sys.executable


def git(args: list[str], cwd: Path, **kwargs) -> subprocess.CompletedProcess:
    """Run a git command inside cwd."""
    return subprocess.run(
        ["git"] + args,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        **kwargs,
    )


def run_hook(cwd: Path) -> subprocess.CompletedProcess:
    """Execute the pre-commit hook Python script directly."""
    return subprocess.run(
        [PYTHON, str(HOOK_SCRIPT)],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


@pytest.fixture
def git_repo(tmp_path):
    """Create a minimal git repository in a temp directory."""
    git(["init", "-b", "main"], cwd=tmp_path)
    git(["config", "user.email", "test@example.com"], cwd=tmp_path)
    git(["config", "user.name", "Test User"], cwd=tmp_path)
    # Create an initial commit so repo is not empty
    readme = tmp_path / "README.md"
    readme.write_text("# Test Project\n", encoding="utf-8")
    git(["add", "README.md"], cwd=tmp_path)
    git(["commit", "-m", "init"], cwd=tmp_path)
    return tmp_path


def test_hook_allows_clean_staged_file(git_repo):
    """Pre-commit hook exits 0 when no active secrets are staged."""
    clean_file = git_repo / "clean_module.py"
    clean_file.write_text(
        "def add(a, b):\n    return a + b\n\n# No secrets here\n",
        encoding="utf-8",
    )
    git(["add", "clean_module.py"], cwd=git_repo)
    result = run_hook(git_repo)
    assert result.returncode == 0, f"Expected exit 0 but got {result.returncode}.\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    assert "clean" in result.stdout.lower() or "allowed" in result.stdout.lower()


def test_hook_blocks_staged_github_token(git_repo, fake):
    """Pre-commit hook exits 1 when a staged file contains a GitHub PAT."""
    dirty_file = git_repo / "config.py"
    dirty_file.write_text(
        f"# GitHub token accidentally committed\nGITHUB_TOKEN = '{fake['gh']}'\n",
        encoding="utf-8",
    )
    git(["add", "config.py"], cwd=git_repo)
    result = run_hook(git_repo)
    assert result.returncode == 1, f"Expected exit 1 (blocked) but got {result.returncode}.\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    assert "ALERT" in result.stdout or "blocked" in result.stdout.lower()


def test_hook_blocks_staged_aws_key(git_repo, fake):
    """Pre-commit hook exits 1 when a staged file contains an AWS access key."""
    dirty_file = git_repo / "deploy.py"
    dirty_file.write_text(
        f"AWS_ACCESS_KEY_ID = '{fake['aws']}'\nREGION = 'us-east-1'\n",
        encoding="utf-8",
    )
    git(["add", "deploy.py"], cwd=git_repo)
    result = run_hook(git_repo)
    assert result.returncode == 1, f"Expected exit 1 (blocked) but got {result.returncode}."


def test_hook_passes_when_nothing_staged(git_repo):
    """Pre-commit hook exits 0 immediately when no files are staged."""
    result = run_hook(git_repo)
    assert result.returncode == 0, f"Expected exit 0 on empty staging area, got {result.returncode}."


def test_hook_ignores_unstaged_dirty_file(git_repo, fake):
    """Pre-commit hook only inspects staged files; unstaged dirty files must NOT cause a block."""
    # Unstaged dirty file — not git add'd
    untracked = git_repo / "untracked_secrets.py"
    untracked.write_text(
        f"SECRET_KEY = '{fake['stripe']}'\n",
        encoding="utf-8",
    )
    # Stage something clean instead
    clean_file = git_repo / "utils.py"
    clean_file.write_text("def noop(): pass\n", encoding="utf-8")
    git(["add", "utils.py"], cwd=git_repo)

    result = run_hook(git_repo)
    assert result.returncode == 0, (
        f"Hook should NOT block on unstaged files. Got exit {result.returncode}.\n"
        f"STDOUT: {result.stdout}"
    )


def test_hook_blocks_mixed_staged_files(git_repo, fake):
    """Pre-commit hook exits 1 when at least one staged file has an active secret,
    even if other staged files are clean."""
    clean_file = git_repo / "helpers.py"
    clean_file.write_text("def greet(name):\n    return f'Hello, {name}'\n", encoding="utf-8")

    dirty_file = git_repo / "settings.py"
    dirty_file.write_text(
        f"DEBUG = True\nSTRIPE_KEY = '{fake['stripe']}'\n",
        encoding="utf-8",
    )

    git(["add", "helpers.py", "settings.py"], cwd=git_repo)
    result = run_hook(git_repo)
    assert result.returncode == 1, f"Expected exit 1 for mixed staged files, got {result.returncode}."
