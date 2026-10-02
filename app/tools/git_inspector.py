from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from app.security.permissions import is_authorized_path
from app.security.sensitive_data import redact_text

MAX_GIT_OUTPUT_CHARS = 12000
MAX_CHANGED_FILES = 100
MAX_RECENT_COMMITS = 10
MAX_DIFF_CHARS = 4000
GIT_TIMEOUT_SECONDS = 10
RESTRICTED_PARTS = {".env", ".git", ".venv", "__pycache__", "node_modules"}


def _bounded(value: str, limit: int, *, redact: bool = True) -> tuple[str, bool]:
    redacted = redact_text(value or "") if redact else (value or "")
    if len(redacted) <= limit:
        return redacted, False
    return redacted[:limit] + "\n... [TRUNCATED]", True


def _safe_path(value: str) -> str | None:
    path = value.strip().replace("\\", "/")
    parts = Path(path).parts
    lowered_parts = {part.lower() for part in parts}
    lowered_name = Path(path).name.lower()
    if lowered_parts & RESTRICTED_PARTS:
        return None
    if lowered_name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}:
        return None
    if any(marker in lowered_name for marker in (".pem", ".key", "credentials", "secret")):
        return None
    return redact_text(path)


def _run_git(
    root: Path,
    arguments: list[str],
    timeout: int,
    *,
    redact_output: bool = True,
) -> tuple[str, str, bool]:
    result = subprocess.run(
        ["git", *arguments],
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
        check=False,
    )
    stdout, stdout_truncated = _bounded(
        result.stdout or "", MAX_GIT_OUTPUT_CHARS, redact=redact_output
    )
    stderr, stderr_truncated = _bounded(
        result.stderr or "", MAX_GIT_OUTPUT_CHARS, redact=redact_output
    )
    return stdout, stderr, stdout_truncated or stderr_truncated


def _failure(root: Path, message: str, *, timeout: bool = False) -> dict[str, Any]:
    bounded, truncated = _bounded(message, MAX_GIT_OUTPUT_CHARS)
    return {
        "source": "git",
        "repository": str(root),
        "is_git_repository": False,
        "branch": "",
        "status": "TIMEOUT" if timeout else "UNAVAILABLE",
        "changed_files": [],
        "staged_files": [],
        "unstaged_files": [],
        "untracked_files": [],
        "recent_commits": [],
        "diff_summary": "",
        "error": bounded,
        "truncated": truncated,
    }


def inspect_git_repository(workspace_path: str, timeout_seconds: int = GIT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Collect bounded, read-only Git evidence for the authorized workspace."""

    root = Path(workspace_path).resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("Authorized workspace does not exist or is not a directory.")
    if root.name.lower() in RESTRICTED_PARTS:
        raise ValueError("Git inspection is not allowed inside a restricted directory.")
    if not is_authorized_path(str(root), root):
        raise ValueError("Requested workspace is outside the authorized workspace.")

    timeout = max(1, min(int(timeout_seconds), GIT_TIMEOUT_SECONDS))
    try:
        top_level, error, truncated = _run_git(root, ["rev-parse", "--show-toplevel"], timeout)
    except subprocess.TimeoutExpired:
        return _failure(root, "Git repository detection timed out.", timeout=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return _failure(root, f"Git repository detection failed: {exc}")

    if not top_level.strip() or error.strip():
        return _failure(root, "The authorized workspace is not a Git repository.")

    try:
        repository_root = Path(top_level.strip().splitlines()[0]).resolve()
        repository_root.relative_to(root)
        root.relative_to(repository_root)
    except (ValueError, OSError):
        raise ValueError("Git repository is outside the authorized workspace.")

    result: dict[str, Any] = {
        "source": "git",
        "repository": str(repository_root),
        "is_git_repository": True,
        "branch": "",
        "status": "UNKNOWN",
        "changed_files": [],
        "staged_files": [],
        "unstaged_files": [],
        "untracked_files": [],
        "recent_commits": [],
        "diff_summary": "",
        "truncated": truncated,
    }

    try:
        branch, branch_error, branch_truncated = _run_git(root, ["branch", "--show-current"], timeout)
        porcelain, status_error, status_truncated = _run_git(root, ["status", "--porcelain=v1", "-uall"], timeout)
        diff_stat, diff_error, diff_truncated = _run_git(root, ["diff", "--stat"], timeout)
        recent, log_error, log_truncated = _run_git(
            root,
            ["log", f"-{MAX_RECENT_COMMITS}", "--date=iso", "--pretty=format:%H%x09%ad%x09%s"],
            timeout,
            redact_output=False,
        )
    except subprocess.TimeoutExpired:
        return _failure(root, "Git inspection timed out.", timeout=True)
    except (OSError, subprocess.SubprocessError) as exc:
        return _failure(root, f"Git inspection failed: {exc}")

    result["truncated"] = any((branch_truncated, status_truncated, diff_truncated, log_truncated))
    result["branch"] = redact_text(branch.strip())
    result["status"] = "CHANGED" if porcelain.strip() else "CLEAN"

    changed: list[str] = []
    staged: list[str] = []
    unstaged: list[str] = []
    untracked: list[str] = []
    files_truncated = False
    for line in porcelain.splitlines():
        if len(line) < 3:
            continue
        code, path_text = line[:2], line[3:]
        path = _safe_path(path_text.split(" -> ")[-1])
        if not path:
            continue
        if path not in changed:
            if len(changed) < MAX_CHANGED_FILES:
                changed.append(path)
            else:
                files_truncated = True
        if code == "??":
            if len(untracked) < MAX_CHANGED_FILES:
                untracked.append(path)
            else:
                files_truncated = True
            continue
        if code[0] != " " and len(staged) < MAX_CHANGED_FILES:
            staged.append(path)
        elif code[0] != " ":
            files_truncated = True
        if code[1] != " " and len(unstaged) < MAX_CHANGED_FILES:
            unstaged.append(path)
        elif code[1] != " ":
            files_truncated = True

    result["changed_files"] = changed
    result["staged_files"] = staged
    result["unstaged_files"] = unstaged
    result["untracked_files"] = untracked
    result["diff_summary"], diff_summary_truncated = _bounded(diff_stat, MAX_DIFF_CHARS)
    result["truncated"] = result["truncated"] or diff_summary_truncated or files_truncated

    commits: list[dict[str, str]] = []
    for line in recent.splitlines()[:MAX_RECENT_COMMITS]:
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        commit_id, date, subject = (redact_text(part) for part in parts)
        commits.append({"id": commit_id, "date": date, "subject": subject})
    result["recent_commits"] = commits

    errors = "\n".join(error for error in (branch_error, status_error, diff_error, log_error) if error.strip())
    if errors:
        result["error"], error_truncated = _bounded(errors, MAX_GIT_OUTPUT_CHARS)
        result["truncated"] = result["truncated"] or error_truncated
    return result


inspect_git = inspect_git_repository
