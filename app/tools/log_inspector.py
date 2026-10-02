from __future__ import annotations

from pathlib import Path

from app.security.permissions import is_authorized_path
from app.security.sensitive_data import redact_text

MAX_LOG_CHARS = 20000
ALLOWED_LOG_EXTENSIONS = {".log", ".txt", ".out", ".err"}
IGNORED_DIRECTORIES = {".env", ".git", ".venv", "__pycache__", "node_modules"}


def inspect_log_file(workspace_path: str, log_path: str, max_chars: int = MAX_LOG_CHARS) -> dict[str, object]:
    """Read a bounded, read-only log file inside the authorized workspace."""

    root = Path(workspace_path).resolve()
    target = Path(log_path)

    if not target.is_absolute():
        resolved = (root / target).resolve()
    else:
        resolved = target.resolve()

    if not is_authorized_path(str(resolved), root):
        raise ValueError("Requested log path is outside the authorized workspace.")

    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Requested log path is outside the authorized workspace.") from exc

    if any(part in IGNORED_DIRECTORIES for part in relative.parts):
        raise ValueError("Requested log file is inside a restricted directory.")

    if resolved.suffix.lower() not in ALLOWED_LOG_EXTENSIONS:
        raise ValueError("Requested log type is not an allowed log file.")

    if not resolved.exists() or not resolved.is_file():
        raise ValueError("Requested log file does not exist.")

    content = resolved.read_text(encoding="utf-8", errors="replace")
    truncated = len(content) > max_chars
    bounded = redact_text(content[:max_chars])
    if truncated:
        bounded = bounded + "\n... [TRUNCATED]"

    return {
        "source": "log",
        "path": str(relative).replace("\\", "/"),
        "content": bounded,
        "truncated": truncated,
        "max_chars": max_chars,
    }
