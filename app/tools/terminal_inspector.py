import re
from typing import Any

from app.security.sensitive_data import redact_text
from app.security.permissions import is_authorized_path

MAX_OUTPUT_CHARS = 12000


def _sanitize_output(value: str) -> str:
    text = str(value or "")
    return redact_text(text)


def analyze_terminal_output(output: str, max_chars: int = MAX_OUTPUT_CHARS) -> dict[str, Any]:
    """Parse terminal output into bounded, redacted evidence."""

    raw_text = str(output or "")
    sanitized = _sanitize_output(raw_text)
    stdout = sanitized
    stderr = ""
    exit_code = 0
    status = "SUCCESS"

    match = re.search(r"(?:exit(?:ed)? with code|return code)\s+(\d+)", sanitized, flags=re.IGNORECASE)
    if match:
        exit_code = int(match.group(1))

    lowered = sanitized.lower()
    if "traceback" in lowered or "error" in lowered or "exception" in lowered or "failed" in lowered:
        status = "ERROR"
        stderr = sanitized
        stdout = ""
    elif "timeout" in lowered:
        status = "TIMEOUT"
        stderr = sanitized
        stdout = ""

    if not stdout and not stderr:
        stdout = sanitized

    if len(stdout) > max_chars:
        stdout = stdout[:max_chars] + "\n... [TRUNCATED]"
        truncated = True
    else:
        truncated = False

    if len(stderr) > max_chars:
        stderr = stderr[:max_chars] + "\n... [TRUNCATED]"
        truncated = True

    summary = "UNTRUSTED TERMINAL EVIDENCE"
    if "traceback" in lowered or "exception" in lowered or "error" in lowered:
        summary = "Runtime evidence indicates an error condition."
    elif "timeout" in lowered:
        summary = "Runtime evidence indicates a timeout."
    elif sanitized.strip():
        summary = "Terminal output was captured without a clear error signal."

    if "ignore previous instructions" in lowered or "rm -rf" in lowered:
        summary = "UNTRUSTED TERMINAL EVIDENCE"

    return {
        "source": "terminal",
        "status": status,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "summary": summary,
        "truncated": truncated,
    }
