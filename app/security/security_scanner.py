from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.memory.sqlite_memory import DEFAULT_DB_PATH
from app.security.audit_logger import record_audit_event
from app.security.permissions import get_authorized_workspace, is_authorized_path
from app.security.sensitive_data import redact_sensitive_data, redact_text

SCANNER_NAME = "windows_defender"
SCANNER_EXECUTABLE = "powershell.exe"
SCAN_TIMEOUT_SECONDS = 30
MAX_OUTPUT_CHARS = 12000
MAX_FINDINGS = 20
MAX_TARGET_FILES = 1000
MAX_TARGET_BYTES = 50 * 1024 * 1024
RESTRICTED_PARTS = {".env", ".git", ".venv", "__pycache__", "node_modules"}
RESTRICTED_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials", "credentials.json",
}

# This is fixed application code. The target is supplied only as PowerShell's
# positional argument and is never interpolated into the script.
_FIXED_DEFENDER_SCRIPT = (
    "$ErrorActionPreference='Stop'; "
    "Start-MpScan -ScanType CustomScan -ScanPath $env:NEXUS_SCAN_PATH; "
    "$threats=@(Get-MpThreatDetection); "
    "if($threats.Count -gt 0) { "
    "$payload=@{status='THREAT_DETECTED'; findings=@($threats | Select-Object -First 20 ThreatID,ThreatName,SeverityID,Resources)} "
    "} else { $payload=@{status='CLEAN'; findings=@()} }; "
    "$payload | ConvertTo-Json -Compress -Depth 5"
)


def _audit(event_type: str, **payload: Any) -> bool:
    return record_audit_event(event_type, **payload)


def _result(
    status: str,
    target: str,
    *,
    target_type: str = "",
    findings: list[dict[str, Any]] | None = None,
    raw_status: str = "",
    error: str = "",
    timed_out: bool = False,
    truncated: bool = False,
) -> dict[str, Any]:
    return redact_sensitive_data({
        "scanner": SCANNER_NAME,
        "status": status,
        "target": redact_text(target),
        "target_type": target_type,
        "threat_detected": status == "THREAT_DETECTED",
        "severity": "high" if status == "THREAT_DETECTED" else "none",
        "findings": (findings or [])[:MAX_FINDINGS],
        "raw_status": redact_text(raw_status)[:200],
        "error": redact_text(error)[:1000],
        "timed_out": timed_out,
        "truncated": truncated,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })


def _invalid(status: str, target: str, reason: str, target_type: str = "") -> dict[str, Any]:
    _audit("security_scan_failed", actor="security_scanner", tool="security_scan", target=target, result=status, reason=reason)
    return _result(status, target, target_type=target_type, error=reason)


def _validate_target(target: str | Path, workspace_root: str | Path | None) -> tuple[Path | None, str, str]:
    root = Path(workspace_root).resolve() if workspace_root is not None else Path(get_authorized_workspace()).resolve()
    candidate = Path(str(target))
    if candidate.is_absolute() and (str(candidate).startswith("\\\\") or candidate.drive and candidate.drive != root.drive):
        return None, "", "Network and cross-volume targets are not authorized."
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    if not is_authorized_path(str(resolved), root):
        return None, "", "Target is outside the authorized workspace."
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return None, "", "Target is outside the authorized workspace."
    parts = {part.lower() for part in relative.parts}
    if parts & RESTRICTED_PARTS or resolved.name.lower() in RESTRICTED_NAMES:
        return None, "", "Target is inside a restricted or credential-sensitive path."
    if not resolved.exists():
        return None, "", "Target does not exist."
    if not resolved.is_file() and not resolved.is_dir():
        return None, "", "Target type is unsupported."
    target_type = "file" if resolved.is_file() else "directory"
    if resolved.is_file() and resolved.stat().st_size > MAX_TARGET_BYTES:
        return None, target_type, "Target exceeds the scan size limit."
    if resolved.is_dir():
        file_count = 0
        total_bytes = 0
        for current_root, directories, files in os.walk(resolved, followlinks=False):
            directories[:] = [name for name in directories if name.lower() not in RESTRICTED_PARTS]
            for name in files:
                file_path = Path(current_root) / name
                if name.lower() in RESTRICTED_NAMES or any(part.lower() in RESTRICTED_PARTS for part in file_path.relative_to(root).parts):
                    continue
                file_count += 1
                try:
                    total_bytes += file_path.stat().st_size
                except OSError:
                    return None, target_type, "Target could not be safely inspected."
                if file_count > MAX_TARGET_FILES or total_bytes > MAX_TARGET_BYTES:
                    return None, target_type, "Target exceeds the bounded scan scope."
    return resolved, target_type, ""


def _parse_output(stdout: str, target: str, target_type: str, truncated: bool) -> dict[str, Any]:
    bounded = redact_text(stdout[:MAX_OUTPUT_CHARS])
    try:
        payload = json.loads(bounded)
    except (json.JSONDecodeError, TypeError):
        return _result("SCAN_ERROR", target, target_type=target_type, raw_status=bounded, error="Scanner returned an unrecognized result.", truncated=truncated)
    if not isinstance(payload, dict):
        return _result("SCAN_ERROR", target, target_type=target_type, error="Scanner returned an invalid result object.", truncated=truncated)
    raw_status = str(payload.get("status", "")).upper()
    if raw_status == "CLEAN":
        return _result("CLEAN", target, target_type=target_type, raw_status=raw_status, truncated=truncated)
    if raw_status in {"THREAT", "THREAT_DETECTED"}:
        raw_findings = payload.get("findings", [])
        findings = [redact_sensitive_data(item) for item in raw_findings[:MAX_FINDINGS]] if isinstance(raw_findings, list) else []
        return _result("THREAT_DETECTED", target, target_type=target_type, findings=findings, raw_status=raw_status, truncated=truncated or len(raw_findings) > MAX_FINDINGS if isinstance(raw_findings, list) else truncated)
    return _result("SCAN_ERROR", target, target_type=target_type, raw_status=raw_status, error="Scanner returned an unknown status.", truncated=truncated)


def scan_target(
    target: str | Path,
    *,
    workspace_root: str | Path | None = None,
    timeout_seconds: int = SCAN_TIMEOUT_SECONDS,
    runner: Any | None = None,
) -> dict[str, Any]:
    """Run one fixed local Defender scan against an authorized bounded target."""

    target_text = redact_text(target)
    if not _audit("security_scan_requested", actor="nexus", tool="security_scan", target=target_text, result="Scan requested."):
        return _result("SCAN_ERROR", target_text, error="Audit persistence failed before scanning.")
    resolved, target_type, reason = _validate_target(target, workspace_root)
    if resolved is None:
        return _invalid("INVALID_TARGET" if "outside" not in reason.lower() and "restricted" not in reason.lower() else "ACCESS_DENIED", target_text, reason, target_type)
    executable = shutil.which(SCANNER_EXECUTABLE)
    if not executable:
        _audit("security_scan_unavailable", actor="security_scanner", tool="security_scan", target=target_text, result="SCANNER_UNAVAILABLE", reason="Windows PowerShell executable is unavailable.")
        return _result("SCANNER_UNAVAILABLE", target_text, target_type=target_type, error="Windows Defender scanner adapter is unavailable.")
    if not _audit("security_scan_authorized", actor="risk_engine", tool="security_scan", risk_level="READ_ONLY", target=target_text, result="Authorized target."):
        return _result("SCAN_ERROR", target_text, target_type=target_type, error="Audit persistence failed during authorization.")
    if not _audit("security_scan_started", actor="security_scanner", tool="security_scan", risk_level="READ_ONLY", target=target_text, result="Scan started."):
        return _result("SCAN_ERROR", target_text, target_type=target_type, error="Audit persistence failed before scanner execution.")

    timeout = max(1, min(int(timeout_seconds), SCAN_TIMEOUT_SECONDS))
    command = [executable, "-NoProfile", "-NonInteractive", "-Command", _FIXED_DEFENDER_SCRIPT]
    try:
        execute = runner or subprocess.run
        environment = os.environ.copy()
        environment["NEXUS_SCAN_PATH"] = str(resolved)
        completed = execute(command, capture_output=True, text=True, timeout=timeout, shell=False, check=False, env=environment)
        stdout = str(getattr(completed, "stdout", "") or "")
        stderr = redact_text(getattr(completed, "stderr", "") or "")[:MAX_OUTPUT_CHARS]
        truncated = len(stdout) > MAX_OUTPUT_CHARS or len(stderr) >= MAX_OUTPUT_CHARS
        if getattr(completed, "returncode", 1) != 0:
            result = _result("SCAN_ERROR", target_text, target_type=target_type, raw_status=stderr, error="Scanner returned a non-zero status.", truncated=truncated)
        else:
            result = _parse_output(stdout, target_text, target_type, truncated)
    except FileNotFoundError:
        result = _result("SCANNER_UNAVAILABLE", target_text, target_type=target_type, error="Scanner executable is unavailable.")
    except subprocess.TimeoutExpired:
        result = _result("SCAN_TIMEOUT", target_text, target_type=target_type, error="Scanner exceeded the bounded timeout.", timed_out=True)
    except PermissionError:
        result = _result("ACCESS_DENIED", target_text, target_type=target_type, error="Scanner access was denied.")
    except (OSError, TypeError, ValueError) as exc:
        result = _result("SCAN_ERROR", target_text, target_type=target_type, error=str(exc))

    event = "security_scan_threat_detected" if result["status"] == "THREAT_DETECTED" else "security_scan_completed" if result["status"] == "CLEAN" else "security_scan_timeout" if result["status"] == "SCAN_TIMEOUT" else "security_scan_failed"
    if not _audit(event, actor="security_scanner", tool="security_scan", risk_level="READ_ONLY", target=target_text, result=result["status"], reason=result.get("error", ""), metadata={"finding_count": len(result.get("findings", [])), "truncated": result["truncated"]}):
        return _result("SCAN_ERROR", target_text, target_type=target_type, error="Audit persistence failed after scanning.")
    return redact_sensitive_data(result)
