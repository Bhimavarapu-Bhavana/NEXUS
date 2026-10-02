from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from datetime import datetime, timezone
from typing import Any, Callable

from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.agent.capability_context import validate_capability_context, context_is_fresh

MAX_WINDOWS = 50
MAX_TITLE_CHARS = 500
MAX_PROCESS_NAME_CHARS = 260
OBSERVATION_TIMEOUT_SECONDS = 2
AUTHORIZED_APPLICATIONS = frozenset({
    "code.exe",
    "powershell.exe",
    "windowsterminal.exe",
    "python.exe",
})


def _audit(event_type: str, **payload: Any) -> bool:
    return record_audit_event(event_type, **payload)


def _window_text(user32: Any, hwnd: int) -> str:
    length = user32.GetWindowTextLengthW(hwnd)
    if not length:
        return ""
    buffer = ctypes.create_unicode_buffer(min(length + 1, MAX_TITLE_CHARS + 1))
    user32.GetWindowTextW(hwnd, buffer, len(buffer))
    return buffer.value[:MAX_TITLE_CHARS]


def _window_bounds(user32: Any, hwnd: int) -> dict[str, int] | None:
    rectangle = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rectangle)):
        return None
    return {
        "left": int(rectangle.left),
        "top": int(rectangle.top),
        "right": int(rectangle.right),
        "bottom": int(rectangle.bottom),
        "width": max(0, int(rectangle.right - rectangle.left)),
        "height": max(0, int(rectangle.bottom - rectangle.top)),
    }


def _process_id(user32: Any, hwnd: int) -> int:
    process_id = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))
    return int(process_id.value)


def _process_name(process_id: int) -> str:
    # Process identity is best-effort metadata; no process is opened or controlled.
    if process_id == os.getpid():
        return os.path.basename(__file__)[:MAX_PROCESS_NAME_CHARS]
    return ""


def _authorized_process_name(process_id: int) -> str:
    if process_id == os.getpid():
        return os.path.basename("python.exe")
    if os.name != "nt":
        return ""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    process = kernel32.OpenProcess(0x1000, False, process_id)
    if not process:
        return ""
    try:
        buffer = ctypes.create_unicode_buffer(MAX_PROCESS_NAME_CHARS)
        size = wintypes.DWORD(len(buffer))
        if kernel32.QueryFullProcessImageNameW(process, 0, buffer, ctypes.byref(size)):
            return os.path.basename(buffer.value[:size.value]).lower()
        return ""
    finally:
        kernel32.CloseHandle(process)


def _collect_snapshot(
    allowed_applications: frozenset[str] = AUTHORIZED_APPLICATIONS,
    *,
    include_handles: bool = False,
) -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "UNSUPPORTED", "windows": [], "active_window": None}

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetForegroundWindow.restype = wintypes.HWND

    active_handle = int(user32.GetForegroundWindow() or 0)
    windows: list[dict[str, Any]] = []
    started = time.monotonic()

    @callback_type
    def callback(hwnd: int, _lparam: int) -> bool:
        if time.monotonic() - started >= OBSERVATION_TIMEOUT_SECONDS:
            return False
        if len(windows) >= MAX_WINDOWS:
            return False
        if not user32.IsWindowVisible(hwnd):
            return True
        title = _window_text(user32, hwnd)
        if not title.strip():
            return True
        process_id = _process_id(user32, hwnd)
        process_name = _authorized_process_name(process_id)
        if process_name not in allowed_applications:
            return True
        window = {
            "title": title,
            "process_id": process_id,
            "process_name": process_name,
            "bounds": _window_bounds(user32, hwnd),
            "is_foreground": int(hwnd) == active_handle,
        }
        if include_handles:
            window["_hwnd"] = int(hwnd)
        windows.append(window)
        return True

    user32.EnumWindows(callback, 0)
    active = next((window for window in windows if window["is_foreground"]), None)
    return {"status": "OK", "windows": windows, "active_window": active}


def _resolve_authorized_window(
    application: str,
    window_title: str,
    *,
    allowed_applications: frozenset[str] = AUTHORIZED_APPLICATIONS,
) -> dict[str, Any] | None:
    """Resolve an exact observed window internally without exposing its handle."""

    application_name = str(application or "").strip().lower()
    title = str(window_title or "").strip()
    if not application_name or not title or application_name not in allowed_applications:
        return None
    snapshot = _collect_snapshot(allowed_applications, include_handles=True)
    matches = [
        window for window in snapshot.get("windows", [])
        if window.get("process_name", "").lower() == application_name
        and window.get("title", "") == title
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def observe_desktop(
    *,
    collector: Callable[[], dict[str, Any]] | None = None,
    authorized_applications: frozenset[str] = AUTHORIZED_APPLICATIONS,
    capability_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return bounded, read-only visible desktop metadata."""

    if not _audit("desktop_observation_requested", actor="nexus", tool="desktop_observer", result="Desktop observation requested."):
        return {"source": "desktop", "status": "ERROR", "error": "Audit persistence failed before desktop observation."}

    if not _audit("desktop_observation_started", actor="nexus", tool="desktop_observer", risk_level="READ_ONLY", result="Desktop observation started."):
        return {"source": "desktop", "status": "ERROR", "error": "Audit persistence failed before desktop observation."}

    try:
        safe_context = validate_capability_context(capability_context) if capability_context is not None else None
        if safe_context is not None and safe_context.get("application_id") != "desktop":
            raise ValueError("The capability context is not a desktop context.")
        if safe_context is not None and not context_is_fresh(safe_context):
            raise ValueError("The desktop capability context is stale.")
        allowlist = frozenset(str(name).strip().lower() for name in authorized_applications)
        if not allowlist:
            _audit("desktop_observation_blocked", actor="risk_engine", tool="desktop_observer", risk_level="BLOCKED", approved=False, result="Blocked", reason="No authorized applications configured.")
            return {"source": "desktop", "status": "BLOCKED", "windows": [], "truncated": False}
        snapshot = collector() if collector is not None else _collect_snapshot(allowlist)
        windows = list(snapshot.get("windows", []))[:MAX_WINDOWS]
        authorized_windows = [
            window for window in windows
            if str(window.get("process_name", "")).lower() in allowlist
        ]
        if not _audit("desktop_observation_authorization", actor="risk_engine", tool="desktop_observer", risk_level="READ_ONLY", approved=False, result="Authorized application scope applied.", metadata={"authorized_window_count": len(authorized_windows)}):
            return {"source": "desktop", "status": "ERROR", "error": "Audit persistence failed during desktop authorization."}
        evidence = redact_sensitive_data({
            "source": "desktop",
            "status": snapshot.get("status", "OK"),
            "active_window": next((window for window in authorized_windows if window.get("is_foreground")), None),
            "windows": authorized_windows,
            "window_count": len(authorized_windows),
            "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "truncated": len(snapshot.get("windows", [])) > MAX_WINDOWS or len(authorized_windows) < len(windows),
            "task_id": safe_context.get("task_id", "") if safe_context else "",
            "subgoal_id": safe_context.get("subgoal_id", "") if safe_context else "",
            "context_id": safe_context.get("observation_id", "") if safe_context else "",
        })
        if not _audit("desktop_observation_completed", actor="nexus", tool="desktop_observer", risk_level="READ_ONLY", result=evidence["status"], metadata={"window_count": evidence["window_count"], "truncated": evidence["truncated"]}):
            return {"source": "desktop", "status": "ERROR", "error": "Audit persistence failed after desktop observation."}
        return evidence
    except (OSError, TimeoutError, ValueError) as exc:
        error = redact_text(str(exc))
        _audit("desktop_observation_failed", actor="nexus", tool="desktop_observer", risk_level="READ_ONLY", result="ERROR", reason=error)
        return {"source": "desktop", "status": "ERROR", "error": error, "windows": [], "truncated": False}


def observe_active_window(
    *,
    collector: Callable[[], dict[str, Any]] | None = None,
    authorized_applications: frozenset[str] = AUTHORIZED_APPLICATIONS,
    capability_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return only the currently foreground window from a desktop observation."""

    evidence = observe_desktop(collector=collector, authorized_applications=authorized_applications, capability_context=capability_context)
    active_window = evidence.get("active_window")
    return redact_sensitive_data({
        "source": "desktop",
        "status": evidence.get("status", "ERROR"),
        "active_window": active_window,
        "observed_at": evidence.get("observed_at", ""),
        "truncated": evidence.get("truncated", False),
    })
