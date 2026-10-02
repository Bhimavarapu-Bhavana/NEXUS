from __future__ import annotations

import ctypes
from typing import Any, Callable

from app.security.audit_logger import record_audit_event
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.tools.desktop_observer import (
    AUTHORIZED_APPLICATIONS,
    _resolve_authorized_window,
)
from app.agent.capability_context import validate_capability_context, context_is_fresh

MAX_DESKTOP_ACTIONS = 1
SUPPORTED_ACTIONS = frozenset({
    "FOCUS_AUTHORIZED_WINDOW",
    "MINIMIZE_AUTHORIZED_WINDOW",
    "RESTORE_AUTHORIZED_WINDOW",
})
_FORBIDDEN_FIELDS = frozenset({
    "coordinates", "x", "y", "keys", "keyboard", "command", "api", "handle", "hwnd",
})


def _audit(event_type: str, **payload: Any) -> bool:
    return record_audit_event(event_type, **payload)


def _decision(action_type: str) -> dict[str, Any]:
    return evaluate_risk(
        f"desktop {action_type.lower()}",
        tool_name="desktop_" + action_type.lower(),
    )


def _blocked(reason: str, risk_decision: dict[str, Any] | None = None) -> dict[str, Any]:
    return redact_sensitive_data({
        "source": "desktop_action",
        "status": "BLOCKED",
        "risk_decision": risk_decision or {
            "risk_level": BLOCKED,
            "allowed": False,
            "approval_required": False,
            "reason": reason,
            "category": "DESKTOP_ACTION",
        },
        "action_result": reason,
        "verification": "NOT_RUN",
        "approved": False,
    })


def _validate_action(action: Any, observation: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(action, dict):
        raise ValueError("Malformed desktop action.")
    if set(action) & _FORBIDDEN_FIELDS:
        raise ValueError("Arbitrary desktop control fields are not allowed.")
    action_type = action.get("action_type")
    if action_type not in SUPPORTED_ACTIONS:
        raise ValueError("Unsupported desktop action.")
    application = str(action.get("application") or "").strip().lower()
    title = str(action.get("window_title") or "").strip()
    if not application or not title:
        raise ValueError("Desktop action requires an application and window title.")
    if application not in AUTHORIZED_APPLICATIONS:
        raise ValueError("Application is not authorized for desktop actions.")
    if not isinstance(observation, dict) or observation.get("status") != "OK":
        raise ValueError("Desktop action requires a successful prior observation.")
    windows = observation.get("windows")
    if not isinstance(windows, list):
        raise ValueError("Observation does not contain window records.")
    matches = [
        window for window in windows
        if isinstance(window, dict)
        and str(window.get("process_name", "")).lower() == application
        and window.get("title") == title
    ]
    if len(matches) != 1:
        raise ValueError("Desktop action target is not grounded in the prior observation.")
    observed_window = matches[0]
    if "_hwnd" in observed_window or "handle" in observed_window:
        raise ValueError("Window handles cannot be supplied as action authority.")
    return action, observed_window


def _native_execute(action_type: str, hwnd: int) -> None:
    if action_type == "FOCUS_AUTHORIZED_WINDOW":
        if not ctypes.windll.user32.SetForegroundWindow(hwnd):
            raise OSError("Unable to focus authorized window.")
        return
    if action_type == "MINIMIZE_AUTHORIZED_WINDOW":
        if not ctypes.windll.user32.ShowWindow(hwnd, 6):
            raise OSError("Unable to minimize authorized window.")
        return
    if action_type == "RESTORE_AUTHORIZED_WINDOW":
        if not ctypes.windll.user32.ShowWindow(hwnd, 9):
            raise OSError("Unable to restore authorized window.")
        return
    raise ValueError("Unsupported desktop action.")


def _native_verify(action_type: str, hwnd: int) -> bool:
    user32 = ctypes.windll.user32
    if action_type == "FOCUS_AUTHORIZED_WINDOW":
        return int(user32.GetForegroundWindow() or 0) == int(hwnd)
    if action_type == "MINIMIZE_AUTHORIZED_WINDOW":
        return bool(user32.IsIconic(hwnd))
    if action_type == "RESTORE_AUTHORIZED_WINDOW":
        return not bool(user32.IsIconic(hwnd))
    return False


def _perform_desktop_action(
    action: dict[str, Any],
    observation: dict[str, Any],
    *,
    approved: bool = False,
    action_count: int = 0,
    resolver: Callable[[str, str], dict[str, Any] | None] | None = None,
    executor: Callable[[str, int], None] | None = None,
    verifier: Callable[[str, int], bool] | None = None,
    capability_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Perform one explicitly allowlisted action against an observed window."""

    action_type = action.get("action_type", "") if isinstance(action, dict) else ""
    target = redact_text(action.get("window_title", "")) if isinstance(action, dict) else ""
    if not _audit("desktop_action_proposed", actor="nexus", tool="desktop_actions", target=target, result="Desktop action proposed."):
        return _blocked("Audit persistence failed before desktop action validation.")

    try:
        safe_context = validate_capability_context(capability_context) if capability_context is not None else None
        if safe_context is not None and safe_context.get("application_id") != "desktop":
            raise ValueError("The capability context is not a desktop context.")
        if safe_context is not None and not context_is_fresh(safe_context):
            raise ValueError("The desktop capability context is stale.")
        validated_action, observed_window = _validate_action(action, observation)
    except (TypeError, ValueError) as exc:
        reason = redact_text(str(exc))
        _audit("desktop_action_rejected", actor="risk_engine", tool="desktop_actions", risk_level=BLOCKED, approved=False, target=target, result="Rejected", reason=reason)
        return _blocked(reason)

    risk_decision = _decision(validated_action["action_type"])
    _audit(
        "desktop_action_risk_evaluated",
        actor="risk_engine",
        tool="desktop_actions",
        risk_level=risk_decision["risk_level"],
        approval_required=risk_decision["approval_required"],
        approved=False,
        target=target,
        result=str(risk_decision["allowed"]),
        reason=risk_decision["reason"],
    )
    if not risk_decision["allowed"] or risk_decision["risk_level"] == BLOCKED:
        return _blocked(risk_decision["reason"], risk_decision)
    if action_count >= MAX_DESKTOP_ACTIONS:
        return _blocked("Desktop action count limit reached.", risk_decision)
    if not approved:
        _audit("desktop_action_approval_required", actor="nexus", tool="desktop_actions", risk_level=risk_decision["risk_level"], approval_required=True, approved=False, target=target, result="Approval required.")
        return redact_sensitive_data({
            "source": "desktop_action",
            "status": "APPROVAL_REQUIRED",
            "risk_decision": risk_decision,
            "approved": False,
            "verification": "NOT_RUN",
        })

    if not _audit("desktop_action_approved", actor="human", tool="desktop_actions", risk_level=risk_decision["risk_level"], approval_required=True, approved=True, target=target, result="Approval granted."):
        return _blocked("Audit persistence failed after approval.", risk_decision)

    resolve = resolver or (
        lambda application, title: _resolve_authorized_window(
            application, title, allowed_applications=AUTHORIZED_APPLICATIONS
        )
    )
    current_window = resolve(validated_action["application"], validated_action["window_title"])
    if safe_context is not None:
        observed_context_task = str(observation.get("task_id") or "")
        observed_context_subgoal = str(observation.get("subgoal_id") or "")
        if observed_context_task and observed_context_task != safe_context.get("task_id"):
            return _blocked("Desktop observation belongs to a different task.", risk_decision)
        if observed_context_subgoal and observed_context_subgoal != safe_context.get("subgoal_id"):
            return _blocked("Desktop observation belongs to a different subgoal.", risk_decision)
    if not current_window or current_window.get("title") != observed_window.get("title") or current_window.get("process_name", "").lower() != observed_window.get("process_name", "").lower() or current_window.get("process_id") != observed_window.get("process_id"):
        _audit("desktop_action_revalidated", actor="risk_engine", tool="desktop_actions", risk_level=BLOCKED, approved=False, target=target, result="Failed", reason="Target changed, disappeared, or is no longer grounded.")
        return _blocked("Stale or changed desktop observation.", risk_decision)
    hwnd = current_window.get("_hwnd")
    if not isinstance(hwnd, int) or hwnd <= 0:
        return _blocked("Authorized window handle was not resolved.", risk_decision)
    if not _audit("desktop_action_revalidated", actor="risk_engine", tool="desktop_actions", risk_level=risk_decision["risk_level"], approved=True, target=target, result="Passed."):
        return _blocked("Audit persistence failed during revalidation.", risk_decision)

    try:
        (executor or _native_execute)(validated_action["action_type"], hwnd)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        reason = redact_text(str(exc))
        _audit("desktop_action_rejected", actor="nexus", tool="desktop_actions", risk_level=risk_decision["risk_level"], approved=True, target=target, result="Execution failed", reason=reason)
        return redact_sensitive_data({"source": "desktop_action", "status": "EXECUTION_FAILED", "risk_decision": risk_decision, "verification": "NOT_RUN", "action_result": reason})

    _audit("desktop_action_executed", actor="nexus", tool="desktop_actions", risk_level=risk_decision["risk_level"], approval_required=True, approved=True, target=target, result="Action executed.")
    verified = bool((verifier or _native_verify)(validated_action["action_type"], hwnd))
    verification = "SUCCESS" if verified else "FAILED"
    _audit("desktop_action_verification", actor="nexus", tool="desktop_actions", risk_level=risk_decision["risk_level"], approved=True, target=target, result=verification)
    return redact_sensitive_data({
        "source": "desktop_action",
        "status": "COMPLETED" if verified else "VERIFICATION_FAILED",
        "risk_decision": risk_decision,
        "approved": True,
        "target": {"application": validated_action["application"], "window_title": validated_action["window_title"]},
        "verification": verification,
        "retry_allowed": False,
    })


def focus_authorized_window(action: dict[str, Any], observation: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    action = dict(action)
    action["action_type"] = "FOCUS_AUTHORIZED_WINDOW"
    return _perform_desktop_action(action, observation, **kwargs)


def minimize_authorized_window(action: dict[str, Any], observation: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    action = dict(action)
    action["action_type"] = "MINIMIZE_AUTHORIZED_WINDOW"
    return _perform_desktop_action(action, observation, **kwargs)


def restore_authorized_window(action: dict[str, Any], observation: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    action = dict(action)
    action["action_type"] = "RESTORE_AUTHORIZED_WINDOW"
    return _perform_desktop_action(action, observation, **kwargs)
