from __future__ import annotations

import inspect
from typing import Any, Callable

from app.security.audit_logger import record_audit_event
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.tools.browser_observer import MAX_REDIRECTS, validate_browser_url, observe_browser_page

MAX_BROWSER_ACTIONS = 3
ACTION_TIMEOUT_SECONDS = 10
ALLOWED_ACTION_TYPES = {"navigate_observed", "follow_observed_link"}
_BLOCKED_ELEMENT_TERMS = (
    "password",
    "credential",
    "token",
    "api key",
    "private key",
    "payment",
    "card number",
    "security code",
    "otp",
    "one-time code",
)


def _audit(event_type: str, **payload: Any) -> bool:
    return record_audit_event(event_type, **payload)


def _blocked(reason: str, *, risk_decision: dict[str, Any] | None = None) -> dict[str, Any]:
    decision = risk_decision or {
        "risk_level": BLOCKED,
        "allowed": False,
        "approval_required": False,
        "reason": reason,
        "category": "BROWSER_ACTION",
    }
    return redact_sensitive_data({
        "source": "browser_action",
        "status": "BLOCKED",
        "risk_decision": decision,
        "approved": False,
        "action_result": reason,
        "verification": "NOT_RUN",
    })


def _validate_structured_action(
    action: dict[str, Any],
    observed_page: dict[str, Any],
    expected_type: str,
) -> tuple[str, str]:
    if not isinstance(action, dict):
        raise ValueError("Browser actions must be structured mappings.")
    if action.get("action_type") != expected_type:
        raise ValueError("Unknown or mismatched browser action type.")
    if not isinstance(observed_page, dict) or observed_page.get("status") != "OK":
        raise ValueError("Browser action requires a successful observed page state.")
    if action.get("requested_value"):
        raise ValueError("Typing and value injection are not supported in this phase.")

    identifier = str(action.get("element_identifier") or "").strip().lower()
    if any(term in identifier for term in _BLOCKED_ELEMENT_TERMS):
        raise ValueError("Credential and payment-related browser targets are blocked.")

    observed_target = validate_browser_url(str(action.get("observed_target") or ""))
    page_targets = {
        validate_browser_url(str(observed_page.get("url") or "")),
        validate_browser_url(str(observed_page.get("final_url") or observed_page.get("url") or "")),
    }
    if observed_target not in page_targets:
        raise ValueError("Action is not grounded in the supplied observed page.")

    target_url = validate_browser_url(str(action.get("target_url") or ""))
    if expected_type == "navigate_observed" and target_url not in page_targets:
        raise ValueError("Navigation target was not present in the observed page state.")

    if expected_type == "follow_observed_link":
        links = observed_page.get("links")
        if not isinstance(links, list):
            raise ValueError("Observed page has no structured links to follow.")
        matching = [
            link for link in links
            if isinstance(link, dict) and link.get("url") == target_url
        ]
        if not matching or identifier not in {target_url.lower(), "link:" + str(links.index(matching[0]))}:
            raise ValueError("The requested link was not present in the observed page state.")

    return observed_target, target_url


def _execute_grounded_action(
    action: dict[str, Any],
    observed_page: dict[str, Any],
    expected_type: str,
    *,
    approved: bool,
    action_count: int,
    observer: Callable[[str], dict[str, Any]] | None,
    revalidator: Callable[[], dict[str, Any]] | None,
) -> dict[str, Any]:
    target_hint = redact_text(action.get("target_url", "")) if isinstance(action, dict) else ""
    if not _audit("browser_action_proposed", actor="nexus", tool=expected_type, target=target_hint, result="Structured action proposed."):
        return _blocked("Audit persistence failed before browser action validation.")

    try:
        observed_target, target_url = _validate_structured_action(action, observed_page, expected_type)
    except (TypeError, ValueError) as exc:
        reason = redact_text(str(exc))
        _audit("browser_action_blocked", actor="risk_engine", tool=expected_type, risk_level=BLOCKED, target=target_hint, result="Blocked", reason=reason)
        return _blocked(reason)

    risk_decision = evaluate_risk(
        f"browser {expected_type}",
        tool_name="browser_" + expected_type,
        target_path=None,
    )
    _audit(
        "browser_action_risk_decision",
        actor="risk_engine",
        tool=expected_type,
        risk_level=risk_decision["risk_level"],
        approval_required=risk_decision["approval_required"],
        approved=False,
        target=target_url,
        result=str(risk_decision["allowed"]),
        reason=risk_decision["reason"],
    )
    if not risk_decision["allowed"] or risk_decision["risk_level"] == BLOCKED:
        _audit("browser_action_blocked", actor="risk_engine", tool=expected_type, risk_level=BLOCKED, target=target_url, result="Blocked", reason=risk_decision["reason"])
        return _blocked(risk_decision["reason"], risk_decision=risk_decision)

    if not approved:
        _audit("browser_action_approval_requested", actor="nexus", tool=expected_type, risk_level=risk_decision["risk_level"], approval_required=True, approved=False, target=target_url, result="Approval required.")
        return redact_sensitive_data({
            "source": "browser_action",
            "status": "APPROVAL_REQUIRED",
            "risk_decision": risk_decision,
            "approved": False,
            "target_url": target_url,
            "verification": "NOT_RUN",
        })

    if action_count >= MAX_BROWSER_ACTIONS:
        return _blocked("Browser action count limit reached.", risk_decision=risk_decision)

    if not _audit("browser_action_approval_granted", actor="human", tool=expected_type, risk_level=risk_decision["risk_level"], approval_required=True, approved=True, target=target_url, result="Approval granted."):
        return _blocked("Audit persistence failed after approval.", risk_decision=risk_decision)

    try:
        current_page = revalidator() if revalidator is not None else observed_page
        revalidated_observed, revalidated_target = _validate_structured_action(action, current_page, expected_type)
        if revalidated_observed != observed_target or revalidated_target != target_url:
            raise ValueError("Observed browser state changed before execution.")
    except (TypeError, ValueError) as exc:
        reason = redact_text(str(exc))
        _audit("browser_action_revalidation", actor="risk_engine", tool=expected_type, risk_level=BLOCKED, approved=False, target=target_url, result="Failed", reason=reason)
        return _blocked(reason, risk_decision=risk_decision)

    _audit("browser_action_revalidation", actor="risk_engine", tool=expected_type, risk_level=risk_decision["risk_level"], approved=True, target=target_url, result="Passed.", metadata={"max_redirects": MAX_REDIRECTS})
    if not _audit("browser_action_execution", actor="nexus", tool=expected_type, risk_level=risk_decision["risk_level"], approval_required=True, approved=True, target=target_url, result="GET observation action started."):
        return _blocked("Audit persistence failed before browser action execution.", risk_decision=risk_decision)

    observer_fn = observer or observe_browser_page
    parameters = inspect.signature(observer_fn).parameters
    if "timeout_seconds" in parameters or any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()):
        result = observer_fn(target_url, timeout_seconds=ACTION_TIMEOUT_SECONDS)
    else:
        result = observer_fn(target_url)
    safe_result = redact_sensitive_data(result)
    _audit("browser_action_result", actor="nexus", tool=expected_type, risk_level=risk_decision["risk_level"], approved=True, target=target_url, result=safe_result.get("status", "ERROR"), reason=safe_result.get("error", ""))
    _audit("browser_post_action_observation", actor="nexus", tool="browser_observer", risk_level="READ_ONLY", target=target_url, result=safe_result.get("status", "ERROR"))

    verification = "SUCCESS" if safe_result.get("status") == "OK" and safe_result.get("final_url") else "UNCERTAIN"
    _audit("browser_action_verification", actor="nexus", tool=expected_type, risk_level=risk_decision["risk_level"], approved=True, target=target_url, result=verification)
    return redact_sensitive_data({
        "source": "browser_action",
        "status": "COMPLETED" if verification == "SUCCESS" else "UNCERTAIN",
        "risk_decision": risk_decision,
        "approved": True,
        "observed_target": observed_target,
        "target_url": target_url,
        "action_result": safe_result,
        "post_action_observation": safe_result,
        "verification": verification,
        "retry_allowed": False,
    })


def navigate_observed_page(
    action: dict[str, Any],
    observed_page: dict[str, Any],
    *,
    approved: bool = False,
    action_count: int = 0,
    observer: Callable[[str], dict[str, Any]] | None = None,
    revalidator: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return _execute_grounded_action(action, observed_page, "navigate_observed", approved=approved, action_count=action_count, observer=observer, revalidator=revalidator)


def follow_observed_link(
    action: dict[str, Any],
    observed_page: dict[str, Any],
    *,
    approved: bool = False,
    action_count: int = 0,
    observer: Callable[[str], dict[str, Any]] | None = None,
    revalidator: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return _execute_grounded_action(action, observed_page, "follow_observed_link", approved=approved, action_count=action_count, observer=observer, revalidator=revalidator)
