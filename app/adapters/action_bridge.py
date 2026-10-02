from __future__ import annotations

from typing import Any

from app.adapters.application_context import validate_application_context
from app.adapters.jobs import fill_application, submit_application
from app.adapters.registry import ADAPTER_REGISTRY
from app.security.risk_engine import HIGH_RISK, MEDIUM_RISK

ADAPTER_ACTION_TYPES = ("job_application_fill_action", "job_application_submit_action")

_ACTION_TO_PROVIDER_ID = {
    "job_application_fill_action": "fixture_application",
    "job_application_submit_action": "fixture_application",
}

_ACTION_TO_OPERATION = {
    "job_application_fill_action": ("application", "APPLICATION_FILL", "fill"),
    "job_application_submit_action": ("application", "APPLICATION_SUBMIT", "submit"),
}

_ACTION_TO_RISK = {
    "job_application_fill_action": MEDIUM_RISK,
    "job_application_submit_action": HIGH_RISK,
}


def adapter_declared_risk(action_type: str) -> str:
    """Declared authorization risk for an adapter action from adapter metadata."""
    if action_type in _ACTION_TO_RISK:
        return _ACTION_TO_RISK[action_type]
    return "BLOCKED"


def _authorize_action(action_type: str, capability_context: dict[str, Any] | None) -> str:
    if action_type not in _ACTION_TO_OPERATION:
        raise PermissionError(f"Unknown adapter action {action_type!r}.")
    context = dict(capability_context or {})
    validate_application_context(context)
    application_id, capability_name, operation = _ACTION_TO_OPERATION[action_type]
    if str(context.get("application_id") or "").strip() != application_id:
        raise PermissionError(f"Capability context is not bound to application {application_id!r}.")
    provider_id = _ACTION_TO_PROVIDER_ID[action_type]
    provider = ADAPTER_REGISTRY.provider(provider_id)
    if provider is None:
        raise PermissionError(f"No authorized provider for {application_id!r}.")
    return provider_id


def execute_adapter_action(
    action_type: str,
    capability_context: dict[str, Any] | None,
    spec: dict[str, Any] | None,
    *,
    approved: bool,
) -> dict[str, Any]:
    """Dispatch an authorization-bound adapter action.

    This is the only sanctioned bridge for adapter actions: it fails closed
    when the capability application is not part of the supplied context."""
    _authorize_action(action_type, capability_context)
    payload = dict(spec or {})
    payload.setdefault("provider", ADAPTER_REGISTRY.provider(_ACTION_TO_PROVIDER_ID[action_type]).provider_id)
    payload.pop("workflow", None)
    if action_type == "job_application_fill_action":
        result = fill_application(payload, approved=approved, capability_context=capability_context)
    elif action_type == "job_application_submit_action":
        result = submit_application(payload, approved=approved, capability_context=capability_context)
    else:  # pragma: no cover - guarded upstream
        raise PermissionError(f"Unknown adapter action {action_type!r}.")
    result.setdefault("declared_risk", adapter_declared_risk(action_type))
    result.setdefault("verified", result.get("status") == "ok")
    if result.get("status") == "ok" and result.get("verified"):
        prior = str(result.get("verification") or "")
        if prior and prior != "SUCCESS":
            result.setdefault("verification_detail", prior)
        result["verification"] = "SUCCESS"
    return result


__all__ = ["ADAPTER_ACTION_TYPES", "adapter_declared_risk", "execute_adapter_action"]