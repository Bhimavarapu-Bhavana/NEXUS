from __future__ import annotations

from typing import Any

from app.agent.capability_context import (
    build_capability_context,
    context_is_fresh,
    evidence_hash,
    validate_capability_context,
)
from app.adapters.model import AuthorizationState
from app.adapters.registry import resolve_authorization
from app.security.sensitive_data import redact_sensitive_data, redact_text

ADAPTER_APPLICATIONS = {
    "email",
    "calendar",
    "browser",
    "comms",
    "job_search",
    "application",
}

MAX_CONTEXT_FIELD = 500


def _bounded(value: Any, *, required: bool = False) -> str:
    text = redact_text(value)
    if required and not text:
        raise ValueError("Application context contains a required empty field.")
    return text.strip()[:MAX_CONTEXT_FIELD]


def build_application_context(
    *,
    task_id: str,
    subgoal_id: str,
    application_id: str,
    provider_id: str,
    capability_id: str,
    operation_name: str,
    target: str = "",
    session_id: str = "",
    evidence: Any = None,
    evidence_refs: list[str] | None = None,
    environment_fingerprint: str,
    freshness_deadline: str = "",
) -> dict[str, Any]:
    """Build a capability context extended with the provider/application binding.

    This does not weaken the Phase 33/36/37 lineage: task, subgoal, capability,
    tool, evidence hash, and environment fingerprint all remain bound and are
    validated by the same ``validate_capability_context`` gate.
    """
    if application_id not in ADAPTER_APPLICATIONS:
        raise ValueError("Application context application is not an authorized adapter application.")
    base = build_capability_context(
        task_id=task_id,
        subgoal_id=subgoal_id,
        application_id=application_id,
        capability_id=capability_id,
        tool_name=f"{capability_id}:{operation_name}",
        target=target,
        session_id=session_id,
        evidence_refs=evidence_refs,
        evidence=evidence,
        freshness_deadline=freshness_deadline,
        environment_fingerprint=environment_fingerprint,
    )
    context = dict(base)
    context["provider_id"] = _bounded(provider_id, required=True)
    context["operation_name"] = _bounded(operation_name, required=True)
    context["capability_id_raw"] = _bounded(capability_id, required=True)
    context["application_id_raw"] = _bounded(application_id, required=True)
    return validate_application_context(context)


def validate_application_context(context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise ValueError("Application context must be a mapping.")
    safe = validate_capability_context(context)
    provider_id = _bounded(context.get("provider_id"), required=True)
    operation_name = _bounded(context.get("operation_name"), required=True)
    application_id = _bounded(context.get("application_id"), required=True)
    capability_id = _bounded(context.get("capability_id"), required=True)
    if application_id not in ADAPTER_APPLICATIONS:
        raise ValueError("Application context application is not an authorized adapter application.")
    result = dict(safe)
    result["provider_id"] = provider_id
    result["operation_name"] = operation_name
    result["application_id"] = application_id
    result["capability_id"] = capability_id
    return redact_sensitive_data(result)


def application_context_binds(context: dict[str, Any], *, application_id: str, provider_id: str, capability_id: str, operation_name: str) -> bool:
    """Verify a context is bound to the exact application/provider/capability/operation."""
    if not isinstance(context, dict):
        return False
    return (
        str(context.get("application_id") or "").strip() == str(application_id or "").strip()
        and str(context.get("provider_id") or "").strip() == str(provider_id or "").strip()
        and str(context.get("capability_id") or "").strip() == str(capability_id or "").strip()
        and str(context.get("operation_name") or "").strip() == str(operation_name or "").strip()
    )


def operation_authorized_in_context(context: dict[str, Any]) -> bool:
    """Resolve the authoritative authorization state for the bound operation.

    Fails closed: any missing or non-permitted state is unauthorized."""
    if not isinstance(context, dict):
        return False
    from app.adapters.registry import ADAPTER_REGISTRY

    provider = ADAPTER_REGISTRY.provider(str(context.get("provider_id") or ""))
    if provider is None:
        return False
    state = resolve_authorization(
        provider,
        str(context.get("capability_id") or ""),
        str(context.get("operation_name") or ""),
    )
    return state in {
        AuthorizationState.OPERATION_PERMITTED,
        AuthorizationState.OPERATION_REQUIRES_APPROVAL,
    }


__all__ = [
    "ADAPTER_APPLICATIONS",
    "application_context_binds",
    "build_application_context",
    "operation_authorized_in_context",
    "validate_application_context",
]