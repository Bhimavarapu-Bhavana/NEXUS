from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.agent.capability_context import build_capability_context, context_is_fresh
from app.security.risk_engine import BLOCKED, READ_ONLY, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text

CLASSIFICATIONS = {"PUBLIC", "INTERNAL", "PERSONAL", "SENSITIVE", "SECRET", "CREDENTIAL"}
SENSITIVITY_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
AUTHORIZATION_SCOPES = {"workspace-only", "project-only", "authorized-personal-folder", "authorized-image-folder"}
PERSONAL_APPLICATION = "personal_data"


@dataclass(frozen=True)
class PersonalCapability:
    capability_id: str
    tool_name: str
    target_types: tuple[str, ...]
    read_only: bool
    risk_level: str
    requires_approval: bool
    requires_verification: bool


PERSONAL_CAPABILITIES = {
    "FILE_OBSERVE": PersonalCapability("FILE_OBSERVE", "personal_file_observer", ("txt", "md", "pdf", "docx", "csv", "json"), True, READ_ONLY, False, True),
    "IMAGE_OBSERVE": PersonalCapability("IMAGE_OBSERVE", "image_observer", ("png", "jpg", "jpeg", "gif", "bmp", "webp"), True, READ_ONLY, False, True),
    "DOCUMENT_OBSERVE": PersonalCapability("DOCUMENT_OBSERVE", "personal_file_observer", ("txt", "md", "pdf", "docx", "csv", "json"), True, READ_ONLY, False, True),
}


def classify_data(*, target: str, content: str = "", explicit_classification: str = "") -> str:
    requested = str(explicit_classification or "").upper().strip()
    if requested and requested not in CLASSIFICATIONS:
        raise ValueError("Unknown data classification.")
    lowered = f"{target} {content}".lower()
    if any(marker in lowered for marker in ("password", "passwd", "private key", "credential", "cookie", "api_key", "api-key", "access_token")):
        return "CREDENTIAL" if any(marker in lowered for marker in ("password", "passwd", "credential", "cookie")) else "SECRET"
    if requested:
        return requested
    if any(marker in lowered for marker in ("ssn", "social security", "bank account", "credit card", "financial", "medical")):
        return "SENSITIVE"
    if any(marker in lowered for marker in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", "photo", "image", "personal", "diary", "journal", "family")):
        return "PERSONAL"
    if any(marker in lowered for marker in ("readme", "public", "license")):
        return "PUBLIC"
    return "INTERNAL"


def _sensitivity(classification: str) -> str:
    return {"PUBLIC": "LOW", "INTERNAL": "LOW", "PERSONAL": "MEDIUM", "SENSITIVE": "HIGH", "SECRET": "CRITICAL", "CREDENTIAL": "CRITICAL"}[classification]


def build_personal_capability_context(*, task_id: str, subgoal_id: str, capability_id: str, target: str, authorization_scope: str, environment_fingerprint: str, evidence_refs: list[str] | None = None, freshness_deadline: str = "", classification: str = "", content: str = "") -> dict[str, Any]:
    capability = PERSONAL_CAPABILITIES.get(str(capability_id or "").upper())
    if capability is None:
        raise ValueError("Personal capability is not registered.")
    if str(authorization_scope or "").strip().lower() not in AUTHORIZATION_SCOPES:
        raise ValueError("Personal capability requires a recognized explicit authorization scope.")
    data_classification = classify_data(target=target, content=content, explicit_classification=classification)
    risk = evaluate_risk(f"observe personal data {target}", tool_name=capability.tool_name)
    if data_classification in {"SECRET", "CREDENTIAL"}:
        risk = {"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": "Secret and credential observation is blocked by default."}
    context = build_capability_context(task_id=task_id, subgoal_id=subgoal_id, application_id=PERSONAL_APPLICATION, capability_id=capability.capability_id, tool_name=capability.tool_name, target=target, evidence_refs=evidence_refs, freshness_deadline=freshness_deadline, environment_fingerprint=environment_fingerprint)
    context.update({"authorization_scope": redact_text(authorization_scope)[:500], "data_classification": data_classification, "sensitivity": _sensitivity(data_classification), "risk_level": risk.get("risk_level", capability.risk_level), "requires_approval": capability.requires_approval, "requires_verification": capability.requires_verification})
    return redact_sensitive_data(context)


def validate_personal_capability_context(context: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(context, dict) or context.get("application_id") != PERSONAL_APPLICATION:
        raise ValueError("Personal capability context is required.")
    required = ("task_id", "subgoal_id", "capability_id", "tool_name", "target", "authorization_scope", "data_classification", "sensitivity", "risk_level", "environment_fingerprint")
    if any(not str(context.get(key) or "").strip() for key in required):
        raise ValueError("Personal capability context is incomplete.")
    if str(context["data_classification"]).upper() not in CLASSIFICATIONS or str(context["sensitivity"]).upper() not in SENSITIVITY_LEVELS:
        raise ValueError("Personal capability context classification is invalid.")
    if str(context["authorization_scope"]).lower() not in AUTHORIZATION_SCOPES:
        raise ValueError("Personal capability authorization scope is invalid.")
    if not context_is_fresh(context):
        raise ValueError("Personal capability context is stale.")
    if str(context["risk_level"]).upper() == BLOCKED:
        raise ValueError("Personal capability context is blocked by risk policy.")
    return redact_sensitive_data(dict(context))


__all__ = ["AUTHORIZATION_SCOPES", "CLASSIFICATIONS", "PERSONAL_CAPABILITIES", "PersonalCapability", "build_personal_capability_context", "classify_data", "validate_personal_capability_context"]
