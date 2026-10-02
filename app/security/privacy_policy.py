"""Deterministic privacy-policy layer.

Scope separation, stated once:

- Permission Authority = whether NEXUS may PERFORM an action.
- Privacy Policy = whether NEXUS may ACCESS, STORE, or RETAIN particular
  personal data.

The two are evaluated independently and both must pass: a permission never
overrides a privacy denial, and a privacy allowance never authorizes an
action. Nothing here grants, checks, or stores permissions.

Decisions are pure functions of canonical (category, operation) pairs plus
an explicit ``authorization_present`` flag supplied by the caller. Free text
— including prompt-injected content — can never influence a decision:
unknown categories or operations raise ValueError (fail closed).

Data categories reuse the personal-capability classifications so privacy and
observation stay in one vocabulary.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text

DATA_CATEGORIES = {"PUBLIC", "INTERNAL", "PERSONAL", "SENSITIVE", "SECRET", "CREDENTIAL"}

PRIVACY_OPERATIONS = {"OBSERVE", "STORE", "RETAIN"}

PRIVACY_DECISIONS = {"ALLOW", "REQUIRES_AUTHORIZATION", "DENY"}

# Retention limits in days. SECRET and CREDENTIAL are never retained.
RETENTION_DAYS = {
    "PUBLIC": 365,
    "INTERNAL": 365,
    "PERSONAL": 90,
    "SENSITIVE": 30,
    "SECRET": 0,
    "CREDENTIAL": 0,
}

# Categories whose content must always be redacted in derived artifacts.
# Only PUBLIC data is exempt; everything else is redacted by default.
REDACT_CATEGORIES = {"INTERNAL", "PERSONAL", "SENSITIVE", "SECRET", "CREDENTIAL"}


def _canonical_category(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text not in DATA_CATEGORIES:
        raise ValueError(f"Unknown data category: {value}")
    return text


def _canonical_operation(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text not in PRIVACY_OPERATIONS:
        raise ValueError(f"Unknown privacy operation: {value}")
    return text


def _audit(
    event_type: str,
    *,
    audit_db_path: str | Path | None = None,
    **payload: Any,
) -> None:
    try:
        record_audit_event(event_type, db_path=audit_db_path, mirror_central=True, **payload)
    except Exception:
        pass


def must_redact(category: str) -> bool:
    """Return whether derived artifacts for the category must be redacted."""
    return _canonical_category(category) in REDACT_CATEGORIES


def retention_days(category: str) -> int:
    """Return the maximum retention window in days for the category."""
    return RETENTION_DAYS[_canonical_category(category)]


def is_retention_expired(category: str, stored_at: str, *, now: datetime | None = None) -> bool:
    """Return whether data stored at the ISO timestamp exceeds retention.

    Unparseable timestamps fail closed as expired. Categories with a zero
    retention window are always expired: secrets are never retained.
    """
    canon = _canonical_category(category)
    if RETENTION_DAYS[canon] <= 0:
        return True
    try:
        stored = datetime.fromisoformat(str(stored_at or "").strip().replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return True
    if stored.tzinfo is None:
        stored = stored.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return (current - stored).days > RETENTION_DAYS[canon]


def evaluate_privacy(
    category: str,
    *,
    operation: str,
    authorization_present: bool = False,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Decide whether personal data may be observed, stored, or retained.

    - PUBLIC / INTERNAL: ALLOW.
    - PERSONAL: ALLOW (scoped observation, bounded retention).
    - SENSITIVE: REQUIRES_AUTHORIZATION without an explicit grant, else ALLOW.
      The caller supplies ``authorization_present`` from an explicit
      AUTHORIZATION record; this engine never looks preferences up itself.
    - SECRET / CREDENTIAL: DENY for every operation, unconditionally.
      No authorization flag can override a secret denial.

    DENY and REQUIRES_AUTHORIZATION outcomes are audited; ALLOW is not, to
    keep routine read-only observation noise out of the audit trail.
    """
    canon_category = _canonical_category(category)
    canon_operation = _canonical_operation(operation)
    authorized = bool(authorization_present)

    decision = _decide(canon_category, canon_operation, authorized)

    if decision["decision"] in {"DENY", "REQUIRES_AUTHORIZATION"}:
        _audit(
            "privacy_denied",
            audit_db_path=audit_db_path,
            actor="privacy_policy",
            tool="privacy_policy",
            target=canon_category,
            result=decision["decision"],
            reason=decision["reason"],
            metadata={"category": canon_category, "operation": canon_operation},
        )
    return decision


def _decide(category: str, operation: str, authorized: bool) -> dict[str, Any]:
    """Pure decision core shared by evaluation and read-only description."""
    if category in {"SECRET", "CREDENTIAL"}:
        return _decision(
            "DENY",
            f"{category} data may not be {operation.lower()}d.",
            category,
            operation,
            authorized,
        )
    if category == "SENSITIVE" and not authorized:
        return _decision(
            "REQUIRES_AUTHORIZATION",
            f"{category} data requires an explicit authorization grant before it may be {operation.lower()}d.",
            category,
            operation,
            authorized,
        )
    return _decision(
        "ALLOW",
        f"{category} data may be {operation.lower()}d under bounded retention.",
        category,
        operation,
        authorized,
    )


def _decision(
    outcome: str, reason: str, category: str, operation: str, authorized: bool
) -> dict[str, Any]:
    return {
        "decision": outcome,
        "reason": reason,
        "category": category,
        "operation": operation,
        "authorization_present": authorized,
        "retention_days": RETENTION_DAYS[category],
        "must_redact": category in REDACT_CATEGORIES,
    }


def describe_privacy_policy() -> dict[str, Any]:
    """Return the deterministic policy table for read-only UI/API surfaces.

    Side-effect free: uses the pure decision core so describing the policy
    never emits audit events.
    """
    return redact_sensitive_data({
        "categories": sorted(DATA_CATEGORIES),
        "operations": sorted(PRIVACY_OPERATIONS),
        "decisions": {
            category: {
                operation: _decide(category, operation, False)["decision"]
                for operation in sorted(PRIVACY_OPERATIONS)
            }
            for category in sorted(DATA_CATEGORIES)
        },
        "retention_days": dict(RETENTION_DAYS),
        "note": "Permission Authority governs actions; this table governs data access and retention only.",
    })


__all__ = [
    "DATA_CATEGORIES",
    "PRIVACY_DECISIONS",
    "PRIVACY_OPERATIONS",
    "REDACT_CATEGORIES",
    "RETENTION_DAYS",
    "describe_privacy_policy",
    "evaluate_privacy",
    "is_retention_expired",
    "must_redact",
    "retention_days",
]
