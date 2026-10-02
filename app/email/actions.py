from __future__ import annotations

from typing import Any

from app.email.drafting import DRAFT_OPERATIONS, prepare_reply_draft
from app.email.models import EmailMessage, normalize_email_message
from app.email.providers import get_provider, provider_credentials_required
from app.security.audit_logger import record_audit_event
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text

EMAIL_SEND_TOOL = "email_send_action"
EMAIL_SEND_OPERATIONS = set(DRAFT_OPERATIONS)
_OWN_ACCOUNTS = ("me@nexus.local", "nexus@nexus.local")


def _audit(event: str, **payload: Any) -> bool:
    payload["tool"] = payload.get("tool") or EMAIL_SEND_TOOL
    return record_audit_event(event, **payload)


def _bounded_result(status: str, *, verification: str, approved: bool, **payload: Any) -> dict[str, Any]:
    return redact_sensitive_data({"source": "email_action", "tool": EMAIL_SEND_TOOL, "status": status, "verification": verification, "approved": bool(approved), "risk_decision": payload.pop("risk_decision", {}), **payload})


def _recipient_matches_observed(spec: dict[str, Any], target: EmailMessage | None) -> bool:
    if target is None:
        return False
    observed = str(target.sender.get("email") or "").strip().lower()
    proposed_dict = spec.get("to")
    proposed_email = ""
    if isinstance(proposed_dict, dict):
        proposed_email = str(proposed_dict.get("email") or "").strip().lower()
    else:
        proposed_email = str(proposed_dict or "").strip().lower()
    return bool(observed) and observed == proposed_email


def email_send_action(spec: Any, *, approved: bool = False, provider: str = "fixture", task_id: str = "", actor: str = "email_action", email_state: Any = None) -> dict[str, Any]:
    """Execute ONE bounded, grounded email reply through the approval path.

    Only ``send_reply`` is supported. The recipient must exactly match the
    sender of an observed message (no arbitrary recipients), the body is bound
    as proposed, and sending is only ever a mock on the fixture provider so the
    approval/audit/verification pipeline can be exercised without a real send.
    """
    if not isinstance(spec, dict):
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=False, risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": "Email actions require a structured specification.", "category": "EMAIL_ACTION"}, action_result="Email actions require a structured specification.")

    operation = str(spec.get("operation") or "").strip().lower()
    if operation not in EMAIL_SEND_OPERATIONS:
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": True, "reason": "Unknown or arbitrary email operations are blocked.", "category": "EMAIL_ACTION"}, action_result="Unsupported email operation.")

    provider_instance = None
    try:
        provider_instance = get_provider(provider)
    except ValueError as exc:
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": str(exc), "category": "EMAIL_ACTION"}, action_result=str(exc))
    if not provider_instance.supports_send():
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": "The email provider does not support authenticated sending.", "category": "EMAIL_ACTION"}, action_result="The email provider does not support authenticated sending.")
    if provider_credentials_required(provider):
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": "Credential-based providers are not used by NEXUS; sending is refused.", "category": "EMAIL_ACTION"}, action_result="Credential-based providers are refused by NEXUS.")

    risk_decision = evaluate_risk("execute email_send_action", tool_name=EMAIL_SEND_TOOL)
    _audit("email_action_risk_decision", actor=actor, risk_level=risk_decision["risk_level"], approval_required=risk_decision["approval_required"], approved=False, target=redact_text(str(spec.get("message_id") or provider)), result=str(risk_decision["allowed"]), reason=risk_decision["reason"])
    if not risk_decision["allowed"] or risk_decision["risk_level"] == BLOCKED:
        _audit("email_action_blocked", actor=actor, risk_level=BLOCKED, approved=False, target=redact_text(str(spec.get("message_id") or "")), result="BLOCKED", reason=risk_decision["reason"])
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision=risk_decision, action_result=risk_decision["reason"])

    if not approved:
        _audit("email_action_approval_requested", actor=actor, risk_level=risk_decision["risk_level"], approval_required=True, approved=False, target=redact_text(str(spec.get("message_id") or "")), result="APPROVAL_REQUIRED", reason="Approval is required before any email can be sent.")
        return _bounded_result("APPROVAL_REQUIRED", verification="NOT_RUN", approved=False, risk_decision=risk_decision, action_result="Approval is required before any email can be sent.")

    if not _audit("email_action_approval_propagation", actor=actor, risk_level=risk_decision["risk_level"], approval_required=True, approved=True, target=redact_text(str(spec.get("message_id") or "")), result="APPROVED", reason="Approval propagated to the bounded email action."):
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=True, risk_decision=risk_decision, action_result="Audit persistence failed before email action execution.")

    target = redact_text(str(spec.get("message_id") or ""))
    try:
        message_id = str(spec.get("message_id") or "").strip()
        if not message_id:
            raise ValueError("Sending a reply requires a grounded message identifier.")
        target_message = provider_instance.get_message(message_id)
        if target_message is None:
            raise ValueError("The target email message was not observed and cannot be replied to.")
        if not _recipient_matches_observed(spec, target_message):
            raise ValueError("Reply recipient must exactly match the observed message sender; arbitrary recipients are refused.")
        if str(target_message.sender.get("email") or "").lower() in _OWN_ACCOUNTS:
            raise ValueError("Refusing to reply to NEXUS' own account.")

        subject = redact_text(spec.get("subject") or "").strip()
        body = redact_text(spec.get("body") or "").strip()
        if not subject:
            raise ValueError("A reply requires a subject.")
        if not body:
            raise ValueError("A reply requires message content; nothing is invented.")

        sent = provider_instance.send_message(
            to=redact_sensitive_data(dict(target_message.sender)),
            subject=subject[:1000],
            body=body[:4000],
            in_reply_to=message_id,
            thread_id=str(spec.get("thread_id") or target_message.thread_id or ""),
        )
        sent_id = str(sent.get("sent_id") or "")
        verified = provider_instance.verify_send_binding(
            sent_id,
            to=redact_sensitive_data(dict(target_message.sender)),
            subject=subject,
            body=body,
        )
        verification = "SUCCESS" if verified else "FAILED"
        outcome = "COMPLETED" if verified else "VERIFICATION_FAILED"
        _audit("email_action_executed", actor=actor, risk_level=risk_decision["risk_level"], approved=True, target=message_id, result=outcome, reason="Bounded reply sent through the fixture mock." if verified else "Sent reply failed post-send verification.", metadata={"sent_id": sent_id, "operation": operation, "task_id": task_id, "verification": verification})
        return _bounded_result(outcome, verification=verification, approved=True, risk_decision=risk_decision, operation=operation, message_id=message_id, sent_id=sent_id, to=redact_sensitive_data(dict(target_message.sender)), action_result="Reply sent through the approval path and verified." if verified else "Reply was recorded but failed binding verification.")
    except (TypeError, ValueError) as exc:
        reason = redact_text(str(exc))
        _audit("email_action_blocked", actor=actor, risk_level=BLOCKED, approved=False, target=target, result="BLOCKED", reason=reason)
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=True, risk_decision=risk_decision, action_result=reason)


def parse_email_request(request: str, observed_messages: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Build one grounded reply spec from the user's request, or return None.

    Returns None unless the request explicitly asks to reply/respond and a
    single observed message can be matched by subject phrase or identifier.
    NEXUS never fabricates email content or invents a target.
    """
    lowered = redact_text(request or "").lower()
    if not any(marker in lowered for marker in ("reply to", "reply ", "respond to", "respond ", "acknowledge", "acknowledged")):
        return None
    messages = [message for message in (observed_messages or []) if isinstance(message, dict)]
    matched: dict[str, Any] | None = None
    for message in messages:
        subject = str(message.get("subject") or "")
        message_id = str(message.get("message_id") or "")
        if subject and subject.lower() in lowered:
            candidate = message
        elif message_id and message_id.lower() in lowered:
            candidate = message
        else:
            continue
        if matched is not None:
            return None
        matched = candidate
    if matched is None:
        return None
    try:
        draft = prepare_reply_draft(request, matched, provider_name=str(matched.get("provider") or "fixture"))
    except (TypeError, ValueError):
        return None
    return redact_sensitive_data({
        "operation": draft["operation"],
        "to": draft["to"],
        "subject": draft["subject"],
        "body": draft["body"],
        "in_reply_to": draft["in_reply_to"],
        "thread_id": draft["thread_id"],
        "message_id": draft["message_id"],
        "provider": draft["provider"],
        "task_id": draft["task_id"],
        "is_draft": True,
        "never_auto_send": True,
        "requires_approval": True,
        "grounded_in": draft["grounded_in"],
        "message_snapshot": draft["message_snapshot"],
    })


__all__ = ["EMAIL_SEND_TOOL", "EMAIL_SEND_OPERATIONS", "email_send_action", "parse_email_request"]