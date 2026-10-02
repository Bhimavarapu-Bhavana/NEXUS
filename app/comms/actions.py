from __future__ import annotations

from typing import Any

from app.comms.drafting import MAX_DRAFT_CHARS, draft_reply_to_message
from app.comms.models import CommunicationMessage
from app.comms.providers import get_provider, provider_credentials_required
from app.security.audit_logger import record_audit_event
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text

COMMS_SEND_TOOL = "comms_send_action"
COMMS_SEND_OPERATIONS = {"send_reply"}


def _audit(event: str, **payload: Any) -> bool:
    payload["tool"] = payload.get("tool") or COMMS_SEND_TOOL
    return record_audit_event(event, **payload)


def _bounded_result(status: str, *, verification: str, approved: bool, **payload: Any) -> dict[str, Any]:
    risk_decision = payload.pop("risk_decision", {})
    return redact_sensitive_data({
        "source": "comms_action",
        "tool": COMMS_SEND_TOOL,
        "status": status,
        "verification": verification,
        "approved": bool(approved),
        "risk_decision": risk_decision,
        **payload,
    })


def _recipient_matches_observed(spec: dict[str, Any], target: CommunicationMessage) -> bool:
    observed = str(target.sender.get("id") or "").strip().lower()
    proposed = spec.get("recipient")
    if isinstance(proposed, dict):
        proposed_id = str(proposed.get("id") or "").strip().lower()
    elif isinstance(proposed, str):
        proposed_id = proposed.strip().lower()
    else:
        proposed_id = ""
    return bool(observed) and observed == proposed_id


def _conversation_matches_observed(spec: dict[str, Any], target: CommunicationMessage) -> bool:
    proposed_conversation = str(spec.get("conversation_id") or "").strip()
    proposed_channel = str(spec.get("channel") or "").strip()
    return (
        proposed_conversation == str(target.conversation_id or "").strip()
        and proposed_channel == str(target.channel or "").strip()
    )


def comms_send_action(spec: Any, *, approved: bool = False, provider: str = "comms", task_id: str = "", actor: str = "comms_action", comms_state: Any = None) -> dict[str, Any]:
    """Execute ONE bounded, grounded communication reply through the approval path.

    Only ``send_reply`` is supported. The recipient, conversation, and channel
    must exactly match an observed message (no arbitrary recipients or channels),
    the content is bound exactly as proposed, and sending is only ever a mock on
    the fixture provider so the approval/audit/verification pipeline can be
    exercised without a real communication account.
    """
    if not isinstance(spec, dict):
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=False, risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": "Communication actions require a structured specification.", "category": "COMMS_ACTION"}, action_result="Communication actions require a structured specification.")

    operation = str(spec.get("operation") or "").strip().lower()
    if operation not in COMMS_SEND_OPERATIONS:
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": True, "reason": "Unknown or arbitrary communication operations are blocked.", "category": "COMMS_ACTION"}, action_result="Unsupported communication operation.")

    try:
        provider_instance = get_provider(provider)
    except ValueError as exc:
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": redact_text(str(exc)), "category": "COMMS_ACTION"}, action_result=redact_text(str(exc)))
    if not provider_instance.supports_send():
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": "The communication provider does not support authenticated sending.", "category": "COMMS_ACTION"}, action_result="The communication provider does not support authenticated sending.")
    if provider_credentials_required(provider):
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision={"risk_level": BLOCKED, "allowed": False, "approval_required": False, "reason": "Credential-based providers are not used by NEXUS; sending is refused.", "category": "COMMS_ACTION"}, action_result="Credential-based providers are refused by NEXUS.")

    risk_decision = evaluate_risk("execute comms_send_action", tool_name=COMMS_SEND_TOOL)
    _audit("comms_action_risk_decision", actor=actor, risk_level=risk_decision["risk_level"], approval_required=risk_decision["approval_required"], approved=False, target=redact_text(str(spec.get("message_id") or provider)), result=str(risk_decision["allowed"]), reason=risk_decision["reason"])
    if not risk_decision["allowed"] or risk_decision["risk_level"] == BLOCKED:
        _audit("comms_action_blocked", actor=actor, risk_level=BLOCKED, approved=False, target=redact_text(str(spec.get("message_id") or "")), result="BLOCKED", reason=risk_decision["reason"])
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=bool(approved), risk_decision=risk_decision, action_result=risk_decision["reason"])

    if not approved:
        _audit("comms_action_approval_requested", actor=actor, risk_level=risk_decision["risk_level"], approval_required=True, approved=False, target=redact_text(str(spec.get("message_id") or "")), result="APPROVAL_REQUIRED", reason="Approval is required before any communication can be sent.")
        return _bounded_result("APPROVAL_REQUIRED", verification="NOT_RUN", approved=False, risk_decision=risk_decision, action_result="Approval is required before any communication can be sent.")

    if not _audit("comms_action_approval_propagation", actor=actor, risk_level=risk_decision["risk_level"], approval_required=True, approved=True, target=redact_text(str(spec.get("message_id") or "")), result="APPROVED", reason="Approval propagated to the bounded communication action."):
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=True, risk_decision=risk_decision, action_result="Audit persistence failed before communication action execution.")

    target_ref = redact_text(str(spec.get("message_id") or ""))
    try:
        message_id = str(spec.get("message_id") or "").strip()
        if not message_id:
            raise ValueError("Sending a reply requires a grounded message identifier.")
        target_message = provider_instance.get_message(message_id)
        if target_message is None:
            raise ValueError("The target communication message was not observed and cannot be replied to.")
        if not _conversation_matches_observed(spec, target_message):
            raise ValueError("Reply conversation and channel must exactly match the observed message; arbitrary channels are refused.")
        if not _recipient_matches_observed(spec, target_message):
            raise ValueError("Reply recipient must exactly match the observed message sender; arbitrary recipients are refused.")
        own = {str(identifier).lower() for identifier in getattr(provider_instance, "own_participants", ("nexus@nexus.local", "nexus"))}
        if str(target_message.sender.get("id") or "").lower() in own:
            raise ValueError("Refusing to reply to NEXUS' own account.")

        content = redact_text(spec.get("content") or "").strip()
        if not content:
            raise ValueError("A reply requires message content; nothing is invented.")
        if len(content) > MAX_DRAFT_CHARS:
            raise ValueError("Reply content exceeds the bounded length limit.")

        sent = provider_instance.send_message(
            conversation_id=str(target_message.conversation_id or ""),
            channel=str(target_message.channel or ""),
            to=redact_sensitive_data(dict(target_message.sender)),
            content=content[:4000],
            in_reply_to=message_id,
        )
        sent_id = str(sent.get("sent_id") or "")
        verified = provider_instance.verify_send_binding(
            sent_id,
            conversation_id=str(spec.get("conversation_id") or target_message.conversation_id or ""),
            channel=str(spec.get("channel") or target_message.channel or ""),
            to=redact_sensitive_data(dict(target_message.sender)),
            content=content,
        )
        verification = "SUCCESS" if verified else "FAILED"
        outcome = "COMPLETED" if verified else "VERIFICATION_FAILED"
        reason = "Bounded communication reply sent through the fixture mock." if verified else "Sent reply failed post-send binding verification."
        _audit("comms_action_executed", actor=actor, risk_level=risk_decision["risk_level"], approved=True, target=message_id, result=outcome, reason=reason, metadata={"sent_id": sent_id, "operation": operation, "task_id": task_id, "verification": verification, "conversation_id": redact_text(str(target_message.conversation_id))[:300], "channel": redact_text(str(target_message.channel))[:200]})
        return _bounded_result(outcome, verification=verification, approved=True, risk_decision=risk_decision, operation=operation, message_id=message_id, conversation_id=target_message.conversation_id, channel=target_message.channel, sent_id=sent_id, to=redact_sensitive_data(dict(target_message.sender)), action_result="Communication reply sent through the approval path and verified." if verified else "Communication reply was recorded but failed binding verification.")
    except (TypeError, ValueError) as exc:
        reason = redact_text(str(exc))
        _audit("comms_action_blocked", actor=actor, risk_level=BLOCKED, approved=False, target=target_ref, result="BLOCKED", reason=reason)
        return _bounded_result("BLOCKED", verification="NOT_RUN", approved=True, risk_decision=risk_decision, action_result=reason)


def parse_comms_request(request: str, observed_messages: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Build one grounded communication reply spec, or return None.

    Returns None unless the request explicitly asks to reply/respond and a
    single observed message can be matched by identifier or content phrase.
    NEXUS never fabricates communication content or invents a target.
    """
    lowered = redact_text(request or "").lower()
    if not any(marker in lowered for marker in ("reply to", "reply ", "respond to", "respond ", "acknowledge", "acknowledged")):
        return None
    messages = [message for message in (observed_messages or []) if isinstance(message, dict)]
    matched: dict[str, Any] | None = None
    by_id: list[dict[str, Any]] = []
    by_content: list[dict[str, Any]] = []
    by_conversation: list[dict[str, Any]] = []
    for message in messages:
        message_id = str(message.get("message_id") or "")
        conversation_id = str(message.get("conversation_id") or "")
        content = str(message.get("content") or "")
        if message_id and message_id.lower() in lowered:
            by_id.append(message)
        elif content and content.lower().strip() in lowered:
            by_content.append(message)
        elif conversation_id and conversation_id.lower() in lowered:
            by_conversation.append(message)
    if len(by_id) == 1:
        matched = by_id[0]
    elif len(by_id) > 1:
        return None
    elif len(by_content) == 1:
        matched = by_content[0]
    elif len(by_content) > 1:
        return None
    elif by_conversation:
        own = {str(identifier).lower() for identifier in ("nexus@nexus.local", "nexus")}
        external = [message for message in by_conversation if str((message.get("sender") or {}).get("id") or "").lower() not in own]
        pool = external or by_conversation
        latest = max(pool, key=lambda message: (str(message.get("timestamp") or ""), str(message.get("message_id") or "")))
        matched = latest
    if matched is None:
        return None
    try:
        draft = draft_reply_to_message(str(matched.get("provider") or "comms"), str(matched.get("message_id") or ""), draft_body=request)
    except (TypeError, ValueError):
        return None
    message_snapshot = redact_sensitive_data({key: matched.get(key) for key in ("message_id", "conversation_id", "channel", "sender", "content", "attachments")})
    return redact_sensitive_data({
        "operation": "send_reply",
        "recipient": draft["recipient"],
        "conversation_id": draft["conversation_id"],
        "channel": draft["channel"],
        "content": draft["content"],
        "in_reply_to": draft["in_reply_to"],
        "message_id": draft["in_reply_to"],
        "provider": draft["provider"],
        "task_id": "",
        "is_draft": True,
        "never_auto_send": True,
        "requires_approval": True,
        "grounded_in": draft["grounding"],
        "message_snapshot": message_snapshot,
    })


__all__ = ["COMMS_SEND_TOOL", "COMMS_SEND_OPERATIONS", "comms_send_action", "parse_comms_request"]