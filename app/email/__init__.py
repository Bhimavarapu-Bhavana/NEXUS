from app.email.models import EmailMessage
from app.email.providers import FixtureEmailProvider, PROVIDER_REGISTRY, get_provider, provider_credentials_required
from app.email.actions import EMAIL_SEND_TOOL, email_send_action, parse_email_request
from app.email.drafting import EMAIL_DRAFT_TOOL, prepare_reply_draft
from app.email.service import (
    attach_email_deadline_to_task,
    build_email_evidence_list,
    classify_email_message,
    create_task_from_email_fact,
    detect_action_required,
    detect_commitments,
    detect_deadlines,
    detect_follow_ups,
    detect_meetings,
    email_observatory,
    get_email_message,
    get_email_thread,
    list_email_messages,
    possible_unanswered_messages,
)

__all__ = [
    "EmailMessage",
    "FixtureEmailProvider",
    "PROVIDER_REGISTRY",
    "EMAIL_DRAFT_TOOL",
    "EMAIL_SEND_TOOL",
    "attach_email_deadline_to_task",
    "build_email_evidence_list",
    "classify_email_message",
    "create_task_from_email_fact",
    "detect_action_required",
    "detect_commitments",
    "detect_deadlines",
    "detect_follow_ups",
    "detect_meetings",
    "email_observatory",
    "email_send_action",
    "get_email_message",
    "get_email_thread",
    "get_provider",
    "list_email_messages",
    "parse_email_request",
    "possible_unanswered_messages",
    "prepare_reply_draft",
    "provider_credentials_required",
]