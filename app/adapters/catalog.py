from __future__ import annotations

from app.adapters.builders import capability, descriptor, read_op, write_op
from app.adapters.fixtures import APPLICATION_PROVIDER, JOB_PROVIDER, MAX_JOBS
from app.adapters.model import ProviderDescriptor, ProviderKind
from app.adapters.registry import ADAPTER_REGISTRY, register_provider
from app.security.risk_engine import HIGH_RISK, LOW_RISK, MEDIUM_RISK, READ_ONLY

EMAIL_READ_OPS = (
    read_op("list_messages", target_type="authorized_mailbox", description="List bounded observed messages."),
    read_op("get_message", target_type="observed_message", description="Get one observed message by identifier."),
    read_op("get_thread", target_type="observed_thread", description="Get one observed thread by identifier."),
)
EMAIL_DRAFT_OPS = (
    read_op("prepare_reply_draft", risk=LOW_RISK, target_type="grounded_email_draft", description="Prepare one grounded reply draft bound to an observed message."),
)
EMAIL_SEND_OPS = (
    write_op("send_reply", risk=MEDIUM_RISK, target_type="grounded_email_reply", description="Send one exact, grounded reply to an observed message sender.", required=("message_id", "subject", "body"), prohibited=("credentials", "attachments")),
)

CALENDAR_READ_OPS = (
    read_op("list_events", target_type="authorized_calendar", description="List bounded observed calendar events."),
    read_op("get_event", target_type="observed_event", description="Get one observed event by identifier."),
    read_op("detect_conflicts", target_type="authorized_calendar", description="Detect bounded overlaps between observed events."),
)
CALENDAR_MUTATE_OPS = (
    write_op("create_event", risk=MEDIUM_RISK, target_type="grounded_calendar_event", description="Create one event with explicit title and start time.", required=("title", "start_time")),
    write_op("update_event", risk=MEDIUM_RISK, target_type="grounded_calendar_event", description="Update one observed event with explicit fields.", required=("event_id",)),
    write_op("delete_event", risk=HIGH_RISK, target_type="observed_event", description="Delete one observed calendar event.", required=("event_id",)),
    write_op("cancel_event", risk=HIGH_RISK, target_type="observed_event", description="Cancel one observed calendar event.", required=("event_id",)),
)

BROWSER_OBSERVE_OPS = (
    read_op("observe_page", target_type="observed_page", description="Observe bounded evidence from one authorized public page."),
)
BROWSER_NAVIGATE_OPS = (
    write_op("follow_observed_link", risk=MEDIUM_RISK, target_type="observed_link", description="Follow one exact link present in the observed page.", required=("target_url",)),
    write_op("navigate_observed", risk=MEDIUM_RISK, target_type="observed_page", description="Navigate only to the currently observed page URL.", required=("target_url",)),
)

COMMS_READ_OPS = (
    read_op("list_messages", target_type="authorized_conversations", description="List bounded observed messages."),
    read_op("get_message", target_type="observed_message", description="Get one observed message by identifier."),
    read_op("get_conversation", target_type="observed_conversation", description="Get one observed conversation by identifier."),
)
COMMS_DRAFT_OPS = (
    read_op("prepare_reply_draft", risk=LOW_RISK, target_type="grounded_comms_draft", description="Prepare one grounded reply draft bound to an observed message."),
)
COMMS_SEND_OPS = (
    write_op("send_reply", risk=MEDIUM_RISK, target_type="grounded_comms_reply", description="Send one exact grounded reply to an observed message in the observed channel.", required=("message_id", "conversation_id", "channel", "content"), prohibited=("credentials", "uploads")),
)

JOB_SEARCH_OPS = (
    read_op("search", target_type="job_board_queries", description="Search bounded fixture or mock job postings with explicit terms; never fabricates postings."),
    read_op("get_details", target_type="observed_job_posting", description="Get one observed job posting by identifier."),
    read_op("application_requirements", target_type="observed_job_posting", description="Extract explicit application requirements from one observed posting."),
)
APPLICATION_PREPARE_OPS = (
    read_op("prepare", risk=LOW_RISK, target_type="grounded_application_proposal", description="Build an application proposal grounded only in the truthful profile and explicit posting requirements; missing facts return NEEDS_USER_INPUT."),
)
APPLICATION_FILL_OPS = (
    write_op("fill", risk=MEDIUM_RISK, target_type="authorized_application_form", description="Fill one authorized fixture/mock application form with the prepared, truthful content.", required=("job_id", "application_content"), prohibited=("credentials", "fabricated_facts")),
)
APPLICATION_SUBMIT_OPS = (
    write_op("submit", risk=HIGH_RISK, target_type="authorized_application_submission", description="Submit one filled fixture/mock application; always consequential and approval-gated.", required=("job_id", "application_id"), prohibited=("credentials",)),
)


def _email_capabilities():
    return (
        capability("EMAIL_READ", "email", EMAIL_READ_OPS),
        capability("EMAIL_DRAFT", "email", EMAIL_DRAFT_OPS),
        capability("EMAIL_SEND", "email", EMAIL_SEND_OPS),
    )


def _calendar_capabilities():
    return (
        capability("CALENDAR_READ", "calendar", CALENDAR_READ_OPS),
        capability("CALENDAR_MUTATE", "calendar", CALENDAR_MUTATE_OPS),
    )


def _browser_capabilities():
    return (
        capability("BROWSER_OBSERVE", "browser", BROWSER_OBSERVE_OPS),
        capability("BROWSER_NAVIGATE", "browser", BROWSER_NAVIGATE_OPS),
    )


def _comms_capabilities():
    return (
        capability("COMMS_READ", "comms", COMMS_READ_OPS),
        capability("COMMS_DRAFT", "comms", COMMS_DRAFT_OPS),
        capability("COMMS_SEND", "comms", COMMS_SEND_OPS),
    )


def _job_capabilities():
    return (
        capability("JOB_SEARCH", "job_search", JOB_SEARCH_OPS),
        capability("JOB_DETAILS", "job_search", JOB_SEARCH_OPS),
        capability("APPLICATION_PREPARE", "application", APPLICATION_PREPARE_OPS),
        capability("APPLICATION_FILL", "application", APPLICATION_FILL_OPS),
        capability("APPLICATION_SUBMIT", "application", APPLICATION_SUBMIT_OPS),
    )


def build_adapters_catalog() -> tuple[ProviderDescriptor, ...]:
    """Deterministically register all adapter provider descriptors.

    Real integrations are intentionally NOT configured/authenticated and are
    represented by UNAVAILABLE_PROVIDER or unconfigured REAL_PROVIDER entries,
    so every operation against them fails closed."""
    return (
        # Email
        descriptor("fixture_email", "email", "Local Email Fixture", ProviderKind.FIXTURE_PROVIDER, _email_capabilities(), send_is_mocked=True, description="Deterministic local mailbox; sending is a mock."),
        descriptor("mock_email_gateway", "email", "Mock Email Gateway", ProviderKind.MOCK_PROVIDER, _email_capabilities(), send_is_mocked=True, description="Local mock gateway mirroring the email operations."),
        descriptor("gmail_real", "email", "Gmail (real)", ProviderKind.REAL_PROVIDER, _email_capabilities(), credential_requirement="real", oauth=True, real_account=True, external_connection=True, configured=False, description="Real integration not configured; operations are unavailable."),
        descriptor("u_email", "email", "Unavailable Email Provider", ProviderKind.UNAVAILABLE_PROVIDER, _email_capabilities(), description="Always unavailable; fail closed."),
        # Calendar
        descriptor("fixture_calendar", "calendar", "Local Calendar Fixture", ProviderKind.FIXTURE_PROVIDER, _calendar_capabilities(), mutation_is_mocked=True, description="Deterministic local calendar; mutations are mocks."),
        descriptor("mock_calendar", "calendar", "Mock Calendar Service", ProviderKind.MOCK_PROVIDER, _calendar_capabilities(), mutation_is_mocked=True, description="Local mock calendar service."),
        descriptor("google_calendar_real", "calendar", "Google Calendar (real)", ProviderKind.REAL_PROVIDER, _calendar_capabilities(), credential_requirement="real", oauth=True, real_account=True, external_connection=True, configured=False, description="Real integration not configured; operations are unavailable."),
        descriptor("u_calendar", "calendar", "Unavailable Calendar Provider", ProviderKind.UNAVAILABLE_PROVIDER, _calendar_capabilities(), description="Always unavailable; fail closed."),
        # Browser
        descriptor("fixture_browser", "browser", "Bounded Browser Fixture", ProviderKind.FIXTURE_PROVIDER, _browser_capabilities(), description="Bounded observation and navigation through the existing browser architecture."),
        descriptor("mock_browser", "browser", "Mock Browser", ProviderKind.MOCK_PROVIDER, _browser_capabilities(), description="Local mock browser mirroring the bounded observe/navigate operations."),
        descriptor("chrome_real", "browser", "Google Chrome (real)", ProviderKind.REAL_PROVIDER, _browser_capabilities(), credential_requirement="real", oauth=True, real_account=True, external_connection=True, configured=False, description="Real browser integration not configured; operations are unavailable."),
        descriptor("u_browser", "browser", "Unavailable Browser Provider", ProviderKind.UNAVAILABLE_PROVIDER, _browser_capabilities(), description="Always unavailable; fail closed."),
        # Comms
        descriptor("fixture_comms", "comms", "Local Comms Fixture", ProviderKind.FIXTURE_PROVIDER, _comms_capabilities(), send_is_mocked=True, description="Deterministic local messages; sending is a mock."),
        descriptor("mock_comms", "comms", "Mock Comms Service", ProviderKind.MOCK_PROVIDER, _comms_capabilities(), send_is_mocked=True, description="Local mock communication service."),
        descriptor("slack_real", "comms", "Slack (real)", ProviderKind.REAL_PROVIDER, _comms_capabilities(), credential_requirement="real", oauth=True, real_account=True, external_connection=True, configured=False, description="Real integration not configured; operations are unavailable."),
        descriptor("u_comms", "comms", "Unavailable Comms Provider", ProviderKind.UNAVAILABLE_PROVIDER, _comms_capabilities(), description="Always unavailable; fail closed."),
        # Jobs / applications
        descriptor(JOB_PROVIDER, "job_search", "Local Internship Fixture Board", ProviderKind.FIXTURE_PROVIDER, (capability("JOB_SEARCH", "job_search", JOB_SEARCH_OPS),), description="Deterministic fake job postings; never a real employer."),
        descriptor("mock_job_board", "job_search", "Mock Job Board", ProviderKind.MOCK_PROVIDER, (capability("JOB_SEARCH", "job_search", JOB_SEARCH_OPS),), description="Local mock job board mirroring the search operations."),
        descriptor(APPLICATION_PROVIDER, "application", "Local Fixture Application Service", ProviderKind.FIXTURE_PROVIDER, (capability("APPLICATION_PREPARE", "application", APPLICATION_PREPARE_OPS), capability("APPLICATION_FILL", "application", APPLICATION_FILL_OPS), capability("APPLICATION_SUBMIT", "application", APPLICATION_SUBMIT_OPS)), mutation_is_mocked=True, description="Deterministic fixture application service; submissions are mocks recorded locally."),
        descriptor("mock_application_service", "application", "Mock Application Service", ProviderKind.MOCK_PROVIDER, (capability("APPLICATION_PREPARE", "application", APPLICATION_PREPARE_OPS), capability("APPLICATION_FILL", "application", APPLICATION_FILL_OPS), capability("APPLICATION_SUBMIT", "application", APPLICATION_SUBMIT_OPS)), mutation_is_mocked=True, description="Local mock application service."),
        descriptor("internshala_real", "job_search", "Internshala (real)", ProviderKind.REAL_PROVIDER, (capability("JOB_SEARCH", "job_search", JOB_SEARCH_OPS),), credential_requirement="real", oauth=True, real_account=True, external_connection=True, configured=False, description="Real integration not configured; operations are unavailable."),
        descriptor("linkedin_real", "application", "LinkedIn (real)", ProviderKind.REAL_PROVIDER, (capability("APPLICATION_PREPARE", "application", APPLICATION_PREPARE_OPS), capability("APPLICATION_FILL", "application", APPLICATION_FILL_OPS), capability("APPLICATION_SUBMIT", "application", APPLICATION_SUBMIT_OPS)), credential_requirement="real", oauth=True, real_account=True, external_connection=True, configured=False, description="Real integration not configured; operations are unavailable."),
        descriptor("u_jobs", "job_search", "Unavailable Job Provider", ProviderKind.UNAVAILABLE_PROVIDER, (capability("JOB_SEARCH", "job_search", JOB_SEARCH_OPS),), description="Always unavailable; fail closed."),
        descriptor("u_applications", "application", "Unavailable Application Provider", ProviderKind.UNAVAILABLE_PROVIDER, (capability("APPLICATION_PREPARE", "application", APPLICATION_PREPARE_OPS), capability("APPLICATION_FILL", "application", APPLICATION_FILL_OPS), capability("APPLICATION_SUBMIT", "application", APPLICATION_SUBMIT_OPS)), description="Always unavailable; fail closed."),
    )


_ADAPTERS_REGISTERED = False


def ensure_adapters_registered() -> None:
    """Register the deterministic adapter catalog exactly once."""
    global _ADAPTERS_REGISTERED
    if _ADAPTERS_REGISTERED:
        return
    for provider in build_adapters_catalog():
        if ADAPTER_REGISTRY.exists(provider.provider_id):
            continue
        from app.adapters.secure_boundary import SECURE_BOUNDARY

        register_provider(SECURE_BOUNDARY.authorize_descriptor(provider))
    _ADAPTERS_REGISTERED = True


__all__ = [
    "MAX_JOBS",
    "ensure_adapters_registered",
    "build_adapters_catalog",
]