from __future__ import annotations

from typing import Any, Callable

from app.tools.error_detector import detect_python_errors
from app.tools.logic_inspector import inspect_python_logic
from app.tools.relevant_file_selector import select_relevant_files
from app.tools.runtime_inspector import run_python_file
from app.tools.workspace_inspector import inspect_workspace
from app.tools.terminal_inspector import analyze_terminal_output
from app.tools.log_inspector import inspect_log_file
from app.tools.git_inspector import inspect_git_repository
from app.tools.browser_observer import observe_browser_page
from app.tools.browser_actions import navigate_observed_page, follow_observed_link
from app.tools.browser_controller import browser_controller_entrypoint
from app.tools.desktop_observer import observe_desktop
from app.tools.desktop_actions import (
    focus_authorized_window,
    minimize_authorized_window,
    restore_authorized_window,
)
from app.tools.fixer import fix_python_logic
from app.security.security_scanner import scan_target
from app.security.sensitive_data import redact_sensitive_data
from app.security.risk_engine import READ_ONLY, evaluate_risk, evaluate_tool_risk
from app.tools.personal_data_observer import observe_personal_file
from app.tools.document_intelligence import compare_documents, observe_document
from app.tools.calendar_observer import observe_calendar
from app.calendar.actions import calendar_event_action
from app.tools.email_observer import observe_email
from app.email.actions import email_send_action
from app.email.drafting import prepare_reply_draft
from app.tools.comms_observer import observe_comms
from app.comms.actions import comms_send_action
from app.comms.drafting import prepare_draft as prepare_comms_draft
from app.tools.attention_observer import observe_attention
from app.adapters.jobs import (
    get_application_requirements,
    get_job_details,
    prepare_application,
    search_jobs,
)
from app.adapters.action_bridge import execute_adapter_action

MAX_TOOLS_PER_PLAN = 5


class ToolRegistry(dict[str, dict[str, Any]]):
    """Expose a read-only filtered view while preserving the full registry for allowlist membership checks."""

    _READ_ONLY_EXCLUDED = {"browser_controller", "fixer"}

    def items(self):
        return [(name, value) for name, value in super().items() if name not in self._READ_ONLY_EXCLUDED]

    def values(self):
        return [value for name, value in self.items()]

    def keys(self):
        return super().keys()

    def __iter__(self):
        return super().__iter__()


TOOL_REGISTRY: ToolRegistry = ToolRegistry({
    "workspace_inspector": {
        "function": inspect_workspace,
        "description": "Inspect files and directories in the authorized workspace.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "relevant_file_selector": {
        "function": select_relevant_files,
        "description": "Select candidate files relevant to the user's request.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "error_detector": {
        "function": detect_python_errors,
        "description": "Detect Python syntax or parse errors in source files.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "logic_inspector": {
        "function": inspect_python_logic,
        "description": "Read Python source and inspect logic without executing it.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "runtime_inspector": {
        "function": run_python_file,
        "description": "Run a safe authorized Python file and capture runtime evidence.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "terminal_inspector": {
        "function": analyze_terminal_output,
        "description": "Analyze supplied terminal output as bounded, redacted evidence.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "log_inspector": {
        "function": inspect_log_file,
        "description": "Read a bounded log file from the authorized workspace.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "git_inspector": {
        "function": inspect_git_repository,
        "description": "Inspect bounded, read-only Git state for the authorized workspace.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "browser_observer": {
        "function": observe_browser_page,
        "description": "Observe bounded evidence from one authorized HTTP(S) page without browser actions.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "browser_navigate_observed": {
        "function": navigate_observed_page,
        "description": "Navigate only to the currently observed authorized page URL.",
        "read_only": False,
        "requires_approval": True,
        "allowed": True,
    },
    "browser_follow_observed_link": {
        "function": follow_observed_link,
        "description": "Follow only an exact HTTP(S) link present in the observed page.",
        "read_only": False,
        "requires_approval": True,
        "allowed": True,
    },
    "browser_controller": {
        "function": browser_controller_entrypoint,
        "description": "Bounded local browser automation using only grounded page observations and explicit public HTTP(S) targets.",
        "read_only": False,
        "requires_approval": True,
        "allowed": True,
    },
    "desktop_observer": {
        "function": observe_desktop,
        "description": "Observe bounded visible desktop and foreground-window metadata without control actions.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "desktop_focus_authorized_window": {
        "function": focus_authorized_window,
        "description": "Focus one exact allowlisted window grounded in prior observation.",
        "read_only": False,
        "requires_approval": True,
        "allowed": True,
    },
    "desktop_minimize_authorized_window": {
        "function": minimize_authorized_window,
        "description": "Minimize one exact allowlisted window grounded in prior observation.",
        "read_only": False,
        "requires_approval": True,
        "allowed": True,
    },
    "desktop_restore_authorized_window": {
        "function": restore_authorized_window,
        "description": "Restore one exact allowlisted window grounded in prior observation.",
        "read_only": False,
        "requires_approval": True,
        "allowed": True,
    },
    "security_scan": {
        "function": scan_target,
        "description": "Run a bounded read-only local security scan on an authorized workspace target.",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    },
    "fixer": {
        "function": fix_python_logic,
        "description": "Apply an exact approved Python source replacement through the authoritative executor.",
        "read_only": False,
        "requires_approval": True,
        "allowed": True,
    },
    "personal_file_observer": {
        "function": observe_personal_file,
        "description": "Observe bounded authorized personal documents without modifying or exporting them.",
        "application": "personal_data",
        "capability": "DOCUMENT_OBSERVE",
        "target_type": "authorized_document",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "image_observer": {
        "function": observe_personal_file,
        "description": "Observe bounded metadata and basic properties of an authorized local image.",
        "application": "personal_data",
        "capability": "IMAGE_OBSERVE",
        "target_type": "authorized_image",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "document_observer": {
        "function": observe_document,
        "description": "Observe bounded local document text, facts, and provenance without execution.",
        "application": "personal_data",
        "capability": "DOCUMENT_INTELLIGENCE",
        "target_type": "authorized_document",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "document_comparator": {
        "function": compare_documents,
        "description": "Compare two authorized local documents without modifying either document.",
        "application": "personal_data",
        "capability": "DOCUMENT_COMPARE",
        "target_type": "authorized_document_pair",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "calendar_observer": {
        "function": observe_calendar,
        "description": "Observe bounded, read-only calendar events and deadlines without mutating calendar state.",
        "application": "calendar",
        "capability": "CALENDAR_OBSERVE",
        "target_type": "authorized_calendar",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "calendar_event_action": {
        "function": calendar_event_action,
        "description": "Apply one exact, grounded calendar mutation (create/update/delete/cancel) through the approval path.",
        "application": "calendar",
        "capability": "CALENDAR_MUTATE",
        "target_type": "grounded_calendar_event",
        "read_only": False,
        "requires_approval": True,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
        "operation": "EXECUTE",
    },
    "email_observer": {
        "function": observe_email,
        "description": "Observe bounded, read-only email messages, threads, and intelligence without sending or mutating email state.",
        "application": "email",
        "capability": "EMAIL_OBSERVE",
        "target_type": "authorized_mailbox",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "email_draft_preparation": {
        "function": prepare_reply_draft,
        "description": "Prepare one grounded reply draft bound to an observed message. Read-only; never sends automatically.",
        "application": "email",
        "capability": "EMAIL_DRAFT",
        "target_type": "grounded_email_draft",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "email_send_action": {
        "function": email_send_action,
        "description": "Send one exact, grounded email reply to the observed message sender through the approval path.",
        "application": "email",
        "capability": "EMAIL_SEND",
        "target_type": "grounded_email_reply",
        "read_only": False,
        "requires_approval": True,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
        "operation": "EXECUTE",
    },
    "comms_observer": {
        "function": observe_comms,
        "description": "Observe bounded, read-only provider-independent communication messages, conversations, channels, and intelligence without sending or mutating any communication state.",
        "application": "comms",
        "capability": "COMMS_OBSERVE",
        "target_type": "authorized_communication_access",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "comms_draft_preparation": {
        "function": prepare_comms_draft,
        "description": "Prepare one grounded communication reply draft bound to an observed message. Read-only; never sends automatically.",
        "application": "comms",
        "capability": "COMMS_DRAFT",
        "target_type": "grounded_communication_draft",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "comms_send_action": {
        "function": comms_send_action,
        "description": "Send one exact, grounded communication reply to the observed message sender and conversation through the approval path.",
        "application": "comms",
        "capability": "COMMS_SEND",
        "target_type": "grounded_communication_reply",
        "read_only": False,
        "requires_approval": True,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
        "operation": "EXECUTE",
    },
    "attention_observer": {
        "function": observe_attention,
        "description": "Observe a bounded, read-only cross-application attention snapshot so nothing that needs attention is missed.",
        "application": "attention",
        "capability": "ATTENTION_OBSERVE",
        "target_type": "authorized_workspace_context",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "job_search": {
        "function": search_jobs,
        "description": "Search bounded fixture or mock internship/job postings with explicit terms; never fabricates postings.",
        "application": "job_search",
        "capability": "JOB_SEARCH",
        "target_type": "job_board_queries",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "job_details": {
        "function": get_job_details,
        "description": "Get one observed job posting by identifier, including requirements and verification gates.",
        "application": "job_search",
        "capability": "JOB_DETAILS",
        "target_type": "observed_job_posting",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "application_requirements": {
        "function": get_application_requirements,
        "description": "Extract explicit application requirements from one observed posting without executing posting content.",
        "application": "job_search",
        "capability": "JOB_DETAILS",
        "target_type": "observed_job_posting",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "application_preparation": {
        "function": prepare_application,
        "description": "Build an application proposal grounded only in the truthful profile and explicit posting requirements; missing data returns NEEDS_USER_INPUT.",
        "application": "application",
        "capability": "APPLICATION_PREPARE",
        "target_type": "grounded_application_proposal",
        "read_only": True,
        "requires_approval": False,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
    },
    "job_application_fill_action": {
        "function": execute_adapter_action,
        "description": "Fill one authorized fixture/mock application form with prepared, truthful content through the approval path.",
        "application": "application",
        "capability": "APPLICATION_FILL",
        "target_type": "authorized_application_form",
        "read_only": False,
        "requires_approval": True,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
        "operation": "EXECUTE",
    },
    "job_application_submit_action": {
        "function": execute_adapter_action,
        "description": "Submit one filled fixture/mock application through a second explicit approval. Always consequential.",
        "application": "application",
        "capability": "APPLICATION_SUBMIT",
        "target_type": "authorized_application_submission",
        "read_only": False,
        "requires_approval": True,
        "requires_verification": True,
        "authorization_required": True,
        "allowed": True,
        "operation": "EXECUTE",
    },
})

ALLOWED_MODIFICATION_TOOLS = {"fixer", "calendar_event_action", "email_send_action", "comms_send_action", "job_application_fill_action", "job_application_submit_action"}
MODIFICATION_TOOL_RISKS = {"fixer": "MEDIUM_RISK"}

for _tool_info in TOOL_REGISTRY.values():
    _tool_info.setdefault("risk_level", READ_ONLY)
    _tool_info.setdefault("application", "workspace")
    _tool_info.setdefault("capability", "observe" if _tool_info.get("read_only") else "act")
    _tool_info.setdefault("operation", "READ" if _tool_info.get("read_only") else "EXECUTE")
    _tool_info.setdefault("authorization_required", True)
    _tool_info.setdefault("requires_verification", not _tool_info.get("read_only", False))
    _tool_info.setdefault("supported_target", "authorized_workspace" if _tool_info.get("read_only") else "grounded_target")
    _tool_info.setdefault("allowed_arguments", [])

# Keep action tools available via direct indexing while read-only scans still exercise the safe allowlist.
TOOL_REGISTRY["browser_controller"]["read_only"] = False
TOOL_REGISTRY["browser_controller"]["requires_approval"] = True


def get_tool_risk(tool_name: str, **kwargs: Any) -> dict[str, Any]:
    if tool_name in MODIFICATION_TOOL_RISKS:
        return evaluate_risk(
            tool_name,
            tool_name=tool_name,
            target_path=kwargs.get("target_path"),
            workspace_root=kwargs.get("workspace_root"),
        )
    if tool_name in TOOL_REGISTRY:
        return evaluate_tool_risk(tool_name, workspace_root=kwargs.get("workspace_root"))
    return evaluate_risk(tool_name, workspace_root=kwargs.get("workspace_root"))


def validate_tool_plan(raw_plan: list[str]) -> list[str]:
    """Validate planner output against the allowlist and enforce bounded tool selection."""

    trusted: list[str] = []
    seen: set[str] = set()

    for name in raw_plan:
        if not isinstance(name, str):
            continue

        tool_name = name.strip()
        if not tool_name:
            continue

        if tool_name in ALLOWED_MODIFICATION_TOOLS:
            continue

        if tool_name not in TOOL_REGISTRY:
            continue

        if tool_name in seen:
            continue

        trusted.append(tool_name)
        seen.add(tool_name)

        if len(trusted) >= MAX_TOOLS_PER_PLAN:
            break

    return trusted


def get_trusted_tool_plan(user_request: str) -> list[str]:
    """Choose the minimum allowlisted tool plan justified by the request."""

    request = user_request.lower()
    tool_names: list[str] = []
    browser_indicated = any(
        term in request
        for term in (
            "browser",
            "chrome",
            "web page",
            "webpage",
            "observe page",
            "observe url",
            "http://",
            "https://",
            "open ",
            "navigate to",
            "go to",
            "visit",
        )
    )
    git_requested = any(
        term in request
        for term in ["git", "branch", "commit", "repository", "repo", "changed files", "working tree"]
    )

    def finalize_plan(names: list[str]) -> list[str]:
        if git_requested and not browser_indicated and "git_inspector" not in names:
            names.append("git_inspector")
        return validate_tool_plan(names)

    action_requested = any(term in request for term in ("ask for my approval", "requires approval", "before taking", "before interacting", "before making"))
    if any(term in request for term in ("malware", "threat scan", "security scan", "antivirus")):
        return finalize_plan(["security_scan"])

    attention_topics = any(term in request for term in (
        "attention",
        "what needs my attention",
        "what should i do",
        "what should i focus",
        "anything urgent",
        "anything important",
        "what's on my plate",
        "what is on my plate",
        "upcoming deadlines",
        "overdue",
        "what deserves my attention",
        "what should i prioritize",
        "attention summary",
        "any deadlines",
    ))
    calendar_topics = any(term in request for term in ("calendar", "meeting", "appointment", "upcoming events", "schedule", "availability", "event on", "deadline", "calendar event", "events due"))
    calendar_mutations = any(term in request for term in ("add a calendar", "add calendar", "create a calendar", "create calendar", "add an event", "add a meeting", "schedule a meeting", "schedule an appointment", "add an appointment", "delete the event", "delete event", "remove the event", "remove event", "update the event", "update event", "update the calendar", "cancel the event", "cancel event", "cancel the meeting", "reschedule the event", "reschedule event", "set a reminder", "add a deadline"))
    if calendar_topics or calendar_mutations:
        return finalize_plan(["calendar_observer"])

    if attention_topics:
        return finalize_plan(["attention_observer"])

    comms_requested = any(term in request for term in ("reply on slack", "reply in slack", "reply in teams", "reply in the channel", "reply to the conversation", "reply in the conversation", "reply to the chat", "reply to the message in the channel", "reply to the message in the conversation", "post in the channel", "respond in the channel", "respond in the conversation", "message in the channel", "message in the conversation", "send a message in", "reply in discord"))
    comms_topics = any(term in request for term in ("slack", "teams", "discord", "conversation", "channel", "chat messages", "unread messages", "communications", "comms_observer"))
    if comms_requested or comms_topics:
        return finalize_plan(["comms_observer"])

    email_requested = any(term in request for term in ("reply by email", "reply to the email", "reply to the observed email", "respond by email", "respond to the email", "reply to the message", "send a reply email", "send a reply to", "acknowledge the email", "acknowledge the message"))
    email_topics = any(term in request for term in ("email", "messages", "inbox", "unread", "unanswered", "thread", "deadline emails", "action required", "follow-up email", "follow up emails"))
    if email_requested or email_topics:
        return finalize_plan(["email_observer"])

    job_requested = any(term in request for term in ("internship", "job posting", "job postings", "job board", "find a job", "find an internship", "search jobs", "search internships", "look for internship", "look for a job", "open role", "openings"))
    if job_requested:
        return finalize_plan(["job_search"])

    if any(term in request for term in ("focus an authorized", "minimize an authorized", "restore an authorized", "interact with it", "interacting with it")):
        names = ["desktop_observer"]
        if action_requested:
            if "minimize" in request:
                names.append("desktop_minimize_authorized_window")
            elif "restore" in request:
                names.append("desktop_restore_authorized_window")
            else:
                names.append("desktop_focus_authorized_window")
        return finalize_plan(names)

    if any(term in request for term in ("navigate using", "follow the observed", "click the observed", "navigate to the observed", "take the navigation action")):
        return finalize_plan(["browser_observer", "browser_follow_observed_link"])

    interactive_browser_requested = any(term in request for term in (
        "real browser",
        "actual browser",
        "headless browser",
        "playwright",
        "chromium",
        "open this webpage in",
        "open the page in",
        "open the webpage in",
        "click the grounded",
        "type into the",
        "interact with the page",
        "interacting with the page",
        "navigate to the next page",
    ))
    if interactive_browser_requested and ("http://" in request or "https://" in request):
        # Interactive behavior: read-only observation plus the approval-gated
        # controller. Registry dispatch stays fail-closed for the controller
        # (consequential tools only execute via the Action Executor); the
        # legacy investigator also filters consequential tools out, so this
        # selection only records intent, never launches a browser here.
        return finalize_plan(["browser_observer", "browser_controller"])

    if any(term in request for term in ("open youtube", "youtube", "browser", "chrome", "web page", "webpage", "observe page", "observe url", "http://", "https://", "open ")) and not any(term in request for term in ("do not open", "without opening")):
        return finalize_plan(["browser_observer"])

    if any(term in request for term in ["desktop", "foreground window", "active window", "visible application", "open windows"]):
        return finalize_plan(["desktop_observer"])

    if any(term in request for term in ["security scan", "security issue", "malware scan", "antivirus", "threat scan"]):
        return finalize_plan(["security_scan"])

    if any(term in request for term in ["terminal", "stderr", "stdout", "log", "runtime error", "traceback", "error output", "application log"]):
        if "log" in request and "terminal" not in request:
            tool_names.append("log_inspector")
        else:
            tool_names.append("terminal_inspector")
        if "log" in request:
            tool_names.append("log_inspector")
        return finalize_plan(tool_names)

    modification_terms = ("modify ", "edit ", "change ", "update ", "write ", "fix ")
    modification_prohibited = any(term in request for term in ("do not modify", "do not make any changes", "without modifying", "no automatic remediation"))
    if any(term in request for term in modification_terms) and not modification_prohibited:
        return finalize_plan(["relevant_file_selector", "logic_inspector"])

    if any(term in request for term in ["read ", "read file", "explain", "what this program does", "what this file does", "understand this file", "understand this program", "explain what this program does", "what kind of project", "what type of project"]):
        if any(term in request for term in [".py", "program", "file", "code", "project", "workspace"]):
            tool_names.append("logic_inspector")
            if "project" in request or "workspace" in request:
                tool_names.insert(0, "relevant_file_selector")
            return finalize_plan(tool_names)

    if any(term in request for term in ["syntax", "parse", "error", "invalid", "traceback", "lint"]):
        tool_names.append("error_detector")
        return finalize_plan(tool_names)

    if any(term in request for term in ["which files", "relevant files", "what files", "file selection", "bug", "project"]):
        tool_names.append("relevant_file_selector")
        if any(term in request for term in ["logic", "why", "understand", "reading", "code"]):
            tool_names.append("logic_inspector")
        return finalize_plan(tool_names)

    if any(term in request for term in ["crash", "runtime", "run", "fails", "exception", "not working"]):
        tool_names = ["runtime_inspector", "error_detector"]
        if any(term in request for term in ["which files", "relevant", "bug", "project", "application", "python"]):
            tool_names.insert(0, "relevant_file_selector")
        if "log" in request or "terminal" in request:
            tool_names.append("terminal_inspector")
        return finalize_plan(tool_names)

    if any(term in request for term in ["logic", "understand", "why", "code", "reading"]):
        tool_names.append("logic_inspector")
        if "project" in request:
            tool_names.insert(0, "relevant_file_selector")
        return finalize_plan(tool_names)

    if git_requested:
        tool_names.append("git_inspector")
    else:
        tool_names.append("workspace_inspector")
    return finalize_plan(tool_names)


def execute_selected_tools(tool_names: list[str], **kwargs: Any) -> list[dict[str, Any]]:
    """Execute only trusted, allowlisted tools with application-controlled arguments."""

    results: list[dict[str, Any]] = []

    for tool_name in validate_tool_plan(tool_names):
        tool_info = TOOL_REGISTRY[tool_name]

        if not tool_info.get("read_only", True):
            results.append({
                "tool": tool_name,
                "status": "blocked",
                "result": "Consequential tools may only execute through the durable Action Executor approval chain; registry dispatch is fail-closed for read-only evidence collection.",
            })
            continue

        function = tool_info["function"]

        try:
            risk_decision = get_tool_risk(tool_name, workspace_root=kwargs.get("workspace_path", "workspace"))
            if not risk_decision["allowed"]:
                results.append({
                    "tool": tool_name,
                    "status": "blocked",
                    "risk_decision": risk_decision,
                    "result": risk_decision["reason"],
                })
                continue

            argument_payload: dict[str, Any] = {}
            if tool_name == "workspace_inspector":
                argument_payload["workspace_path"] = kwargs.get("workspace_path", "workspace")
            elif tool_name == "relevant_file_selector":
                argument_payload["workspace_path"] = kwargs.get("workspace_path", "workspace")
                argument_payload["user_request"] = kwargs.get("user_request", "")
                argument_payload["max_files"] = kwargs.get("max_files", 10)
            elif tool_name == "error_detector":
                argument_payload["workspace_path"] = kwargs.get("workspace_path", "workspace")
            elif tool_name == "logic_inspector":
                argument_payload["workspace_path"] = kwargs.get("workspace_path", "workspace")
                argument_payload["file_names"] = kwargs.get("file_names")
            elif tool_name == "runtime_inspector":
                argument_payload["workspace_path"] = kwargs.get("workspace_path", "workspace")
                argument_payload["file_name"] = kwargs.get("file_name", "shop_project.py")
                argument_payload["timeout_seconds"] = kwargs.get("timeout_seconds", 30)
            elif tool_name == "terminal_inspector":
                argument_payload["output"] = kwargs.get("terminal_output", "")
            elif tool_name == "log_inspector":
                argument_payload["workspace_path"] = kwargs.get("workspace_path", "workspace")
                argument_payload["log_path"] = kwargs.get("log_path", "")
            elif tool_name == "git_inspector":
                argument_payload["workspace_path"] = kwargs.get("workspace_path", "workspace")
            elif tool_name == "browser_observer":
                argument_payload["url"] = kwargs.get("url", "")
            elif tool_name == "browser_controller":
                argument_payload["action"] = kwargs.get("action", "open_page")
                argument_payload["url"] = kwargs.get("url", "")
                argument_payload["page_id"] = kwargs.get("page_id", "")
                argument_payload["grounded_id"] = kwargs.get("grounded_id", "")
                argument_payload["value"] = kwargs.get("value", "")
                argument_payload["approved"] = kwargs.get("approved", False)
                argument_payload["action_count"] = kwargs.get("action_count", 0)
                argument_payload["timeout_seconds"] = kwargs.get("timeout_seconds", 15)
                argument_payload["capability_context"] = kwargs.get("capability_context")
            elif tool_name == "desktop_observer":
                argument_payload = {"capability_context": kwargs.get("capability_context")}
            elif tool_name == "calendar_observer":
                argument_payload["provider"] = kwargs.get("calendar_provider", "fixture")
                argument_payload["capability_context"] = kwargs.get("capability_context")
            elif tool_name == "email_observer":
                argument_payload["provider"] = kwargs.get("email_provider", "fixture")
                argument_payload["capability_context"] = kwargs.get("capability_context")
            elif tool_name == "email_draft_preparation":
                argument_payload["request"] = kwargs.get("user_request", "")
                argument_payload["message"] = kwargs.get("email_grounding_message", {})
                argument_payload["provider_name"] = kwargs.get("email_provider", "fixture")
                argument_payload["task_id"] = kwargs.get("task_id", "")
            elif tool_name == "comms_observer":
                argument_payload["provider"] = kwargs.get("comms_provider", "comms")
                argument_payload["capability_context"] = kwargs.get("capability_context")
            elif tool_name == "attention_observer":
                argument_payload["provider_name"] = kwargs.get("attention_provider", kwargs.get("email_provider", "fixture"))
                argument_payload["capability_context"] = kwargs.get("capability_context")
                argument_payload["workspace_path"] = kwargs.get("workspace_path", "workspace")
                if kwargs.get("approx_attention"):
                    argument_payload["approx"] = kwargs.get("approx_attention")
            elif tool_name == "comms_draft_preparation":
                argument_payload["provider_name"] = kwargs.get("comms_provider", "comms")
                argument_payload["message_id"] = kwargs.get("comms_grounding_message_id", "")
                argument_payload["draft_body"] = kwargs.get("user_request", "")
                argument_payload["requested_by"] = kwargs.get("actor", "operator")
            elif tool_name == "security_scan":
                argument_payload["target"] = kwargs.get("security_scan_target", "")
                argument_payload["workspace_root"] = kwargs.get("workspace_path", "workspace")
            elif tool_name in {
                "desktop_focus_authorized_window",
                "desktop_minimize_authorized_window",
                "desktop_restore_authorized_window",
            }:
                argument_payload["action"] = kwargs.get("desktop_action", {})
                argument_payload["observation"] = kwargs.get("desktop_observation", {})
                argument_payload["approved"] = kwargs.get("approved", False)
                argument_payload["action_count"] = kwargs.get("action_count", 0)
                argument_payload["capability_context"] = kwargs.get("capability_context")
            elif tool_name == "job_search":
                argument_payload["query"] = kwargs.get("job_search_query", kwargs.get("user_request", ""))
                argument_payload["provider"] = kwargs.get("job_provider", "fixture_jobs")
                argument_payload["capability_context"] = kwargs.get("capability_context")
            elif tool_name == "job_details":
                argument_payload["job_id"] = kwargs.get("job_id", "")
                argument_payload["provider"] = kwargs.get("job_provider", "fixture_jobs")
                argument_payload["capability_context"] = kwargs.get("capability_context")
            elif tool_name in {"application_requirements", "application_preparation"}:
                argument_payload["job_id"] = kwargs.get("job_id", "")
                argument_payload["provider"] = kwargs.get("application_provider", "fixture_application")
                argument_payload["capability_context"] = kwargs.get("capability_context")
            elif tool_name in {"job_application_fill_action", "job_application_submit_action"}:
                argument_payload["action_type"] = tool_name
                argument_payload["spec"] = kwargs.get("adapter_action_spec", {})
                argument_payload["approved"] = kwargs.get("approved", False)
                argument_payload["capability_context"] = kwargs.get("capability_context")
            elif tool_name in {"browser_navigate_observed", "browser_follow_observed_link"}:
                argument_payload["action"] = kwargs.get("browser_action", {})
                argument_payload["observed_page"] = kwargs.get("observed_page", {})
                argument_payload["approved"] = kwargs.get("approved", False)
                argument_payload["action_count"] = kwargs.get("action_count", 0)
                argument_payload["revalidator"] = kwargs.get("browser_revalidator")

            result = redact_sensitive_data(function(**argument_payload))
            results.append({
                "tool": tool_name,
                "status": "ok",
                "risk_decision": risk_decision,
                "result": result,
            })
        except Exception as error:  # pragma: no cover - defensive guard
            results.append({
                "tool": tool_name,
                "status": "failed",
                "result": f"Tool execution failed: {error}",
            })

    return results


def resolve_tool_permission(tool_name: str) -> dict[str, Any]:
    """Resolve the deterministic tool → capability → action_class binding.

    The binding is derived from this registry's own metadata, so there is no
    second permission registry to keep in sync:

    - capability comes from the entry's ``capability`` field (explicit values
      such as CALENDAR_MUTATE/EMAIL_SEND, otherwise the registry defaults
      ``observe`` for read-only tools and ``act`` for consequential tools).
    - action_class comes from the entry's ``operation`` field when it names a
      valid permission action class (READ for read-only tools, EXECUTE for
      consequential tools), and otherwise falls back deterministically to
      READ for read_only tools and EXECUTE for consequential tools.

    Unknown or disallowed tools raise ValueError so permission gates fail
    closed. Note that several consequential tools intentionally share the
    default ``act`` capability; finer-grained per-tool capabilities can be
    added here later without changing this function.
    """

    from app.security.permission_authority import ACTION_CLASSES

    name = str(tool_name or "").strip()
    metadata = TOOL_REGISTRY.get(name)
    if not metadata or not metadata.get("allowed"):
        raise ValueError(f"Tool is not authorized by the Tool Registry: {tool_name}")
    # Mirror this registry's own default convention: entries excluded from the
    # read-only filtered view (fixer, browser_controller) never received the
    # setdefault pass, so the same observe/act + READ/EXECUTE defaults apply
    # here instead of failing or inventing a parallel mapping.
    read_only = bool(metadata.get("read_only", False))
    capability = str(metadata.get("capability") or ("observe" if read_only else "act")).strip().upper()
    if not capability:
        raise ValueError(f"Tool has no permission capability: {tool_name}")
    operation = str(metadata.get("operation") or ("READ" if read_only else "EXECUTE")).strip().upper()
    if operation in ACTION_CLASSES:
        action_class = operation
    elif read_only:
        action_class = "READ"
    else:
        action_class = "EXECUTE"
    return {
        "tool_name": name,
        "capability": capability,
        "action_class": action_class,
        "read_only": bool(metadata.get("read_only", False)),
    }
