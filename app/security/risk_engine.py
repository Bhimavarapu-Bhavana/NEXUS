from __future__ import annotations

from pathlib import Path
from typing import Any

from app.security.permissions import get_authorized_workspace, is_authorized_path

READ_ONLY = "READ_ONLY"
LOW_RISK = "LOW_RISK"
MEDIUM_RISK = "MEDIUM_RISK"
HIGH_RISK = "HIGH_RISK"
BLOCKED = "BLOCKED"

BROWSER_ACTION_TOOLS = {"browser_navigate_observed", "browser_follow_observed_link", "browser_controller"}
DESKTOP_ACTION_TOOLS = {
    "desktop_focus_authorized_window",
    "desktop_minimize_authorized_window",
    "desktop_restore_authorized_window",
}
CALENDAR_ACTION_TOOLS = {"calendar_event_action"}
EMAIL_ACTION_TOOLS = {"email_send_action"}
COMMS_ACTION_TOOLS = {"comms_send_action"}
JOB_READ_ONLY_TOOLS = {"job_search", "job_details", "application_requirements", "application_preparation"}
APPLICATION_FILL_TOOL = "job_application_fill_action"
APPLICATION_SUBMIT_TOOL = "job_application_submit_action"
APPLICATION_CONSEQUENTIAL_TOOLS = {APPLICATION_FILL_TOOL, APPLICATION_SUBMIT_TOOL}

RESTRICTED_PARTS = {".env", ".git", ".venv", "__pycache__", "node_modules"}
RESTRICTED_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
DESTRUCTIVE_GIT_TERMS = {
    "git push",
    "git reset",
    "git checkout",
    "git switch",
    "git clean",
    "git rebase",
    "git merge",
    "git revert",
    "git branch -d",
    "git branch --delete",
}
BLOCKED_TERMS = (
    "arbitrary command",
    "shell command",
    "shell execution",
    "subprocess",
    "execute command",
    "credentials",
    "secrets access",
    "private key",
    "workspace escape",
    "outside the workspace",
    "unauthorized path",
    "purchase",
    "payment",
    "destructive action",
    "delete remote",
)
HIGH_RISK_TERMS = (
    "send email",
    "send message",
    "external communication",
    "submit form",
    "browser submit",
    "delete",
    "wipe",
    "format disk",
    "many files",
    "bulk modification",
    "external action",
)
MEDIUM_RISK_TERMS = (
    "modify",
    "write file",
    "create file",
    "apply fix",
    "apply code fix",
    "edit source",
    "change source",
    "fixer",
)
LOW_RISK_TERMS = (
    "temporary analysis artifact",
    "temporary artifact",
    "local preparation",
    "non-destructive preparation",
)
READ_ONLY_TERMS = (
    "inspect",
    "read",
    "analyze",
    "status",
    "diff",
    "log",
    "branch",
    "terminal evidence",
    "memory",
    "browser observation",
    "observe browser",
    "observe page",
    "desktop observation",
    "observe desktop",
    "desktop application",
    "active window",
    "foreground application",
)


def _decision(
    risk_level: str,
    allowed: bool,
    approval_required: bool,
    reason: str,
    category: str,
) -> dict[str, Any]:
    return {
        "risk_level": risk_level,
        "allowed": allowed,
        "approval_required": approval_required,
        "reason": reason,
        "category": category,
    }


def _restricted_path(path: str, workspace_root: str | Path | None) -> bool:
    candidate = Path(path)
    root = Path(workspace_root).resolve() if workspace_root is not None else Path(get_authorized_workspace()).resolve()
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    if not is_authorized_path(str(resolved), root):
        return True
    parts = {part.lower() for part in resolved.parts}
    return bool(parts & RESTRICTED_PARTS) or resolved.name.lower() in RESTRICTED_NAMES


def evaluate_risk(
    action: str,
    *,
    target_path: str | Path | None = None,
    workspace_root: str | Path | None = None,
    tool_name: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic permission decision for a proposed action.

    The action text is evidence only. It cannot provide or override the result.
    Unknown actions fail closed as BLOCKED.
    """

    description = " ".join(str(action or "").lower().split())
    tool = str(tool_name or "").lower().strip()

    if target_path is not None and _restricted_path(str(target_path), workspace_root):
        return _decision(BLOCKED, False, False, "Target path is outside or restricted by the authorized workspace policy.", "PATH_SECURITY")

    if any(term in description for term in DESTRUCTIVE_GIT_TERMS):
        return _decision(BLOCKED, False, False, "Destructive Git operations are prohibited.", "DESTRUCTIVE_GIT")

    if any(term in description for term in BLOCKED_TERMS):
        return _decision(BLOCKED, False, False, "The action matches a prohibited execution or secret-access operation.", "PROHIBITED_ACTION")

    if any(term in description for term in HIGH_RISK_TERMS):
        return _decision(HIGH_RISK, True, True, "The action is consequential and requires explicit human approval.", "CONSEQUENTIAL_ACTION")

    if tool in BROWSER_ACTION_TOOLS:
        return _decision(MEDIUM_RISK, True, True, "The grounded browser action requires human approval.", "BROWSER_ACTION")

    if tool in DESKTOP_ACTION_TOOLS:
        return _decision(MEDIUM_RISK, True, True, "The grounded desktop action requires human approval.", "DESKTOP_ACTION")

    if tool in CALENDAR_ACTION_TOOLS:
        return _decision(MEDIUM_RISK, True, True, "The calendar action modifies calendar state and requires human approval.", "CALENDAR_ACTION")

    if tool in EMAIL_ACTION_TOOLS:
        return _decision(MEDIUM_RISK, True, True, "The email action sends bounded content and requires human approval.", "EMAIL_ACTION")

    if tool in COMMS_ACTION_TOOLS:
        return _decision(MEDIUM_RISK, True, True, "The communication action sends bounded content and requires human approval.", "COMMS_ACTION")

    if tool == APPLICATION_SUBMIT_TOOL:
        return _decision(HIGH_RISK, True, True, "Submitting a job application is always consequential and requires explicit human approval.", "JOB_APPLICATION_SUBMIT")

    if tool == APPLICATION_FILL_TOOL:
        return _decision(MEDIUM_RISK, True, True, "Filling a job application form is consequential and requires human approval.", "JOB_APPLICATION_FILL")

    if tool in JOB_READ_ONLY_TOOLS:
        return _decision(READ_ONLY, True, False, "The job or application preparation tool only observes or drafts bounded local evidence.", "JOB_READ_ONLY")

    if tool == "fixer" or any(term in description for term in MEDIUM_RISK_TERMS):
        return _decision(MEDIUM_RISK, True, True, "The action modifies authorized workspace content and requires human approval.", "WORKSPACE_MODIFICATION")

    if any(term in description for term in LOW_RISK_TERMS):
        return _decision(LOW_RISK, True, False, "The action is bounded, local, and non-destructive.", "LOCAL_PREPARATION")

    if tool in {"workspace_inspector", "relevant_file_selector", "error_detector", "logic_inspector", "runtime_inspector", "terminal_inspector", "log_inspector", "git_inspector", "browser_observer", "desktop_observer", "security_scan", "personal_file_observer", "image_observer", "document_observer", "document_comparator", "calendar_observer", "email_observer", "email_draft_preparation", "comms_observer", "comms_draft_preparation", "attention_observer", "job_search", "job_details", "application_requirements", "application_preparation"}:
        return _decision(READ_ONLY, True, False, "The registered tool is read-only evidence collection.", "READ_ONLY_TOOL")

    if any(term in description for term in READ_ONLY_TERMS):
        return _decision(READ_ONLY, True, False, "The action only observes or analyzes local evidence.", "READ_ONLY")

    return _decision(BLOCKED, False, False, "The action could not be deterministically classified as safe.", "UNKNOWN_ACTION")


def classify_action(action: str, **kwargs: Any) -> dict[str, Any]:
    """Compatibility alias for deterministic risk evaluation."""

    return evaluate_risk(action, **kwargs)


def evaluate_tool_risk(tool_name: str, **kwargs: Any) -> dict[str, Any]:
    return evaluate_risk(tool_name, tool_name=tool_name, **kwargs)
