import os
import re
import sys
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from langgraph.graph import StateGraph, END

from app.agent.state import NexusState

from app.tools.workspace_inspector import inspect_workspace
from app.tools.relevant_file_selector import select_relevant_files
from app.tools.code_inspector import inspect_python_files
from app.tools.logic_inspector import inspect_python_logic
from app.tools.error_detector import detect_python_errors
from app.tools.runtime_inspector import run_python_file
from app.tools.diagnoser import diagnose_problem
from app.tools.fixer import fix_python_logic
from app.memory.sqlite_memory import search_memory, store_memory
from app.memory.task_ledger import create_task, get_task, update_task_status
from app.tools.tool_registry import execute_selected_tools, get_trusted_tool_plan, resolve_tool_permission
from app.tools.workspace_monitor import WorkspaceMonitor
from app.security.sensitive_data import redact_text
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.audit_logger import record_audit_event
from app.security.permission_authority import check_permission_before_execution
from app.security.user_dna import check_authorization, get_effective_preferences
from app.security.privacy_policy import evaluate_privacy
from app.security.automation_scope import check_scope, scope_area_for_tool
from app.agent.personal_capabilities import classify_data
from app.tools.browser_actions import ACTION_TIMEOUT_SECONDS
from app.tools.browser_observer import extract_requested_url, observe_browser_page
from app.agent.evidence import correlate_evidence, build_reasoning_context, normalize_tool_results
from app.agent.goal_decomposition import decompose_goal
from app.agent.autonomous_policy import (
    FAILURE_CLASS_HUMAN_REQUIRED,
    FAILURE_CLASS_PERMANENT_FAILURE,
    FAILURE_CLASS_SECURITY_BLOCK,
    FAILURE_CLASS_UNKNOWN,
    OUTCOME_EMPTY,
    OUTCOME_HUMAN_REQUIRED,
    OUTCOME_INVALID_TARGET,
    SUCCESSFUL_OUTCOMES,
    TERMINAL_FAILURE_STATUSES,
    MAX_RECOVERY_ATTEMPTS_PER_TASK,
    MAX_REPLAN_ATTEMPTS_PER_TASK,
    MAX_REVALIDATIONS_PER_SUBGOAL,
    RECOVERY_DECISION_ALTERNATIVE_TOOL,
    RECOVERY_DECISION_FAIL_TERMINALLY,
    RECOVERY_DECISION_PAUSE_FOR_HUMAN,
    RECOVERY_DECISION_REBUILD_EVIDENCE,
    RECOVERY_DECISION_REPLAN,
    RECOVERY_DECISION_REVALIDATE_APPROVAL,
    RECOVERY_DECISION_REVALIDATE_CONTEXT,
    RECOVERY_DECISION_RETRY,
    alternative_capability_tool,
    bounded_next_action,
    can_auto_replan_failure_class,
    classify_failure,
    classify_failure_class,
    classify_subgoal_outcome,
    decide_recovery_for_failure_class,
    is_retryable_failure_class,
    make_plan_version,
    never_auto_retry_failure_class,
    next_ready_subgoal,
    plan_hash,
    plan_versions_are_compatible,
    validate_autonomous_plan,
)
from app.agent.capability_context import build_capability_context, evidence_hash
from app.adapters.application_context import build_application_context
from app.agent.approval_authority import create_approval, decide_approval, get_approval, validate_approval
from app.agent.action_executor import execute_authorized_action, proposal_hash
from app.agent.execution_journal import create_checkpoint, load_checkpoint, update_checkpoint
from app.calendar.actions import parse_calendar_request
from app.email.actions import parse_email_request
from app.comms.actions import parse_comms_request

MAX_RETRIES = 2
MAX_PHASE32_LOOP_STEPS = 20
CONTEXT_FRESHNESS_SECONDS = 600


def _set_decision(state: NexusState, stage: str, *, reason: str = "", final_outcome: str | None = None) -> None:
    state["decision_stage"] = stage
    if reason:
        state["decision_reason"] = reason
    if final_outcome is not None:
        state["final_outcome"] = final_outcome


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _audit_event(state: NexusState, event_type: str, *, fail_closed: bool = False, **payload: object) -> bool:
    stored = record_audit_event(event_type, **payload)
    if stored:
        return True

    state["audit_error"] = f"Audit persistence failed for event: {event_type}"
    if fail_closed:
        state["approved"] = False
        state["approval_required"] = False
    return False


def _reset_request_scoped_state(state: NexusState) -> None:
    """Clear transient evidence from prior requests so each independent invocation starts fresh."""
    transient_fields = {
        "observations": [],
        "priority": "",
        "selected_tool": "",
        "investigation": [],
        "plan": [],
        "target_file": "",
        "old_code": "",
        "new_code": "",
        "approval_required": False,
        "approved": False,
        "action_result": "",
        "verification": "",
        "retry_count": 0,
        "verification_history": [],
        "last_verification": "",
        "memory_context": "",
        "selected_tools": [],
        "selected_files": [],
        "observation_results": [],
        "action_tool": "",
        "action_spec": {},
        "action_target": "",
        "action_type": "",
        "approval_id": "",
        "journal_checkpoint_id": "",
        "proposal_hash": "",
        "execution_id": "",
        "tool_results": [],
        "workspace_event": "",
        "monitoring_active": True,
        "risk_decision": {},
        "audit_error": "",
        "browser_url": "",
        "normalized_evidence": [],
        "evidence_correlations": [],
        "evidence_conflicts": [],
        "reasoning_context": "",
        "decision_stage": "REQUEST",
        "decision_reason": "",
        "final_outcome": "",
        "user_constraints": {},
        "request_intent": "",
        "evidence_scope": "",
        "goal_plan": [],
        "goal_error": "",
        "task_resume_requested": False,
        "task_resume_reason": "",
        "task_context": "",
        "persistence_db_path": "",
        "journal_db_path": "",
        "approval_db_path": "",
        "permission_id": "",
        "permission_decision": {},
        "permission_db_path": "",
        "dna_db_path": "",
        "dna_preferences": [],
        "scope_decision": {},
        "scope_db_path": "",
        "privacy_decision": {},
    }
    for key, value in transient_fields.items():
        state[key] = value


def retrieve_memory(state: NexusState):
    state["user_request"] = redact_text(state.get("user_request", ""))
    state.setdefault("task_id", "")
    state.setdefault("task_status", "CREATED")
    stale_request_state = (
        not state.get("task_id")
        and bool(
            state.get("investigation")
            or state.get("selected_tools")
            or state.get("tool_results")
            or state.get("memory_context")
            or state.get("final_outcome")
            or state.get("decision_stage") not in {"", "REQUEST"}
        )
    )
    if stale_request_state:
        _reset_request_scoped_state(state)
    state.setdefault("decision_stage", "REQUEST")
    state.setdefault("decision_reason", "")
    state.setdefault("final_outcome", "")
    state.setdefault("task_resume_requested", False)
    state.setdefault("task_resume_reason", "")
    state.setdefault("task_context", "")

    if not state.get("task_id"):
        task = create_task(
            state["user_request"],
            current_stage="REQUEST",
            status="CREATED",
            status_reason="Task created for bounded investigation.",
            db_path=state.get("persistence_db_path") or None,
        )
        state["task_id"] = task["task_id"]
        state["task_status"] = task["status"]
        state["task_context"] = f"Task {task['task_id']} created for evaluation."

    task = get_task(state["task_id"], db_path=state.get("persistence_db_path") or None) if state.get("task_id") else None
    if task is not None:
        state["task_status"] = task["status"]
        state["task_context"] = task["status_output"]

    state.setdefault("goal_plan", [])
    state.setdefault("goal_error", "")
    state.setdefault("plan_version", "v1")
    state.setdefault("plan_hash", "")
    state.setdefault("plan_revisions", 0)
    state.setdefault("current_subgoal_id", "")
    state.setdefault("subgoal_statuses", {})
    state.setdefault("completed_subgoals", [])
    state.setdefault("pending_subgoals", [])
    state.setdefault("blocked_subgoals", [])
    state.setdefault("task_retry_count", 0)
    state.setdefault("subgoal_retry_count", {})
    state.setdefault("failure_classifications", {})
    state.setdefault("adaptation_history", [])
    state.setdefault("completion_evidence", [])
    state.setdefault("capability_context", {})
    state.setdefault("subgoal_contexts", {})
    state.setdefault("subgoal_lineage", {})
    state.setdefault("execution_ids", {})
    state.setdefault("consumed_execution_ids", [])
    state.setdefault("selected_files", [])
    state.setdefault("request_intent", "")
    state["evidence_scope"] = state.get("task_id", "")

    _set_decision(state, "REQUEST", reason="Request accepted for bounded investigation.")
    _audit_event(
        state,
        "request_received",
        actor="nexus",
        target="request",
        result="Request accepted for bounded investigation.",
    )
    query = state["user_request"]
    memory_context = "" if stale_request_state else search_memory(query, limit=5)
    state["memory_context"] = memory_context
    _audit_event(
        state,
        "memory_retrieval",
        actor="nexus",
        result="Memory retrieval completed.",
        metadata={"result_count": 0 if not memory_context else 1},
    )
    return state


def monitor_workspace(state: NexusState):
    if not state.get("monitoring_active", False):
        return state

    monitor = WorkspaceMonitor(workspace_path="workspace")
    monitor.start()
    events = monitor.poll_events()
    monitor.stop()

    if not events:
        state["workspace_event"] = ""
        return state

    latest = events[-1]
    state["workspace_event"] = (
        f"EVENT_TYPE: {latest['event_type']}\n"
        f"PATH: {latest['path']}\n"
        f"TIMESTAMP: {latest['timestamp']}"
    )
    state["user_request"] = (
        state.get("user_request", "")
        + "\nWORKSPACE_EVENT: " + state["workspace_event"]
    )
    return state


def should_resume_action(state: NexusState):
    return "execute_action" if state.get("task_resume_requested") and state.get("approved") else "monitor_workspace"


def _extract_explicit_constraints(request: str) -> dict[str, bool]:
    lower = (request or "").lower()
    return {
        "do_not_modify": "do not modify" in lower or "do not make any changes" in lower or "without modifying" in lower or "no automatic remediation" in lower,
        "do_not_propose_fixes": "do not propose any fixes" in lower or "do not propose fixes" in lower or "do not suggest fixes" in lower or "do not propose any fix" in lower,
    }


def _classify_request_intent(request: str, constraints: dict[str, bool] | None = None) -> str:
    lower = (request or "").lower()
    constraints = constraints or _extract_explicit_constraints(request)
    if any(term in lower for term in ("malware", "threat scan", "security scan", "antivirus")):
        return "SECURITY_SCAN_REQUEST"
    if any(term in lower for term in ("attention", "what needs my attention", "what should i do", "anything urgent", "anything important", "what's on my plate", "upcoming deadlines", "what deserves my attention", "what should i prioritize", "attention summary")):
        return "ATTENTION_REQUEST"
    if any(term in lower for term in ("focus an authorized", "minimize an authorized", "restore an authorized", "interact with it", "interacting with it")):
        return "DESKTOP_ACTION_REQUEST"
    if any(term in lower for term in ("navigate using", "follow the observed", "click the observed", "navigate to the observed", "take the navigation action")):
        return "BROWSER_ACTION_REQUEST"
    calendar_mutation = any(term in lower for term in
        ("add a calendar", "add calendar", "create a calendar", "create calendar",
         "add an event", "add a meeting", "add an appointment", "schedule a meeting",
         "schedule an appointment", "schedule a calendar", "add a deadline",
         "set a reminder", "delete the event", "delete event", "remove the event",
         "remove event", "remove the calendar entry", "update the event", "update event",
         "update the calendar", "change the event", "change event", "reschedule the event",
         "reschedule event", "cancel the event", "cancel event", "cancel the meeting",
         "cancel the appointment", "cancel the calendar"))
    if calendar_mutation:
        return "CALENDAR_ACTION_REQUEST"
    if any(term in lower for term in ("reply on slack", "reply in slack", "reply in teams", "reply in the channel", "reply to the conversation", "reply in the conversation", "reply to the chat", "reply to the message in the channel", "reply to the message in the conversation", "post in the channel", "respond in the channel", "respond in the conversation", "message in the channel", "message in the conversation", "send a message in", "reply in discord")):
        return "COMMS_ACTION_REQUEST"
    if any(term in lower for term in ("reply by email", "reply to the email", "reply to the observed email", "respond by email", "respond to the email", "reply to the message", "send a reply email", "send a reply to", "acknowledge the email", "acknowledge the message")):
        return "EMAIL_ACTION_REQUEST"
    if any(term in lower for term in ("submit the application", "submit my application", "submit the internship application", "submit my internship application", "fill the application", "fill out the application", "fill the application form", "apply for the intern", "apply for the internship", "apply to the job", "apply for the role", "apply for the position", "submit an application for")):
        return "JOB_ACTION_REQUEST"
    if any(term in lower for term in ("open youtube", "youtube", "chrome", "browser", "web page", "webpage", "visit", "open ", "navigate to", "go to", "browse")) and not any(term in lower for term in ("do not open", "without opening")):
        return "BROWSER_ACTION_REQUEST"
    modification_requested = any(term in lower for term in ("fix", "modify", "change", "update", "write", "delete", "create"))
    if modification_requested and not constraints.get("do_not_modify"):
        return "MODIFICATION_REQUEST"
    if any(term in lower for term in ("read ", "explain", "what kind of project", "what type of project", "what this program does", "what this file does", "understand")):
        return "READ_ONLY_UNDERSTANDING"
    if any(term in lower for term in ("diagnose", "cause", "why", "root cause")):
        return "DIAGNOSIS"
    if any(term in lower for term in ("find", "inspect", "check", "syntax", "error", "issue", "problem")):
        return "INVESTIGATION"
    return "READ_ONLY_UNDERSTANDING"


def _target_hash(target: str, workspace_root: str = "workspace") -> str:
    path = (Path(workspace_root) / target).resolve()
    if not path.is_file():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _persist_action_lineage(state: NexusState, *, action_type: str, tool_name: str, target: str, risk_decision: dict[str, object]) -> None:
    task_id = str(state.get("task_id") or "")
    if not task_id:
        return
    current_hash = proposal_hash(action_type=action_type, tool_name=tool_name, target=target, old_code=state.get("old_code", ""), new_code=state.get("new_code", ""), action_spec=state.get("action_spec", {}))
    db_path = state.get("persistence_db_path") or None
    journal_db_path = state.get("journal_db_path") or db_path
    approval_db_path = state.get("approval_db_path") or db_path
    # Durable action payload: the exact patch/spec content the executor needs
    # for faithful resume-after-approval. Bound by proposal_hash; the
    # executor revalidates bindings before use and refuses vacuous content.
    action_payload: dict[str, object] = {}
    if tool_name == "fixer":
        action_payload = {"old_code": str(state.get("old_code", "")), "new_code": str(state.get("new_code", ""))}
    elif isinstance(state.get("action_spec"), dict) and state.get("action_spec"):
        action_payload = {"action_spec": dict(state.get("action_spec") or {})}
    checkpoint = create_checkpoint(task_id, current_stage="APPROVAL_PENDING", current_sub_goal=state.get("decision_reason", ""), selected_tools=[tool_name], action_type=action_type, action_target=target, target_hash=_target_hash(target), proposal_hash=current_hash, action_payload=action_payload, risk_level=str(risk_decision.get("risk_level", "")), approval_status="PENDING", evidence_refs=[f"{tool_name}:{task_id}"], environment_fingerprint=str(Path("workspace").resolve()), db_path=journal_db_path or None)
    approval = create_approval(task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], proposal_hash=current_hash, action_type=action_type, tool_name=tool_name, target=target, risk_level=str(risk_decision.get("risk_level", "")), reason=str(risk_decision.get("reason", "")), capability_context=state.get("capability_context") or None, target_hash=checkpoint.get("target_hash", ""), evidence_hash_value=str((state.get("capability_context") or {}).get("evidence_hash", "")), db_path=approval_db_path or None)
    update_checkpoint(checkpoint["checkpoint_id"], approval_binding=approval, approval_status="PENDING", approval_expiry=approval.get("expires_at", ""), db_path=journal_db_path or None)
    state["action_type"] = action_type
    state["approval_id"] = approval["approval_id"]
    state["journal_checkpoint_id"] = checkpoint["checkpoint_id"]
    state["proposal_hash"] = current_hash
    state["action_target"] = target
    state["approval_expires_at"] = approval.get("expires_at", "")
    update_task_status(task_id, "WAITING_APPROVAL", current_stage="APPROVAL_PENDING", current_sub_goal=state.get("decision_reason", ""), action_lineage={"checkpoint_id": checkpoint["checkpoint_id"], "proposal_hash": current_hash, "action_type": action_type, "tool_name": tool_name, "target": target, "risk_level": risk_decision.get("risk_level")}, approval_lineage=approval, status_reason="Durable approval is required before execution.", db_path=state.get("persistence_db_path") or None)


def _evaluate_action_permission(state: NexusState, *, tool_name: str, target: str) -> bool:
    """Enforce the Risk Engine → Permission Authority step of the security chain.

    Called after risk classification and before any approval lineage is
    created or any consequential execution proceeds. The tool →
    capability → action_class binding comes from the Tool Registry via
    resolve_tool_permission; the decision comes from a fresh Permission
    Authority read. The outcome is stored on the state for lineage and
    re-checked (never trusted) by the Action Executor immediately before
    dispatch, so revoke/expire/recovery/resume paths always re-evaluate.

    Enforcement activates when ``permission_db_path`` is explicitly bound in
    the state. Without an explicit binding the decision is recorded with
    audit lineage but does not block, preserving existing read-only and
    unwired flows. Returns True when the proposal may proceed.
    """
    state.setdefault("permission_id", "")
    state.setdefault("permission_decision", {})
    try:
        binding = resolve_tool_permission(tool_name)
    except ValueError as exc:
        denied = {
            "outcome": "DENIED",
            "allowed": False,
            "reason": redact_text(str(exc)),
            "metadata": {"tool_name": str(tool_name or ""), "target": redact_text(target)},
        }
        state["permission_id"] = ""
        state["permission_decision"] = denied
        state["approval_required"] = False
        state["approved"] = False
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=str(exc), final_outcome="BLOCKED")
        _audit_event(
            state,
            "action_blocked",
            actor="permission_authority",
            tool=str(tool_name or ""),
            result="DENIED",
            reason=str(exc),
            metadata={"task_id": str(state.get("task_id") or "")},
        )
        return False
    permission_db = state.get("permission_db_path") or None
    enforced = bool(str(state.get("permission_db_path") or "").strip())
    risk_level = str((state.get("risk_decision") or {}).get("risk_level") or "")
    decision = check_permission_before_execution(
        capability=binding["capability"],
        action_class=binding["action_class"],
        target=target,
        task_id=str(state.get("task_id") or ""),
        risk_level=risk_level,
        db_path=permission_db,
    )
    state["permission_id"] = str((decision.get("metadata") or {}).get("permission_id") or "")
    state["permission_decision"] = decision
    _audit_event(
        state,
        "permission_checked",
        actor="permission_authority",
        tool=tool_name,
        risk_level=risk_level,
        approval_required=bool((decision.get("metadata") or {}).get("requires_approval", False)),
        approved=False,
        target=target,
        result=str(decision.get("outcome") or ""),
        reason=str(decision.get("reason") or ""),
        metadata={
            "task_id": str(state.get("task_id") or ""),
            "subgoal_id": str(state.get("current_subgoal_id") or ""),
            "permission_id": state["permission_id"],
            "capability": binding["capability"],
            "action_class": binding["action_class"],
            "decision": str(decision.get("outcome") or ""),
            "enforced": enforced,
        },
    )
    if enforced and str(decision.get("outcome") or "") not in {"ALLOWED", "APPROVAL_REQUIRED"}:
        state["approval_required"] = False
        state["approved"] = False
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=str(decision.get("reason") or ""), final_outcome="BLOCKED")
        _audit_event(
            state,
            "action_blocked",
            actor="permission_authority",
            tool=tool_name,
            risk_level=risk_level,
            approved=False,
            target=target,
            result=str(decision.get("outcome") or ""),
            reason=str(decision.get("reason") or ""),
            metadata={"task_id": str(state.get("task_id") or ""), "permission_id": state["permission_id"]},
        )
        return False
    return True


def _apply_user_preferences(state: NexusState) -> None:
    """Load effective User DNA preferences for observability only.

    Runs when ``dna_db_path`` is explicitly bound; otherwise a no-op.
    Preferences are recorded on the state for selection/presentation use and
    audited by key count only (never values). This function cannot authorize
    anything: it reads PREFERENCE records exclusively and never touches
    approvals, permissions, or execution gates.
    """
    state.setdefault("dna_preferences", [])
    dna_db = str(state.get("dna_db_path") or "").strip()
    if not dna_db:
        return
    try:
        records = get_effective_preferences(db_path=dna_db)
    except (OSError, ValueError):
        return
    state["dna_preferences"] = [
        {
            "key": str(record.get("record_key") or ""),
            "value": str(record.get("record_value") or ""),
            "confidence": str(record.get("confidence") or ""),
        }
        for record in records
    ]
    _audit_event(
        state,
        "dna_preferences_applied",
        actor="user_dna",
        result=f"{len(state['dna_preferences'])} effective preference(s) loaded.",
        metadata={
            "task_id": str(state.get("task_id") or ""),
            "preference_keys": sorted({str(item["key"]) for item in state["dna_preferences"]}),
            "preference_count": len(state["dna_preferences"]),
        },
    )


def _evaluate_privacy(state: NexusState, *, tool_name: str, target: str) -> bool:
    """Enforce the Privacy Policy step: data access before action authorization.

    Classifies the target with the shared personal-capability vocabulary and
    evaluates the OBSERVE operation. SECRET and CREDENTIAL data are denied
    unconditionally. SENSITIVE data requires an explicit AUTHORIZATION record,
    enforced when ``dna_db_path`` is bound and advisory otherwise (legacy
    preservation). The outcome is stored for lineage; callers after this point
    must not proceed on False.
    """
    state.setdefault("privacy_decision", {})
    try:
        category = classify_data(target=target)
    except ValueError as exc:
        denied = {
            "decision": "DENY",
            "reason": redact_text(str(exc)),
            "category": "UNKNOWN",
            "operation": "OBSERVE",
        }
        state["privacy_decision"] = denied
        state["approval_required"] = False
        state["approved"] = False
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=str(exc), final_outcome="BLOCKED")
        return False
    dna_db = str(state.get("dna_db_path") or "").strip()
    authorized = False
    if dna_db and category == "SENSITIVE":
        try:
            authorized = check_authorization("data:SENSITIVE", db_path=dna_db)
        except (OSError, ValueError):
            authorized = False
    decision = evaluate_privacy(category, operation="OBSERVE", authorization_present=authorized)
    state["privacy_decision"] = decision
    _audit_event(
        state,
        "privacy_checked",
        actor="privacy_policy",
        tool=tool_name,
        approved=False,
        target=target,
        result=str(decision.get("decision") or ""),
        reason=str(decision.get("reason") or ""),
        metadata={
            "task_id": str(state.get("task_id") or ""),
            "subgoal_id": str(state.get("current_subgoal_id") or ""),
            "category": category,
            "operation": "OBSERVE",
            "decision": str(decision.get("decision") or ""),
            "authorization_present": authorized,
        },
    )
    if str(decision.get("decision") or "") == "DENY":
        state["approval_required"] = False
        state["approved"] = False
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=str(decision.get("reason") or ""), final_outcome="BLOCKED")
        return False
    if str(decision.get("decision") or "") == "REQUIRES_AUTHORIZATION" and dna_db:
        state["approval_required"] = False
        state["approved"] = False
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=str(decision.get("reason") or ""), final_outcome="BLOCKED")
        _audit_event(
            state,
            "action_blocked",
            actor="privacy_policy",
            tool=tool_name,
            approved=False,
            target=target,
            result="REQUIRES_AUTHORIZATION",
            reason=str(decision.get("reason") or ""),
            metadata={"task_id": str(state.get("task_id") or "")},
        )
        return False
    return True


def _evaluate_automation_scope(state: NexusState, *, tool_name: str, target: str) -> bool:
    """Enforce the Automation Scope step for the tool's capability area.

    The area comes from the Tool Registry via scope_area_for_tool; the
    decision comes from a fresh scope-store read. Enforcement activates when
    ``scope_db_path`` is explicitly bound; otherwise the decision is recorded
    with audit lineage but does not block, preserving existing flows.
    Returns True when the proposal may proceed.
    """
    state.setdefault("scope_decision", {})
    try:
        area = scope_area_for_tool(tool_name)
    except ValueError as exc:
        state["scope_decision"] = {
            "outcome": "DENIED",
            "allowed": False,
            "reason": redact_text(str(exc)),
        }
        state["approval_required"] = False
        state["approved"] = False
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=str(exc), final_outcome="BLOCKED")
        return False
    scope_db = state.get("scope_db_path") or None
    enforced = bool(str(state.get("scope_db_path") or "").strip())
    decision = check_scope(
        area=area,
        target=target,
        task_id=str(state.get("task_id") or ""),
        db_path=scope_db,
    )
    state["scope_decision"] = decision
    _audit_event(
        state,
        "scope_checked",
        actor="automation_scope",
        tool=tool_name,
        approved=False,
        target=target,
        result=str(decision.get("outcome") or ""),
        reason=str(decision.get("reason") or ""),
        metadata={
            "task_id": str(state.get("task_id") or ""),
            "subgoal_id": str(state.get("current_subgoal_id") or ""),
            "area": area,
            "scope_id": str(decision.get("scope_id") or ""),
            "decision": str(decision.get("outcome") or ""),
            "enforced": enforced,
        },
    )
    if enforced and not decision.get("allowed"):
        state["approval_required"] = False
        state["approved"] = False
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=str(decision.get("reason") or ""), final_outcome="BLOCKED")
        _audit_event(
            state,
            "action_blocked",
            actor="automation_scope",
            tool=tool_name,
            approved=False,
            target=target,
            result=str(decision.get("outcome") or ""),
            reason=str(decision.get("reason") or ""),
            metadata={"task_id": str(state.get("task_id") or ""), "scope_id": str(decision.get("scope_id") or "")},
        )
        return False
    return True


def understand(state: NexusState):
    print("\n[NEXUS] Understanding request...")

    request = (state.get("user_request") or "").strip()
    observation = (
        f"Current request: {request}"
        if request
        else "Current request is empty."
    )

    state["observations"] = [observation]
    state["user_constraints"] = _extract_explicit_constraints(request)
    state["request_intent"] = _classify_request_intent(request, state["user_constraints"])
    _set_decision(state, "OBSERVE", reason="The request was observed and normalized for the bounded investigation.")
    _audit_event(state, "observation", actor="nexus", result=observation)
    _apply_user_preferences(state)

    return state


def prioritize(state: NexusState):
    print("[NEXUS] Prioritizing request...")

    state["priority"] = "medium"
    _set_decision(state, "OBSERVE", reason="The request has been prioritized before evidence collection.")

    return state


def select_tool(state: NexusState):
    print("[NEXUS] Selecting tool...")

    state["browser_url"] = extract_requested_url(state["user_request"])
    selected_tools = get_trusted_tool_plan(state["user_request"])
    state["selected_tools"] = selected_tools
    state["selected_tool"] = selected_tools[0] if selected_tools else "workspace_inspector"
    _set_decision(state, "TOOL_SELECTION", reason="Allowlisted tools were selected through the trusted registry.")

    print(
        f"[NEXUS] Selected tools: {selected_tools}"
    )
    _audit_event(
        state,
        "tool_selected",
        actor="nexus",
        tool=", ".join(selected_tools),
        result="Allowlisted tools selected.",
    )

    return state


def select_relevant(state: NexusState):
    print("[NEXUS] Selecting relevant files...")

    if "relevant_file_selector" not in state.get("selected_tools", []):
        state["selected_files"] = []
        _set_decision(state, "EVIDENCE", reason="The selected request path does not require workspace file selection.")
        return state

    result = select_relevant_files(
        workspace_path="workspace",
        user_request=state["user_request"],
        max_files=10,
    )

    state["selected_files"] = [
        match.strip().replace("\\", "/")
        for match in re.findall(r"^FILE:\s*(.*?)\s*\|", result, flags=re.MULTILINE)
        if match.strip()
    ]
    requested_files = {
        match.replace("\\", "/").strip().lstrip("./")
        for match in re.findall(r"(?<![\w./\\-])[\w./\\-]+\.(?:py|js|jsx|ts|tsx|java|c|cpp|h|html|css|json|md|txt)", state["user_request"], flags=re.IGNORECASE)
    }
    if requested_files:
        exact_targets = [
            path for path in state["selected_files"]
            if path.lstrip("./") in requested_files or os.path.basename(path) in requested_files
        ]
        state["selected_files"] = exact_targets
    state["investigation"].append("RELEVANT FILE SELECTION:\n" + result)
    _set_decision(state, "EVIDENCE", reason="Relevant files were narrowed to the current investigation scope.")

    return state


def investigate(state: NexusState):
    print("[NEXUS] Investigating...")

    if _phase32_enabled(state):
        state["observation_results"] = []
        state["tool_results"] = []
        _set_decision(state, "EVIDENCE", reason="Legacy investigation is deferred; durable Phase 32 subgoals own tool dispatch.")
        return state

    tool_names = state.get("selected_tools", [])
    action_tools = {
        "browser_navigate_observed", "browser_follow_observed_link", "browser_controller",
        "desktop_focus_authorized_window", "desktop_minimize_authorized_window", "desktop_restore_authorized_window",
    }
    chosen_tools = [tool for tool in tool_names if tool not in {"relevant_file_selector"} and tool not in action_tools]
    if not chosen_tools and state.get("request_intent") == "READ_ONLY_UNDERSTANDING":
        chosen_tools = ["logic_inspector"]
    if not chosen_tools:
        chosen_tools = [state.get("selected_tool", "workspace_inspector")]

    results = execute_selected_tools(
        chosen_tools,
        workspace_path="workspace",
        user_request=state["user_request"],
        file_name=(state.get("selected_files") or [""])[0],
        file_names=state.get("selected_files", []),
        timeout_seconds=30,
        max_files=10,
        url=state.get("browser_url", ""),
        capability_context=state.get("capability_context") or None,
        security_scan_target="." if state.get("request_intent") == "SECURITY_SCAN_REQUEST" else "",
    )
    _set_decision(state, "EVIDENCE", reason="Current tool evidence is being normalized into a bounded reasoning context.")

    selector_result = next(
        (item for item in state.get("investigation", []) if item.startswith("RELEVANT FILE SELECTION:")),
        "",
    )
    scoped_results = []
    if selector_result:
        scoped_results.append({
            "tool": "relevant_file_selector",
            "status": "ok",
            "result": selector_result,
        })
    scoped_results.extend(results)

    state["observation_results"] = list(results)
    state["tool_results"] = []
    for tool_result in results:
        _audit_event(
            state,
            "tool_execution",
            actor="nexus",
            tool=tool_result["tool"],
            result=tool_result.get("result", ""),
            reason=tool_result.get("status", ""),
            metadata={"status": tool_result.get("status", "")},
        )
        state["tool_results"].append(
            f"TOOL: {tool_result['tool']}\nSTATUS: {tool_result['status']}\nRESULT: {tool_result['result']}"
        )

    for entry in state["tool_results"]:
        state["investigation"].append(entry)

    normalized = normalize_tool_results(scoped_results, scope_id=state.get("evidence_scope", ""))
    correlation = correlate_evidence(normalized)
    state["normalized_evidence"] = normalized
    state["evidence_correlations"] = correlation["correlations"]
    state["evidence_conflicts"] = correlation["conflicts"]
    state["reasoning_context"] = build_reasoning_context(
        state["user_request"],
        normalized,
        correlation,
        state.get("memory_context", ""),
    )
    state["investigation"].append(
        "CROSS_SOURCE_CONTEXT:\n" + state["reasoning_context"]
    )

    if not state.get("target_file") and results:
        latest_result = results[-1].get("result", "")
        if latest_result:
            state["action_result"] = str(latest_result)
            state["verification"] = (
                "Read-only verification evidence:\n"
                f"{latest_result}"
            )
            state["last_verification"] = state["verification"]

    _audit_event(
        state,
        "evidence_normalized",
        actor="nexus",
        result="Tool results normalized into bounded evidence.",
        metadata={"evidence_count": len(normalized)},
    )
    _audit_event(
        state,
        "evidence_correlated",
        actor="nexus",
        result="Evidence grouped by observed target.",
        metadata={
            "correlation_count": len(correlation["correlations"]),
            "conflict_count": len(correlation["conflicts"]),
        },
    )
    for conflict in correlation["conflicts"]:
        _audit_event(
            state,
            "evidence_conflict_detected",
            actor="nexus",
            result="Evidence conflict preserved for reasoning.",
            metadata=conflict,
        )

    return state


def diagnose(state: NexusState):
    print("[NEXUS] Diagnosing...")

    _set_decision(state, "REASON", reason="Cross-source evidence is being interpreted against the request and the current runtime state.")
    combined_investigation = state.get("reasoning_context", "") or "\n\n".join(state["investigation"])

    memory_context = state.get("memory_context", "")
    if memory_context and not state.get("reasoning_context"):
        combined_investigation = (
            f"PREVIOUS MEMORY:\n{memory_context}\n\n"
            f"CURRENT EVIDENCE:\n{combined_investigation}"
        )

    diagnosis = diagnose_problem(
        state["user_request"],
        combined_investigation,
    )

    print("\n========== NEXUS DIAGNOSIS ==========")
    print(diagnosis)

    state["investigation"].append(
        "DIAGNOSIS:\n" + diagnosis
    )
    _audit_event(
        state,
        "cross_source_reasoning_completed",
        actor="nexus",
        result="Structured cross-source context was supplied to diagnosis.",
        metadata={
            "evidence_count": len(state.get("normalized_evidence", [])),
            "conflict_count": len(state.get("evidence_conflicts", [])),
        },
    )

    return state


def should_create_proposal(state: NexusState):
    constraints = state.get("user_constraints") or _extract_explicit_constraints(state.get("user_request", ""))
    if constraints.get("do_not_modify") or constraints.get("do_not_propose_fixes"):
        return "create_plan"
    if state.get("request_intent") == "MODIFICATION_REQUEST":
        return "create_proposal"
    if state.get("request_intent") in {"BROWSER_ACTION_REQUEST", "DESKTOP_ACTION_REQUEST", "CALENDAR_ACTION_REQUEST", "EMAIL_ACTION_REQUEST", "COMMS_ACTION_REQUEST", "JOB_ACTION_REQUEST"}:
        return "create_action_proposal"
    return "create_plan"


def _source_for_target(state: NexusState, target_file: str) -> str:
    for result in state.get("observation_results", []):
        if result.get("tool") != "logic_inspector":
            continue
        content = str(result.get("result", ""))
        match = re.search(
            rf"--- FILE:\s*{re.escape(target_file)}\s*---\s*(.*?)(?=\n--- FILE:|$)",
            content,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if match:
            return match.group(1)
    return ""


def _build_deterministic_modification_proposal(state: NexusState) -> str:
    request = state.get("user_request", "")
    target_file = next(iter(state.get("selected_files", [])), "")
    if not target_file:
        return "NO_FIX"
    source = _source_for_target(state, target_file)
    if not source:
        return "NO_FIX"
    requested_text = re.search(r"\bprint\s+([\"'])(.*?)\1", request, flags=re.IGNORECASE)
    if not requested_text:
        return "NO_FIX"
    desired = requested_text.group(2)
    current = re.search(r"^\s*print\s*\(\s*([\"'])(.*?)\1\s*\)\s*$", source, flags=re.MULTILINE)
    if not current:
        return "NO_FIX"
    old_line = current.group(0).strip()
    new_line = f'print("{desired}")'
    return f"FILE: {target_file}\nOLD: {old_line}\nNEW: {new_line}"


def _deferred_browser_observation(state: NexusState) -> dict[str, object] | None:
    """Bridge the Phase 32 deferred observation gap: observe the explicit URL through
    the trusted registry when no OK browser observation exists yet. Fail closed."""
    url = str(state.get("browser_url") or "")
    if not url:
        return None
    results = execute_selected_tools(
        ["browser_observer"],
        workspace_path="workspace",
        user_request=state.get("user_request", ""),
        file_name="",
        file_names=[],
        timeout_seconds=30,
        max_files=10,
        url=url,
        capability_context=state.get("capability_context", {}),
    )
    state["observation_results"] = list(state.get("observation_results", [])) + results
    return next((item.get("result") for item in results if item.get("tool") == "browser_observer"), None)


def _deferred_desktop_observation(state: NexusState) -> dict[str, object] | None:
    """Bridge the Phase 32 deferred observation gap: observe the authorized
    desktop through the trusted registry when no OK desktop observation
    exists yet. Read-only grounding only; fail closed."""
    results = execute_selected_tools(
        ["desktop_observer"],
        workspace_path="workspace",
        user_request=state.get("user_request", ""),
        file_name="",
        file_names=[],
        timeout_seconds=30,
        max_files=10,
        capability_context=None,
    )
    state["observation_results"] = list(state.get("observation_results", [])) + results
    return next((item.get("result") for item in results if item.get("tool") == "desktop_observer"), None)


_FOLLOW_DIRECTIVE_TERMS = (
    "follow",
    "click",
    "open the link",
    "open that link",
    "open it",
    "navigate to the",
    "navigate the",
    "navigate using",
    "navigate to the observed",
    "follow the observed",
    "click the observed",
    "take the navigation action",
    "go to the",
    "go to that",
    "take me to",
    "click the link",
    "nav ",
)


def _is_explicit_follow_request(request: str) -> bool:
    lower = str(request or "").lower()
    return any(term in lower for term in _FOLLOW_DIRECTIVE_TERMS)


_REAL_BROWSER_DIRECTIVE_TERMS = (
    "real browser",
    "actual browser",
    "headless browser",
    "playwright",
    "chromium",
    "in a browser, not just",
    "open this webpage in",
    "open the page in",
    "open the webpage in",
    "click the grounded",
    "type into the",
    "interact with the page",
    "interacting with the page",
    "navigate to the next page",
)


def _is_real_browser_request(request: str) -> bool:
    """Detect an explicit request for real interactive browser behavior.

    Read-only observation stays on browser_observer; only a natural-language
    directive that requires a live browser/page (open in a real browser,
    grounded click/type, next-page navigation) selects browser_controller.
    """
    lower = str(request or "").lower()
    return any(term in lower for term in _REAL_BROWSER_DIRECTIVE_TERMS)


def _is_deferred_browser_approval_wait(state: NexusState, subgoal_id: str) -> bool:
    """Narrowly detect the legitimate deferred browser-controller approval wait.

    True only when an interactive browser request has a valid URL, successful
    observer grounding, a supported controller proposal with a durable approval
    already created, and the Phase 32 failure is purely the honest
    approval-wait deferral (never a missing/unsupported target, which stays
    HUMAN_REQUIRED/BLOCKED). No new approvals are created here.
    """
    if not subgoal_id or not _is_real_browser_request(state.get("user_request", "")):
        return False
    plan_item = next((item for item in state.get("goal_plan", []) if str(item.get("sub_goal_id")) == subgoal_id), None)
    if not isinstance(plan_item, dict):
        return False
    selected = list(plan_item.get("selected_tools") or [])
    if "browser_controller" not in selected or not bool(plan_item.get("action_required", False)):
        return False
    if str(state.get("action_tool") or "") != "browser_controller":
        return False
    if not str(state.get("approval_id") or ""):
        return False
    if not str(state.get("browser_url") or ""):
        return False
    observed_ok = any(
        isinstance(item.get("result"), dict)
        and item.get("tool") == "browser_observer"
        and item["result"].get("status") == "OK"
        for item in state.get("observation_results", [])
    )
    return bool(observed_ok)


def _reuse_browser_approval_lineage(state: NexusState) -> bool | None:
    """Reuse a durable, still-valid approval for an identical observed browser action on resume.

    Returns True when the prior approval/checkpoint lineage was bound, False when no
    prior lineage exists (a fresh lineage should be created), and None when the stored
    lineage or approval is inconsistent or spent, in which case a terminal outcome was
    set and the caller must stop (no navigation, no new approval).
    """
    task_id = str(state.get("task_id") or "")
    if not task_id:
        return False
    db_path = state.get("persistence_db_path") or None
    journal_db_path = state.get("journal_db_path") or db_path
    approval_db_path = state.get("approval_db_path") or db_path
    task = get_task(task_id, db_path=db_path)
    if task is None:
        return False
    lineage = task.get("action_lineage") or {}
    if not lineage:
        return False
    checkpoint_id = str(lineage.get("checkpoint_id") or "")
    approval_id = str((task.get("approval_lineage") or {}).get("approval_id") or "")
    stored_hash = str(lineage.get("proposal_hash") or "")
    stored_target = str(lineage.get("target") or "")
    stored_type = str(lineage.get("action_type") or "")
    current_hash = proposal_hash(
        action_type=str(state.get("action_tool") or ""),
        tool_name=str(state.get("action_tool") or ""),
        target=str(state.get("action_target") or ""),
        old_code=state.get("old_code", ""),
        new_code=state.get("new_code", ""),
        action_spec=state.get("action_spec", {}),
    )
    checkpoint = None
    if checkpoint_id:
        try:
            checkpoint = load_checkpoint(task_id, checkpoint_id=checkpoint_id, db_path=journal_db_path)
        except ValueError:
            checkpoint = None
    matches = (
        checkpoint is not None
        and checkpoint.get("is_valid") == 1
        and str(checkpoint.get("proposal_hash") or "") == current_hash
        and str(checkpoint.get("action_target") or "") == str(state.get("action_target") or "")
        and current_hash == stored_hash
        and str(state.get("action_target") or "") == stored_target
    )
    if not approval_id or not checkpoint_id or not matches:
        if approval_id or checkpoint_id:
            state["final_outcome"] = "BLOCKED"
            _set_decision(state, "FINAL_OUTCOME", reason="The observed browser state or stored lineage changed; no navigation and no new approval were created.", final_outcome="BLOCKED")
            return None
        return False
    approval = get_approval(approval_id, db_path=approval_db_path)
    if approval is None:
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason="The stored approval for the observed browser action no longer exists.", final_outcome="BLOCKED")
        return None
    status = str(approval.get("status") or "").upper()
    if status in {"REJECTED", "CONSUMED", "EXPIRED", "INVALIDATED"}:
        state["final_outcome"] = "APPROVAL_REJECTED" if status == "REJECTED" else "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=f"The prior browser approval is {status.lower()}; no navigation and no new approval were created.", final_outcome=state["final_outcome"])
        return None
    state["action_type"] = stored_type or str(state.get("action_tool") or "")
    state["approval_id"] = approval_id
    state["journal_checkpoint_id"] = checkpoint_id
    state["proposal_hash"] = current_hash
    state["approval_expires_at"] = str(approval.get("expires_at") or "")
    stored_context = approval.get("capability_context") or {}
    if isinstance(stored_context, str):
        try:
            import json as _json

            parsed = _json.loads(stored_context)
            stored_context = parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            stored_context = {}
    if isinstance(stored_context, dict) and stored_context:
        # Resume must execute the EXACT approved binding (task/subgoal/target/
        # evidence/observation), not a freshly rebuilt context that would
        # mismatch the durable approval and fail closed in the executor.
        state["capability_context"] = dict(stored_context)
    return True


def _reuse_desktop_approval_lineage(state: NexusState) -> bool | None:
    """Reuse a durable, still-valid approval for an identical observed desktop action on resume.

    Desktop counterpart to ``_reuse_browser_approval_lineage`` with the same
    contract: True when the prior lineage was bound (no new approval is
    created), False when no prior lineage exists (a fresh lineage should be
    created), None when the stored lineage or approval is inconsistent or
    spent (terminal outcome set; caller must stop with no new approval).
    Desktop proposals carry no capability context; dispatch-time re-grounding
    of the exact window title/process/PID remains mandatory downstream.
    """
    task_id = str(state.get("task_id") or "")
    if not task_id:
        return False
    db_path = state.get("persistence_db_path") or None
    journal_db_path = state.get("journal_db_path") or db_path
    approval_db_path = state.get("approval_db_path") or db_path
    task = get_task(task_id, db_path=db_path)
    if task is None:
        return False
    lineage = task.get("action_lineage") or {}
    if not lineage:
        return False
    checkpoint_id = str(lineage.get("checkpoint_id") or "")
    approval_id = str((task.get("approval_lineage") or {}).get("approval_id") or "")
    stored_hash = str(lineage.get("proposal_hash") or "")
    stored_target = str(lineage.get("target") or "")
    stored_type = str(lineage.get("action_type") or "")
    current_hash = proposal_hash(
        action_type=str(state.get("action_tool") or ""),
        tool_name=str(state.get("action_tool") or ""),
        target=str(state.get("action_target") or ""),
        old_code=state.get("old_code", ""),
        new_code=state.get("new_code", ""),
        action_spec=state.get("action_spec", {}),
    )
    checkpoint = None
    if checkpoint_id:
        try:
            checkpoint = load_checkpoint(task_id, checkpoint_id=checkpoint_id, db_path=journal_db_path)
        except ValueError:
            checkpoint = None
    matches = (
        checkpoint is not None
        and checkpoint.get("is_valid") == 1
        and str(checkpoint.get("proposal_hash") or "") == current_hash
        and str(checkpoint.get("action_target") or "") == str(state.get("action_target") or "")
        and current_hash == stored_hash
        and str(state.get("action_target") or "") == stored_target
    )
    if not approval_id or not checkpoint_id or not matches:
        if approval_id or checkpoint_id:
            state["final_outcome"] = "BLOCKED"
            _set_decision(state, "FINAL_OUTCOME", reason="The observed desktop state or stored lineage changed; no action and no new approval were created.", final_outcome="BLOCKED")
            return None
        return False
    approval = get_approval(approval_id, db_path=approval_db_path)
    if approval is None:
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason="The stored approval for the observed desktop action no longer exists.", final_outcome="BLOCKED")
        return None
    status = str(approval.get("status") or "").upper()
    if status in {"REJECTED", "CONSUMED", "EXPIRED", "INVALIDATED"}:
        state["final_outcome"] = "APPROVAL_REJECTED" if status == "REJECTED" else "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=f"The prior desktop approval is {status.lower()}; no action and no new approval were created.", final_outcome=state["final_outcome"])
        return None
    try:
        expiry = datetime.fromisoformat(str(approval.get("expires_at", "")).replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            state["final_outcome"] = "BLOCKED"
            _set_decision(state, "FINAL_OUTCOME", reason="The prior desktop approval is expired; no action and no new approval were created.", final_outcome="BLOCKED")
            return None
    except (ValueError, TypeError):
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason="The prior desktop approval expiry is malformed; no action and no new approval were created.", final_outcome="BLOCKED")
        return None
    state["action_type"] = stored_type or str(state.get("action_tool") or "")
    state["approval_id"] = approval_id
    state["journal_checkpoint_id"] = checkpoint_id
    state["proposal_hash"] = current_hash
    state["approval_expires_at"] = str(approval.get("expires_at") or "")
    return True


def _browser_action_performed(state: NexusState) -> bool:
    return bool(state.get("browser_action_executed"))


def create_action_proposal(state: NexusState):
    state.setdefault("action_tool", "")
    state.setdefault("action_spec", {})
    state.setdefault("action_target", "")
    intent = state.get("request_intent")
    if intent == "BROWSER_ACTION_REQUEST":
        observed = next((item.get("result") for item in state.get("observation_results", []) if item.get("tool") == "browser_observer"), None)
        if not isinstance(observed, dict) or observed.get("status") != "OK":
            observed = _deferred_browser_observation(state)
        if not isinstance(observed, dict) or observed.get("status") != "OK":
            state["final_outcome"] = "NO_ACTION"
            _set_decision(state, "FINAL_OUTCOME", reason="No successful browser observation is available for a grounded action.", final_outcome="NO_ACTION")
            return state
        if _is_real_browser_request(state.get("user_request", "")):
            # Interactive behavior was explicitly requested: propose the existing
            # grounded browser_controller (open_page) through the same approval
            # path. The URL is dynamically extracted and validated; nothing is
            # invented and read-only tasks never reach this branch.
            target_url = ""
            try:
                target_url = extract_requested_url(state.get("user_request", ""))
            except ValueError:
                target_url = ""
            if not target_url:
                target_url = str(state.get("browser_url") or "")
            if not target_url and isinstance(observed, dict):
                target_url = str(observed.get("final_url") or observed.get("url") or "")
            if not target_url:
                state["final_outcome"] = "NO_ACTION"
                _set_decision(state, "FINAL_OUTCOME", reason="A real-browser action requires an explicit public HTTP(S) target; none was supplied.", final_outcome="NO_ACTION")
                return state
            state["action_tool"] = "browser_controller"
            state["action_target"] = target_url
            state["action_spec"] = {
                "controller_action": "open_page",
                "url": target_url,
                "observed_target": str(observed.get("final_url") or observed.get("url") or target_url),
                "timeout_seconds": 15,
            }
            try:
                state["capability_context"] = build_capability_context(
                    task_id=str(state.get("task_id") or ""),
                    subgoal_id=str(state.get("current_subgoal_id") or "open_real_browser_page"),
                    application_id="browser",
                    capability_id="interact",
                    tool_name="browser_controller",
                    target=target_url,
                    session_id=str((state.get("capability_context") or {}).get("session_id", "")),
                    observation_id=f"obs-{uuid.uuid4().hex[:12]}",
                    evidence_refs=["browser:observation"],
                    evidence=observed,
                    freshness_deadline=(datetime.now(timezone.utc) + timedelta(seconds=CONTEXT_FRESHNESS_SECONDS)).isoformat(timespec="seconds"),
                    environment_fingerprint=str(state.get("environment_fingerprint") or str(Path("workspace").resolve())),
                )
            except ValueError as exc:
                state["final_outcome"] = "NO_ACTION"
                _set_decision(state, "FINAL_OUTCOME", reason=f"The real-browser action could not be bound to a valid capability context: {exc}", final_outcome="NO_ACTION")
                return state
            reuse = _reuse_browser_approval_lineage(state)
            if reuse is None:
                return state
        else:
            links = observed.get("links") or []
            link = next((item for item in links if isinstance(item, dict) and item.get("url")), None)
            if not link:
                state["final_outcome"] = "NO_ACTION"
                _set_decision(state, "FINAL_OUTCOME", reason="No suitable observed browser link is available for navigation.", final_outcome="NO_ACTION")
                return state
            if not _is_explicit_follow_request(state.get("user_request", "")):
                state["final_outcome"] = "NO_ACTION"
                _set_decision(state, "FINAL_OUTCOME", reason="The browser request is read-only; an explicit directive to follow or click an observed link is required before navigation is proposed.", final_outcome="NO_ACTION")
                return state
            state["action_tool"] = "browser_follow_observed_link"
            state["action_target"] = str(link["url"])
            state["action_spec"] = {
                "action_type": "follow_observed_link",
                "element_identifier": "link:0",
                "observed_target": observed.get("final_url") or observed.get("url", ""),
                "target_url": link["url"],
            }
            reuse = _reuse_browser_approval_lineage(state)
            if reuse is None:
                return state
    elif intent == "DESKTOP_ACTION_REQUEST":
        observed = next((item.get("result") for item in state.get("observation_results", []) if item.get("tool") == "desktop_observer"), None)
        if not isinstance(observed, dict) or observed.get("status") != "OK":
            observed = _deferred_desktop_observation(state)
        window = observed.get("windows", [])[0] if isinstance(observed, dict) and observed.get("status") == "OK" and observed.get("windows") else None
        if not isinstance(window, dict) or not window.get("process_name") or not window.get("title"):
            state["final_outcome"] = "NO_ACTION"
            _set_decision(state, "FINAL_OUTCOME", reason="No authorized visible desktop window is available for a grounded action.", final_outcome="NO_ACTION")
            return state
        state["action_tool"] = "desktop_focus_authorized_window"
        state["action_target"] = str(window["title"])
        state["action_spec"] = {
            "action_type": "FOCUS_AUTHORIZED_WINDOW",
            "application": window["process_name"],
            "window_title": window["title"],
        }
        reuse = _reuse_desktop_approval_lineage(state)
        if reuse is None:
            return state
    elif intent == "CALENDAR_ACTION_REQUEST":
        observed = next((item.get("result") for item in state.get("observation_results", []) if item.get("tool") == "calendar_observer"), None)
        if not isinstance(observed, dict) or observed.get("status") != "OK" or not isinstance(observed.get("events"), list):
            state["final_outcome"] = "NO_ACTION"
            _set_decision(state, "FINAL_OUTCOME", reason="No calendar observation is available for a grounded calendar action.", final_outcome="NO_ACTION")
            return state
        spec = parse_calendar_request(state["user_request"], observed.get("events") or [])
        if not isinstance(spec, dict) or not spec.get("operation"):
            state["final_outcome"] = "NO_ACTION"
            _set_decision(state, "FINAL_OUTCOME", reason="The calendar request could not be deterministically grounded; no action was invented.", final_outcome="NO_ACTION")
            return state
        state["action_tool"] = "calendar_event_action"
        state["action_target"] = str(spec.get("event_id") or spec.get("title") or "calendar")
        state["action_spec"] = spec
        state["calendar_provider"] = str(observed.get("provider") or "fixture")
    elif intent == "EMAIL_ACTION_REQUEST":
        observed = next((item.get("result") for item in state.get("observation_results", []) if item.get("tool") == "email_observer"), None)
        if not isinstance(observed, dict) or observed.get("status") != "OK" or not isinstance(observed.get("messages"), list):
            state["final_outcome"] = "NO_ACTION"
            _set_decision(state, "FINAL_OUTCOME", reason="No email observation is available for a grounded reply.", final_outcome="NO_ACTION")
            return state
        spec = parse_email_request(state["user_request"], observed.get("messages") or [])
        if not isinstance(spec, dict) or spec.get("operation") != "send_reply":
            state["final_outcome"] = "NO_ACTION"
            _set_decision(state, "FINAL_OUTCOME", reason="The email request could not be deterministically grounded to one observed message; no send was prepared.", final_outcome="NO_ACTION")
            return state
        state["action_tool"] = "email_send_action"
        state["action_target"] = str(spec.get("message_id") or "email")
        state["action_spec"] = spec
        state["email_provider"] = str(spec.get("provider") or observed.get("provider") or "fixture")
    elif intent == "COMMS_ACTION_REQUEST":
        observed = next((item.get("result") for item in state.get("observation_results", []) if item.get("tool") == "comms_observer"), None)
        if not isinstance(observed, dict) or observed.get("status") != "OK" or not isinstance(observed.get("messages"), list):
            state["final_outcome"] = "NO_ACTION"
            _set_decision(state, "FINAL_OUTCOME", reason="No communication observation is available for a grounded reply.", final_outcome="NO_ACTION")
            return state
        spec = parse_comms_request(state["user_request"], observed.get("messages") or [])
        if not isinstance(spec, dict) or spec.get("operation") != "send_reply":
            state["final_outcome"] = "NO_ACTION"
            _set_decision(state, "FINAL_OUTCOME", reason="The communication request could not be deterministically grounded to one observed message; no send was prepared.", final_outcome="NO_ACTION")
            return state
        state["action_tool"] = "comms_send_action"
        state["action_target"] = str(spec.get("message_id") or "comms")
        state["action_spec"] = spec
        state["comms_provider"] = str(spec.get("provider") or observed.get("provider") or "comms")
    elif intent == "JOB_ACTION_REQUEST":
        prep = next((item.get("result") for item in state.get("observation_results", []) if item.get("tool") == "application_preparation"), None)
        prep_status = prep.get("status") if isinstance(prep, dict) else ""
        if isinstance(prep, dict) and prep_status == "human_required":
            state["final_outcome"] = "HUMAN_REQUIRED"
            _set_decision(state, "FINAL_OUTCOME", reason="The target posting requires human interaction before any application can be filled or submitted.", final_outcome="HUMAN_REQUIRED")
            return state
        if isinstance(prep, dict) and prep_status == "blocked":
            state["final_outcome"] = "NO_ACTION"
            _set_decision(state, "FINAL_OUTCOME", reason="The target posting was rejected as hostile content; no application action is produced.", final_outcome="NO_ACTION")
            return state
        content = prep.get("application_content") if isinstance(prep, dict) else None
        job_id = str((content or {}).get("job_id") or (prep or {}).get("job_id") or "")
        if not job_id:
            match = re.search(r"\bfixture-job-\d+\b", str(state.get("user_request") or ""))
            job_id = match.group(0) if match else ""
        if not job_id:
            state["final_outcome"] = "HUMAN_REQUIRED"
            _set_decision(state, "FINAL_OUTCOME", reason="No known posting could be grounded for the application action; a specific posting must be identified first.", final_outcome="HUMAN_REQUIRED")
            return state
        lower = str(state.get("user_request") or "").lower()
        if "submit" in lower:
            state["action_tool"] = "job_application_submit_action"
            state["action_spec"] = {"job_id": job_id, "provider": "fixture_application", "application_id": f"fixture_application-{job_id}"}
            operation_name = "submit"
            capability_id = "APPLICATION_SUBMIT"
        else:
            state["action_tool"] = "job_application_fill_action"
            state["action_spec"] = {"job_id": job_id, "provider": "fixture_application", "application_content": dict(content or {})}
            operation_name = "fill"
            capability_id = "APPLICATION_FILL"
        state["action_target"] = job_id
        state["application_provider"] = "fixture_application"
        base_context = state.get("capability_context") or {}
        try:
            state["capability_context"] = build_application_context(
                task_id=str(state.get("task_id") or ""),
                subgoal_id=str(state.get("current_subgoal_id") or base_context.get("subgoal_id") or ""),
                application_id="application",
                provider_id="fixture_application",
                capability_id=capability_id,
                operation_name=operation_name,
                target=job_id,
                session_id=str(base_context.get("session_id") or ""),
                evidence_refs=list(base_context.get("evidence_refs") or []),
                environment_fingerprint=str(state.get("environment_fingerprint") or base_context.get("environment_fingerprint") or str(Path("workspace").resolve())),
            )
        except ValueError:
            state["capability_context"] = base_context
    else:
        state["final_outcome"] = "NO_ACTION"
        _set_decision(state, "FINAL_OUTCOME", reason="Unsupported action intent.", final_outcome="NO_ACTION")
        return state

    risk_decision = evaluate_risk(
        f"execute {state['action_tool']}",
        tool_name=state["action_tool"],
    )
    state["risk_decision"] = risk_decision
    if not _evaluate_action_permission(state, tool_name=state["action_tool"], target=state["action_target"]):
        return state
    if not _evaluate_privacy(state, tool_name=state["action_tool"], target=state["action_target"]):
        return state
    if not _evaluate_automation_scope(state, tool_name=state["action_tool"], target=state["action_target"]):
        return state
    if state.get("task_id") and not state.get("approval_id"):
        _persist_action_lineage(
            state,
            action_type=state["action_tool"],
            tool_name=state["action_tool"],
            target=state["action_target"],
            risk_decision=risk_decision,
        )
    state["approval_required"] = bool(risk_decision.get("approval_required"))
    state["approved"] = False
    _set_decision(state, "APPROVAL_PENDING" if state["approval_required"] else "FINAL_OUTCOME", reason=risk_decision.get("reason", "Action evaluated."))
    _audit_event(state, "action_proposed", actor="nexus", tool=state["action_tool"], risk_level=risk_decision.get("risk_level"), approval_required=state["approval_required"], approved=False, target=state["action_target"], result="Grounded action proposal created.")
    return state


def create_proposal(state: NexusState):
    print("[NEXUS] Creating fix proposal...")
    state.setdefault("decision_stage", "RISK_EVALUATION")
    _set_decision(state, "RISK_EVALUATION", reason="The action is being evaluated against the allowlist, risk engine, and approval gate.")

    # ---------------------------------------------------------
    # SAFETY GATE
    # ---------------------------------------------------------
    # NEXUS must obey the diagnosis.
    #
    # If the diagnosis says:
    #
    # FIX_ALLOWED: NO
    #
    # then NEXUS MUST NOT:
    # - propose a code change
    # - request approval
    # - modify any file
    #
    # This prevents the proposal model from overriding
    # the diagnostic decision.
    # ---------------------------------------------------------

    diagnosis_text = ""

    for item in state["investigation"]:
        if item.startswith("DIAGNOSIS:"):
            diagnosis_text = item

    user_constraints = state.get("user_constraints") or _extract_explicit_constraints(state.get("user_request", ""))
    if user_constraints.get("do_not_modify") or user_constraints.get("do_not_propose_fixes"):
        print("[NEXUS] Explicit modification or fix constraints prohibit any proposal.")
        state["approval_required"] = False
        state["approved"] = False
        state["target_file"] = ""
        state["old_code"] = ""
        state["new_code"] = ""
        state["final_outcome"] = state.get("final_outcome", "")
        _set_decision(state, "FINAL_OUTCOME", reason="User constraints explicitly prohibit any modification or fix proposal.")
        _audit_event(
            state,
            "action_blocked",
            actor="nexus",
            risk_level=state.get("risk_decision", {}).get("risk_level", BLOCKED),
            approved=False,
            result="No modification proposed.",
            reason="User constraints explicitly prohibit any fix proposal or file modification.",
        )
        return state

    if "FIX_ALLOWED: NO" in diagnosis_text.upper():

        print(
            "[NEXUS] Diagnosis does not allow a code fix."
        )

        state["approval_required"] = False
        state["approved"] = False
        state["target_file"] = ""
        state["old_code"] = ""
        state["new_code"] = ""
        state["final_outcome"] = state.get("final_outcome", "")
        _set_decision(state, "FINAL_OUTCOME", reason="Diagnosis did not allow a fix.")
        _audit_event(
            state,
            "action_blocked",
            actor="nexus",
            risk_level=state.get("risk_decision", {}).get("risk_level", BLOCKED),
            approved=False,
            result="No modification proposed.",
            reason="Diagnosis did not allow a fix.",
        )

        return state

    # ---------------------------------------------------------
    # ONLY REACH THIS SECTION IF A FIX IS ALLOWED
    # ---------------------------------------------------------

    combined_investigation = "\n\n".join(
        state["investigation"]
    )

    proposal_prompt = f"""
You are proposing a safe code fix.

User request:
{state["user_request"]}

Investigation:
{combined_investigation}

IMPORTANT:
The diagnosis must explicitly establish that a fix is allowed.

If the diagnosis contains:

FIX_ALLOWED: NO

you MUST return:

NO_FIX

If the diagnosis contains:

FIX_ALLOWED: YES

and the evidence clearly identifies a logical error,
return exactly:

FILE: <relative file path>
OLD: <exact old code>
NEW: <exact new code>

Rules:

- Use only code actually present in the investigation.
- Do not invent code.
- Preserve indentation.
- Change only the smallest necessary code section.
- Do not rewrite working code for style.
- Do not replace code with an equivalent expression.
- The proposed change must directly address the diagnosed problem.
- Do not propose a fix based only on assumptions.
- Do not modify files yourself.

If no safe fix can be proposed, return:

NO_FIX
"""

    from app.tools.diagnoser import llm

    if llm is None:
        proposal = _build_deterministic_modification_proposal(state)
    else:
        try:
            response = llm.invoke(
                [
                    (
                        "system",
                        "You are a careful software debugging agent."
                    ),
                    (
                        "human",
                        proposal_prompt
                    ),
                ]
            )
            proposal = response.content.strip()
        except Exception:
            proposal = "NO_FIX"

    if proposal == "NO_FIX":
        if "FIX_ALLOWED: YES" in diagnosis_text.upper():
            risk_decision = evaluate_risk(
                "apply approved code fix",
                tool_name="fixer",
                target_path=state.get("target_file", "workspace"),
                workspace_root="workspace",
            )
            state["risk_decision"] = risk_decision
            state["approval_required"] = True
            state["approved"] = False
            _set_decision(
                state,
                "APPROVAL_PENDING",
                reason="The diagnosis allowed a fix, but the environment could not emit a structured patch. Explicit approval is required before any action is taken.",
            )
            _audit_event(
                state,
                "modification_approval_required",
                actor="nexus",
                tool="fixer",
                risk_level=risk_decision["risk_level"],
                approval_required=True,
                approved=False,
                target=state.get("target_file", "workspace"),
                result="Fix was allowed but no structured proposal was generated; approval boundary remains active.",
            )
            return state

        print("[NEXUS] No safe fix proposed.")

        state["approval_required"] = False
        _audit_event(
            state,
            "modification_proposed",
            actor="nexus",
            result="NO_FIX",
            reason="No safe modification proposal was returned.",
        )

        return state

    lines = proposal.splitlines()

    file_name = ""
    old_code = ""
    new_code = ""

    for line in lines:

        if line.startswith("FILE:"):
            file_name = line.replace(
                "FILE:", "", 1
            ).strip()

        elif line.startswith("OLD:"):
            old_code = line.replace(
                "OLD:", "", 1
            ).strip()

        elif line.startswith("NEW:"):
            new_code = line.replace(
                "NEW:", "", 1
            ).strip()

    if not file_name or not old_code or not new_code:

        print(
            "[NEXUS] Could not create a safe structured proposal."
        )

        state["approval_required"] = False
        _audit_event(
            state,
            "error",
            actor="nexus",
            result="Malformed modification proposal rejected.",
            reason="Proposal did not contain the required file and code fields.",
        )

        return state

    state["target_file"] = file_name
    state["old_code"] = old_code
    state["new_code"] = new_code
    risk_decision = evaluate_risk(
        "apply approved code fix",
        tool_name="fixer",
        target_path=file_name,
        workspace_root="workspace",
    )
    state["risk_decision"] = risk_decision
    if not _evaluate_action_permission(state, tool_name="fixer", target=file_name):
        return state
    if not _evaluate_privacy(state, tool_name="fixer", target=file_name):
        return state
    if not _evaluate_automation_scope(state, tool_name="fixer", target=file_name):
        return state
    if state.get("task_id") and not state.get("approval_id"):
        _persist_action_lineage(
            state,
            action_type="apply approved code fix",
            tool_name="fixer",
            target=file_name,
            risk_decision=risk_decision,
        )
    _audit_event(
        state,
        "risk_decision",
        actor="risk_engine",
        tool="fixer",
        risk_level=risk_decision["risk_level"],
        approval_required=risk_decision["approval_required"],
        approved=False,
        target=file_name,
        result=str(risk_decision["allowed"]),
        reason=risk_decision["reason"],
    )

    if risk_decision["risk_level"] == BLOCKED:
        print("[NEXUS] Proposed action was blocked by the risk engine.")
        state["approval_required"] = False
        state["approved"] = False
        state["target_file"] = ""
        state["old_code"] = ""
        state["new_code"] = ""
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason=risk_decision["reason"], final_outcome="BLOCKED")
        _audit_event(
            state,
            "action_blocked",
            actor="risk_engine",
            tool="fixer",
            risk_level=BLOCKED,
            approved=False,
            target=file_name,
            result="Blocked",
            reason=risk_decision["reason"],
        )
        return state

    state["approval_required"] = risk_decision["approval_required"]
    _set_decision(state, "APPROVAL_PENDING" if state["approval_required"] else "FINAL_OUTCOME", reason="A controlled approval boundary is required before the action can proceed." if state["approval_required"] else "The action is safe to proceed without further approval.", final_outcome="READY" if not state["approval_required"] else None)
    _audit_event(
        state,
        "modification_proposed",
        actor="nexus",
        tool="fixer",
        risk_level=risk_decision["risk_level"],
        approval_required=state["approval_required"],
        approved=False,
        target=file_name,
        result="Structured modification proposal created.",
    )

    print(
        f"[NEXUS] Proposed file: {file_name}"
    )

    return state


def should_request_approval(state: NexusState):

    if state.get("risk_decision", {}).get("risk_level") == BLOCKED:
        return "create_plan"

    if state["approval_required"]:
        return "request_approval"

    return "create_plan"


def request_approval(state: NexusState):
    state.setdefault("decision_stage", "APPROVAL_PENDING")
    state.setdefault("decision_reason", "Human approval is required before the action can proceed.")

    if state.get("risk_decision", {}).get("risk_level") == BLOCKED:
        state["approved"] = False
        state["approval_required"] = False
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason="The risk engine blocked the action before approval.", final_outcome="BLOCKED")
        return state

    if state.get("audit_error"):
        state["approved"] = False
        state["approval_required"] = False
        state["final_outcome"] = "AUDIT_ERROR"
        _set_decision(state, "FINAL_OUTCOME", reason="Audit persistence failed; the decision loop is closed safely.", final_outcome="AUDIT_ERROR")
        return state

    override = str(state.get("approval_override") or "").upper()
    approval_tool = state.get("action_tool") or "fixer"
    approval_target = state.get("action_target") or state.get("target_file", "")
    if state.get("approval_id"):
        try:
            if override in {"APPROVED", "REJECTED"}:
                decided = decide_approval(state["approval_id"], override, actor="approval_override", db_path=state.get("approval_db_path") or state.get("persistence_db_path") or None)
            else:
                decided = get_approval(state["approval_id"], db_path=state.get("approval_db_path") or state.get("persistence_db_path") or None)
            status = str((decided or {}).get("status", "")).upper()
            if status == "APPROVED":
                state["approved"] = True
                state["approval_required"] = False
                _set_decision(state, "ACTION", reason="Durable approval is valid for the bound task, checkpoint, proposal, tool, target, and risk.")
                return state
            if status in {"REJECTED", "EXPIRED", "INVALIDATED", "CONSUMED"}:
                state["approved"] = False
                state["approval_required"] = False
                state["final_outcome"] = "APPROVAL_REJECTED" if status == "REJECTED" else "BLOCKED"
                _set_decision(state, "FINAL_OUTCOME", reason=f"Durable approval is {status.lower()}.", final_outcome=state["final_outcome"])
                return state
            state["approved"] = False
            state["approval_required"] = True
            state["final_outcome"] = "APPROVAL_REQUIRED"
            _set_decision(state, "APPROVAL_PENDING", reason="A durable approval decision is required before execution.", final_outcome="APPROVAL_REQUIRED")
            return state
        except ValueError as exc:
            state["approved"] = False
            state["approval_required"] = False
            state["final_outcome"] = "BLOCKED"
            _set_decision(state, "FINAL_OUTCOME", reason=str(exc), final_outcome="BLOCKED")
            return state
    if override in {"APPROVED", "REJECTED"}:
        state["approved"] = override == "APPROVED"
        state["approval_required"] = not state["approved"]
        if state["approved"]:
            _set_decision(state, "ACTION", reason="Approval override granted; the approved action may proceed through the controlled execution path.")
            _audit_event(
                state,
                "approval_granted",
                actor="approval_override",
                tool=approval_tool,
                risk_level=state.get("risk_decision", {}).get("risk_level", "MEDIUM_RISK"),
                approval_required=True,
                approved=True,
                target=approval_target,
                result="Approval override was granted for this non-interactive run.",
            )
        else:
            state["final_outcome"] = "APPROVAL_REJECTED"
            _set_decision(state, "FINAL_OUTCOME", reason="Approval override rejected the action.", final_outcome="APPROVAL_REJECTED")
            _audit_event(
                state,
                "approval_denied",
                actor="approval_override",
                tool=approval_tool,
                risk_level=state.get("risk_decision", {}).get("risk_level", "MEDIUM_RISK"),
                approval_required=True,
                approved=False,
                target=approval_target,
                result="Approval override rejected the action.",
            )
        return state

    in_pytest = "PYTEST_CURRENT_TEST" in os.environ
    is_interactive = hasattr(sys.stdin, "isatty") and sys.stdin.isatty()

    # In automated tests, a mocked input() is often used to simulate a human decision.
    # That response must be honored before the fail-closed non-interactive guard fires.
    # In real non-interactive runs without an explicit response, we still fail closed.
    answer = None
    if not (not is_interactive or in_pytest):
        print("\n========== NEXUS APPROVAL ==========")

        print("\nNEXUS wants to modify:")
        print(state["target_file"])

        print("\nProposed change:")

        print("\nOLD:")
        print(state["old_code"])

        print("\nNEW:")
        print(state["new_code"])

    try:
        answer = input("\nApprove this change? (yes/no): ").strip().lower()
    except (EOFError, OSError, TypeError):
        answer = None

    if answer is None and (not is_interactive or in_pytest):
        state["approved"] = False
        state["approval_required"] = False
        state["final_outcome"] = "APPROVAL_REQUIRED"
        _set_decision(state, "FINAL_OUTCOME", reason="Approval requires an explicit interactive or UI-bound decision in this environment.", final_outcome="APPROVAL_REQUIRED")
        _audit_event(
            state,
            "approval_required",
            actor="nexus",
            tool=approval_tool,
            risk_level=state.get("risk_decision", {}).get("risk_level", "MEDIUM_RISK"),
            approval_required=True,
            approved=False,
            target=approval_target,
            result="Non-interactive environment cannot safely accept approval.",
        )
        return state

    if answer is None:
        answer = "no"

    _audit_event(
        state,
        "approval_requested",
        actor="nexus",
        tool=approval_tool,
        risk_level=state.get("risk_decision", {}).get("risk_level", "MEDIUM_RISK"),
        approval_required=True,
        approved=False,
        target=approval_target,
        result="Human approval requested.",
    )

    if answer in {"yes", "y"}:

        state["approved"] = True
        _set_decision(state, "ACTION", reason="Approval granted; the approved action may proceed through the controlled execution path.")
        if not _audit_event(
            state,
            "approval_granted",
            actor="human",
            tool=approval_tool,
            risk_level=state.get("risk_decision", {}).get("risk_level", "MEDIUM_RISK"),
            approval_required=True,
            approved=True,
            target=approval_target,
            result="Human approval granted.",
        ):
            state["approved"] = False
            state["approval_required"] = False

        print(
            "[NEXUS] Approval granted."
        )

    else:

        state["approved"] = False
        state["approval_required"] = False
        state["final_outcome"] = "APPROVAL_REJECTED"
        _set_decision(state, "FINAL_OUTCOME", reason="Human approval was denied for the proposed action.", final_outcome="APPROVAL_REJECTED")
        _audit_event(
            state,
            "approval_denied",
            actor="human",
            tool="fixer",
            risk_level=state.get("risk_decision", {}).get("risk_level", "MEDIUM_RISK"),
            approval_required=True,
            approved=False,
            target=state["target_file"],
            result="Human approval denied.",
        )

        print(
            "[NEXUS] Change rejected."
        )

    return state


def should_execute_action(state: NexusState):
    if state.get("approved") and not state.get("approval_required"):
        return "execute_action"
    return "create_plan"


def execute_action(state: NexusState):
    _set_decision(state, "ACTION", reason="The approved action is now entering the controlled execution path.")

    if state.get("task_id") and state.get("approval_id") and state.get("journal_checkpoint_id"):
        if str(state.get("action_tool") or "").startswith("browser_"):
            spec = state.get("action_spec") or {}
            observed_target = str(spec.get("observed_target") or "")
            if observed_target:

                def _browser_revalidator(*, _target: str = observed_target):
                    try:
                        return observe_browser_page(_target, timeout_seconds=ACTION_TIMEOUT_SECONDS)
                    except Exception as exc:
                        return {"source": "browser", "url": str(_target)[:2048], "status": "ERROR", "error": redact_text(str(exc))}

                state["browser_revalidator"] = _browser_revalidator
        if str(state.get("action_tool") or "") == "browser_controller":
            # Defense in depth: the controller never runs without a validated
            # browser capability context binding this exact task/subgoal/target.
            # The proposal path builds it; anything else fails closed here.
            try:
                from app.agent.capability_context import validate_capability_context as _validate_context
                existing = state.get("capability_context")
                if not isinstance(existing, dict) or not existing:
                    raise ValueError("Browser controller dispatch requires a capability context.")
                validated = _validate_context(existing)
                if validated.get("application_id") != "browser" or validated.get("tool_name") != "browser_controller":
                    raise ValueError("The capability context is not bound to the browser controller.")
                if validated.get("task_id") != str(state.get("task_id") or ""):
                    raise ValueError("The capability context is not bound to this task.")
                if state.get("action_target") and validated.get("target") and validated.get("target") != str(state.get("action_target") or ""):
                    raise ValueError("The capability context target drifted from the approved action target.")
                state["capability_context"] = validated
            except ValueError as exc:
                state["action_result"] = f"Browser controller dispatch refused: {exc}"
                state["final_outcome"] = "BLOCKED"
                _set_decision(state, "FINAL_OUTCOME", reason="Browser controller dispatch was refused without a validated bound capability context.", final_outcome="BLOCKED")
                _audit_event(state, "action_blocked", actor="nexus", tool="browser_controller", risk_level=BLOCKED, approved=False, target=str(state.get("action_target", "")), result="BLOCKED", reason="Validated browser capability context is required before controller dispatch.")
                return state
        execution = execute_authorized_action(state, db_path=state.get("approval_db_path") or state.get("persistence_db_path") or None)
        state["action_result"] = execution.get("result", execution.get("error", ""))
        state["execution_id"] = execution.get("execution_id", "")
        state["verification"] = str(execution.get("verification", ""))
        state["last_verification"] = state["verification"]
        if str(state.get("action_tool") or "").startswith("browser_"):
            if isinstance(execution, dict) and execution.get("status") == "COMPLETED":
                state["browser_action_executed"] = True
                result_payload = execution.get("result")
                if isinstance(result_payload, dict):
                    state["browser_action_result"] = dict(result_payload)
                    page_id = str(result_payload.get("page_id") or "")
                    if page_id and str(state.get("action_tool") or "") == "browser_controller":
                        context = dict(state.get("capability_context") or {})
                        context["page_id"] = page_id
                        state["capability_context"] = context
        if execution.get("status") != "COMPLETED":
            state["final_outcome"] = "BLOCKED" if execution.get("status") == "BLOCKED" else "FAILED_VERIFICATION"
        if state.get("task_id"):
            # A blocked dispatch is terminal ledger truth, not a running
            # task: record BLOCKED so downstream nodes and the runner cannot
            # reinterpret a security denial as ongoing or successful work.
            dispatch_blocked = execution.get("status") == "BLOCKED"
            if dispatch_blocked:
                state["task_status"] = "BLOCKED"
            update_task_status(
                state["task_id"],
                "BLOCKED" if dispatch_blocked else "RUNNING",
                current_stage="ACTION",
                current_sub_goal=state.get("decision_reason", ""),
                action_lineage={"checkpoint_id": state.get("journal_checkpoint_id", ""), "proposal_hash": state.get("proposal_hash", ""), "approval_id": state.get("approval_id", ""), "execution_id": state.get("execution_id", ""), "tool_name": state.get("action_tool", ""), "target": state.get("action_target", "")},
                db_path=state.get("persistence_db_path") or None,
            )
        _audit_event(state, "action_execution_result", actor="action_executor", tool=state.get("action_tool", "fixer"), risk_level=state.get("risk_decision", {}).get("risk_level", BLOCKED), approved=bool(state.get("approved")), target=state.get("action_target", state.get("target_file", "")), result=str(execution.get("status", "FAILED")), metadata={"approval_id": state.get("approval_id", ""), "checkpoint_id": state.get("journal_checkpoint_id", ""), "verification": execution.get("verification", "")})
        return state

    if state.get("action_tool") and state.get("action_tool") != "fixer":
        state["action_result"] = "Consequential application actions require the durable Action Executor approval path."
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason="Direct consequential dispatch was rejected because durable approval/checkpoint authority was unavailable.", final_outcome="BLOCKED")
        _audit_event(
            state,
            "action_blocked",
            actor="nexus",
            tool=str(state.get("action_tool")),
            risk_level=state.get("risk_decision", {}).get("risk_level", BLOCKED),
            approved=False,
            target=state.get("action_target", ""),
            result="BLOCKED",
            reason="Durable Action Executor authority is required.",
        )
        return state

    risk_decision = evaluate_risk(
        "apply approved code fix",
        tool_name="fixer",
        target_path=state.get("target_file", ""),
        workspace_root="workspace",
    )
    state["risk_decision"] = risk_decision

    if not state["approved"] or not risk_decision["allowed"] or state.get("audit_error"):

        state["action_result"] = (
            "Action not executed because it was not approved or was blocked "
            "by the risk engine."
        )
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason="Execution was halted because the approved action did not satisfy the risk boundary.", final_outcome="BLOCKED")
        _audit_event(
            state,
            "action_blocked",
            actor="nexus",
            tool="fixer",
            risk_level=risk_decision["risk_level"],
            approved=False,
            target=state.get("target_file", ""),
            result=state["action_result"],
            reason=risk_decision["reason"],
        )

        return state

    if not _audit_event(
        state,
        "action_execution_started",
        actor="nexus",
        tool="fixer",
        risk_level=risk_decision["risk_level"],
        approval_required=risk_decision["approval_required"],
        approved=True,
        target=state["target_file"],
        result="Approved mutation is starting.",
        fail_closed=True,
    ):
        state["action_result"] = "Action not executed because audit persistence failed."
        return state

    state["action_result"] = "Consequential execution requires durable Action Executor authority."
    state["final_outcome"] = "BLOCKED"
    _set_decision(state, "FINAL_OUTCOME", reason="Direct mutation dispatch was rejected because durable task, checkpoint, approval, and proposal bindings were unavailable.", final_outcome="BLOCKED")
    _audit_event(
        state,
        "action_blocked",
        actor="nexus",
        tool="fixer",
        risk_level=risk_decision["risk_level"],
        approval_required=risk_decision["approval_required"],
        approved=True,
        target=state["target_file"],
        result="BLOCKED",
        reason=state["action_result"],
    )
    return state


def evaluate_verification(state: NexusState):
    """Evaluate runtime evidence and decide whether a bounded retry is allowed."""
    _set_decision(state, "VERIFICATION", reason="Fresh runtime evidence is being compared to the approved action.")

    _audit_event(
        state,
        "verification_started",
        actor="nexus",
        tool="runtime_inspector",
        risk_level="READ_ONLY",
        approved=bool(state.get("approved")),
        target=state.get("target_file", ""),
        result="Runtime verification started.",
    )

    # A terminal dispatch denial must stick: when the executor blocked the
    # action before any execution ran, there is no runtime evidence to
    # reinterpret and no retry to schedule. Overwriting BLOCKED here (or
    # downstream) would convert a security denial into a success story.
    if str(state.get("final_outcome") or "") == "BLOCKED" and not state.get("execution_id"):
        _set_decision(state, "FINAL_OUTCOME", reason="The blocked dispatch stands; no execution occurred to verify.", final_outcome="BLOCKED")
        _audit_event(
            state,
            "verification_skipped",
            actor="nexus",
            tool="runtime_inspector",
            risk_level="READ_ONLY",
            approved=False,
            target=state.get("target_file", state.get("action_target", "")),
            result="BLOCKED",
            reason="Verification skipped because dispatch was blocked before execution.",
        )
        return "stop"

    if state.get("action_tool") and state.get("action_tool") != "fixer":
        action_result = state.get("action_result") or {}
        result_text = str(action_result).upper()
        verified = isinstance(action_result, dict) and (
            action_result.get("verification") == "SUCCESS"
            or action_result.get("status") == "COMPLETED"
        )
        if verified or "VERIFICATION\": \"SUCCESS" in result_text or '"VERIFICATION": "SUCCESS"' in result_text or "STATUS: COMPLETED" in result_text:
            state["final_outcome"] = "SUCCESS"
            _set_decision(state, "FINAL_OUTCOME", reason="The approved grounded action produced verified post-action evidence.", final_outcome="SUCCESS")
            return "success"
        state["final_outcome"] = "FAILED_VERIFICATION"
        _set_decision(state, "FINAL_OUTCOME", reason="The approved grounded action did not produce verified post-action evidence.", final_outcome="FAILED_VERIFICATION")
        return "stop"

    if not state.get("approved"):
        state["verification"] = (
            "No verification performed because the action was not approved."
        )
        state["last_verification"] = state["verification"]
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason="The loop did not execute because approval was missing.", final_outcome="BLOCKED")
        return "stop"

    if not state.get("target_file"):
        state["verification"] = (
            "Verification failed: no target file was approved for execution."
        )
        state["last_verification"] = state["verification"]
        state["final_outcome"] = "BLOCKED"
        _set_decision(state, "FINAL_OUTCOME", reason="No approved target file was available for verification.", final_outcome="BLOCKED")
        return "stop"

    runtime_result = run_python_file(
        workspace_path="workspace",
        file_name=state["target_file"],
        timeout_seconds=30,
    )

    state["last_verification"] = runtime_result
    state["verification_history"] = state.get("verification_history", []) + [runtime_result]
    state["verification"] = (
        "Actual runtime evidence:\n"
        f"{runtime_result}"
    )

    _audit_event(
        state,
        "verification_result",
        actor="nexus",
        tool="runtime_inspector",
        risk_level="READ_ONLY",
        approved=bool(state.get("approved")),
        target=state.get("target_file", ""),
        result=runtime_result,
    )

    if "STATUS: SUCCESS" in runtime_result.upper():
        state["final_outcome"] = "SUCCESS"
        _set_decision(state, "FINAL_OUTCOME", reason="Runtime verification succeeded after the approved action.", final_outcome="SUCCESS")
        return "success"

    if state.get("retry_count", 0) >= MAX_RETRIES:
        state["verification"] = (
            "MAXIMUM SELF-CORRECTION ATTEMPTS REACHED.\n"
            "NEXUS could not verify a successful fix within the allowed attempts.\n"
            "No further modification was performed.\n\n"
            f"Actual runtime evidence:\n{runtime_result}"
        )
        state["last_verification"] = state["verification"]
        state["final_outcome"] = "FAILED_VERIFICATION"
        _set_decision(state, "FINAL_OUTCOME", reason="The bounded retry limit was reached without successful verification.", final_outcome="FAILED_VERIFICATION")
        return "stop"

    state["retry_count"] = int(state.get("retry_count", 0)) + 1
    state["approval_required"] = True
    state["approved"] = False
    state["verification"] = (
        "Runtime verification failed.\n"
        "A revised proposal requires fresh human approval.\n\n"
        f"Actual runtime evidence:\n{runtime_result}"
    )
    state["last_verification"] = runtime_result
    state["final_outcome"] = "RETRY"
    _set_decision(state, "RETRY", reason="Fresh observation and a revised proposal are required after failed verification.", final_outcome="RETRY")
    _audit_event(
        state,
        "retry",
        actor="nexus",
        tool="runtime_inspector",
        risk_level="READ_ONLY",
        approved=False,
        target=state.get("target_file", ""),
        result="Fresh approval is required after failed verification.",
        metadata={"retry_count": state["retry_count"]},
    )
    return "retry"


def should_retry_verification(state: NexusState):
    action_result = state.get("action_result")
    if state.get("action_tool") and state.get("action_tool") != "fixer":
        if isinstance(action_result, dict) and action_result.get("verification") == "SUCCESS":
            return "success"
        if isinstance(action_result, dict) and action_result.get("status") in {"COMPLETED", "BLOCKED", "VERIFICATION_FAILED", "EXECUTION_FAILED"}:
            return "stop"
        return "stop"

    if not state.get("last_verification"):
        return "stop"

    if "STATUS: SUCCESS" in state["last_verification"].upper():
        return "success"

    if state.get("retry_count", 0) >= MAX_RETRIES:
        return "stop"

    return "retry"


def verify_result(state: NexusState):

    print(
        "\n[NEXUS] Verifying result..."
    )

    outcome = evaluate_verification(state)
    state["verification"] = state.get("verification", "")
    state["last_verification"] = state.get("last_verification", state["verification"])
    return state


def _phase32_enabled(state: NexusState) -> bool:
    return bool(state.get("autonomous_execution_enabled", False))


def _phase32_persist(state: NexusState) -> None:
    task_id = str(state.get("task_id") or "")
    if not task_id:
        return
    update_task_status(
        task_id,
        str(state.get("task_status") or "RUNNING"),
        current_stage=state.get("decision_stage", "REQUEST"),
        current_sub_goal=state.get("current_subgoal_id", ""),
        selected_tools=state.get("selected_tools", []),
        evidence_refs=state.get("completion_evidence", []),
        final_outcome=state.get("final_outcome", ""),
        status_reason=state.get("decision_reason", ""),
        goal_plan=state.get("goal_plan", []),
        subgoal_statuses=state.get("subgoal_statuses", {}),
        current_subgoal_id=state.get("current_subgoal_id", ""),
        plan_version=state.get("plan_version", "v1"),
        plan_hash=state.get("plan_hash", ""),
        task_retry_count=state.get("task_retry_count", 0),
        subgoal_retry_count=state.get("subgoal_retry_count", {}),
        failure_classifications=state.get("failure_classifications", {}),
        adaptation_history=state.get("adaptation_history", []),
        completion_evidence=state.get("completion_evidence", []),
        subgoal_lineage=state.get("subgoal_lineage", {}),
        execution_ids=state.get("execution_ids", {}),
        consumed_execution_ids=state.get("consumed_execution_ids", []),
        plan_history=state.get("plan_history", []),
        recovery_history=state.get("recovery_history", []),
        recovery_attempts=state.get("recovery_attempts", 0),
        db_path=state.get("persistence_db_path") or None,
    )

def _application_for_tool(tool_name: str) -> str:
    name = str(tool_name or "")
    if name.startswith("browser_"):
        return "browser"
    if name.startswith("desktop_"):
        return "desktop"
    if name == "calendar_observer":
        return "calendar"
    if name in {"email_observer", "email_draft_preparation", "email_send_action"}:
        return "email"
    if name in {"comms_observer", "comms_draft_preparation", "comms_send_action"}:
        return "comms"
    if name in {"job_search", "job_details", "application_requirements"}:
        return "job_search"
    if name in {"application_preparation", "job_application_fill_action", "job_application_submit_action"}:
        return "application"
    if name == "git_inspector":
        return "git"
    if name in {"runtime_inspector"}:
        return "runtime"
    if name in {"terminal_inspector"}:
        return "terminal"
    if name in {"log_inspector"}:
        return "log"
    if name in {"security_scan"}:
        return "security"
    if name in {"logic_inspector"}:
        return "logic"
    return "workspace"


def _subgoal_target(state: NexusState, subgoal: dict[str, object], tool_name: str) -> str:
    if tool_name.startswith("browser_"):
        return str(state.get("browser_url") or "")
    if tool_name.startswith("desktop_"):
        action = state.get("action_spec") or {}
        return str(action.get("window_title") or "")
    if tool_name in {"job_details", "application_requirements", "application_preparation", "job_application_fill_action", "job_application_submit_action"}:
        return str(state.get("action_target") or "")
    if tool_name in {"workspace_inspector", "git_inspector", "security_scan", "runtime_inspector", "logic_inspector", "error_detector", "relevant_file_selector"}:
        return str((state.get("selected_files") or ["workspace"])[0])
    return "workspace"


def _first_observed_job_id(state: NexusState) -> str:
    for item in state.get("observation_results", []):
        if item.get("tool") != "job_search":
            continue
        result = item.get("result") or {}
        if not isinstance(result, dict):
            continue
        observed = result.get("results") or []
        if observed:
            return str(observed[0].get("id") or "")
    return ""


def _build_subgoal_context(state: NexusState, subgoal: dict[str, object], tool_name: str, *, evidence: object = None) -> dict[str, object]:
    declared_application = str(subgoal.get("application_id") or "")
    application = _application_for_tool(tool_name) if not declared_application or (declared_application == "workspace" and tool_name not in {"workspace_inspector", "relevant_file_selector"}) else declared_application
    capability = str(subgoal.get("capability_id") or "inspect")
    freshness_deadline = ""
    if evidence is not None:
        freshness_deadline = (datetime.now(timezone.utc) + timedelta(seconds=CONTEXT_FRESHNESS_SECONDS)).isoformat(timespec="seconds")
    return build_capability_context(
        task_id=str(state.get("task_id") or ""),
        subgoal_id=str(state.get("current_subgoal_id") or ""),
        application_id=application,
        capability_id=capability,
        tool_name=tool_name,
        target=_subgoal_target(state, subgoal, tool_name),
        session_id=str(state.get("capability_context", {}).get("session_id", "")),
        page_id=str(state.get("capability_context", {}).get("page_id", "")),
        window_identity=str(state.get("capability_context", {}).get("window_identity", "")),
        observation_id=f"obs-{uuid.uuid4().hex[:12]}",
        evidence_refs=list(subgoal.get("input_evidence_refs") or []),
        evidence=evidence,
        freshness_deadline=freshness_deadline,
        environment_fingerprint=str(state.get("environment_fingerprint") or ""),
    )


def should_enter_phase32_loop(state: NexusState):
    if str(state.get("final_outcome") or "") == "BLOCKED":
        return "end"
    if _phase32_enabled(state) and state.get("goal_plan"):
        return "select_next_subgoal"
    return "end"


def _plan_bound_to_current_hash(state: NexusState) -> list[dict[str, object]]:
    plan_hash_now = str(state.get("plan_hash") or "")
    subgoal_hashes = state.get("subgoal_plan_hash") or {}
    plan: list[dict[str, object]] = []
    for item in state.get("goal_plan", []):
        sid = str(item.get("sub_goal_id") or "")
        if not sid:
            continue
        bound_hash = str(subgoal_hashes.get(sid, "") or "")
        if bound_hash and plan_hash_now and bound_hash != plan_hash_now:
            continue
        plan.append(item)
    return plan


def select_next_subgoal(state: NexusState):
    state["phase32_loop_steps"] = int(state.get("phase32_loop_steps", 0)) + 1
    if state["phase32_loop_steps"] > MAX_PHASE32_LOOP_STEPS:
        state["task_status"] = "FAILED"
        state["final_outcome"] = "FATAL"
        _set_decision(state, "FINAL_OUTCOME", reason="The bounded Phase 32 loop limit was reached.", final_outcome="FATAL")
        _phase32_persist(state)
        return state

    completed = set(state.get("completed_subgoals") or [])
    completed.update(key for key, value in (state.get("subgoal_statuses") or {}).items() if value == "COMPLETED")
    blocked = {key for key, value in (state.get("subgoal_statuses") or {}).items() if value in TERMINAL_FAILURE_STATUSES or value in {"BLOCKED", "FAILED", "HUMAN_REQUIRED"}}
    active_plan = _plan_bound_to_current_hash(state)
    next_goal = next_ready_subgoal(active_plan, completed=completed, blocked=blocked)
    if next_goal is None:
        state["current_subgoal_id"] = ""
        state["selected_tool"] = ""
        state["selected_tools"] = []
        required_ids = {str(item.get("sub_goal_id")) for item in active_plan if item.get("sub_goal_id")}
        completed_ids = {key for key, value in (state.get("subgoal_statuses") or {}).items() if value == "COMPLETED"}
        if required_ids and required_ids.issubset(completed_ids):
            if state.get("approval_required") and not state.get("approved"):
                state["task_status"] = "WAITING_APPROVAL"
                state["final_outcome"] = state.get("final_outcome") or "READ_ONLY"
                _set_decision(state, "APPROVAL_PENDING", reason="All eligible Phase 32 subgoals completed with bounded evidence; a durable approval is still required before any authorized action executes.", final_outcome=state["final_outcome"])
            else:
                state["task_status"] = "COMPLETED"
                state["final_outcome"] = "SUCCESS" if _browser_action_performed(state) else (state.get("final_outcome") or "READ_ONLY")
                _set_decision(state, "FINAL_OUTCOME", reason="All eligible Phase 32 subgoals completed with bounded evidence.", final_outcome=state["final_outcome"])
        else:
            state["task_status"] = "FAILED"
            state["final_outcome"] = "EVIDENCE_CONFLICT"
            _set_decision(state, "FINAL_OUTCOME", reason="Phase 32 could not verify every planned subgoal.", final_outcome="EVIDENCE_CONFLICT")
        _phase32_persist(state)
        return state

    subgoal_id = str(next_goal["sub_goal_id"])
    state["current_subgoal_id"] = subgoal_id
    state["selected_tools"] = list(next_goal.get("selected_tools") or [])
    state["selected_tool"] = state["selected_tools"][0] if state["selected_tools"] else ""
    statuses = dict(state.get("subgoal_statuses") or {})
    statuses[subgoal_id] = "READY"
    state["subgoal_statuses"] = statuses
    _set_decision(state, "SELECT_NEXT_SUBGOAL", reason=f"Selected ready subgoal {subgoal_id} after dependency validation.")
    _phase32_persist(state)
    return state


def execute_phase32_subgoal(state: NexusState):
    subgoal_id = str(state.get("current_subgoal_id") or "")
    plan_item = next((item for item in state.get("goal_plan", []) if item.get("sub_goal_id") == subgoal_id), {})
    selected_tools = list(plan_item.get("selected_tools") or [])
    state["selected_tools"] = selected_tools
    state["selected_tool"] = selected_tools[0] if selected_tools else ""
    statuses = dict(state.get("subgoal_statuses") or {})

    persisted_execution_id = str((state.get("execution_ids") or {}).get(subgoal_id, ""))
    consumed = set(state.get("consumed_execution_ids") or [])
    if persisted_execution_id and persisted_execution_id in consumed:
        state["_phase32_replay_guard"] = True
        statuses[subgoal_id] = "COMPLETED"
        state["subgoal_statuses"] = statuses
        state.setdefault("completed_subgoals", [])
        if subgoal_id not in state["completed_subgoals"]:
            state["completed_subgoals"] = list(state["completed_subgoals"]) + [subgoal_id]
        state.setdefault("completion_evidence", [])
        if f"{subgoal_id}:verified" not in state["completion_evidence"]:
            state["completion_evidence"] = list(state["completion_evidence"]) + [f"{subgoal_id}:verified"]
        _set_decision(state, "CLASSIFY_RESULT", reason=f"Subgoal {subgoal_id} was already consumed by a prior execution; it will not be replayed.")
        _phase32_persist(state)
        return state

    if "browser_observer" in selected_tools and not state.get("browser_url"):
        statuses[subgoal_id] = "HUMAN_REQUIRED"
        state["subgoal_statuses"] = statuses
        state["action_result"] = "Browser observation requires an explicit public HTTP(S) target."
        state.setdefault("failure_classifications", {})[subgoal_id] = "HUMAN_REQUIRED"
        state["task_status"] = "BLOCKED"
        state["final_outcome"] = "HUMAN_REQUIRED"
        _set_decision(state, "FINAL_OUTCOME", reason="An explicit browser target is required; no URL was invented.", final_outcome="HUMAN_REQUIRED")
        _phase32_persist(state)
        return state
    try:
        context = _build_subgoal_context(
            state,
            plan_item,
            selected_tools[0] if selected_tools else "workspace_inspector",
            evidence=state.get("normalized_evidence", []) if not selected_tools else None,
        )
    except ValueError as exc:
        statuses[subgoal_id] = "INVALID_TARGET"
        state["subgoal_statuses"] = statuses
        state["action_result"] = redact_text(str(exc))
        state.setdefault("failure_classifications", {})[subgoal_id] = "INVALID_TARGET"
        state["task_status"] = "FAILED"
        state["final_outcome"] = "INVALID_TARGET"
        _set_decision(state, "FINAL_OUTCOME", reason=f"Subgoal {subgoal_id} could not be bound to a valid capability context.", final_outcome="INVALID_TARGET")
        _phase32_persist(state)
        return state
    state["capability_context"] = context
    state.setdefault("subgoal_contexts", {})[subgoal_id] = context
    state.setdefault("execution_ids", {})[subgoal_id] = f"execution-{uuid.uuid4().hex[:16]}"
    state.setdefault("subgoal_lineage", {})[subgoal_id] = {
        "task_id": context["task_id"],
        "subgoal_id": context["subgoal_id"],
        "application_id": context["application_id"],
        "capability_id": context["capability_id"],
        "tool_name": context["tool_name"],
        "target": context["target"],
        "session_id": context.get("session_id", ""),
        "page_id": context.get("page_id", ""),
        "window_identity": context.get("window_identity", ""),
        "observation_id": context.get("observation_id", ""),
        "evidence_refs": list(context.get("evidence_refs") or []),
        "evidence_hash": context.get("evidence_hash", ""),
        "freshness_deadline": context.get("freshness_deadline", ""),
        "environment_fingerprint": context.get("environment_fingerprint", ""),
        "execution_id": state["execution_ids"][subgoal_id],
        "attempt": int((state.get("subgoal_retry_count") or {}).get(subgoal_id, 0)) + 1,
        "status": "EXECUTING",
    }
    statuses[subgoal_id] = "EXECUTING"
    state["subgoal_statuses"] = statuses
    _set_decision(state, "SELECT_TOOLS", reason=f"Allowlisted tools selected for subgoal {subgoal_id}.")
    print(f"[NEXUS] Phase 32 subgoal: {subgoal_id}")
    print(f"[NEXUS] Phase 32 selected tools: {selected_tools}")

    _set_decision(state, "EXECUTE_SUBGOAL", reason=f"Executing subgoal {subgoal_id} through the trusted Tool Registry.")
    passthrough_tools = [tool for tool in selected_tools if tool != "browser_controller"]
    deferred_records: list[dict[str, object]] = []
    if "browser_controller" in selected_tools:
        # The consequential controller never executes through the read-only
        # registry loop (registry dispatch is fail-closed for it). Attach the
        # real Action Executor evidence when this run already performed the
        # approved browser action; otherwise record an honest block without
        # launching any browser.
        if not state.get("browser_url"):
            statuses[subgoal_id] = "HUMAN_REQUIRED"
            state["subgoal_statuses"] = statuses
            state["action_result"] = "Real-browser execution requires an explicit public HTTP(S) target."
            state.setdefault("failure_classifications", {})[subgoal_id] = "HUMAN_REQUIRED"
            state["task_status"] = "BLOCKED"
            state["final_outcome"] = "HUMAN_REQUIRED"
            _set_decision(state, "FINAL_OUTCOME", reason="An explicit browser target is required; no URL was invented.", final_outcome="HUMAN_REQUIRED")
            _phase32_persist(state)
            return state
        controller_evidence = state.get("browser_action_result") if state.get("browser_action_executed") else None
        if (
            isinstance(controller_evidence, dict)
            and controller_evidence.get("source") == "browser_controller"
            and str(controller_evidence.get("status") or "") in {"OK", "COMPLETED"}
        ):
            deferred_records.append({"tool": "browser_controller", "status": "ok", "result": controller_evidence})
            executed_id = str((state.get("execution_ids") or {}).get(subgoal_id, ""))
            if executed_id:
                state["consumed_execution_ids"] = list(dict.fromkeys(list(state.get("consumed_execution_ids") or []) + [executed_id]))
        else:
            deferred_records.append({
                "tool": "browser_controller",
                "status": "blocked",
                "result": "Interactive browser execution requires the durable Action Executor approval path; no browser was launched from the read-only evidence loop.",
            })
    results = execute_selected_tools(
        passthrough_tools,
        workspace_path="workspace",
        user_request=state.get("user_request", ""),
        file_name=(state.get("selected_files") or [""])[0],
        file_names=state.get("selected_files", []),
        timeout_seconds=30,
        max_files=10,
        url=state.get("browser_url", ""),
        capability_context=state.get("capability_context", {}),
        security_scan_target="." if state.get("request_intent") == "SECURITY_SCAN_REQUEST" else "",
        job_search_query=state.get("user_request", ""),
        job_id=state.get("action_target", "") or _first_observed_job_id(state),
        job_provider="fixture_jobs",
        application_provider="fixture_application",
    ) if passthrough_tools else []
    results = list(results) + deferred_records
    state["observation_results"] = list(state.get("observation_results", [])) + results
    state["tool_results"] = [
        f"TOOL: {item.get('tool', '')}\nSTATUS: {item.get('status', '')}\nRESULT: {item.get('result', '')}"
        for item in results
    ]
    for item in results:
        state["investigation"].append(state["tool_results"][results.index(item)])
    normalized = normalize_tool_results(results, scope_id=state.get("evidence_scope", ""))
    state["normalized_evidence"] = list(state.get("normalized_evidence", [])) + normalized
    correlation = correlate_evidence(state["normalized_evidence"])
    state["evidence_correlations"] = correlation["correlations"]
    state["evidence_conflicts"] = correlation["conflicts"]
    state["reasoning_context"] = build_reasoning_context(state.get("user_request", ""), state["normalized_evidence"], correlation, state.get("memory_context", ""))
    state["action_result"] = results[-1].get("result", "") if results else state.get("reasoning_context", "")
    if "attention_observer" in selected_tools:
        attention_result = next(
            (item.get("result") for item in results if item.get("tool") == "attention_observer" and item.get("status") == "ok"),
            None,
        )
        if isinstance(attention_result, dict) and attention_result.get("status") == "OK" and isinstance(attention_result.get("items"), list):
            state["attention_snapshot"] = attention_result
    lineage = dict(state.setdefault("subgoal_lineage", {}).get(subgoal_id, {}))
    lineage.update({
        "status": "OBSERVED",
        "evidence_refs": [f"{item.get('tool')}:{subgoal_id}" for item in results],
        "evidence_hash": evidence_hash(normalized),
        "result_start_index": len(state["observation_results"]) - len(results),
    })
    state["subgoal_lineage"][subgoal_id] = lineage
    statuses[subgoal_id] = "VERIFYING"
    state["subgoal_statuses"] = statuses
    _set_decision(state, "OBSERVE_RESULT", reason=f"Subgoal {subgoal_id} returned bounded tool evidence.")
    _phase32_persist(state)
    return state


def verify_phase32_subgoal(state: NexusState):
    subgoal_id = str(state.get("current_subgoal_id") or "")
    plan_item = next((item for item in state.get("goal_plan", []) if item.get("sub_goal_id") == subgoal_id), {})
    action_required = bool(plan_item.get("action_required", False))
    lineage = state.setdefault("subgoal_lineage", {}).get(subgoal_id, {})
    result_start = lineage.get("result_start_index")

    evidence_slice = state.get("observation_results", [])
    if isinstance(result_start, int):
        evidence_slice = evidence_slice[result_start:]
    selected_tools = state.get("selected_tools", [])
    results = [item for item in evidence_slice if item.get("tool") in selected_tools] if selected_tools else []
    latest = results[-1].get("result") if results else None
    executed_evidence = bool(results)
    if action_required:
        consumed = set(state.get("consumed_execution_ids") or [])
        executed_id = str((state.get("execution_ids") or {}).get(subgoal_id, ""))
        executed_evidence = bool(results) and bool(executed_id) and executed_id in consumed

    if not results and not selected_tools:
        outcome = classify_subgoal_outcome(action_required=action_required, executed_evidence=executed_evidence, normalized_evidence=state.get("normalized_evidence", []))
    else:
        tool_record = results[-1] if results else None
        outcome = classify_subgoal_outcome(tool_result=tool_record, payload=latest, action_required=action_required, executed_evidence=executed_evidence, normalized_evidence=state.get("normalized_evidence", []))
    successful = outcome in SUCCESSFUL_OUTCOMES
    print(f"[NEXUS] Phase 32 observation result: {latest}")
    print(f"[NEXUS] Phase 32 verification: {'SUCCESS' if successful else 'FAILED'} ({outcome})")
    state["verification"] = str(latest or state.get("reasoning_context", ""))
    state["last_verification"] = state["verification"]
    state.setdefault("verification_history", []).append(state["verification"])
    statuses = dict(state.get("subgoal_statuses") or {})
    statuses[subgoal_id] = "VERIFYING"
    state["subgoal_statuses"] = statuses
    _set_decision(state, "VERIFY_SUBGOAL", reason=f"Verifying evidence for subgoal {subgoal_id}.")
    state["_phase32_subgoal_success"] = successful
    state["_phase32_subgoal_outcome"] = outcome
    lineage = dict(state.setdefault("subgoal_lineage", {}).get(subgoal_id, {}))
    lineage.update({"verification": "SUCCESS" if successful else "FAILED", "outcome": outcome, "status": "VERIFIED" if successful else "FAILED"})
    state["subgoal_lineage"][subgoal_id] = lineage
    return state


def classify_phase32_subgoal(state: NexusState):
    subgoal_id = str(state.get("current_subgoal_id") or "")
    successful = bool(state.get("_phase32_subgoal_success"))
    if successful:
        statuses = dict(state.get("subgoal_statuses") or {})
        statuses[subgoal_id] = "COMPLETED"
        state["subgoal_statuses"] = statuses
        state.setdefault("completion_evidence", []).append(f"{subgoal_id}:verified")
        state["completed_subgoals"] = list(dict.fromkeys(list(state.get("completed_subgoals") or []) + [subgoal_id]))
        state.setdefault("failure_classifications", {}).pop(subgoal_id, None)
        executed_id = str((state.get("execution_ids") or {}).get(subgoal_id, ""))
        if executed_id:
            state["consumed_execution_ids"] = list(dict.fromkeys(list(state.get("consumed_execution_ids") or []) + [executed_id]))
        lineage = dict(state.setdefault("subgoal_lineage", {}).get(subgoal_id, {}))
        lineage.update({
            "outcome": state.get("_phase32_subgoal_outcome") or lineage.get("outcome", "SUCCESS"),
            "verification": "SUCCESS",
            "status": "VERIFIED",
            "completion_state": "COMPLETED",
            "failure_classification": "",
        })
        state["subgoal_lineage"][subgoal_id] = lineage
        _set_decision(state, "CLASSIFY_RESULT", reason=f"Subgoal {subgoal_id} verified successfully.")
        ordered_ids = [str(item.get("sub_goal_id")) for item in state.get("goal_plan", [])]
        all_completed = bool(ordered_ids) and all(statuses.get(item_id) == "COMPLETED" for item_id in ordered_ids)
        if all_completed:
            if state.get("approval_required") and not state.get("approved"):
                state["task_status"] = "WAITING_APPROVAL"
                _set_decision(state, "APPROVAL_PENDING", reason="Planned subgoals completed read-only; a durable approval is still required before any authorized action executes.", final_outcome="READ_ONLY")
            else:
                state["task_status"] = "COMPLETED"
                state["final_outcome"] = "SUCCESS" if _browser_action_performed(state) else "READ_ONLY"
                _set_decision(state, "FINAL_OUTCOME", reason="The final Phase 32 subgoal was verified successfully.", final_outcome=state["final_outcome"])
            state["current_subgoal_id"] = ""
        _phase32_persist(state)
        return state

    attempts = int((state.get("subgoal_retry_count") or {}).get(subgoal_id, 0)) + 1
    state.setdefault("subgoal_retry_count", {})[subgoal_id] = attempts
    classification = classify_failure(reason=str(state.get("action_result", "")), attempt_count=attempts, retry_count=state.get("task_retry_count", 0))
    state.setdefault("failure_classifications", {})[subgoal_id] = classification
    outcome = str(state.get("_phase32_subgoal_outcome") or classification)
    if classification == "RECOVERABLE" and attempts <= MAX_RETRIES:
        statuses = dict(state.get("subgoal_statuses") or {})
        statuses[subgoal_id] = "RETRYABLE_FAILURE"
        state["subgoal_statuses"] = statuses
        lineage = dict(state.setdefault("subgoal_lineage", {}).get(subgoal_id, {}))
        lineage.update({
            "outcome": outcome,
            "verification": "FAILED",
            "status": "RETRYABLE_FAILURE",
            "failure_classification": classification,
            "completion_state": "INCOMPLETE",
            "attempt": attempts,
        })
        state["subgoal_lineage"][subgoal_id] = lineage
        _set_decision(state, "SELECT_NEXT_SUBGOAL", reason=f"Subgoal {subgoal_id} will retry within the bounded retry limit.")
        return state
    statuses = dict(state.get("subgoal_statuses") or {})
    statuses[subgoal_id] = classification
    state["subgoal_statuses"] = statuses
    state["task_status"] = "BLOCKED" if classification in {"BLOCKED", "HUMAN_REQUIRED"} else "FAILED"
    state["final_outcome"] = classification if classification in {"BLOCKED", "HUMAN_REQUIRED"} else outcome
    lineage = dict(state.setdefault("subgoal_lineage", {}).get(subgoal_id, {}))
    lineage.update({
        "outcome": outcome,
        "verification": "FAILED",
        "status": classification,
        "failure_classification": classification,
        "completion_state": "INCOMPLETE",
        "attempt": attempts,
    })
    state["subgoal_lineage"][subgoal_id] = lineage
    _set_decision(state, "FINAL_OUTCOME", reason=f"Subgoal {subgoal_id} stopped with classification {classification} (outcome {outcome}).", final_outcome=state["final_outcome"])
    return state


def phase32_next_after_classification(state: NexusState):
    if not state.get("current_subgoal_id"):
        return "store_task_memory"
    substatus = str((state.get("subgoal_statuses") or {}).get(str(state.get("current_subgoal_id")), ""))
    if substatus == "COMPLETED":
        if state.get("decision_stage") in {"FINAL_OUTCOME", "APPROVAL_PENDING"}:
            return "store_task_memory"
        return "select_next_subgoal"
    return "make_recovery_decision"


def recovery_decision_routes(state: NexusState):
    if state.get("decision_stage") in {"FINAL_OUTCOME", "APPROVAL_PENDING"}:
        return "store_task_memory"
    return "select_next_subgoal"


def _recovery_record(state: NexusState, *, subgoal_id: str, failure_class: str, decision_type: str, reason: str, bounded_action: str, phase: str) -> dict[str, object]:
    return {
        "recovery_id": f"recovery-{uuid.uuid4().hex[:16]}",
        "task_id": str(state.get("task_id") or ""),
        "affected_task": str(state.get("task_id") or ""),
        "affected_subgoal": subgoal_id,
        "attempt": int((state.get("subgoal_retry_count") or {}).get(subgoal_id, 1)) or 1,
        "failure_outcome": str(state.get("_phase32_subgoal_outcome") or state.get("final_outcome") or ""),
        "failure_class": failure_class,
        "previous_classification": str((state.get("failure_classifications") or {}).get(subgoal_id) or ""),
        "decision_type": decision_type,
        "reason": redact_text(reason),
        "evidence": [redact_text(str(item)) for item in (state.get("completion_evidence") or [])][-5:],
        "bounded_next_action": bounded_action,
        "result": "SCHEDULED",
        "verification": "",
        "phase": phase,
        "created_at": _now_iso(),
    }


def _replan_for_failure(state: NexusState, failed_subgoal_id: str) -> dict[str, object] | None:
    plan = list(state.get("goal_plan") or [])
    by_id = {str(item.get("sub_goal_id")): item for item in plan}
    if failed_subgoal_id not in by_id:
        return None
    completed = {key for key, value in (state.get("subgoal_statuses") or {}).items() if value == "COMPLETED"}
    drops = {failed_subgoal_id}
    changed = True
    while changed:
        changed = False
        for item in plan:
            sid = str(item.get("sub_goal_id") or "")
            if sid in drops or sid in completed:
                continue
            if any(str(dep) in drops for dep in (item.get("dependencies") or [])):
                drops.add(sid)
                changed = True
    kept = [dict(item) for item in plan if str(item.get("sub_goal_id") or "") not in drops and str(item.get("sub_goal_id") or "") in completed]
    remaining = [dict(item) for item in plan if str(item.get("sub_goal_id") or "") not in drops and str(item.get("sub_goal_id") or "") not in completed]
    if not remaining:
        return None
    new_plan = kept + remaining
    try:
        validate_autonomous_plan(new_plan)
        if not plan_versions_are_compatible(plan, new_plan):
            return None
    except ValueError:
        return None

    old_version = str(state.get("plan_version") or "v1")
    old_hash = str(state.get("plan_hash") or "")
    new_version = make_plan_version(old_version)
    new_hash = plan_hash(new_plan)

    statuses = dict(state.get("subgoal_statuses") or {})
    for sid in drops:
        statuses[sid] = "REPLAN_OUT"
        lineage = dict(state.setdefault("subgoal_lineage", {}).get(sid, {}))
        lineage.update({
            "completion_state": "REPLACED",
            "status": "REPLAN_OUT",
            "replaced_by_plan_version": new_version,
            "replaced_by_plan_hash": new_hash,
        })
        state["subgoal_lineage"][sid] = lineage

    state["goal_plan"] = new_plan
    state["plan_version"] = new_version
    state["plan_hash"] = new_hash
    state["subgoal_statuses"] = statuses
    state["replan_attempts"] = int(state.get("replan_attempts", 0)) + 1
    state["subgoal_plan_hash"] = {str(item.get("sub_goal_id")): new_hash for item in new_plan if item.get("sub_goal_id")}
    history = list(state.get("plan_history") or [])
    history.append({
        "plan_version": new_version,
        "plan_hash": new_hash,
        "plan": [dict(item) for item in new_plan],
        "reason": f"recovery replan after failed subgoal {failed_subgoal_id}",
        "replaces": old_version,
        "replaces_hash": old_hash,
        "created_at": _now_iso(),
    })
    state["plan_history"] = history
    return {"plan_version": new_version, "plan_hash": new_hash}


def make_recovery_decision(state: NexusState):
    subgoal_id = str(state.get("current_subgoal_id") or "")
    statuses = dict(state.get("subgoal_statuses") or {})
    if not subgoal_id or statuses.get(subgoal_id, "") in {"", "COMPLETED"}:
        state["recovery_phase"] = "IDLE"
        _set_decision(state, "SELECT_NEXT_SUBGOAL", reason="No subgoal failure was reported; the loop resumes dependency-ordered dispatch.")
        _phase32_persist(state)
        return state

    outcome = str(state.get("_phase32_subgoal_outcome") or "")
    classification = str((state.get("failure_classifications") or {}).get(subgoal_id, "") or "")
    final_outcome = str(state.get("final_outcome") or "")
    failure_class = classify_failure_class(outcome=outcome, final_outcome=final_outcome, classification=classification)
    decision_type = decide_recovery_for_failure_class(failure_class)
    attempts = int((state.get("subgoal_retry_count") or {}).get(subgoal_id, 1)) or 1
    state["recovery_attempts"] = int(state.get("recovery_attempts", 0)) + 1
    bounded_action = bounded_next_action(decision_type, attempt=attempts, max_attempt=MAX_RETRIES)
    reason = f"Subgoal {subgoal_id} failed with class {failure_class} (outcome {outcome or final_outcome}); previous classification {classification or 'NONE'}."

    if failure_class == FAILURE_CLASS_UNKNOWN:
        decision_type = RECOVERY_DECISION_FAIL_TERMINALLY
        bounded_action = bounded_next_action(decision_type)
        reason = f"Subgoal {subgoal_id} produced an unclassifiable failure (outcome {outcome}); the recovery engine fails closed."
    elif failure_class == FAILURE_CLASS_PERMANENT_FAILURE:
        decision_type = RECOVERY_DECISION_FAIL_TERMINALLY
        bounded_action = bounded_next_action(decision_type)
    if int(state.get("recovery_attempts", 0)) > MAX_RECOVERY_ATTEMPTS_PER_TASK:
        decision_type = RECOVERY_DECISION_FAIL_TERMINALLY
        failure_class = FAILURE_CLASS_PERMANENT_FAILURE
        bounded_action = bounded_next_action(decision_type)
        reason = f"Subgoal {subgoal_id} exceeded the bounded per-task recovery budget of {MAX_RECOVERY_ATTEMPTS_PER_TASK}."

    if decision_type in {
        RECOVERY_DECISION_RETRY,
        RECOVERY_DECISION_REVALIDATE_CONTEXT,
        RECOVERY_DECISION_REBUILD_EVIDENCE,
    }:
        budget = MAX_RETRIES if decision_type == RECOVERY_DECISION_RETRY else MAX_REVALIDATIONS_PER_SUBGOAL
        if attempts > budget:
            if can_auto_replan_failure_class(failure_class) and int(state.get("replan_attempts", 0)) < MAX_REPLAN_ATTEMPTS_PER_TASK:
                decision_type = RECOVERY_DECISION_REPLAN
                bounded_action = bounded_next_action(decision_type)
            else:
                decision_type = RECOVERY_DECISION_FAIL_TERMINALLY
                bounded_action = bounded_next_action(decision_type)

    record = _recovery_record(
        state,
        subgoal_id=subgoal_id,
        failure_class=failure_class,
        decision_type=decision_type,
        reason=reason,
        bounded_action=bounded_action,
        phase=state.get("recovery_phase") or "RECOVERING",
    )

    if decision_type in {RECOVERY_DECISION_RETRY, RECOVERY_DECISION_REVALIDATE_CONTEXT, RECOVERY_DECISION_REBUILD_EVIDENCE}:
        statuses[subgoal_id] = "RETRYABLE_FAILURE"
        state["subgoal_statuses"] = statuses
        state["context_validity"] = dict(state.get("context_validity") or {})
        if decision_type == RECOVERY_DECISION_REVALIDATE_CONTEXT:
            state["context_validity"][subgoal_id] = "STALE"
            state["capability_context"] = {}
        elif decision_type == RECOVERY_DECISION_REBUILD_EVIDENCE:
            state["context_validity"][subgoal_id] = "REBUILDING"
            state["normalized_evidence"] = []
            state["evidence_conflicts"] = []
        else:
            state["context_validity"][subgoal_id] = "STALE"
        state["recovery_phase"] = "RECOVERING"
        state["recovery_decision"] = record
        state["recovery_history"] = list(state.get("recovery_history") or []) + [record]
        _set_decision(state, "SELECT_NEXT_SUBGOAL", reason=f"{reason} Recovery decision: {decision_type}; {bounded_action}.")
        _phase32_persist(state)
        return state

    if decision_type == RECOVERY_DECISION_ALTERNATIVE_TOOL:
        plan_item = next((item for item in state.get("goal_plan", []) if str(item.get("sub_goal_id")) == subgoal_id), {})
        replacement = alternative_capability_tool(plan_item)
        if not replacement:
            if int(state.get("replan_attempts", 0)) < MAX_REPLAN_ATTEMPTS_PER_TASK:
                decision_type = RECOVERY_DECISION_REPLAN
                bounded_action = bounded_next_action(decision_type)
                record.update({"decision_type": RECOVERY_DECISION_REPLAN})
            else:
                decision_type = RECOVERY_DECISION_PAUSE_FOR_HUMAN
                bounded_action = bounded_next_action(decision_type)
                record.update({"decision_type": RECOVERY_DECISION_PAUSE_FOR_HUMAN})
        else:
            old_hash = str(state.get("plan_hash") or "")
            old_version = str(state.get("plan_version") or "v1")
            replacement_item = dict(plan_item)
            replacement_item["selected_tools"] = [replacement]
            replacement_item["application_id"] = _application_for_tool(replacement)
            state["goal_plan"] = [replacement_item if str(item.get("sub_goal_id")) == subgoal_id else item for item in state.get("goal_plan", [])]
            new_hash = plan_hash(state["goal_plan"])
            state["plan_version"] = make_plan_version(old_version)
            state["plan_hash"] = new_hash
            state["replan_attempts"] = int(state.get("replan_attempts", 0)) + 1
            state["subgoal_plan_hash"] = {str(item.get("sub_goal_id")): new_hash for item in state["goal_plan"] if item.get("sub_goal_id")}
            state["plan_history"] = list(state.get("plan_history") or []) + [{
                "plan_version": state["plan_version"],
                "plan_hash": new_hash,
                "plan": [dict(item) for item in state["goal_plan"]],
                "reason": f"recovery selected alternative tool {replacement} for subgoal {subgoal_id}",
                "replaces": old_version,
                "replaces_hash": old_hash,
                "created_at": _now_iso(),
            }]
            statuses[subgoal_id] = "RETRYABLE_FAILURE"
            state["subgoal_statuses"] = statuses
            state["recovery_phase"] = "REPLANNED"
            state["recovery_decision"] = record
            record.update({"bounded_next_action": bounded_action, "reason": f"Selected authorized alternative tool {replacement} for the same capability."})
            state["recovery_history"] = list(state.get("recovery_history") or []) + [record]
            _set_decision(state, "SELECT_NEXT_SUBGOAL", reason=f"{reason} Recovery decision: {RECOVERY_DECISION_ALTERNATIVE_TOOL}; {bounded_action}.")
            _phase32_persist(state)
            return state

    if decision_type == RECOVERY_DECISION_REPLAN:
        replacement = _replan_for_failure(state, subgoal_id)
        if replacement is not None:
            record.update({"decision_type": RECOVERY_DECISION_REPLAN})
            state["recovery_phase"] = "REPLANNED"
            state["recovery_decision"] = record
            record.update({"bounded_next_action": bounded_action, "reason": f"Built bounded replacement plan {replacement['plan_version']} after failed subgoal {subgoal_id}."})
            state["recovery_history"] = list(state.get("recovery_history") or []) + [record]
            _set_decision(state, "SELECT_NEXT_SUBGOAL", reason=f"{reason} Recovery decision: {RECOVERY_DECISION_REPLAN}; the remaining plan is preserved and the failed subgoal is replaced.")
            _phase32_persist(state)
            return state
        decision_type = RECOVERY_DECISION_PAUSE_FOR_HUMAN
        bounded_action = bounded_next_action(decision_type)
        record.update({"decision_type": RECOVERY_DECISION_PAUSE_FOR_HUMAN, "bounded_next_action": bounded_action})

    if decision_type == RECOVERY_DECISION_REVALIDATE_APPROVAL:
        statuses[subgoal_id] = "WAITING_APPROVAL"
        state["subgoal_statuses"] = statuses
        state["task_status"] = "WAITING_APPROVAL"
        state["recovery_phase"] = "PAUSED_FOR_HUMAN"
        state["recovery_decision"] = record
        record.update({"bounded_next_action": bounded_action, "reason": "Revalidation is routed back through the Approval Authority; a rejected or invalidated approval is never auto-approved."})
        state["recovery_history"] = list(state.get("recovery_history") or []) + [record]
        _set_decision(state, "APPROVAL_PENDING", reason=f"{reason} Recovery decision: {RECOVERY_DECISION_REVALIDATE_APPROVAL}; awaiting a valid durable approval.")
        _phase32_persist(state)
        return state

    if decision_type == RECOVERY_DECISION_PAUSE_FOR_HUMAN:
        if _is_deferred_browser_approval_wait(state, subgoal_id):
            # Legitimate interactive-browser approval wait: a valid URL,
            # successful grounding, and a durable approval already exist, so the
            # controller subgoal waits for the existing approval endpoint
            # instead of terminally blocking the task. Missing/unsupported
            # targets never reach here (no URL/approval) and stay BLOCKED.
            statuses[subgoal_id] = "WAITING_APPROVAL"
            state["subgoal_statuses"] = statuses
            state["task_status"] = "WAITING_APPROVAL"
            state["final_outcome"] = "APPROVAL_REQUIRED"
            state["recovery_phase"] = "PAUSED_FOR_HUMAN"
            state["recovery_decision"] = record
            state["recovery_history"] = list(state.get("recovery_history") or []) + [record]
            record.update({"bounded_next_action": bounded_action, "reason": f"{reason} Recovery decision: {RECOVERY_DECISION_PAUSE_FOR_HUMAN}; deferred browser-controller execution awaits the durable approval."})
            _set_decision(state, "APPROVAL_PENDING", reason=f"{reason} Recovery decision: {RECOVERY_DECISION_PAUSE_FOR_HUMAN}; awaiting the durable browser approval.", final_outcome=state["final_outcome"])
            _phase32_persist(state)
            return state
        if failure_class == FAILURE_CLASS_SECURITY_BLOCK:
            state["task_status"] = "BLOCKED"
            state["final_outcome"] = "SECURITY_BLOCK"
        elif failure_class == FAILURE_CLASS_HUMAN_REQUIRED:
            state["task_status"] = "BLOCKED"
            state["final_outcome"] = "HUMAN_REQUIRED"
        else:
            state["task_status"] = "WAITING_APPROVAL"
            state["final_outcome"] = "APPROVAL_REQUIRED"
        statuses[subgoal_id] = "HUMAN_REQUIRED" if failure_class == FAILURE_CLASS_HUMAN_REQUIRED else state["final_outcome"]
        state["subgoal_statuses"] = statuses
        state["recovery_phase"] = "PAUSED_FOR_HUMAN"
        state["recovery_decision"] = record
        state["recovery_history"] = list(state.get("recovery_history") or []) + [record]
        _set_decision(state, "FINAL_OUTCOME", reason=f"{reason} Recovery decision: {RECOVERY_DECISION_PAUSE_FOR_HUMAN}; no autonomous action proceeds without explicit human input.", final_outcome=state["final_outcome"])
        _phase32_persist(state)
        return state

    if failure_class == FAILURE_CLASS_UNKNOWN:
        state["final_outcome"] = "UNKNOWN_FAILURE"
    elif not final_outcome or final_outcome in SUCCESSFUL_OUTCOMES:
        state["final_outcome"] = str(outcome or "FATAL")
    else:
        state["final_outcome"] = final_outcome
    if not state["final_outcome"]:
        state["final_outcome"] = "FATAL"
    statuses[subgoal_id] = "FAILED"
    state["subgoal_statuses"] = statuses
    state["task_status"] = "FAILED"
    state["recovery_phase"] = "TERMINAL"
    state["recovery_decision"] = record
    record.update({"bounded_next_action": bounded_action, "reason": "Terminal failure; no further autonomous recovery is attempted."})
    state["recovery_history"] = list(state.get("recovery_history") or []) + [record]
    _set_decision(state, "FINAL_OUTCOME", reason=f"{reason} Recovery decision: {RECOVERY_DECISION_FAIL_TERMINALLY}; the task stops truthfully.", final_outcome=state["final_outcome"])
    _phase32_persist(state)
    return state


def phase32_next_after_selection(state: NexusState):
    if state.get("decision_stage") in {"FINAL_OUTCOME", "APPROVAL_PENDING"} or not state.get("current_subgoal_id"):
        return "store_task_memory"
    return "execute_phase32_subgoal"


def phase32_next_after_execution(state: NexusState):
    if state.get("decision_stage") in {"FINAL_OUTCOME", "APPROVAL_PENDING"}:
        return "store_task_memory"
    return "verify_phase32_subgoal"


def create_plan(state: NexusState):
    task_id = state.get("task_id") or ""
    db_path = state.get("persistence_db_path") or None
    if not task_id:
        task = create_task(
            state.get("user_request", ""),
            current_stage="REQUEST",
            status="CREATED",
            status_reason="Task created during graph plan assembly.",
            db_path=db_path,
        )
        state["task_id"] = task["task_id"]
        state["task_status"] = task["status"]
        task_id = task["task_id"]
    elif get_task(task_id, db_path=db_path) is None:
        task = create_task(
            state.get("user_request", ""),
            task_id=task_id,
            current_stage="REQUEST",
            status="CREATED",
            status_reason="Task created during graph plan assembly.",
            db_path=db_path,
        )
        state["task_id"] = task["task_id"]
        state["task_status"] = task["status"]
        task_id = task["task_id"]

    if state.get("user_request"):
        plan_already_active = bool(state.get("goal_plan")) and any(
            str((state.get("subgoal_statuses") or {}).get(str(item.get("sub_goal_id")), "")) not in {"", "PLANNED"}
            for item in state.get("goal_plan", [])
        )
        if not plan_already_active and not (state.get("recovery_decision") or {}).get("decision_type"):
            try:
                state["goal_plan"] = decompose_goal(
                    state["user_request"],
                    observations=state.get("observations", []),
                    evidence=state.get("normalized_evidence", []),
                    historical_memory=state.get("memory_context", ""),
                )
                state["goal_error"] = ""
            except ValueError as exc:
                state["goal_plan"] = []
                state["goal_error"] = str(exc)

    if task_id and get_task(task_id, db_path=db_path) is not None:
        task_status = state.get("task_status") or "CREATED"
        task_status = "RUNNING" if task_status == "CREATED" else task_status
        task_status = "RUNNING" if task_status == "WAITING_APPROVAL" else task_status
        update_task_status(
            task_id,
            task_status,
            current_stage=state.get("decision_stage", "REQUEST"),
            current_sub_goal=state.get("decision_reason", ""),
            status_reason=state.get("decision_reason") or "Task state advanced through the graph.",
            final_outcome=state.get("final_outcome", ""),
            goal_plan=state.get("goal_plan", []),
            subgoal_statuses=state.get("subgoal_statuses", {}),
            current_subgoal_id=state.get("current_subgoal_id", ""),
            plan_version=state.get("plan_version", "v1"),
            plan_hash=state.get("plan_hash", ""),
            task_retry_count=state.get("task_retry_count", 0),
            subgoal_retry_count=state.get("subgoal_retry_count", {}),
            failure_classifications=state.get("failure_classifications", {}),
            adaptation_history=state.get("adaptation_history", []),
            completion_evidence=state.get("completion_evidence", []),
            subgoal_lineage=state.get("subgoal_lineage", {}),
            execution_ids=state.get("execution_ids", {}),
            consumed_execution_ids=state.get("consumed_execution_ids", []),
            db_path=db_path,
        )

    print(
        "\n[NEXUS] Creating plan..."
    )

    if _phase32_enabled(state):
        state["plan_version"] = str(state.get("plan_version") or "v1")
        state["plan_hash"] = plan_hash(state.get("goal_plan", []))
        state["subgoal_statuses"] = {
            str(item.get("sub_goal_id")): state.get("subgoal_statuses", {}).get(str(item.get("sub_goal_id")), "PLANNED")
            for item in state.get("goal_plan", [])
            if item.get("sub_goal_id")
        }
        state.setdefault("subgoal_plan_hash", {})
        if not state["subgoal_plan_hash"]:
            state["subgoal_plan_hash"] = {str(item.get("sub_goal_id")): state["plan_hash"] for item in state.get("goal_plan", []) if item.get("sub_goal_id")}
        state.setdefault("plan_history", [])
        if not state["plan_history"]:
            state["plan_history"] = [{
                "plan_version": state["plan_version"],
                "plan_hash": state["plan_hash"],
                "plan": [dict(item) for item in state.get("goal_plan", [])],
                "reason": "initial plan",
                "created_at": _now_iso(),
            }]
        state.setdefault("recovery_history", [])
        state.setdefault("recovery_attempts", 0)
        state.setdefault("replan_attempts", 0)
        state.setdefault("context_validity", {})
        state["recovery_phase"] = state.get("recovery_phase") or "IDLE"
        state["task_status"] = "RUNNING"
        if str(state.get("final_outcome") or "") == "BLOCKED":
            # A terminal dispatch denial survives planning: the observation
            # loop must not reinterpret it, and entry routing sends it to END.
            # Task status is terminal truth as well, so no downstream node or
            # runner can report a blocked denial as ongoing work.
            state["task_status"] = "BLOCKED"
            _set_decision(state, "FINAL_OUTCOME", reason="A blocked dispatch stands; planning cannot override a security denial.", final_outcome="BLOCKED")
            return state
        state["final_outcome"] = ""
        _set_decision(state, "VALIDATE_PLAN", reason="The bounded Phase 32 goal plan is ready for dependency-ordered execution.")
        return state

    if state.get("request_intent") == "MODIFICATION_REQUEST":
        plan = [
            "Understand the request",
            "Prioritize the request",
            "Retrieve relevant memory",
            "Validate and select the required allowlisted tools",
            "Execute the selected tools with trusted arguments",
            "Collect evidence from the tool results",
            "Analyze the investigation evidence",
            "Create a safe fix proposal",
        ]
    else:
        plan = [
            "Understand the request",
            "Identify the authorized target",
            "Select a read-only inspection tool",
            "Inspect the target",
            "Collect fresh request-scoped evidence",
            "Analyze the evidence",
            "Provide an evidence-grounded explanation",
            "Verify that no modification occurred",
        ]

    if state["approval_required"]:

        plan.append(
            "Request human approval"
        )

    if state["approved"]:

        plan.append(
            "Apply only the approved code change"
        )

        plan.append(
            "Verify the modification"
        )

    if not state.get("final_outcome"):
        if state.get("request_intent") != "MODIFICATION_REQUEST":
            state["final_outcome"] = "READ_ONLY"
        elif state.get("approved"):
            state["final_outcome"] = "SUCCESS"
        elif state.get("target_file"):
            state["final_outcome"] = "READ_ONLY"
        else:
            state["final_outcome"] = "NO_ACTION"

    state["decision_stage"] = "FINAL_OUTCOME"
    state["decision_reason"] = state.get("decision_reason") or "The bounded loop concluded with the final outcome for this request."
    state["plan"] = plan

    return state


def store_task_memory(state: NexusState):
    record = {
        "user_request": state.get("user_request", ""),
        "target_file": state.get("target_file", ""),
        "diagnosis": "\n".join(item for item in state.get("investigation", []) if item.startswith("DIAGNOSIS:")),
        "proposed_change": state.get("new_code", "") or state.get("old_code", ""),
        "action_result": state.get("action_result", ""),
        "verification_result": state.get("verification", "") or state.get("last_verification", ""),
        "retry_count": state.get("retry_count", 0),
        "success": "STATUS: SUCCESS" in (state.get("verification", "") or state.get("last_verification", "")).upper(),
        "memory_context": state.get("memory_context", ""),
    }

    if state.get("task_id"):
        final_status = state.get("final_outcome", "")
        verification_texts = [
            str(state.get("verification", "")),
            str(state.get("last_verification", "")),
            *[str(item) for item in (state.get("verification_history") or [])],
        ]
        verification_status: str | None = None
        for candidate in reversed(verification_texts):
            upper_candidate = candidate.upper()
            if "STATUS: SUCCESS" in upper_candidate:
                verification_status = "VERIFIED"
                break
            if any(
                marker in upper_candidate
                for marker in ("STATUS: FAILED", "FAILED_VERIFICATION", "RUNTIME ERROR", "STATUS: TIMEOUT", "EXECUTION FAILED")
            ):
                verification_status = "FAILED"
                break
        ledger_status = "RUNNING"
        if state.get("approval_required") and not state.get("approved"):
            ledger_status = "WAITING_APPROVAL"
        elif str(state.get("task_status") or "").upper() == "WAITING_APPROVAL" or final_status in {"APPROVAL_REQUIRED", "APPROVAL_INVALID", "APPROVAL_REJECTED"}:
            ledger_status = "WAITING_APPROVAL"
        elif str(state.get("task_status") or "").upper() == "BLOCKED" or final_status in {"BLOCKED", "SECURITY_BLOCK", "HUMAN_REQUIRED"}:
            ledger_status = "BLOCKED"
        elif str(state.get("task_status") or "").upper() == "FAILED" or final_status in {"FATAL", "UNKNOWN_FAILURE", "FAILED_VERIFICATION", "INVALID_TARGET", "EVIDENCE_CONFLICT"}:
            ledger_status = "FAILED"
        elif final_status in {"SUCCESS", "READ_ONLY", "NO_ACTION", "NO_FIX", "APPROVAL_REJECTED", "FAILED_VERIFICATION", "BLOCKED", "AUDIT_ERROR"}:
            ledger_status = "COMPLETED" if final_status in {"SUCCESS", "READ_ONLY", "NO_ACTION"} else "BLOCKED"
        update_task_status(
            state["task_id"],
            ledger_status,
            current_stage=state.get("decision_stage", "FINAL_OUTCOME"),
            current_sub_goal=state.get("decision_reason", ""),
            status_reason=state.get("decision_reason") or "Task completed and persisted.",
            verification_status=verification_status,
            final_outcome=final_status,
            verification_history=state.get("verification_history", []),
            retry_history=[str(state.get("retry_count", 0))] if state.get("retry_count") else [],
            goal_plan=state.get("goal_plan", []),
            subgoal_statuses=state.get("subgoal_statuses", {}),
            current_subgoal_id=state.get("current_subgoal_id", ""),
            plan_version=state.get("plan_version", "v1"),
            plan_hash=state.get("plan_hash", ""),
            plan_history=state.get("plan_history", []),
            recovery_history=state.get("recovery_history", []),
            recovery_attempts=state.get("recovery_attempts", 0),
            subgoal_retry_count=state.get("subgoal_retry_count", {}),
            failure_classifications=state.get("failure_classifications", {}),
            subgoal_lineage=state.get("subgoal_lineage", {}),
            execution_ids=state.get("execution_ids", {}),
            consumed_execution_ids=state.get("consumed_execution_ids", []),
            db_path=state.get("persistence_db_path") or None,
        )

    stored = store_memory(record)
    _audit_event(
        state,
        "memory_persistence",
        actor="nexus",
        result="Memory persistence completed." if stored else "Memory persistence failed.",
        reason="SQLite memory write result.",
    )
    if not stored:
        state["verification"] = (state.get("verification", "") + "\n\nMemory unavailable: persistent SQLite storage failed.").strip()
        state["last_verification"] = state.get("verification", "")
        print("[NEXUS] Memory unavailable: persistent SQLite storage failed.")
    return state


# ============================================================
# BUILD NEXUS LANGGRAPH
# ============================================================

builder = StateGraph(NexusState)


builder.add_node(
    "retrieve_memory",
    retrieve_memory
)

builder.add_node(
    "monitor_workspace",
    monitor_workspace
)

builder.add_node(
    "understand",
    understand
)

builder.add_node(
    "prioritize",
    prioritize
)

builder.add_node(
    "select_tool",
    select_tool
)

builder.add_node(
    "select_relevant",
    select_relevant
)

builder.add_node(
    "investigate",
    investigate
)

builder.add_node(
    "diagnose",
    diagnose
)

builder.add_node(
    "create_proposal",
    create_proposal
)

builder.add_node(
    "create_action_proposal",
    create_action_proposal
)

builder.add_node(
    "request_approval",
    request_approval
)

builder.add_node(
    "execute_action",
    execute_action
)

builder.add_node(
    "verify_result",
    verify_result
)

builder.add_node(
    "create_plan",
    create_plan
)

builder.add_node(
    "store_task_memory",
    store_task_memory
)

builder.add_node("select_next_subgoal", select_next_subgoal)
builder.add_node("execute_phase32_subgoal", execute_phase32_subgoal)
builder.add_node("verify_phase32_subgoal", verify_phase32_subgoal)
builder.add_node("classify_phase32_subgoal", classify_phase32_subgoal)
builder.add_node("make_recovery_decision", make_recovery_decision)


# ============================================================
# GRAPH FLOW
# ============================================================

builder.set_entry_point(
    "retrieve_memory"
)


builder.add_conditional_edges(
    "retrieve_memory",
    should_resume_action,
    {
        "execute_action": "execute_action",
        "monitor_workspace": "monitor_workspace",
    },
)

builder.add_edge(
    "monitor_workspace",
    "understand"
)

builder.add_edge(
    "understand",
    "prioritize"
)

builder.add_edge(
    "prioritize",
    "select_tool"
)

builder.add_edge(
    "select_tool",
    "select_relevant"
)

builder.add_edge(
    "select_relevant",
    "investigate"
)

builder.add_edge(
    "investigate",
    "diagnose"
)

builder.add_conditional_edges(
    "diagnose",
    should_create_proposal,
    {
        "create_proposal": "create_proposal",
        "create_action_proposal": "create_action_proposal",
        "create_plan": "create_plan",
    },
)

builder.add_conditional_edges(
    "create_action_proposal",
    should_request_approval,
    {
        "request_approval": "request_approval",
        "create_plan": "create_plan",
    },
)


# ============================================================
# APPROVAL DECISION
# ============================================================

builder.add_conditional_edges(
    "create_proposal",
    should_request_approval,
    {
        "request_approval": "request_approval",
        "create_plan": "create_plan",
    },
)


# ============================================================
# APPROVED ACTION FLOW
# ============================================================

builder.add_conditional_edges(
    "request_approval",
    should_execute_action,
    {
        "execute_action": "execute_action",
        "create_plan": "create_plan",
    },
)

builder.add_edge(
    "execute_action",
    "verify_result"
)

builder.add_conditional_edges(
    "verify_result",
    should_retry_verification,
    {
        "retry": "create_proposal",
        "success": "create_plan",
        "stop": "create_plan",
    },
)


# ============================================================
# END
# ============================================================

builder.add_conditional_edges(
    "create_plan",
    should_enter_phase32_loop,
    {
        "select_next_subgoal": "select_next_subgoal",
        "end": END,
    },
)

builder.add_conditional_edges(
    "select_next_subgoal",
    phase32_next_after_selection,
    {
        "execute_phase32_subgoal": "execute_phase32_subgoal",
        "store_task_memory": "store_task_memory",
    },
)
builder.add_conditional_edges(
    "execute_phase32_subgoal",
    phase32_next_after_execution,
    {
        "verify_phase32_subgoal": "verify_phase32_subgoal",
        "store_task_memory": "store_task_memory",
    },
)
builder.add_edge("verify_phase32_subgoal", "classify_phase32_subgoal")
builder.add_conditional_edges(
    "classify_phase32_subgoal",
    phase32_next_after_classification,
    {
        "select_next_subgoal": "select_next_subgoal",
        "make_recovery_decision": "make_recovery_decision",
        "store_task_memory": "store_task_memory",
    },
)
builder.add_conditional_edges(
    "make_recovery_decision",
    recovery_decision_routes,
    {
        "select_next_subgoal": "select_next_subgoal",
        "store_task_memory": "store_task_memory",
    },
)
builder.add_edge("store_task_memory", END)


nexus_graph = builder.compile()