from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_SUB_GOALS_PER_PLAN = 12
MAX_PLAN_REVISIONS = 3
MAX_ADDITIONAL_SUBGOALS_PER_REVISION = 3
MAX_TOTAL_SUBGOALS_PER_TASK = 20
MAX_ADAPTATION_HISTORY_ITEMS = 20
MAX_RETRIES_PER_SUBGOAL = 2
MAX_RETRIES_PER_TASK = 5
MAX_CONSECUTIVE_FAILURES = 3

VALID_FAILURE_CLASSIFICATIONS = {
    "RECOVERABLE",
    "REPLAN_REQUIRED",
    "HUMAN_REQUIRED",
    "BLOCKED",
    "FATAL",
}


def plan_hash(plan: list[dict[str, Any]]) -> str:
    payload = json.dumps(plan, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def classify_failure(*, reason: str = "", status: str = "", attempt_count: int = 0, retry_count: int = 0, target_changed: bool = False, proposal_changed: bool = False, approval_expired: bool = False, security_blocked: bool = False, dependencies_missing: bool = False, evidence_conflict: bool = False, retry_limit_reached: bool = False) -> str:
    text = (reason or "").upper()
    if security_blocked or status.upper() == "BLOCKED":
        return "BLOCKED"
    if approval_expired:
        return "HUMAN_REQUIRED"
    if target_changed or proposal_changed:
        return "BLOCKED"
    if dependencies_missing:
        return "REPLAN_REQUIRED"
    if evidence_conflict:
        return "REPLAN_REQUIRED"
    if retry_limit_reached or attempt_count >= MAX_RETRIES_PER_SUBGOAL:
        return "FATAL"
    if "APPROVAL" in text or "REJECTED" in text or "REQUIRES HUMAN" in text:
        return "HUMAN_REQUIRED"
    if "TIMEOUT" in text or "TEMPORARY" in text or "UNAVAILABLE" in text:
        return "RECOVERABLE"
    if retry_count >= MAX_RETRIES_PER_TASK or attempt_count >= MAX_RETRIES_PER_SUBGOAL:
        return "FATAL"
    return "RECOVERABLE"


def can_retry_subgoal(attempt_count: int, *, max_retries: int = MAX_RETRIES_PER_SUBGOAL) -> bool:
    return int(attempt_count) < int(max_retries)


def can_retry_task(task_retry_count: int, *, max_retries: int = MAX_RETRIES_PER_TASK) -> bool:
    return int(task_retry_count) < int(max_retries)


def validate_autonomous_plan(plan: list[dict[str, Any]], *, max_sub_goals: int = MAX_SUB_GOALS_PER_PLAN) -> list[dict[str, Any]]:
    if not isinstance(plan, list) or not plan:
        raise ValueError("Autonomous goal plans must be non-empty lists of sub-goals.")
    if len(plan) > max_sub_goals:
        raise ValueError(f"Autonomous goal plans cannot exceed {max_sub_goals} sub-goals.")
    seen: set[str] = set()
    for entry in plan:
        if not isinstance(entry, dict):
            raise ValueError("Each sub-goal must be a dictionary.")
        sub_goal_id = str(entry.get("sub_goal_id") or "").strip()
        if not sub_goal_id:
            raise ValueError("Every sub-goal requires a sub_goal_id.")
        if sub_goal_id in seen:
            raise ValueError(f"Duplicate sub-goal id: {sub_goal_id}")
        seen.add(sub_goal_id)
        objective = str(entry.get("objective") or "").strip()
        if not objective:
            raise ValueError(f"Sub-goal {sub_goal_id} requires an objective.")
        deps = entry.get("dependencies") or []
        if not isinstance(deps, list):
            raise ValueError(f"Sub-goal {sub_goal_id} dependencies must be a list.")
        for dep in deps:
            dep_name = str(dep).strip()
            if dep_name not in seen and dep_name not in {str(item.get("sub_goal_id") or "") for item in plan}:
                if dep_name not in {str(item.get("sub_goal_id") or "") for item in plan}:
                    raise ValueError(f"Sub-goal {sub_goal_id} references unknown dependency {dep_name}")
    return plan


def next_ready_subgoal(plan: list[dict[str, Any]], *, completed: set[str] | None = None, blocked: set[str] | None = None) -> dict[str, Any] | None:
    completed = completed or set()
    blocked = blocked or set()
    for item in plan:
        sub_goal_id = str(item.get("sub_goal_id") or "")
        if sub_goal_id in completed or sub_goal_id in blocked:
            continue
        deps = item.get("dependencies") or []
        if all(str(dep).strip() in completed for dep in deps):
            return item
    return None


def make_plan_version(version: str | None = None) -> str:
    current = str(version or "v1")
    try:
        number = int(current.replace("v", "")) + 1
        return f"v{number}"
    except ValueError:
        return "v1"


def normalize_subgoal_status(value: Any) -> str:
    status = str(value or "PLANNED").upper()
    if status not in {"PLANNED", "READY", "OBSERVING", "WAITING_DEPENDENCY", "WAITING_APPROVAL", "EXECUTING", "VERIFYING", "COMPLETED", "RETRYABLE_FAILURE", "REPLAN_REQUIRED", "HUMAN_REQUIRED", "BLOCKED", "FAILED"}:
        return "PLANNED"
    return status


def plan_versions_are_compatible(old_plan: list[dict[str, Any]], new_plan: list[dict[str, Any]]) -> bool:
    old_ids = {str(item.get("sub_goal_id") or "") for item in old_plan if item.get("sub_goal_id")}
    new_ids = {str(item.get("sub_goal_id") or "") for item in new_plan if item.get("sub_goal_id")}
    return len(new_ids - old_ids) <= MAX_ADDITIONAL_SUBGOALS_PER_REVISION


OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_VALID_UNAVAILABLE = "VALID_UNAVAILABLE"
OUTCOME_EMPTY = "EMPTY"
OUTCOME_TOOL_FAILURE = "TOOL_FAILURE"
OUTCOME_INVALID_TARGET = "INVALID_TARGET"
OUTCOME_STALE_CONTEXT = "STALE_CONTEXT"
OUTCOME_TIMEOUT = "TIMEOUT"
OUTCOME_SECURITY_BLOCK = "SECURITY_BLOCK"
OUTCOME_APPROVAL_INVALID = "APPROVAL_INVALID"
OUTCOME_APPLICATION_UNAVAILABLE = "APPLICATION_UNAVAILABLE"
OUTCOME_EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"
OUTCOME_HUMAN_REQUIRED = "HUMAN_REQUIRED"

SUCCESSFUL_OUTCOMES = {OUTCOME_SUCCESS, OUTCOME_VALID_UNAVAILABLE}

TERMINAL_FAILURE_STATUSES = frozenset({
    "BLOCKED",
    "FAILED",
    "HUMAN_REQUIRED",
    "FATAL",
    "REPLAN_REQUIRED",
    "TIMEOUT",
    "TOOL_FAILURE",
    "SECURITY_BLOCK",
    "INVALID_TARGET",
    "STALE_CONTEXT",
    "APPROVAL_INVALID",
    "APPLICATION_UNAVAILABLE",
    "EVIDENCE_CONFLICT",
    "APPROVAL_REJECTED",
    "EXECUTION_FAILED",
    "VERIFICATION_FAILED",
})

MAX_RECOVERY_ATTEMPTS_PER_TASK = 8
MAX_REPLAN_ATTEMPTS_PER_TASK = 3
MAX_REVALIDATIONS_PER_SUBGOAL = 2

FAILURE_CLASS_TRANSIENT_TOOL_FAILURE = "TRANSIENT_TOOL_FAILURE"
FAILURE_CLASS_TIMEOUT = "TIMEOUT"
FAILURE_CLASS_STALE_CONTEXT = "STALE_CONTEXT"
FAILURE_CLASS_INVALID_TARGET = "INVALID_TARGET"
FAILURE_CLASS_APPLICATION_UNAVAILABLE = "APPLICATION_UNAVAILABLE"
FAILURE_CLASS_APPROVAL_INVALID = "APPROVAL_INVALID"
FAILURE_CLASS_APPROVAL_REJECTED = "APPROVAL_REJECTED"
FAILURE_CLASS_EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"
FAILURE_CLASS_SECURITY_BLOCK = "SECURITY_BLOCK"
FAILURE_CLASS_PERMANENT_FAILURE = "PERMANENT_FAILURE"
FAILURE_CLASS_HUMAN_REQUIRED = "HUMAN_REQUIRED"
FAILURE_CLASS_UNKNOWN = "UNKNOWN_FAILURE"

VALID_FAILURE_CLASSES = frozenset({
    FAILURE_CLASS_TRANSIENT_TOOL_FAILURE,
    FAILURE_CLASS_TIMEOUT,
    FAILURE_CLASS_STALE_CONTEXT,
    FAILURE_CLASS_INVALID_TARGET,
    FAILURE_CLASS_APPLICATION_UNAVAILABLE,
    FAILURE_CLASS_APPROVAL_INVALID,
    FAILURE_CLASS_APPROVAL_REJECTED,
    FAILURE_CLASS_EVIDENCE_CONFLICT,
    FAILURE_CLASS_SECURITY_BLOCK,
    FAILURE_CLASS_PERMANENT_FAILURE,
    FAILURE_CLASS_HUMAN_REQUIRED,
    FAILURE_CLASS_UNKNOWN,
})

RECOVERY_DECISION_RETRY = "RETRY_SAME_SUBGOAL"
RECOVERY_DECISION_REVALIDATE_CONTEXT = "REVALIDATE_CONTEXT"
RECOVERY_DECISION_REVALIDATE_APPROVAL = "REVALIDATE_APPROVAL"
RECOVERY_DECISION_REBUILD_EVIDENCE = "REBUILD_EVIDENCE"
RECOVERY_DECISION_ALTERNATIVE_TOOL = "SELECT_ALTERNATIVE_AUTHORIZED_TOOL"
RECOVERY_DECISION_REPLAN = "REPLAN_REMAINING_SUBGOALS"
RECOVERY_DECISION_PAUSE_FOR_HUMAN = "PAUSE_FOR_HUMAN"
RECOVERY_DECISION_FAIL_TERMINALLY = "FAIL_TERMINALLY"

VALID_RECOVERY_DECISIONS = frozenset({
    RECOVERY_DECISION_RETRY,
    RECOVERY_DECISION_REVALIDATE_CONTEXT,
    RECOVERY_DECISION_REVALIDATE_APPROVAL,
    RECOVERY_DECISION_REBUILD_EVIDENCE,
    RECOVERY_DECISION_ALTERNATIVE_TOOL,
    RECOVERY_DECISION_REPLAN,
    RECOVERY_DECISION_PAUSE_FOR_HUMAN,
    RECOVERY_DECISION_FAIL_TERMINALLY,
})

RECOVERY_RETRYABLE_CLASSES = frozenset({
    FAILURE_CLASS_TRANSIENT_TOOL_FAILURE,
    FAILURE_CLASS_TIMEOUT,
    FAILURE_CLASS_STALE_CONTEXT,
    FAILURE_CLASS_INVALID_TARGET,
    FAILURE_CLASS_APPLICATION_UNAVAILABLE,
    FAILURE_CLASS_EVIDENCE_CONFLICT,
})

RECOVERY_REPLAN_CAPABLE_CLASSES = frozenset({
    FAILURE_CLASS_APPLICATION_UNAVAILABLE,
    FAILURE_CLASS_EVIDENCE_CONFLICT,
    FAILURE_CLASS_INVALID_TARGET,
})

RECOVERY_AUTO_APPROVAL_RETRY_DENIED = frozenset({
    FAILURE_CLASS_APPROVAL_INVALID,
    FAILURE_CLASS_APPROVAL_REJECTED,
    FAILURE_CLASS_SECURITY_BLOCK,
})

RECOVERY_NEVER_AUTO_RETRY = frozenset({
    FAILURE_CLASS_APPROVAL_INVALID,
    FAILURE_CLASS_APPROVAL_REJECTED,
    FAILURE_CLASS_SECURITY_BLOCK,
    FAILURE_CLASS_PERMANENT_FAILURE,
    FAILURE_CLASS_HUMAN_REQUIRED,
    FAILURE_CLASS_UNKNOWN,
})

_OUTCOME_TO_FAILURE_CLASS = {
    OUTCOME_TOOL_FAILURE: FAILURE_CLASS_TRANSIENT_TOOL_FAILURE,
    OUTCOME_EMPTY: FAILURE_CLASS_TRANSIENT_TOOL_FAILURE,
    OUTCOME_TIMEOUT: FAILURE_CLASS_TIMEOUT,
    OUTCOME_STALE_CONTEXT: FAILURE_CLASS_STALE_CONTEXT,
    OUTCOME_INVALID_TARGET: FAILURE_CLASS_INVALID_TARGET,
    OUTCOME_SECURITY_BLOCK: FAILURE_CLASS_SECURITY_BLOCK,
    OUTCOME_APPROVAL_INVALID: FAILURE_CLASS_APPROVAL_INVALID,
    OUTCOME_APPLICATION_UNAVAILABLE: FAILURE_CLASS_APPLICATION_UNAVAILABLE,
    OUTCOME_EVIDENCE_CONFLICT: FAILURE_CLASS_EVIDENCE_CONFLICT,
    OUTCOME_HUMAN_REQUIRED: FAILURE_CLASS_HUMAN_REQUIRED,
}

_RECOVERY_DECISION_BY_CLASS = {
    FAILURE_CLASS_TRANSIENT_TOOL_FAILURE: RECOVERY_DECISION_RETRY,
    FAILURE_CLASS_TIMEOUT: RECOVERY_DECISION_RETRY,
    FAILURE_CLASS_STALE_CONTEXT: RECOVERY_DECISION_REVALIDATE_CONTEXT,
    FAILURE_CLASS_INVALID_TARGET: RECOVERY_DECISION_REVALIDATE_CONTEXT,
    FAILURE_CLASS_APPLICATION_UNAVAILABLE: RECOVERY_DECISION_ALTERNATIVE_TOOL,
    FAILURE_CLASS_EVIDENCE_CONFLICT: RECOVERY_DECISION_REBUILD_EVIDENCE,
    FAILURE_CLASS_APPROVAL_INVALID: RECOVERY_DECISION_REVALIDATE_APPROVAL,
    FAILURE_CLASS_APPROVAL_REJECTED: RECOVERY_DECISION_REVALIDATE_APPROVAL,
    FAILURE_CLASS_SECURITY_BLOCK: RECOVERY_DECISION_PAUSE_FOR_HUMAN,
    FAILURE_CLASS_HUMAN_REQUIRED: RECOVERY_DECISION_PAUSE_FOR_HUMAN,
    FAILURE_CLASS_PERMANENT_FAILURE: RECOVERY_DECISION_FAIL_TERMINALLY,
    FAILURE_CLASS_UNKNOWN: RECOVERY_DECISION_FAIL_TERMINALLY,
}

RECOVERY_DECISION_BOUNDED_ACTIONS = {
    RECOVERY_DECISION_RETRY: "reselect the same subgoal within the bounded retry budget",
    RECOVERY_DECISION_REVALIDATE_CONTEXT: "invalidate stale context and re-observe within the revalidation budget",
    RECOVERY_DECISION_REVALIDATE_APPROVAL: "re-select the subgoal through the Approval Authority; never auto-approve",
    RECOVERY_DECISION_REBUILD_EVIDENCE: "rebuild evidence for the subgoal within the bounded evidence budget",
    RECOVERY_DECISION_ALTERNATIVE_TOOL: "select an alternative authorized tool for the same capability",
    RECOVERY_DECISION_REPLAN: "build a bounded replacement plan preserving completed, verified work and user constraints",
    RECOVERY_DECISION_PAUSE_FOR_HUMAN: "await explicit human input before any further autonomous action",
    RECOVERY_DECISION_FAIL_TERMINALLY: "stop the task truthfully and report the failure; no further autonomous action",
}

_ALTERNATIVE_TOOL_BY_APPLICATION = {
    ("git", "inspect"): "workspace_inspector",
    ("workspace", "inspect"): "relevant_file_selector",
    ("email", "observe"): "comms_observer",
    ("calendar", "observe"): "comms_observer",
    ("browser", "observe"): "browser_page_refresh",
}


def classify_failure_class(*, outcome: str = "", final_outcome: str = "", classification: str = "") -> str:
    outcome = _status_text(outcome)
    final_outcome = _status_text(final_outcome)
    classification = _status_text(classification)
    if outcome == OUTCOME_SECURITY_BLOCK or classification == "BLOCKED" or final_outcome == "BLOCKED":
        return FAILURE_CLASS_SECURITY_BLOCK
    if final_outcome == "APPROVAL_REJECTED":
        return FAILURE_CLASS_APPROVAL_REJECTED
    if outcome == OUTCOME_APPROVAL_INVALID or final_outcome == "APPROVAL_INVALID":
        return FAILURE_CLASS_APPROVAL_INVALID
    if outcome == OUTCOME_HUMAN_REQUIRED or classification == "HUMAN_REQUIRED" or final_outcome in {"HUMAN_REQUIRED", "APPROVAL_REQUIRED", "APPROVAL_PENDING"}:
        return FAILURE_CLASS_HUMAN_REQUIRED
    if classification == "FATAL" or final_outcome in {"FATAL", "PERMANENT_FAILURE", "VERIFICATION_FAILED"}:
        return FAILURE_CLASS_PERMANENT_FAILURE
    direct = _OUTCOME_TO_FAILURE_CLASS.get(outcome)
    if direct is not None:
        return direct
    if final_outcome in {"TIMEOUT", "INVALID_TARGET", "STALE_CONTEXT", "SECURITY_BLOCK", "APPLICATION_UNAVAILABLE", "EVIDENCE_CONFLICT", "TOOL_FAILURE"}:
        return _OUTCOME_TO_FAILURE_CLASS.get(final_outcome, FAILURE_CLASS_UNKNOWN)
    return FAILURE_CLASS_UNKNOWN


def decide_recovery_for_failure_class(failure_class: str) -> str:
    return _RECOVERY_DECISION_BY_CLASS.get(_status_text(failure_class), RECOVERY_DECISION_FAIL_TERMINALLY)


def is_retryable_failure_class(failure_class: str) -> bool:
    return failure_class in RECOVERY_RETRYABLE_CLASSES


def can_auto_replan_failure_class(failure_class: str) -> bool:
    return failure_class in RECOVERY_REPLAN_CAPABLE_CLASSES


def never_auto_retry_failure_class(failure_class: str) -> bool:
    return failure_class in RECOVERY_NEVER_AUTO_RETRY


def alternative_capability_tool(subgoal: dict[str, Any]) -> str:
    application = str(subgoal.get("application") or subgoal.get("application_id") or subgoal.get("capability") or "").lower()
    capability = str(subgoal.get("capability") or subgoal.get("capability_id") or "inspect").lower()
    return _ALTERNATIVE_TOOL_BY_APPLICATION.get((application, capability), "")


def bounded_next_action(decision_type: str, *, attempt: int = 0, max_attempt: int = 0) -> str:
    text = RECOVERY_DECISION_BOUNDED_ACTIONS.get(decision_type, "stop truthfully")
    if max_attempt:
        text = f"{text} (attempt {attempt}/{max_attempt})"
    return text


def _status_text(value: Any) -> str:
    return str(value or "").strip().upper()


def classify_subgoal_outcome(*, tool_result: Any = None, payload: Any = None, action_required: bool = False, executed_evidence: bool = False, normalized_evidence: list[Any] | None = None) -> str:
    """Classify a single subgoal's execution into the Phase 33 failure-semantics set.

    Tool failures are never collapsed into SUCCESS. VALID_UNAVAILABLE is the only
    non-success status that counts as completed evidence (a clean, bounded
    'not present / not applicable' answer). A declared-consequential subgoal with
    no executed consequence is HUMAN_REQUIRED, not SUCCESS.
    """
    if action_required and not executed_evidence:
        return OUTCOME_HUMAN_REQUIRED
    payload_status = _status_text((payload or {}).get("status")) if isinstance(payload, dict) else ""
    if payload_status in {"BLOCKED", "DENIED", "SECURITY_BLOCK", "FORBIDDEN"}:
        return OUTCOME_SECURITY_BLOCK
    if payload_status in {"APPROVAL_REQUIRED", "APPROVAL_INVALID", "APPROVAL_REJECTED"}:
        return OUTCOME_APPROVAL_INVALID
    if payload_status in {"STALE", "STALE_CONTEXT"}:
        return OUTCOME_STALE_CONTEXT
    if payload_status == "TIMEOUT":
        return OUTCOME_TIMEOUT
    if payload_status == "APPLICATION_UNAVAILABLE":
        return OUTCOME_APPLICATION_UNAVAILABLE
    if payload_status in {"EVIDENCE_CONFLICT", "CONFLICTING_EVIDENCE"}:
        return OUTCOME_EVIDENCE_CONFLICT
    if payload_status in {"INVALID_TARGET", "INVALID URL", "NO_TARGET"} or (isinstance(payload, dict) and "target" in _status_text(payload.get("error")) and payload_status in {"ERROR", "FAILED"}):
        return OUTCOME_INVALID_TARGET
    if payload_status in {"UNAVAILABLE", "NOT_FOUND", "CLEAN", "NO_CHANGES", "NOT_APPLICABLE"}:
        return OUTCOME_VALID_UNAVAILABLE
    if payload_status in {"ERROR", "FAILED", "EXECUTION_FAILED", "VERIFICATION_FAILED"}:
        return OUTCOME_TOOL_FAILURE
    if payload_status in {"OK", "COMPLETED", "SUCCESS", "OBSERVED", "VERIFIED"}:
        return OUTCOME_SUCCESS
    top_status = _status_text(tool_result.get("status")) if isinstance(tool_result, dict) else ""
    if top_status in {"FAILED", "BLOCKED"}:
        return OUTCOME_TOOL_FAILURE if top_status == "FAILED" else OUTCOME_SECURITY_BLOCK
    if not isinstance(tool_result, dict) and tool_result is None and not normalized_evidence:
        return OUTCOME_EMPTY
    return OUTCOME_SUCCESS


__all__ = [
    "MAX_SUB_GOALS_PER_PLAN",
    "MAX_PLAN_REVISIONS",
    "MAX_ADDITIONAL_SUBGOALS_PER_REVISION",
    "MAX_TOTAL_SUBGOALS_PER_TASK",
    "MAX_ADAPTATION_HISTORY_ITEMS",
    "MAX_RETRIES_PER_SUBGOAL",
    "MAX_RETRIES_PER_TASK",
    "MAX_CONSECUTIVE_FAILURES",
    "VALID_FAILURE_CLASSIFICATIONS",
    "plan_hash",
    "classify_failure",
    "can_retry_subgoal",
    "can_retry_task",
    "validate_autonomous_plan",
    "next_ready_subgoal",
    "make_plan_version",
    "normalize_subgoal_status",
    "plan_versions_are_compatible",
    "classify_subgoal_outcome",
    "OUTCOME_SUCCESS",
    "OUTCOME_VALID_UNAVAILABLE",
    "OUTCOME_EMPTY",
    "OUTCOME_TOOL_FAILURE",
    "OUTCOME_INVALID_TARGET",
    "OUTCOME_STALE_CONTEXT",
    "OUTCOME_TIMEOUT",
    "OUTCOME_SECURITY_BLOCK",
    "OUTCOME_APPROVAL_INVALID",
    "OUTCOME_APPLICATION_UNAVAILABLE",
    "OUTCOME_EVIDENCE_CONFLICT",
    "OUTCOME_HUMAN_REQUIRED",
    "SUCCESSFUL_OUTCOMES",
    "TERMINAL_FAILURE_STATUSES",
    "MAX_RECOVERY_ATTEMPTS_PER_TASK",
    "MAX_REPLAN_ATTEMPTS_PER_TASK",
    "MAX_REVALIDATIONS_PER_SUBGOAL",
    "FAILURE_CLASS_TRANSIENT_TOOL_FAILURE",
    "FAILURE_CLASS_TIMEOUT",
    "FAILURE_CLASS_STALE_CONTEXT",
    "FAILURE_CLASS_INVALID_TARGET",
    "FAILURE_CLASS_APPLICATION_UNAVAILABLE",
    "FAILURE_CLASS_APPROVAL_INVALID",
    "FAILURE_CLASS_APPROVAL_REJECTED",
    "FAILURE_CLASS_EVIDENCE_CONFLICT",
    "FAILURE_CLASS_SECURITY_BLOCK",
    "FAILURE_CLASS_PERMANENT_FAILURE",
    "FAILURE_CLASS_HUMAN_REQUIRED",
    "FAILURE_CLASS_UNKNOWN",
    "VALID_FAILURE_CLASSES",
    "RECOVERY_DECISION_RETRY",
    "RECOVERY_DECISION_REVALIDATE_CONTEXT",
    "RECOVERY_DECISION_REVALIDATE_APPROVAL",
    "RECOVERY_DECISION_REBUILD_EVIDENCE",
    "RECOVERY_DECISION_ALTERNATIVE_TOOL",
    "RECOVERY_DECISION_REPLAN",
    "RECOVERY_DECISION_PAUSE_FOR_HUMAN",
    "RECOVERY_DECISION_FAIL_TERMINALLY",
    "VALID_RECOVERY_DECISIONS",
    "RECOVERY_RETRYABLE_CLASSES",
    "RECOVERY_REPLAN_CAPABLE_CLASSES",
    "RECOVERY_AUTO_APPROVAL_RETRY_DENIED",
    "RECOVERY_NEVER_AUTO_RETRY",
    "RECOVERY_DECISION_BOUNDED_ACTIONS",
    "classify_failure_class",
    "decide_recovery_for_failure_class",
    "is_retryable_failure_class",
    "can_auto_replan_failure_class",
    "never_auto_retry_failure_class",
    "alternative_capability_tool",
    "bounded_next_action",
]
