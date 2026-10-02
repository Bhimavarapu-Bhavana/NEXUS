from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from app.agent.evidence import normalize_tool_results
from app.agent.goal_decomposition import validate_goal_plan
from app.security.audit_logger import record_audit_event
from app.security.risk_engine import BLOCKED, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.tools.tool_registry import TOOL_REGISTRY, execute_selected_tools

WORKFLOW_STATES = {
    "CREATED",
    "RUNNING",
    "WAITING_APPROVAL",
    "WAITING_DEPENDENCY",
    "EXECUTING",
    "VERIFYING",
    "PAUSED",
    "FAILED",
    "BLOCKED",
    "COMPLETED",
    "CANCELLED",
}

TERMINAL_STATES = {"FAILED", "BLOCKED", "COMPLETED", "CANCELLED"}

WORKFLOW_TRANSITIONS: dict[str, set[str]] = {
    "CREATED": {"RUNNING", "WAITING_APPROVAL", "WAITING_DEPENDENCY", "PAUSED", "BLOCKED", "FAILED", "CANCELLED"},
    "RUNNING": {"WAITING_APPROVAL", "WAITING_DEPENDENCY", "EXECUTING", "VERIFYING", "PAUSED", "BLOCKED", "FAILED", "COMPLETED"},
    "WAITING_APPROVAL": {"RUNNING", "BLOCKED", "CANCELLED", "VERIFYING"},
    "WAITING_DEPENDENCY": {"RUNNING", "PAUSED", "BLOCKED", "FAILED"},
    "EXECUTING": {"VERIFYING", "WAITING_APPROVAL", "RUNNING", "BLOCKED", "FAILED", "COMPLETED"},
    "VERIFYING": {"COMPLETED", "FAILED", "RUNNING", "PAUSED", "WAITING_APPROVAL"},
    "PAUSED": {"RUNNING", "WAITING_APPROVAL", "VERIFYING", "WAITING_DEPENDENCY"},
    "FAILED": {"RUNNING"},
    "BLOCKED": {"RUNNING"},
    "COMPLETED": set(),
    "CANCELLED": set(),
}


def validate_workflow_transition(current: str, next_state: str) -> str:
    current_key = str(current or "").upper()
    next_key = str(next_state or "").upper()
    if not next_key:
        raise ValueError("Workflow transition requires a valid next state.")
    if next_key not in WORKFLOW_STATES:
        raise ValueError(f"Unsupported workflow state: {next_state}")
    if current_key == next_key:
        return next_key
    if current_key in TERMINAL_STATES:
        raise ValueError(f"Terminal workflow state {current_key} cannot transition to {next_key}.")
    if next_key not in WORKFLOW_TRANSITIONS.get(current_key, set()):
        raise ValueError(f"Invalid workflow transition from {current_key} to {next_key}.")
    return next_key


def _safe_text(value: Any) -> str:
    return redact_text(value or "")


def _is_expired(value: str | None) -> bool:
    if not value:
        return False
    try:
        expiry = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return True
    return expiry <= datetime.now(timezone.utc)


def _ordered_goal_ids(sub_goals: list[dict[str, Any]]) -> list[str]:
    return [str(item["sub_goal_id"]).strip() for item in sub_goals if str(item.get("sub_goal_id", "")).strip()]


def _tool_authorized(name: str) -> bool:
    candidate = str(name or "").strip()
    metadata = TOOL_REGISTRY.get(candidate)
    return bool(candidate) and bool(metadata and metadata.get("allowed", False))


def _infer_tool_for_sub_goal(sub_goal: dict[str, Any]) -> str:
    selected = sub_goal.get("selected_tools") or []
    for tool in selected:
        if isinstance(tool, str) and _tool_authorized(tool):
            return tool
    objective = str(sub_goal.get("objective") or "").lower()
    interactive_browser_terms = (
        "real browser",
        "actual browser",
        "headless browser",
        "playwright",
        "chromium",
        "in the real browser",
        "browser controller",
        "grounded button",
        "grounded field",
        "click the grounded",
        "type into the",
    )
    if any(term in objective for term in interactive_browser_terms):
        # Consequential selection: the workflow approval gate (MEDIUM_RISK,
        # approval_required) holds this at WAITING_APPROVAL; execution only
        # proceeds through the durable Action Executor, never the registry.
        return "browser_controller"
    if "browser" in objective or "page" in objective or "url" in objective:
        return "browser_observer"
    if "desktop" in objective or "window" in objective:
        return "desktop_observer"
    if "git" in objective or "repo" in objective or "branch" in objective:
        return "git_inspector"
    if "runtime" in objective or "error" in objective or "fail" in objective:
        return "runtime_inspector"
    if "log" in objective or "terminal" in objective:
        return "terminal_inspector"
    return "workspace_inspector"


def _evaluate_sub_goal_risk(sub_goal: dict[str, Any], tool_name: str) -> dict[str, Any]:
    objective = str(sub_goal.get("objective") or "")
    risk = evaluate_risk(objective, tool_name=tool_name, target_path=sub_goal.get("target_ref", "workspace"), workspace_root="workspace")
    return risk


def _safe_history_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return redact_sensitive_data(dict(entry))


def validate_workflow(workflow: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(workflow, dict):
        raise ValueError("Workflow must be a dictionary.")

    safe_workflow = dict(workflow)
    safe_workflow["objective"] = _safe_text(safe_workflow.get("objective", ""))
    if not safe_workflow["objective"]:
        raise ValueError("Workflow objective is required.")

    task_id = str(safe_workflow.get("task_id") or "").strip()
    if not task_id:
        raise ValueError("Workflow requires a task_id.")

    workflow_id = str(safe_workflow.get("workflow_id") or "").strip()
    if not workflow_id:
        safe_workflow["workflow_id"] = f"wf-{uuid.uuid4().hex[:12]}"

    ordered = safe_workflow.get("ordered_sub_goals")
    if ordered is None:
        ordered = safe_workflow.get("goal_plan") or []
    if not isinstance(ordered, list):
        raise ValueError("Workflow ordered_sub_goals must be a list of sub-goal dictionaries.")
    if not ordered:
        raise ValueError("Workflow requires at least one ordered sub-goal.")
    safe_workflow["ordered_sub_goals"] = validate_goal_plan(ordered)
    ordered_ids = _ordered_goal_ids(safe_workflow["ordered_sub_goals"])

    status = str(safe_workflow.get("status") or "CREATED").upper()
    if status not in WORKFLOW_STATES:
        raise ValueError(f"Unsupported workflow status: {status}")
    safe_workflow["status"] = status

    current_stage = str(safe_workflow.get("current_stage") or status).upper()
    if current_stage not in WORKFLOW_STATES and current_stage not in {"REQUEST", "OBSERVE", "EVIDENCE", "REASON", "TOOL_SELECTION", "APPROVAL_PENDING", "ACTION", "VERIFICATION", "FINAL_OUTCOME"}:
        raise ValueError(f"Unsupported workflow stage: {current_stage}")
    safe_workflow["current_stage"] = current_stage

    for item in safe_workflow["ordered_sub_goals"]:
        tools = item.get("selected_tools") or []
        for tool_name in tools:
            if tool_name and not _tool_authorized(str(tool_name)):
                raise ValueError(f"Unauthorized tool in workflow plan: {tool_name}")

    if safe_workflow.get("selected_tool"):
        selected_tool = str(safe_workflow["selected_tool"]).strip()
        if not _tool_authorized(selected_tool):
            raise ValueError(f"Workflow selected tool is not authorized: {selected_tool}")

    completed = safe_workflow.get("completed_sub_goals") or []
    pending = safe_workflow.get("pending_sub_goals") or []
    blocked = safe_workflow.get("blocked_sub_goals") or []
    if not isinstance(completed, list):
        raise ValueError("completed_sub_goals must be a list.")
    if not isinstance(pending, list):
        raise ValueError("pending_sub_goals must be a list.")
    if not isinstance(blocked, list):
        raise ValueError("blocked_sub_goals must be a list.")

    if not pending:
        pending = [goal_id for goal_id in ordered_ids if goal_id not in completed]
    safe_workflow["pending_sub_goals"] = pending
    safe_workflow["completed_sub_goals"] = [goal_id for goal_id in completed if goal_id in ordered_ids]
    safe_workflow["blocked_sub_goals"] = [goal_id for goal_id in blocked if goal_id in ordered_ids]

    current_sub_goal_id = str(safe_workflow.get("current_sub_goal_id") or "").strip()
    if current_sub_goal_id and current_sub_goal_id not in ordered_ids:
        raise ValueError(f"Current sub-goal {current_sub_goal_id} is not in the workflow plan.")
    if not current_sub_goal_id and ordered_ids:
        current_sub_goal_id = ordered_ids[0]
    safe_workflow["current_sub_goal_id"] = current_sub_goal_id

    approval_lineage = safe_workflow.get("approval_lineage") or {}
    if approval_lineage:
        if not isinstance(approval_lineage, dict):
            raise ValueError("approval_lineage must be a dictionary.")
        safe_approval = redact_sensitive_data(approval_lineage)
        if str(safe_approval.get("status") or "").upper() in {"APPROVED", "GRANTED"} and _is_expired(str(safe_approval.get("expires_at") or "")):
            raise ValueError("Expired approval lineage is invalid for workflow continuation.")
        safe_workflow["approval_lineage"] = safe_approval

    if safe_workflow.get("tool_execution_history") is None:
        safe_workflow["tool_execution_history"] = []
    if not isinstance(safe_workflow["tool_execution_history"], list):
        raise ValueError("tool_execution_history must be a list.")
    safe_workflow["tool_execution_history"] = [
        _safe_history_entry(item)
        for item in safe_workflow["tool_execution_history"]
        if isinstance(item, dict)
    ]

    if not isinstance(safe_workflow.get("evidence_refs", []), list):
        raise ValueError("evidence_refs must be a list.")
    safe_workflow["evidence_refs"] = [str(item).strip() for item in safe_workflow.get("evidence_refs", []) if str(item).strip()]

    if safe_workflow.get("allowed_tools") is None:
        safe_workflow["allowed_tools"] = ["workspace_inspector", "relevant_file_selector", "runtime_inspector", "error_detector", "terminal_inspector", "log_inspector", "git_inspector", "browser_observer", "security_scan"]
    allowed_tools = list(safe_workflow.get("allowed_tools") or [])
    for tool_name in allowed_tools:
        if not _tool_authorized(str(tool_name)):
            raise ValueError(f"Disallowed tool in workflow authorization list: {tool_name}")
    safe_workflow["allowed_tools"] = [str(item).strip() for item in allowed_tools if str(item).strip()]

    if safe_workflow.get("risk_decision"):
        risk = safe_workflow["risk_decision"]
        if not isinstance(risk, dict):
            raise ValueError("risk_decision must be a dictionary.")
        safe_workflow["risk_decision"] = redact_sensitive_data(risk)
        if str(safe_workflow["risk_decision"].get("risk_level") or "").upper() == BLOCKED:
            safe_workflow["status"] = "BLOCKED"

    if safe_workflow.get("failure_reason"):
        safe_workflow["failure_reason"] = _safe_text(safe_workflow["failure_reason"])

    if safe_workflow.get("target_ref"):
        safe_workflow["target_ref"] = _safe_text(safe_workflow["target_ref"])

    if safe_workflow.get("approval_lineage"):
        safe_approval = safe_workflow["approval_lineage"]
        target = str(safe_approval.get("target") or safe_workflow.get("target_ref") or "")
        if target and safe_workflow.get("target_ref") and target != safe_workflow["target_ref"]:
            raise ValueError("Approval target does not match the workflow target.")

    current_status = safe_workflow["status"]
    if current_status in {"COMPLETED", "CANCELLED"} and safe_workflow.get("current_stage") not in {"FINAL_OUTCOME", "CANCELLED"}:
        safe_workflow["current_stage"] = "FINAL_OUTCOME" if current_status == "COMPLETED" else "CANCELLED"

    return safe_workflow


def create_workflow(
    objective: str,
    *,
    task_id: str | None = None,
    goal_plan: list[dict[str, Any]] | None = None,
    allowed_tools: list[str] | None = None,
) -> dict[str, Any]:
    safe_objective = _safe_text(objective)
    if not safe_objective:
        raise ValueError("Workflow objective cannot be empty.")

    ordered = goal_plan or []
    if goal_plan is None:
        ordered = validate_goal_plan([
            {
                "sub_goal_id": "observe_target",
                "objective": "Inspect the workspace and establish the relevant target.",
                "dependencies": [],
                "selected_tools": ["workspace_inspector"],
            },
            {
                "sub_goal_id": "collect_evidence",
                "objective": "Collect evidence relevant to the objective.",
                "dependencies": ["observe_target"],
                "selected_tools": ["runtime_inspector", "terminal_inspector"],
                "verification_required": True,
            },
            {
                "sub_goal_id": "determine_outcome",
                "objective": "Correlate the evidence and determine the likely outcome.",
                "dependencies": ["collect_evidence"],
                "selected_tools": [],
            },
        ])
    else:
        ordered = validate_goal_plan(goal_plan)

    ordered_ids = _ordered_goal_ids(ordered)
    workflow = {
        "workflow_id": f"wf-{uuid.uuid4().hex[:12]}",
        "task_id": str(task_id or f"task-{uuid.uuid4().hex[:12]}"),
        "objective": safe_objective,
        "current_sub_goal_id": ordered_ids[0] if ordered_ids else "",
        "ordered_sub_goals": ordered,
        "completed_sub_goals": [],
        "pending_sub_goals": ordered_ids[:],
        "blocked_sub_goals": [],
        "selected_tool": "",
        "allowed_tools": list(allowed_tools or ["workspace_inspector", "relevant_file_selector", "runtime_inspector", "error_detector", "terminal_inspector", "log_inspector", "git_inspector", "browser_observer", "security_scan"]),
        "tool_execution_history": [],
        "evidence_refs": [],
        "dependency_state": {},
        "action_lineage": {},
        "verification_lineage": [],
        "approval_lineage": {},
        "retry_information": {},
        "current_stage": "CREATED",
        "status": "CREATED",
        "failure_reason": "",
        "final_outcome": "",
        "timestamps": {
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
        "target_ref": "",
        "risk_decision": {},
        "checkpoint_id": "",
        "workflow_notes": [],
    }
    return validate_workflow(workflow)


def _mark_pending_and_completed(workflow: dict[str, Any], completed_ids: list[str], blocked_ids: list[str] | None = None) -> dict[str, Any]:
    ordered_ids = _ordered_goal_ids(workflow["ordered_sub_goals"])
    completed = [goal_id for goal_id in ordered_ids if goal_id in set(completed_ids)]
    pending = [goal_id for goal_id in ordered_ids if goal_id not in set(completed)]
    if blocked_ids is None:
        blocked_ids = workflow.get("blocked_sub_goals", [])
    workflow["completed_sub_goals"] = completed
    workflow["pending_sub_goals"] = pending
    workflow["blocked_sub_goals"] = [goal_id for goal_id in blocked_ids if goal_id in ordered_ids]
    if pending:
        workflow["current_sub_goal_id"] = pending[0]
    elif completed:
        workflow["current_sub_goal_id"] = completed[-1]
    else:
        workflow["current_sub_goal_id"] = ""
    return workflow


def execute_workflow_sub_goal(workflow: dict[str, Any], sub_goal_id: str, execution_args: dict[str, Any] | None = None) -> dict[str, Any]:
    validated = validate_workflow(workflow)
    workflow = dict(validated)
    execution_args = dict(execution_args or {})

    if str(workflow.get("status") or "").upper() in TERMINAL_STATES:
        raise ValueError("Cannot execute sub-goals in a terminal workflow state.")

    ordered_ids = _ordered_goal_ids(workflow["ordered_sub_goals"])
    if sub_goal_id not in ordered_ids:
        raise ValueError(f"Unknown sub-goal id: {sub_goal_id}")

    goal_map = {str(item["sub_goal_id"]): item for item in workflow["ordered_sub_goals"]}
    sub_goal = goal_map[sub_goal_id]
    dependencies = [str(dep).strip() for dep in sub_goal.get("dependencies") or [] if str(dep).strip()]
    for dep in dependencies:
        if dep not in workflow.get("completed_sub_goals", []):
            raise ValueError(f"Dependency {dep} must complete before {sub_goal_id} can execute.")

    current_pending = workflow.get("pending_sub_goals") or ordered_ids[:]
    if sub_goal_id not in current_pending:
        raise ValueError(f"Sub-goal {sub_goal_id} is not ready to execute in the current dependency order.")

    selected_tool = _infer_tool_for_sub_goal(sub_goal)
    if not _tool_authorized(selected_tool):
        raise ValueError(f"Selected tool is not permitted by the registry: {selected_tool}")

    approved = bool(workflow.get("approval_lineage", {}).get("status") == "APPROVED")
    risk_decision = _evaluate_sub_goal_risk(sub_goal, selected_tool)
    workflow["selected_tool"] = selected_tool
    workflow["risk_decision"] = risk_decision
    workflow["current_stage"] = "EXECUTING"
    workflow["status"] = "EXECUTING"
    workflow["timestamps"]["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if risk_decision.get("risk_level") == BLOCKED or risk_decision.get("allowed") is False:
        workflow["status"] = "BLOCKED"
        workflow["current_stage"] = "BLOCKED"
        workflow["failure_reason"] = risk_decision.get("reason") or "Sub-goal was blocked by policy."
        workflow["blocked_sub_goals"] = list(dict.fromkeys(workflow.get("blocked_sub_goals", []) + [sub_goal_id]))
        return validate_workflow(workflow)

    if risk_decision.get("approval_required") and not approved:
        workflow["status"] = "WAITING_APPROVAL"
        workflow["current_stage"] = "APPROVAL_PENDING"
        workflow["approval_lineage"] = {
            "task_id": workflow["task_id"],
            "action_type": selected_tool,
            "target": workflow.get("target_ref") or sub_goal_id,
            "risk_level": risk_decision.get("risk_level"),
            "status": "PENDING",
            "reason": risk_decision.get("reason") or "Approval required before execution.",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="seconds"),
        }
        return validate_workflow(workflow)

    if selected_tool == "browser_controller":
        # The browser controller is consequential: it may only execute through
        # the durable Action Executor approval chain (claim/consume), which the
        # lightweight workflow path cannot provide. Fail closed here instead of
        # misreporting a registry block as a tool failure.
        workflow["status"] = "BLOCKED"
        workflow["current_stage"] = "BLOCKED"
        workflow["failure_reason"] = "Browser controller execution requires the durable Action Executor approval path; the workflow registry path is fail-closed."
        workflow["blocked_sub_goals"] = list(dict.fromkeys(workflow.get("blocked_sub_goals", []) + [sub_goal_id]))
        return validate_workflow(workflow)

    if selected_tool not in TOOL_REGISTRY:
        raise ValueError(f"Tool registry entry is missing an executable function: {selected_tool}")

    execution_args = {**execution_args, "workspace_path": execution_args.get("workspace_path", "workspace")}
    if selected_tool == "workspace_inspector":
        execution_args.setdefault("workspace_path", "workspace")
    elif selected_tool == "runtime_inspector":
        execution_args.setdefault("workspace_path", "workspace")
        execution_args.setdefault("file_name", execution_args.get("file_name") or "shop_project.py")
    elif selected_tool == "terminal_inspector":
        execution_args.setdefault("output", execution_args.get("output", ""))
    elif selected_tool == "log_inspector":
        execution_args.setdefault("workspace_path", "workspace")
        execution_args.setdefault("log_path", execution_args.get("log_path", ""))
    elif selected_tool == "git_inspector":
        execution_args.setdefault("workspace_path", "workspace")
    elif selected_tool == "browser_observer":
        target_url = str(execution_args.get("url") or workflow.get("target_ref") or "").strip()
        if not target_url:
            workflow["status"] = "BLOCKED"
            workflow["current_stage"] = "BLOCKED"
            workflow["failure_reason"] = "Browser observation requires an explicit URL; no browser target was supplied."
            workflow["blocked_sub_goals"] = list(dict.fromkeys(workflow.get("blocked_sub_goals", []) + [sub_goal_id]))
            return validate_workflow(workflow)
        execution_args["url"] = target_url
    elif selected_tool == "security_scan":
        execution_args.setdefault("target", execution_args.get("target", "workspace"))
        execution_args.setdefault("workspace_root", execution_args.get("workspace_root", "workspace"))

    if selected_tool in {"workspace_inspector", "git_inspector", "security_scan"}:
        execution_args.setdefault("workspace_path", execution_args.get("workspace_path", "workspace"))

    try:
        registry_results = execute_selected_tools([selected_tool], **execution_args)
        result_record = registry_results[0] if registry_results else {"status": "failed", "result": "No tool result was produced."}
        raw_result = result_record.get("result", "")
        if result_record.get("status") != "ok":
            raise RuntimeError(str(raw_result))
    except Exception as exc:  # pragma: no cover - defensive execution guard
        workflow["status"] = "FAILED"
        workflow["current_stage"] = "FAILED"
        workflow["failure_reason"] = f"Tool execution failed: {exc}"
        return validate_workflow(workflow)

    safe_result = redact_sensitive_data(raw_result)
    entry = {
        "tool": selected_tool,
        "sub_goal_id": sub_goal_id,
        "status": "ok",
        "risk_decision": risk_decision,
        "result": safe_result,
    }
    workflow["tool_execution_history"] = list(workflow.get("tool_execution_history", [])) + [_safe_history_entry(entry)]
    workflow["selected_tool"] = selected_tool
    workflow["evidence_refs"] = list(workflow.get("evidence_refs", [])) + [f"{selected_tool}:{sub_goal_id}"]

    if selected_tool == "browser_observer" and isinstance(safe_result, dict):
        workflow["target_ref"] = str(safe_result.get("url") or workflow.get("target_ref") or "")

    normalized = normalize_tool_results(workflow["tool_execution_history"])
    workflow["verification_lineage"] = normalized
    workflow["dependency_state"][sub_goal_id] = {"status": "completed", "evidence": normalized[-1:] if normalized else []}

    workflow["completed_sub_goals"] = list(dict.fromkeys(workflow.get("completed_sub_goals", []) + [sub_goal_id]))
    workflow["pending_sub_goals"] = [goal_id for goal_id in _ordered_goal_ids(workflow["ordered_sub_goals"]) if goal_id not in workflow["completed_sub_goals"]]
    workflow["current_sub_goal_id"] = sub_goal_id

    if sub_goal.get("verification_required"):
        workflow["status"] = "VERIFYING"
        workflow["current_stage"] = "VERIFYING"
        workflow["verification_lineage"] = normalized
    else:
        workflow["status"] = "RUNNING"
        workflow["current_stage"] = "ACTION"

    all_complete = not workflow["pending_sub_goals"]
    if all_complete:
        workflow["status"] = "COMPLETED"
        workflow["current_stage"] = "FINAL_OUTCOME"
        workflow["final_outcome"] = "SUCCESS"
        workflow["failure_reason"] = ""

    workflow["timestamps"]["updated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return validate_workflow(workflow)


def _coerce_workflow_result(state: dict[str, Any]) -> dict[str, Any]:
    result = validate_workflow(state)
    return result


__all__ = [
    "WORKFLOW_STATES",
    "TERMINAL_STATES",
    "validate_workflow_transition",
    "validate_workflow",
    "create_workflow",
    "execute_workflow_sub_goal",
    "_coerce_workflow_result",
]
