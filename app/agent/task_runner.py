from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.agent.execution_journal import (
    create_checkpoint,
    load_checkpoint,
    update_checkpoint,
)
from app.agent.graph import nexus_graph
from app.agent.recovery_manager import evaluate_recovery
from app.attention.service import summarize_attention_snapshot
from app.memory.task_ledger import create_task, get_task, list_recent_tasks, resume_task, update_task_status
from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text

TERMINAL_TASKS = {"COMPLETED", "FAILED", "BLOCKED", "CANCELLED"}
MAX_TASK_ANSWER_CHARS = 4000


def _bound_answer(value: Any) -> str:
    """Redact and bound a user-facing task answer before persistence."""
    text = redact_text(value)
    if len(text) > MAX_TASK_ANSWER_CHARS:
        return text[:MAX_TASK_ANSWER_CHARS].rstrip() + "\n...[TRUNCATED]"
    return text


def _format_browser_result(result: dict[str, Any]) -> str:
    """Render the deterministic fields produced by browser_observer as a readable report."""
    lines: list[str] = []
    url = str(result.get("url") or result.get("requested_url") or "").strip()
    final_url = str(result.get("final_url") or "").strip()
    if url:
        lines.append(f"URL: {url}")
    if final_url and final_url != url:
        lines.append(f"Resolved to: {final_url}")
    title = str(result.get("title") or "").strip()
    if title:
        lines.append(f"Title: {title}")
    headings = [str(item) for item in (result.get("headings") or []) if str(item).strip()]
    if headings:
        lines.append("Headings: " + ", ".join(headings[:5]))
    visible_text = str(result.get("visible_text") or "").strip()
    if visible_text:
        lines.append(visible_text)
    if not lines:
        lines.append(str(result.get("status") or "OBSERVED"))
    return "\n".join(lines)


def _browser_post_action_answer(state: dict[str, Any]) -> str:
    action_result = state.get("browser_action_result")
    if not isinstance(action_result, dict):
        return ""
    post = action_result.get("post_action_observation")
    if not isinstance(post, dict):
        return ""
    if str(post.get("status") or "").upper() != "OK":
        return ""
    return _bound_answer(_format_browser_result(post))


def _build_task_answer(state: dict[str, Any]) -> str:
    """Derive the smallest deterministic, already-produced result for a finished task.

    Uses existing graph outputs only (observation results, action_result, reasoning
    context, verification, decision reason); never invents or fabricates content.
    """
    browser_post = _browser_post_action_answer(state)
    if browser_post:
        return browser_post
    candidate: Any = None
    for item in reversed(state.get("observation_results") or []):
        if not isinstance(item, dict):
            continue
        if str(item.get("status") or "").lower() != "ok":
            continue
        if "result" in item:
            candidate = item["result"]
        if str(item.get("tool") or "") == "browser_observer" and isinstance(candidate, dict):
            return _bound_answer(_format_browser_result(candidate))
        if candidate is not None:
            break

    if not candidate:
        candidate = state.get("action_result")
    if not candidate:
        candidate = state.get("reasoning_context")
    if not candidate:
        candidate = state.get("last_verification") or state.get("verification")
    if not candidate:
        outcome = str(state.get("final_outcome") or "").strip()
        reason = str(state.get("decision_reason") or "").strip()
        candidate = f"{outcome}: {reason}".strip(": ")
    if not candidate:
        return ""

    if not isinstance(candidate, str):
        candidate = json.dumps(redact_sensitive_data(candidate), ensure_ascii=True, default=str, separators=(",", ":"))
    return _bound_answer(str(candidate))


class TaskRunner:
    """A minimal persistent execution wrapper around the existing NEXUS lifecycle."""

    def __init__(
        self,
        workspace_root: str | Path = "workspace",
        *,
        db_path: str | Path | None = None,
        graph_runner: Any | None = None,
        permission_db_path: str | Path | None = None,
        scope_db_path: str | Path | None = None,
        dna_db_path: str | Path | None = None,
    ) -> None:
        self.workspace_root = str(Path(workspace_root))
        self.db_path = Path(db_path) if db_path is not None else None
        self.graph_runner = graph_runner or nexus_graph.invoke
        self._active_task_id: str | None = None
        # Security-store bindings restored into every resolved graph state so
        # restart/resume re-evaluates permission, scope, and authorization
        # decisions instead of silently downgrading those gates to advisory.
        # Only store locations are restored here; cached decisions never are.
        self.permission_db_path = str(permission_db_path) if permission_db_path is not None else ""
        self.scope_db_path = str(scope_db_path) if scope_db_path is not None else ""
        self.dna_db_path = str(dna_db_path) if dna_db_path is not None else ""

    def _audit(self, event_type: str, *, task_id: str, reason: str, result: str, metadata: dict[str, Any] | None = None) -> None:
        record_audit_event(
            event_type,
            actor="task_runner",
            tool="persistent_runner",
            target=str(task_id),
            result=result,
            reason=reason,
            metadata=metadata or {},
            db_path=self.db_path,
            mirror_central=True,
        )

    def _normalize_task_result(self, task_id: str, task: dict[str, Any] | None = None) -> dict[str, Any]:
        if task is None:
            task = get_task(task_id, db_path=self.db_path) or {}
        return {
            "task_id": task.get("task_id") or task_id,
            "status": task.get("status") or "CREATED",
            "current_stage": task.get("current_stage") or "REQUEST",
            "status_reason": task.get("status_reason") or "",
            "resume_reason": task.get("resume_reason") or "",
            "final_outcome": task.get("final_outcome") or "",
            "objective": task.get("objective") or "",
            "current_sub_goal": task.get("current_sub_goal") or "",
            "task_answer": task.get("task_answer") or "",
            "recovery_phase": (task.get("recovery_history") or [{}])[-1].get("phase", "") if task.get("recovery_history") else "",
            "recovery_decision": (task.get("recovery_history") or [{}])[-1] if task.get("recovery_history") else {},
            "recovery_attempts": int(task.get("recovery_attempts", 0) or 0),
            "plan_version": task.get("plan_version") or "v1",
            "plan_hash": task.get("plan_hash") or "",
        }

    def inspect_task_status(self, task_id: str) -> dict[str, Any]:
        task = get_task(task_id, db_path=self.db_path)
        if task is None:
            raise ValueError(f"Task {task_id} was not found.")
        return self._normalize_task_result(task_id, task)

    def _ensure_checkpoint(self, task_id: str, *, task: dict[str, Any] | None = None) -> dict[str, Any] | None:
        task = task or get_task(task_id, db_path=self.db_path)
        if task is None:
            return None
        existing = load_checkpoint(task_id, db_path=self.db_path)
        if existing is not None:
            return existing
        checkpoint = create_checkpoint(
            task_id,
            current_stage=task.get("current_stage") or "REQUEST",
            current_sub_goal=task.get("current_sub_goal") or "",
            selected_tools=task.get("selected_tools", []),
            action_type="task_runner_checkpoint",
            action_target=self.workspace_root,
            target_hash="",
            proposal_hash="",
            redacted_action_metadata={"runner": "persistent_task_runner"},
            risk_level="READ_ONLY",
            approval_status="UNKNOWN",
            approval_expiry="",
            evidence_refs=task.get("evidence_refs", []),
            verification_snapshot=str(task.get("status_reason") or ""),
            retry_count=0,
            retry_reason="",
            resume_required=False,
            resume_reason=task.get("resume_reason") or "",
            environment_fingerprint=self.workspace_root,
            db_path=self.db_path,
        )
        return checkpoint

    def pause_task(self, task_id: str, reason: str = "Task paused by runner.") -> dict[str, Any]:
        task = get_task(task_id, db_path=self.db_path)
        if task is None:
            raise ValueError(f"Task {task_id} was not found.")
        updated = update_task_status(
            task_id,
            "PAUSED",
            current_stage=task.get("current_stage") or "REQUEST",
            current_sub_goal=task.get("current_sub_goal") or "",
            status_reason=reason,
            resume_reason=reason,
            db_path=self.db_path,
        )
        self._audit("TASK_PAUSED", task_id=task_id, reason=reason, result="PAUSED", metadata={"task_id": task_id})
        self._active_task_id = None
        return self._normalize_task_result(task_id, updated)

    def continue_task(self, task_id: str, reason: str = "Explicit continue requested.") -> dict[str, Any]:
        task = get_task(task_id, db_path=self.db_path)
        if task is None:
            raise ValueError(f"Task {task_id} was not found.")
        if str(task.get("status") or "").upper() in TERMINAL_TASKS:
            return self._normalize_task_result(task_id, task)
        resumed = resume_task(task_id, resume_reason=reason, db_path=self.db_path)
        self._active_task_id = task_id
        self._audit("TASK_RESUMED", task_id=task_id, reason=reason, result="RUNNING", metadata={"resume_reason": reason})
        return self._normalize_task_result(task_id, resumed)

    def stop_task(self, task_id: str, reason: str = "Task cancelled by runner.") -> dict[str, Any]:
        task = get_task(task_id, db_path=self.db_path)
        if task is None:
            raise ValueError(f"Task {task_id} was not found.")
        if str(task.get("status") or "").upper() in TERMINAL_TASKS:
            return self._normalize_task_result(task_id, task)
        updated = update_task_status(
            task_id,
            "CANCELLED",
            current_stage=task.get("current_stage") or "REQUEST",
            current_sub_goal=task.get("current_sub_goal") or "",
            status_reason=reason,
            final_outcome="CANCELLED",
            resume_reason=reason,
            db_path=self.db_path,
        )
        self._audit("TASK_CANCELLED", task_id=task_id, reason=reason, result="CANCELLED", metadata={"task_id": task_id})
        self._active_task_id = None
        return self._normalize_task_result(task_id, updated)

    cancel_task = stop_task

    def _resolve_graph_state(self, task_id: str, *, user_request: str, initial_state: dict[str, Any] | None = None) -> dict[str, Any]:
        task = get_task(task_id, db_path=self.db_path)
        state = {
            "user_request": user_request,
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
            "approval_override": "",
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
            "decision_stage": task.get("current_stage") if task else "REQUEST",
            "decision_reason": task.get("status_reason") if task else "",
            "final_outcome": task.get("final_outcome") if task else "",
            "user_constraints": {},
            "request_intent": "",
            "evidence_scope": "",
            "goal_plan": task.get("goal_plan", []) if task else [],
            "goal_error": "",
            "task_id": task_id,
            "task_status": task.get("status") if task else "CREATED",
            "task_resume_requested": False,
            "task_resume_reason": "",
            "task_context": task.get("status_output") if task else "",
            "persistence_db_path": str(self.db_path) if self.db_path else "",
            "journal_db_path": str(self.db_path) if self.db_path else "",
            "approval_db_path": str(self.db_path) if self.db_path else "",
            "permission_db_path": self.permission_db_path,
            "scope_db_path": self.scope_db_path,
            "dna_db_path": self.dna_db_path,
            "plan_version": task.get("plan_version", "v1") if task else "v1",
            "plan_hash": task.get("plan_hash", "") if task else "",
            "plan_revisions": task.get("plan_revisions", 0) if task else 0,
            "current_subgoal_id": task.get("current_subgoal_id", "") if task else "",
            "subgoal_statuses": task.get("subgoal_statuses", {}) if task else {},
            "completed_subgoals": [],
            "pending_subgoals": [],
            "blocked_subgoals": [],
            "task_retry_count": task.get("task_retry_count", 0) if task else 0,
            "subgoal_retry_count": task.get("subgoal_retry_count", {}) if task else {},
            "failure_classifications": task.get("failure_classifications", {}) if task else {},
            "adaptation_history": task.get("adaptation_history", []) if task else [],
            "completion_evidence": task.get("completion_evidence", []) if task else [],
            "environment_fingerprint": self.workspace_root,
            "autonomous_execution_enabled": True,
            "capability_context": {},
            "subgoal_contexts": {},
            "subgoal_lineage": task.get("subgoal_lineage", {}) if task else {},
            "execution_ids": task.get("execution_ids", {}) if task else {},
            "consumed_execution_ids": task.get("consumed_execution_ids", []) if task else [],
            "plan_history": task.get("plan_history", []) if task else [],
            "recovery_history": task.get("recovery_history", []) if task else [],
            "recovery_attempts": int(task.get("recovery_attempts", 0) or 0) if task else 0,
            "replan_attempts": 0,
            "subgoal_plan_hash": {},
            "context_validity": {},
            "recovery_decision": {},
            "recovery_phase": "IDLE",
        }
        state.update(initial_state or {})
        state.setdefault("user_request", user_request)
        state.setdefault("task_id", task_id)
        state.setdefault("task_status", task.get("status") if task else "CREATED")
        state.setdefault("task_resume_requested", False)
        state.setdefault("task_resume_reason", "")
        state.setdefault("task_context", task.get("status_output") if task else "")
        state.setdefault("decision_stage", task.get("current_stage") if task else "REQUEST")
        state.setdefault("decision_reason", task.get("status_reason") if task else "")
        state.setdefault("final_outcome", task.get("final_outcome") if task else "")
        state.setdefault("goal_plan", task.get("goal_plan", []) if task else [])
        state.setdefault("goal_error", "")
        state.setdefault("plan_version", task.get("plan_version", "v1") if task else "v1")
        state.setdefault("plan_hash", task.get("plan_hash", "") if task else "")
        state.setdefault("plan_revisions", task.get("plan_revisions", 0) if task else 0)
        state.setdefault("current_subgoal_id", task.get("current_subgoal_id", "") if task else "")
        state.setdefault("subgoal_statuses", task.get("subgoal_statuses", {}) if task else {})
        state.setdefault("completed_subgoals", [])
        state.setdefault("pending_subgoals", [])
        state.setdefault("blocked_subgoals", [])
        state.setdefault("task_retry_count", task.get("task_retry_count", 0) if task else 0)
        state.setdefault("subgoal_retry_count", task.get("subgoal_retry_count", {}) if task else {})
        state.setdefault("failure_classifications", task.get("failure_classifications", {}) if task else {})
        state.setdefault("adaptation_history", task.get("adaptation_history", []) if task else [])
        state.setdefault("completion_evidence", task.get("completion_evidence", []) if task else [])
        state.setdefault("persistence_db_path", str(self.db_path) if self.db_path else "")
        state.setdefault("journal_db_path", str(self.db_path) if self.db_path else "")
        state.setdefault("approval_db_path", str(self.db_path) if self.db_path else "")
        state.setdefault("permission_db_path", self.permission_db_path)
        state.setdefault("scope_db_path", self.scope_db_path)
        state.setdefault("dna_db_path", self.dna_db_path)
        state.setdefault("environment_fingerprint", self.workspace_root)
        state.setdefault("workspace_root", self.workspace_root)
        state.setdefault("autonomous_execution_enabled", True)
        state.setdefault("capability_context", {})
        state.setdefault("subgoal_contexts", {})
        state.setdefault("subgoal_lineage", task.get("subgoal_lineage", {}) if task else {})
        state.setdefault("execution_ids", task.get("execution_ids", {}) if task else {})
        state.setdefault("consumed_execution_ids", task.get("consumed_execution_ids", []) if task else [])
        state.setdefault("plan_history", task.get("plan_history", []) if task else [])
        state.setdefault("recovery_history", task.get("recovery_history", []) if task else [])
        state.setdefault("recovery_attempts", int(task.get("recovery_attempts", 0) or 0) if task else 0)
        state.setdefault("replan_attempts", 0)
        state.setdefault("subgoal_plan_hash", {})
        state.setdefault("context_validity", {})
        state.setdefault("recovery_decision", {})
        state.setdefault("recovery_phase", "IDLE")
        return state

    def _apply_graph_result(self, task_id: str, result: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(result, dict):
            result = {}
        task = get_task(task_id, db_path=self.db_path)
        ledger_status = str(result.get("task_status") or (task.get("status") if task else "RUNNING"))
        chosen_status = ledger_status.upper()
        if chosen_status not in {"CREATED", "RUNNING", "WAITING_APPROVAL", "VERIFYING", "PAUSED", "COMPLETED", "FAILED", "BLOCKED", "CANCELLED"}:
            chosen_status = "RUNNING"
        if chosen_status == "CREATED":
            chosen_status = "RUNNING"

        current_status = str(task.get("status") or "CREATED").upper() if task else "CREATED"
        if current_status == "CREATED" and chosen_status not in {"CREATED", "RUNNING"}:
            task = update_task_status(
                task_id,
                "RUNNING",
                current_stage=result.get("decision_stage") or (task.get("current_stage") if task else "REQUEST"),
                current_sub_goal=result.get("decision_reason") or (task.get("current_sub_goal") if task else ""),
                status_reason=result.get("decision_reason") or (task.get("status_reason") if task else "Task started and is now running."),
                final_outcome=(task.get("final_outcome") if task else "") or "",
                db_path=self.db_path,
            )
            current_status = "RUNNING"

        final_outcome = result.get("final_outcome") or (task.get("final_outcome") if task else "")
        if chosen_status == "COMPLETED":
            final_outcome = final_outcome or "SUCCESS"
        if result.get("approval_required") and not result.get("approved"):
            chosen_status = "WAITING_APPROVAL"
        task_update = update_task_status(
            task_id,
            chosen_status,
            current_stage=result.get("decision_stage") or (task.get("current_stage") if task else "REQUEST"),
            current_sub_goal=result.get("decision_reason") or (task.get("current_sub_goal") if task else ""),
            status_reason=result.get("decision_reason") or (task.get("status_reason") if task else "Task runner updated durable state."),
            final_outcome=str(final_outcome) if final_outcome else (task.get("final_outcome") if task else ""),
            task_answer=_build_task_answer(result),
            db_path=self.db_path,
        )
        self._active_task_id = task_id if chosen_status not in TERMINAL_TASKS else None
        normalized = self._normalize_task_result(task_id, task_update)
        snapshot = result.get("attention_snapshot")
        if isinstance(snapshot, dict):
            summary = summarize_attention_snapshot(snapshot)
            if summary:
                normalized["attention_summary"] = summary
        return normalized

    def start_task(
        self,
        user_request: str,
        *,
        task_id: str | None = None,
        current_state: dict[str, Any] | None = None,
        graph_runner: Any | None = None,
    ) -> dict[str, Any]:
        if not user_request or not str(user_request).strip():
            raise ValueError("user_request is required for a new task.")

        if task_id:
            existing = get_task(task_id, db_path=self.db_path)
            if existing is not None:
                if str(existing.get("status") or "").upper() in TERMINAL_TASKS:
                    return self._normalize_task_result(task_id, existing)
                if self._active_task_id and self._active_task_id != task_id:
                    return {
                        "task_id": task_id,
                        "status": "PAUSED",
                        "current_stage": existing.get("current_stage") or "REQUEST",
                        "status_reason": "Another task is already active; this durable task remains paused until the active task settles.",
                        "resume_reason": "Other task active",
                        "final_outcome": existing.get("final_outcome") or "",
                        "objective": existing.get("objective") or user_request,
                    }
                self._active_task_id = task_id
                state = self._resolve_graph_state(task_id, user_request=user_request, initial_state=current_state)
                state["task_status"] = str(existing.get("status") or "RUNNING").upper()
                state["task_id"] = task_id
                runner = graph_runner or self.graph_runner
                result = runner(state)
                if not isinstance(result, dict):
                    result = {"task_status": existing.get("status") or "RUNNING", "final_outcome": existing.get("final_outcome") or ""}
                self._audit("TASK_STARTED", task_id=task_id, reason="Existing task resumed through the active graph runner.", result=str(result.get("task_status") or "RUNNING"), metadata={"graph_result": result})
                return self._apply_graph_result(task_id, result)

        task = create_task(
            user_request,
            task_id=task_id,
            current_stage="REQUEST",
            status="CREATED",
            status_reason="Task created for persistent execution.",
            db_path=self.db_path,
        )
        if task_id and task["task_id"] != task_id:
            task = get_task(task_id, db_path=self.db_path) or task

        self._active_task_id = task["task_id"]
        state = self._resolve_graph_state(task["task_id"], user_request=user_request, initial_state=current_state)
        state["task_status"] = "RUNNING"
        state["task_id"] = task["task_id"]

        runner = graph_runner or self.graph_runner
        result = runner(state)
        if not isinstance(result, dict):
            result = {"task_status": "RUNNING", "final_outcome": ""}
        self._audit("TASK_STARTED", task_id=task["task_id"], reason="New task started through the durable runner.", result=str(result.get("task_status") or "RUNNING"), metadata={"graph_result": result})
        return self._apply_graph_result(task["task_id"], result)

    def recover_interrupted_task(self, task_id: str, *, current_state: dict[str, Any] | None = None) -> dict[str, Any]:
        task = get_task(task_id, db_path=self.db_path)
        if task is None:
            raise ValueError(f"Task {task_id} was not found.")
        status = str(task.get("status") or "").upper()
        if status in TERMINAL_TASKS:
            return self._normalize_task_result(task_id, task)
        if status == "WAITING_APPROVAL" and not task.get("approval_id"):
            return self._normalize_task_result(task_id, task)

        base_state = {
            "user_request": task.get("objective") or task.get("status_reason") or "",
            "target_file": "",
            "selected_tools": task.get("selected_tools", []),
            "approval_required": False,
            "approval_status": "UNKNOWN",
            "approval_expiry": "",
            "resume_reason": task.get("resume_reason") or "",
            "status_reason": task.get("status_reason") or "",
        }
        base_state.update(current_state or {})

        decision = evaluate_recovery(
            task_id,
            current_state=base_state,
            workspace_root=self.workspace_root,
            db_path=self.db_path,
        )
        self._audit("TASK_RECOVERY_STARTED", task_id=task_id, reason=decision.get("reason") or "Recovery evaluation started.", result=decision.get("decision") or "HALT_AND_BLOCK", metadata={"decision": decision})

        if decision.get("decision") in {"CONTINUE_APPROVED_ACTION", "CONTINUE_READ_ONLY"}:
            self._active_task_id = task_id
            resumed = update_task_status(
                task_id,
                "RUNNING",
                current_stage=task.get("current_stage") or "REQUEST",
                current_sub_goal=task.get("current_sub_goal") or "",
                status_reason="Recovery validation passed; task can resume safely.",
                resume_reason="recovery: validated",
                db_path=self.db_path,
            )
            checkpoint = load_checkpoint(task_id, db_path=self.db_path) or {}
            binding = checkpoint.get("approval_binding") or {}
            selected_tools = checkpoint.get("selected_tools") or task.get("selected_tools") or []
            action_tool = str(selected_tools[0]) if selected_tools else "fixer"
            state = self._resolve_graph_state(task_id, user_request=task.get("objective") or "", initial_state=current_state)
            state.update({
                "task_id": task_id,
                "task_status": "RUNNING",
                "task_resume_requested": True,
                "approved": decision.get("decision") == "CONTINUE_APPROVED_ACTION",
                "approval_required": decision.get("decision") == "CONTINUE_APPROVED_ACTION",
                "approval_id": binding.get("approval_id", ""),
                "journal_checkpoint_id": checkpoint.get("checkpoint_id", ""),
                "proposal_hash": checkpoint.get("proposal_hash", ""),
                "action_type": checkpoint.get("action_type", action_tool),
                "action_tool": action_tool,
                "action_target": checkpoint.get("action_target", ""),
                "target_file": checkpoint.get("action_target", "") if action_tool == "fixer" else "",
                # Restore the exact durable action payload so resume executes
                # precisely what was approved (proposal_hash still binds it).
                # Absent payload means the executor fails closed, never a
                # vacuous run.
                "old_code": str((checkpoint.get("action_payload") or {}).get("old_code", "") or ""),
                "new_code": str((checkpoint.get("action_payload") or {}).get("new_code", "") or ""),
                "action_spec": dict((checkpoint.get("action_payload") or {}).get("action_spec", {}) or {}),
                "persistence_db_path": str(self.db_path) if self.db_path else "",
                "journal_db_path": str(self.db_path) if self.db_path else "",
                "approval_db_path": str(self.db_path) if self.db_path else "",
                # A revoked permission, scope, or authorization must still
                # block a resumed task: restore runner bindings unless the
                # resolved state already carries task-specific ones.
                "permission_db_path": str(state.get("permission_db_path") or "") or self.permission_db_path,
                "scope_db_path": str(state.get("scope_db_path") or "") or self.scope_db_path,
                "dna_db_path": str(state.get("dna_db_path") or "") or self.dna_db_path,
            })
            result = self.graph_runner(state)
            return self._apply_graph_result(task_id, result if isinstance(result, dict) else {})

        if decision.get("decision") in {"REVALIDATE_APPROVAL", "REBUILD_PROPOSAL"}:
            paused = update_task_status(
                task_id,
                "PAUSED",
                current_stage=task.get("current_stage") or "REQUEST",
                current_sub_goal=task.get("current_sub_goal") or "",
                status_reason=str(decision.get("reason") or "Recovery requires revalidation before continuing."),
                resume_reason=str(decision.get("reason") or "Recovery requires revalidation."),
                db_path=self.db_path,
            )
            self._active_task_id = None
            return self._normalize_task_result(task_id, paused)

        blocked = update_task_status(
            task_id,
            "BLOCKED",
            current_stage=task.get("current_stage") or "REQUEST",
            current_sub_goal=task.get("current_sub_goal") or "",
            status_reason=str(decision.get("reason") or "Recovery blocked due to an unsafe state."),
            resume_reason=str(decision.get("reason") or "Recovery blocked due to an unsafe state."),
            final_outcome="BLOCKED",
            db_path=self.db_path,
        )
        self._audit("TASK_RECOVERY_BLOCKED", task_id=task_id, reason=str(decision.get("reason") or "Recovery blocked."), result="BLOCKED", metadata={"decision": decision})
        self._active_task_id = None
        return self._normalize_task_result(task_id, blocked)

    def graceful_shutdown(self, task_id: str, reason: str = "Graceful shutdown requested.") -> dict[str, Any]:
        task = get_task(task_id, db_path=self.db_path)
        if task is None:
            raise ValueError(f"Task {task_id} was not found.")
        status = str(task.get("status") or "").upper()
        if status in TERMINAL_TASKS:
            return self._normalize_task_result(task_id, task)

        checkpoint = self._ensure_checkpoint(task_id, task=task)
        if checkpoint is not None:
            update_checkpoint(
                checkpoint["checkpoint_id"],
                current_stage=task.get("current_stage") or "REQUEST",
                current_sub_goal=task.get("current_sub_goal") or "",
                selected_tools=task.get("selected_tools", []),
                action_type="task_runner_shutdown",
                action_target=self.workspace_root,
                resume_required=True,
                resume_reason=f"shutdown: {reason}",
                db_path=self.db_path,
            )

        paused = update_task_status(
            task_id,
            "PAUSED",
            current_stage=task.get("current_stage") or "REQUEST",
            current_sub_goal=task.get("current_sub_goal") or "",
            status_reason=f"Shutdown checkpoint persisted: {reason}",
            resume_reason=f"shutdown: {reason}",
            db_path=self.db_path,
        )
        self._audit("TASK_SHUTDOWN_CHECKPOINT", task_id=task_id, reason=reason, result="PAUSED", metadata={"checkpoint_id": checkpoint.get("checkpoint_id") if checkpoint else None})
        self._active_task_id = None
        return self._normalize_task_result(task_id, paused)

    def startup_recovery(self, *, current_state: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        recovered: list[dict[str, Any]] = []
        for task in list_recent_tasks(limit=100, db_path=self.db_path):
            status = str(task.get("status") or "").upper()
            if status in TERMINAL_TASKS:
                continue
            recovered.append(self.recover_interrupted_task(task["task_id"], current_state=current_state))
        return recovered

    def resume_task(self, task_id: str, reason: str = "Task resumed by runner.") -> dict[str, Any]:
        return self.continue_task(task_id, reason=reason)

    def __repr__(self) -> str:
        return f"TaskRunner(workspace_root={self.workspace_root!r}, active_task_id={self._active_task_id!r})"
