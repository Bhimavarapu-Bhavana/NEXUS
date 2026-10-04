"""Local NEXUS Control Plane.

Operational/control layer over the existing NEXUS runtime. It composes the
existing lifecycle (AutonomousService), StateGraph runner (TaskRunner), task
ledger, approval authority, security monitor, and the adapter catalog into one
bounded, read-only-oriented control surface.

It never introduces a second orchestrator, a parallel planner, a second usage DB,
or arbitrary execution endpoints. Lifecycle transitions are validated against an
explicit legal-transition table and delegated to the existing AutonomousService.
Requests are routed through TaskRunner -> the existing StateGraph, never through
manual tool selection.
"""

from __future__ import annotations

import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
import threading
from pathlib import Path
from typing import Any, Callable

from app.agent.approval_authority import decide_approval as authority_decide_approval
from app.agent.approval_authority import get_approval, list_pending_approvals
from app.agent.autonomous_service import AutonomousService
from app.agent.execution_journal import load_checkpoint, update_checkpoint
from app.agent.task_runner import TERMINAL_TASKS, TaskRunner
from app.adapters.catalog import build_adapters_catalog, ensure_adapters_registered
from app.adapters.model import OperationSchema, ProviderDescriptor, ProviderKind
from app.memory.task_ledger import get_task, list_recent_tasks
from app.security.audit_logger import get_recent_audit_events, record_audit_event
from app.security.security_monitor import SecurityMonitor
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.tools.git_inspector import inspect_git_repository

NOW = datetime.now

TASK_STATUS_ORDER = (
    "CREATED",
    "RUNNING",
    "WAITING_APPROVAL",
    "VERIFYING",
    "PAUSED",
    "COMPLETED",
    "FAILED",
    "BLOCKED",
    "CANCELLED",
)

OPEN_TASK_STATUSES = ("RUNNING", "WAITING_APPROVAL", "VERIFYING")

LIFECYCLE_COMMANDS = frozenset({"START", "STOP", "PAUSE", "RESUME", "RESTART", "SHUTDOWN", "STATUS"})

# Legal lifecycle transitions from a current service state to a command.
# Invalid transitions fail safely without touching the underlying service.
LEGAL_LIFECYCLE_TRANSITIONS = {
    "START": frozenset({"STOPPED", "SHUTDOWN", "DEGRADED", "RESTRICTED", "HUMAN_REQUIRED"}),
    "STOP": frozenset({"RUNNING", "PAUSED", "DEGRADED", "RESTRICTED", "HUMAN_REQUIRED"}),
    "PAUSE": frozenset({"RUNNING", "DEGRADED", "RESTRICTED"}),
    "RESUME": frozenset({"PAUSED", "DEGRADED", "RESTRICTED"}),
    "RESTART": frozenset({"RUNNING", "PAUSED", "STOPPED", "DEGRADED", "RESTRICTED", "HUMAN_REQUIRED", "SHUTDOWN"}),
    "SHUTDOWN": frozenset({"RUNNING", "PAUSED", "DEGRADED", "RESTRICTED", "HUMAN_REQUIRED"}),
    "STATUS": frozenset({"STOPPED", "RUNNING", "PAUSED", "SHUTDOWN", "DEGRADED", "RESTRICTED", "HUMAN_REQUIRED"}),
}

CONTROL_VERBS = frozenset({
    "start", "stop", "pause", "resume", "restart", "shutdown", "status",
    "lifecycle", "tasks", "task", "approvals", "approve", "reject",
    "providers", "capabilities", "security", "resources", "audit", "events",
    "recovery", "workspace", "help", "exit", "quit",
})

ARBITRARY_EXECUTION_HINTS = (
    "shell", "run-python", "run_command", "run-command", "execute-tool",
    "execute_tool", "execute-tool-anything", "os.system", "subprocess",
    "exec(", "eval(", "run python", "run code", "execute command", "execute_custom_command",
)

MAX_APPROVAL_ID_CHARS = 100
MAX_REASON_CHARS = 1000
MAX_RECENT_TASK_SAMPLE = 100
MAX_RESPONSE_BYTES = 120000
WEB_HOST = "127.0.0.1"
WEB_PORT = 8770
WEB_STATIC_DIR = Path(__file__).resolve().parent / "web" / "static"


def _now_iso() -> str:
    return NOW(timezone.utc).isoformat(timespec="seconds")


def _bounded_text(value: Any, limit: int) -> str:
    return redact_text(value)[:limit]


def _valid_identifier(value: str, limit: int = MAX_APPROVAL_ID_CHARS) -> bool:
    text = str(value or "")
    return bool(text) and len(text) <= limit and all(char.isalnum() or char in "-_" for char in text)


def _looks_like_arbitrary_execution(text: str) -> bool:
    lowered = (text or "").lower().strip().lstrip("!:-")
    if not lowered:
        return False
    for hint in ARBITRARY_EXECUTION_HINTS:
        if hint in lowered:
            return True
    if lowered.startswith(("run ", "exec ", "execute ")) and ("--" not in lowered):
        return True
    return False


def _provider_operational_status(provider: ProviderDescriptor) -> str:
    """Map one provider descriptor onto the authorization ladder (fail closed)."""
    kind = provider.kind
    if kind == ProviderKind.UNAVAILABLE_PROVIDER:
        return "UNAVAILABLE"
    if kind == ProviderKind.REAL_PROVIDER:
        if not provider.configured:
            return "NOT_CONFIGURED"
        if not provider.authenticated:
            return "CONFIGURED"
        return "AUTHENTICATED"
    if kind in {ProviderKind.FIXTURE_PROVIDER, ProviderKind.MOCK_PROVIDER}:
        return "CAPABILITY_AUTHORIZED"
    return "OPERATION_UNAVAILABLE"


def _operation_status(provider: ProviderDescriptor, operation: OperationSchema) -> str:
    base = _provider_operational_status(provider)
    if base not in {"CAPABILITY_AUTHORIZED", "AUTHENTICATED", "CONFIGURED", "OPERATION_PERMITTED"}:
        return "OPERATION_UNAVAILABLE"
    if operation.read_only:
        return "OPERATION_PERMITTED"
    if operation.requires_approval:
        return "OPERATION_REQUIRES_APPROVAL"
    return "OPERATION_PERMITTED"


def _is_fixture_or_mock(provider: ProviderDescriptor) -> bool:
    return provider.kind in {ProviderKind.FIXTURE_PROVIDER, ProviderKind.MOCK_PROVIDER}


class ControlPlane:
    """Bounded operational surface over the existing NEXUS runtime.

    ``db_path`` remains the single unified SQLite store passed to the existing
    AutonomousService (lifecycle, ledger, journal, approvals, audit). No second
    database is created.
    """

    def __init__(
        self,
        workspace_root: str | Path = "workspace",
        *,
        db_path: str | Path | None = None,
        security_monitor: SecurityMonitor | None = None,
        resource_provider: Callable[[], dict[str, float]] | None = None,
        service: AutonomousService | None = None,
        task_runner: TaskRunner | None = None,
    ) -> None:
        root = Path(workspace_root)
        self.workspace_root = root.resolve()
        self.db_path = Path(db_path) if db_path is not None else self.workspace_root.parent / "data" / "nexus_service.db"
        if service is not None:
            self.service = service
        else:
            runner = task_runner or TaskRunner(workspace_root=str(self.workspace_root), db_path=self.db_path)
            self.service = AutonomousService(
                self.workspace_root,
                db_path=self.db_path,
                task_runner=runner,
                security_monitor=security_monitor or SecurityMonitor(),
                resource_provider=resource_provider,
            )
        ensure_adapters_registered()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _audit(self, event_type: str, *, target: str = "", result: str = "", reason: str = "", metadata: dict[str, Any] | None = None) -> None:
        record_audit_event(
            event_type,
            actor="control_plane",
            tool="control_plane",
            target=_bounded_text(target, 1000),
            result=_bounded_text(result, 120),
            reason=_bounded_text(reason, 4000),
            metadata=metadata or {},
            db_path=self.db_path,
        )

    def _task_state(self) -> tuple[dict[str, int], list[dict[str, Any]]]:
        counts: dict[str, int] = {status: 0 for status in TASK_STATUS_ORDER}
        recent = list_recent_tasks(limit=MAX_RECENT_TASK_SAMPLE, db_path=self.db_path)
        for task in recent:
            status = str(task.get("status") or "CREATED").upper()
            counts[status] = counts.get(status, 0) + 1
        counts["recent_sample_limit"] = MAX_RECENT_TASK_SAMPLE
        return counts, recent

    def _active_task(self, recent: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
        if recent is None:
            _, recent = self._task_state()
        for task in recent:
            status = str(task.get("status") or "").upper()
            if status in OPEN_TASK_STATUSES:
                return task
        return None

    # ------------------------------------------------------------------
    # Status / observation (all read-only)
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        counts, recent = self._task_state()
        active = self._active_task(recent)
        active_checkpoint = None
        if active is not None:
            checkpoint = load_checkpoint(active["task_id"], db_path=self.db_path)
            if checkpoint is not None:
                active_checkpoint = {
                    "checkpoint_id": checkpoint.get("checkpoint_id", ""),
                    "current_stage": checkpoint.get("current_stage", ""),
                    "action_type": checkpoint.get("action_type", ""),
                    "action_target": checkpoint.get("action_target", ""),
                    "approval_status": checkpoint.get("approval_status", ""),
                    "resume_required": bool(checkpoint.get("resume_required")),
                    "updated_at": checkpoint.get("updated_at", ""),
                }
        service_health = self.service.health()
        pending = self._bounded_pending_approvals()
        verification_statuses = [str(t.get("verification_status") or "PENDING") for t in recent]
        return redact_sensitive_data({
            "lifecycle": self.service.status(),
            "service_health": {
                "health": service_health.get("health", ""),
                "reason": service_health.get("reason", ""),
                "queued_events": int(service_health.get("queued_events") or 0),
                "supervision_events": service_health.get("supervision_events", [])[-5:],
                "last_success_at": service_health.get("last_success_at", ""),
                "pending_approvals": int(service_health.get("pending_approvals") or 0),
            },
            "resource": self.resource_health(),
            "task_counts": counts,
            "verification_statuses": Counter(item for item in verification_statuses if item),
            "active_task": active,
            "active_checkpoint": active_checkpoint,
            "approvals": {
                "pending_count": int(pending["count"]),
                "pending_preview": pending["items"][:3],
            },
            "recovery": self.recovery(),
            "security": self.security_health(),
            "providers": self.provider_health(include_operations=False),
            "workspace": self.workspace_status(),
            "autonomous": {
                "loop_count": self.service.status().get("loop_count", 0),
                "last_error": self.service.status().get("last_error", ""),
                "owner_id": self.service.status().get("owner_id", ""),
                "started_at": self.service.status().get("started_at", ""),
                "last_success_at": self.service.status().get("last_success_at", ""),
                "active_task_id": self.service.status().get("active_task_id", ""),
            },
            "observed_at": _now_iso(),
        })

    def workspace_status(self) -> dict[str, Any]:
        monitor = getattr(self.service, "monitor", None)
        monitor_running = bool(getattr(monitor, "running", False)) if monitor is not None else False
        queued = 0
        try:
            queued = int(self.service._queued_event_count())
        except (AttributeError, TypeError, ValueError):
            queued = 0
        return redact_sensitive_data({
            "workspace_root": str(self.service.workspace_root),
            "monitor_initialized": monitor is not None,
            "monitor_running": monitor_running,
            "queued_workspace_events": queued,
            "recent_workspace_events": self.service.events(limit=10),
        })

    def recovery(self) -> dict[str, Any]:
        _, recent = self._task_state()
        signals = [
            {
                "task_id": task.get("task_id", ""),
                "status": str(task.get("status") or "").upper(),
                "status_reason": task.get("status_reason", ""),
                "resume_reason": task.get("resume_reason", ""),
            }
            for task in recent
            if str(task.get("status") or "").upper() in {"PAUSED", "BLOCKED", "FAILED"}
        ]
        return redact_sensitive_data({
            "recovery_failures": int(self.service.status().get("recovery_failures", 0) or 0),
            "max_recovery_failures": int(self.service.max_recovery_failures),
            "last_error": self.service.status().get("last_error", ""),
            "paused_tasks": signals and sum(1 for item in signals if item["status"] == "PAUSED") or 0,
            "blocked_tasks": signals and sum(1 for item in signals if item["status"] == "BLOCKED") or 0,
            "failed_tasks": signals and sum(1 for item in signals if item["status"] == "FAILED") or 0,
            "recent_signals": signals[-5:],
        })

    def security_health(self) -> dict[str, Any]:
        counts, recent = self._task_state()
        snapshot = self.service.security_monitor.build_health_snapshot(
            active_tasks=int(counts.get("RUNNING", 0) or 0) + int(counts.get("WAITING_APPROVAL", 0) or 0) + int(counts.get("VERIFYING", 0) or 0),
            waiting_approvals=int(counts.get("WAITING_APPROVAL", 0) or 0),
            paused_tasks=int(counts.get("PAUSED", 0) or 0),
            blocked_tasks=int(counts.get("BLOCKED", 0) or 0),
            recent_failures=int(counts.get("FAILED", 0) or 0),
            retry_stats={"recent_tasks": int(sum(int(t.get("task_retry_count") or 0) for t in recent))},
            recent_security_events=self.service.security_monitor.recent_events(20),
            scanner_status="SCANNER_UNAVAILABLE",
            audit_status="HEALTHY",
            task_ledger_status="HEALTHY",
            execution_journal_status="HEALTHY",
            recovery_status="RESTRICTED" if int(self.service.status().get("recovery_failures", 0) or 0) >= int(self.service.max_recovery_failures) else "HEALTHY",
            workflow_status="HEALTHY",
        )
        return redact_sensitive_data(snapshot)

    def resource_health(self) -> dict[str, Any]:
        resource = dict(self.service.health().get("resource") or {})
        cpu = max(0.0, float(resource.get("cpu_percent", 0.0) or 0.0))
        memory = max(0.0, float(resource.get("memory_bytes", 0.0) or 0.0))
        restricted = cpu >= self.service.cpu_threshold_percent or memory >= self.service.memory_threshold_bytes
        return redact_sensitive_data({
            "status": "RESTRICTED" if restricted else "NORMAL",
            "cpu_percent": cpu,
            "memory_bytes": memory,
            "cpu_threshold_percent": self.service.cpu_threshold_percent,
            "memory_threshold_bytes": self.service.memory_threshold_bytes,
            "message": (
                "RESTRICTED: Resource usage is above the bounded threshold; work is restricted."
                if restricted
                else "NORMAL: Resource usage is within the bounded threshold."
            ),
        })

    def provider_health(self, *, include_operations: bool = True) -> list[dict[str, Any]]:
        providers: list[dict[str, Any]] = []
        for provider in build_adapters_catalog():
            capabilities: list[dict[str, Any]] = []
            for capability in provider.capabilities:
                operations: list[dict[str, Any]] = []
                for operation in capability.operations:
                    operations.append({
                        "name": operation.name,
                        "read_only": bool(operation.read_only),
                        "requires_approval": bool(operation.requires_approval),
                        "risk_level": operation.risk_level,
                        "status": _operation_status(provider, operation),
                    })
                capabilities.append({
                    "capability_id": capability.capability_id,
                    "application_id": capability.application_id,
                    "status": "OPERATION_UNAVAILABLE"
                    if _provider_operational_status(provider) == "OPERATION_UNAVAILABLE"
                    else _provider_operational_status(provider),
                    "operations": operations if include_operations else [],
                })
            status = _provider_operational_status(provider)
            providers.append(redact_sensitive_data({
                "provider_id": provider.provider_id,
                "application_id": provider.application_id,
                "display_name": provider.display_name,
                "kind": provider.kind.value if isinstance(provider.kind, ProviderKind) else str(provider.kind),
                "fixture_or_mock": _is_fixture_or_mock(provider),
                "real": provider.kind == ProviderKind.REAL_PROVIDER,
                "configured": bool(provider.configured),
                "authenticated": bool(provider.authenticated),
                "credentials_store": False,
                "status": status,
                "capabilities": capabilities,
            }))
        return providers

    # ------------------------------------------------------------------
    # Lifecycle control (validate legal transitions, then delegate)
    # ------------------------------------------------------------------

    def lifecycle(self, command: str) -> dict[str, Any]:
        normalized = str(command or "").upper().strip()
        if normalized not in LIFECYCLE_COMMANDS:
            return {
                "accepted": False,
                "command": normalized,
                "reason": "Unknown lifecycle command. Allowed: START, STOP, PAUSE, RESUME, RESTART, SHUTDOWN, STATUS.",
            }
        current = str(self.service.status().get("state") or "STOPPED").upper()
        if normalized not in LEGAL_LIFECYCLE_TRANSITIONS:
            return {
                "accepted": False,
                "command": normalized,
                "current_state": current,
                "reason": f"Command {normalized} is not a supported lifecycle transition.",
            }
        if current not in LEGAL_LIFECYCLE_TRANSITIONS[normalized]:
            return {
                "accepted": False,
                "command": normalized,
                "current_state": current,
                "reason": f"Lifecycle transition {current} -> {normalized} is not legal.",
            }
        try:
            if normalized == "START":
                result = self.service.start()
            elif normalized == "STOP":
                result = self.service.stop()
            elif normalized == "PAUSE":
                result = self.service.pause()
            elif normalized == "RESUME":
                result = self.service.resume()
            elif normalized == "RESTART":
                result = self.service.restart()
            elif normalized == "SHUTDOWN":
                result = self.service.shutdown()
            else:
                result = self.service.status()
        except Exception as exc:  # fail closed with a structured explanation
            self._audit("control_plane_lifecycle_failed", target=normalized, result="FAILED", reason=str(exc))
            return {
                "accepted": False,
                "command": normalized,
                "current_state": current,
                "reason": f"Lifecycle transition failed safely: {redact_text(exc)}",
            }
        self._audit("control_plane_lifecycle", target=normalized, result=str(result.get("state", "")), reason=f"Lifecycle command {normalized} applied through AutonomousService.")
        return {
            "accepted": True,
            "command": normalized,
            "current_state": result.get("state", current),
            "result": result,
        }

    # ------------------------------------------------------------------
    # Task control (list / inspect only; never arbitrary execution)
    # ------------------------------------------------------------------

    def list_tasks(self, status: str | None = None) -> dict[str, Any]:
        counts, recent = self._task_state()
        normalized_filter = str(status or "").upper().strip()
        items = []
        for task in recent:
            task_status = str(task.get("status") or "CREATED").upper()
            if normalized_filter and task_status != normalized_filter:
                continue
            items.append({
                "task_id": task.get("task_id", ""),
                "objective": task.get("objective", ""),
                "status": task_status,
                "current_stage": task.get("current_stage", ""),
                "current_sub_goal": task.get("current_sub_goal", ""),
                "final_outcome": task.get("final_outcome", ""),
                "priority": task.get("priority", "NORMAL"),
                "created_at": task.get("created_at", ""),
                "updated_at": task.get("updated_at", ""),
            })
        return redact_sensitive_data({
            "accepted": True,
            "filter": normalized_filter or "ALL",
            "counts": counts,
            "items": items,
        })

    def inspect_task(self, task_id: str) -> dict[str, Any]:
        if not _valid_identifier(task_id, limit=200):
            return {"accepted": False, "reason": "Invalid task identifier."}
        task = get_task(task_id, db_path=self.db_path)
        if task is None:
            return {"accepted": False, "reason": f"Task {task_id} was not found."}
        checkpoint = load_checkpoint(task_id, db_path=self.db_path)
        events = task.get("event_history") or []
        return redact_sensitive_data({
            "accepted": True,
            "task": {
                "task_id": task.get("task_id", ""),
                "objective": task.get("objective", ""),
                "status": task.get("status", ""),
                "current_stage": task.get("current_stage", ""),
                "current_sub_goal": task.get("current_sub_goal", ""),
                "current_subgoal_id": task.get("current_subgoal_id", ""),
                "goal_plan": task.get("goal_plan", []),
                "subgoal_statuses": task.get("subgoal_statuses", {}),
                "plan_version": task.get("plan_version", ""),
                "plan_revisions": task.get("plan_revisions", 0),
                "task_retry_count": task.get("task_retry_count", 0),
                "final_outcome": task.get("final_outcome", ""),
                "status_reason": task.get("status_reason", ""),
                "task_answer": task.get("task_answer", ""),
                "resume_reason": task.get("resume_reason", ""),
                "priority": task.get("priority", "NORMAL"),
                "deadline": task.get("deadline", ""),
                "commitment": task.get("commitment", ""),
                "verification_history": task.get("verification_history", [])[-10:],
                "evidence_refs": task.get("evidence_refs", []),
                "completion_evidence": task.get("completion_evidence", [])[-10:],
                "adaptation_history": task.get("adaptation_history", [])[-10:],
                "created_at": task.get("created_at", ""),
                "updated_at": task.get("updated_at", ""),
                "status_output": task.get("status_output", ""),
            },
            "checkpoint": {
                "checkpoint_id": checkpoint.get("checkpoint_id", ""),
                "current_stage": checkpoint.get("current_stage", ""),
                "action_type": checkpoint.get("action_type", ""),
                "action_target": checkpoint.get("action_target", ""),
                "approval_status": checkpoint.get("approval_status", ""),
                "resume_required": bool(checkpoint.get("resume_required")),
                "approval_binding": checkpoint.get("approval_binding", {}),
                "updated_at": checkpoint.get("updated_at", ""),
            }
            if checkpoint is not None else None,
            "events": events[-20:],
        })

    # ------------------------------------------------------------------
    # Approval control (bounded decisions via ApprovalAuthority only)
    # ------------------------------------------------------------------

    def list_approvals(self, *, limit: int = 20) -> dict[str, Any]:
        pending = list_pending_approvals(db_path=self.db_path)
        bounded: list[dict[str, Any]] = []
        for item in pending:
            bounded.append({
                "approval_id": item.get("approval_id", ""),
                "task_id": item.get("task_id", ""),
                "checkpoint_id": item.get("checkpoint_id", ""),
                "action_type": item.get("action_type", ""),
                "tool_name": item.get("tool_name", ""),
                "target": item.get("target", ""),
                "risk_level": item.get("risk_level", ""),
                "status": item.get("status", ""),
                "reason": item.get("reason", ""),
                "created_at": item.get("created_at", ""),
                "expires_at": item.get("expires_at", ""),
            })
        return redact_sensitive_data({
            "accepted": True,
            "count": len(bounded),
            "items": bounded[: max(1, min(int(limit), 100))],
        })

    def _bounded_pending_approvals(self, *, limit: int = 50) -> dict[str, Any]:
        view = self.list_approvals(limit=limit)
        return {"count": int(view.get("count") or 0), "items": view.get("items", [])}

    def decide(
        self,
        approval_id: str,
        decision: str,
        *,
        reason: str = "",
        expected_task_id: str = "",
        expected_target: str = "",
    ) -> dict[str, Any]:
        normalized = str(decision or "").upper().strip()
        if normalized not in {"APPROVED", "REJECTED"}:
            return {"accepted": False, "reason": "Approval decision must be APPROVED or REJECTED."}
        if not _valid_identifier(approval_id):
            return {"accepted": False, "reason": "Invalid approval identifier."}
        approval = get_approval(approval_id, db_path=self.db_path)
        if approval is None:
            return {"accepted": False, "reason": "Approval does not exist."}
        if str(approval.get("status") or "").upper() != "PENDING":
            return {
                "accepted": False,
                "reason": f"Approval status is {approval.get('status')}; only pending approvals can be decided (replay and stale decisions are rejected).",
            }
        try:
            expiry = datetime.fromisoformat(str(approval.get("expires_at", "")).replace("Z", "+00:00"))
            if expiry <= NOW(timezone.utc):
                return {"accepted": False, "reason": "Approval expired and cannot be decided."}
        except (ValueError, TypeError):
            return {"accepted": False, "reason": "Approval expiry is malformed; the decision is rejected."}
        if expected_task_id and str(expected_task_id) != str(approval.get("task_id", "")):
            return {"accepted": False, "reason": "Approval binding mismatch for task_id; the decision is rejected."}
        if expected_target and str(expected_target) != str(approval.get("target", "")):
            return {"accepted": False, "reason": "Approval binding mismatch for target; the decision is rejected."}
        try:
            result = authority_decide_approval(
                approval_id,
                normalized,
                actor="control_plane",
                reason=_bounded_text(reason, MAX_REASON_CHARS),
                db_path=self.db_path,
            )
        except ValueError as exc:
            return {"accepted": False, "reason": redact_text(str(exc))}
        resume = self._resume_approved_browser_task(result) if normalized == "APPROVED" else {}
        if normalized == "APPROVED":
            self._sync_checkpoint_approval(result)
        return {"accepted": True, "decision": normalized, "approval": redact_sensitive_data(result), **resume}

    def _sync_checkpoint_approval(self, approval: dict[str, Any]) -> None:
        """Mirror an APPROVED decision onto its durable checkpoint.

        The checkpoint keeps a snapshot of the approval binding for recovery
        validation; without this sync it stays PENDING forever and durable
        resume can never proceed. Fail-safe and narrow: only the checkpoint
        named by the decided approval is touched, only when every binding
        (task, action, target, proposal, unexpired expiry) still matches, and
        only from a non-terminal checkpoint state. Any failure (or mismatch)
        leaves the checkpoint untouched so recovery keeps failing closed.
        """

        try:
            if str((approval or {}).get("status") or "").upper() != "APPROVED":
                return
            checkpoint_id = str(approval.get("checkpoint_id") or "")
            task_id = str(approval.get("task_id") or "")
            if not checkpoint_id or not task_id:
                return
            checkpoint = load_checkpoint(task_id, checkpoint_id=checkpoint_id, db_path=self.db_path)
            if checkpoint is None or checkpoint.get("is_valid") != 1:
                return
            if str(checkpoint.get("approval_status") or "") not in {"PENDING", "UNKNOWN", ""}:
                return
            if (
                str(checkpoint.get("action_type") or "") != str(approval.get("action_type") or "")
                or str(checkpoint.get("action_target") or "") != str(approval.get("target") or "")
                or str(checkpoint.get("proposal_hash") or "") != str(approval.get("proposal_hash") or "")
            ):
                return
            try:
                expiry = datetime.fromisoformat(str(approval.get("expires_at", "")).replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry <= NOW(timezone.utc):
                    return
            except (ValueError, TypeError):
                return
            update_checkpoint(
                checkpoint_id,
                approval_binding=redact_sensitive_data(dict(approval)),
                approval_status="APPROVED",
                approval_expiry=str(approval.get("expires_at") or ""),
                db_path=self.db_path,
            )
            self._audit("control_plane_checkpoint_approval_synced", target=task_id, result="SYNCED", reason="Durable checkpoint now reflects the approved approval binding.")
        except Exception:
            return

    def _resume_approved_browser_task(self, approval: dict[str, Any]) -> dict[str, Any]:
        """Resume a non-terminal task only when a browser tool approval was approved.

        Restricted to browser approvals so fixer/desktop/email/calendar/comms/job
        approval decisions keep their existing decide-only behavior. Never rolls back
        a decision; any resume failure is reported in the payload only.
        """
        tool_name = str((approval or {}).get("tool_name") or "")
        task_id = str((approval or {}).get("task_id") or "")
        if not tool_name.lower().startswith("browser_") or not task_id:
            return {}
        task = get_task(task_id, db_path=self.db_path)
        if task is None:
            return {}
        if str(task.get("status") or "").upper() in TERMINAL_TASKS:
            return {}
        objective = str(task.get("objective") or "").strip()
        if not objective:
            return {}
        try:
            resumed = self.service.task_runner.start_task(objective, task_id=task_id)
        except Exception as exc:
            self._audit("control_plane_approval_resume_failed", target=task_id, result="FAILED", reason=redact_text(str(exc)))
            return {"resumed": False, "resume_error": redact_text(str(exc))}
        if not isinstance(resumed, dict):
            resumed = {"task_id": task_id, "status": "RUNNING"}
        return {"resumed": bool(resumed.get("status")) and str(resumed.get("status") or "").upper() != "PAUSED", "task": {
            "task_id": resumed.get("task_id", task_id),
            "status": resumed.get("status", ""),
            "final_outcome": resumed.get("final_outcome", ""),
            "task_answer": resumed.get("task_answer", ""),
            "current_stage": resumed.get("current_stage", ""),
        }}

    # ------------------------------------------------------------------
    # Audit / events (read-only)
    # ------------------------------------------------------------------

    def audit(self, *, limit: int = 50) -> dict[str, Any]:
        events = get_recent_audit_events(limit=limit, db_path=self.db_path)
        return redact_sensitive_data({"accepted": True, "count": len(events), "events": events})

    def events(self, *, limit: int = 20) -> dict[str, Any]:
        entries = self.service.events(limit=limit)
        return redact_sensitive_data({"accepted": True, "count": len(entries), "events": entries})

    # ------------------------------------------------------------------
    # Request path (StateGraph only; no tool-side backdoor)
    # ------------------------------------------------------------------

    def submit(self, user_request: str, *, task_id: str = "", graph_runner: Any | None = None) -> dict[str, Any]:
        text = redact_text(user_request)
        if not text.strip():
            return {"accepted": False, "reason": "A request is required."}
        state = str(self.service.status().get("state") or "STOPPED").upper()
        if state != "RUNNING":
            return {
                "accepted": False,
                "reason": f"Requests are only accepted while the service is RUNNING (current state: {state}).",
            }
        if _looks_like_arbitrary_execution(text):
            self._audit("control_plane_arbitrary_execution_rejected", target=text, result="REJECTED", reason="Arbitrary command execution is not a control-plane operation.")
            return {"accepted": False, "reason": "Arbitrary command execution is not a control-plane operation; requests route through the existing StateGraph."}
        if task_id and not _valid_identifier(task_id, limit=200):
            return {"accepted": False, "reason": "Invalid task identifier."}
        self._audit("control_plane_request", target=text[:200], result="SUBMITTED", reason="Request routed through TaskRunner to the existing StateGraph.")
        try:
            result = self.service.task_runner.start_task(
                text,
                task_id=task_id or None,
                current_state=None,
                graph_runner=graph_runner,
            )
        except ValueError as exc:
            return {"accepted": False, "reason": redact_text(str(exc))}
        return {"accepted": True, **result}

    # ------------------------------------------------------------------
    # Dispatch + CLI
    # ------------------------------------------------------------------

    def dispatch(self, verb: str, *args: str) -> dict[str, Any]:
        normalized = str(verb or "").lower().strip()
        if normalized in {"exit", "quit", "help"}:
            return {"accepted": True, "command": normalized, "help": "status | start|stop|pause|resume|restart|shutdown | tasks [status] | task <id> | approvals | approve|reject <id> | providers | security | resources | recovery | workspace | audit | events | or type any NEXUS request."}
        if normalized not in CONTROL_VERBS:
            return {"accepted": False, "reason": f"Unknown control-plane operation: {verb}"}
        if normalized == "status":
            return {"accepted": True, "status": self.status()}
        if normalized == "lifecycle":
            if not args:
                return {"accepted": False, "reason": "lifecycle requires a command: START, STOP, PAUSE, RESUME, RESTART, SHUTDOWN, STATUS."}
            return self.lifecycle(args[0])
        if normalized in {"start", "stop", "pause", "resume", "restart", "shutdown"}:
            return self.lifecycle(normalized)
        if normalized == "tasks":
            return self.list_tasks(args[0] if args else None)
        if normalized == "task":
            if not args:
                return {"accepted": False, "reason": "task requires a task identifier."}
            return self.inspect_task(args[0])
        if normalized == "approvals":
            return self.list_approvals()
        if normalized in {"approve", "reject"}:
            if not args:
                return {"accepted": False, "reason": f"{normalized} requires an approval identifier."}
            return self.decide(args[0], "APPROVED" if normalized == "approve" else "REJECTED", reason=" ".join(args[1:]))
        if normalized in {"providers", "capabilities"}:
            return {"accepted": True, "providers": self.provider_health()}
        if normalized == "security":
            return {"accepted": True, "security": self.security_health()}
        if normalized == "resources":
            return {"accepted": True, "resources": self.resource_health()}
        if normalized == "recovery":
            return {"accepted": True, "recovery": self.recovery()}
        if normalized == "workspace":
            return {"accepted": True, "workspace": self.workspace_status()}
        if normalized == "audit":
            return self.audit()
        if normalized == "events":
            return self.events()
        return {"accepted": False, "reason": f"Unknown control-plane operation: {verb}"}

    def handle(self, line: str) -> dict[str, Any]:
        """Route one terminal line: control verb -> dispatch; else -> StateGraph request."""
        text = (line or "").strip()
        if not text:
            return {"accepted": False, "reason": "No input."}
        tokens = text.split()
        if str(tokens[0]).lower().startswith("!"):
            self._audit("control_plane_arbitrary_execution_rejected", target=text, result="REJECTED", reason="Direct shell-style invocation is rejected.")
            return {"accepted": False, "reason": "Direct shell-style invocation is not supported by the control plane."}
        if tokens[0].lower() in CONTROL_VERBS:
            return self.dispatch(tokens[0], *tokens[1:])
        return self.submit(text)


def _render(output: dict[str, Any]) -> str:
    import json
    return json.dumps(output, ensure_ascii=True, indent=2, default=str)


_server_thread_started = False


def run_cli(argv: list[str] | None = None) -> int:
    global _server_thread_started
    args = list(sys.argv[1:] if argv is None else argv)
    db_path = os.environ.get("NEXUS_DB_PATH")
    plane = ControlPlane(db_path=db_path) if db_path else ControlPlane()
    if args:
        line = " ".join(args).strip()
        print(_render(plane.handle(line)))
        return 0
    started = plane.lifecycle("START")
    if not started.get("accepted"):
        state = str(started.get("current_state") or "STOPPED")
        print(f"[NEXUS Control Plane] Could not start the service (current state: {state}); requests will be refused until it is running.")
    else:
        state = str(started.get("result", {}).get("state") or "RUNNING")
        print(f"[NEXUS Control Plane] Service is now {state}. Type a control command or any request. Type 'exit' to quit.")
    if not _server_thread_started:
        server_thread = threading.Thread(
            target=run_server,
            args=("127.0.0.1", 8770, plane),
            daemon=True,
        )
        server_thread.start()
        _server_thread_started = True
    while True:
        try:
            line = input("NEXUS> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line.lower() in {"exit", "quit"}:
            break
        print(_render(plane.handle(line)))
    return 0


# ------------------------------------------------------------------
# Localhost-only read surface (no execution endpoints)
# ------------------------------------------------------------------

def _json_payload(payload: Any) -> tuple[Any, int]:
    safe = redact_sensitive_data(payload)
    import json
    try:
        serialized = json.dumps(safe, ensure_ascii=True, default=str)
    except (TypeError, ValueError):
        serialized = ""
    if len(serialized) > MAX_RESPONSE_BYTES:
        return {"status": "TRUNCATED", "message": "Control-plane response exceeded the bounded response size."}, 200
    return safe, 200


def create_control_app(control: ControlPlane | None = None, *, web_ui: bool = True) -> Any:
    """Build the bounded localhost-only read/decision surface (no execution tool).

    ``web_ui`` additionally exposes the local NEXUS web control surface
    (static interface plus the narrowly scoped UI endpoints). No endpoint can
    execute shell commands, Python code, or arbitrary tools; task submission
    only accepts a natural-language request that is routed through the existing
    TaskRunner -> StateGraph path.
    """
    from flask import Flask, jsonify, request, send_from_directory

    plane = control or ControlPlane()
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=4096, DEBUG=False, TESTING=False)

    def respond(payload: Any, status: int = 200) -> Any:
        safe, bounded = _json_payload(payload)
        return jsonify(safe), status

    if web_ui:
        @app.get("/")
        def api_index():
            return send_from_directory(WEB_STATIC_DIR, "index.html")

        @app.get("/static/<path:filename>")
        def api_static(filename):
            return send_from_directory(WEB_STATIC_DIR, filename)

    @app.get("/api/status")
    def api_status():
        return respond({"status": plane.status()})

    @app.get("/api/providers")
    def api_providers():
        return respond({"providers": plane.provider_health()})

    @app.get("/api/approvals")
    def api_approvals():
        return respond(plane.list_approvals())

    @app.post("/api/approvals/<approval_id>/approve")
    def api_approve(approval_id: str):
        if not _valid_identifier(approval_id):
            return respond({"accepted": False, "reason": "Invalid approval identifier."}, 400)
        body = request.get_json(silent=True) or {}
        if any(key not in {"reason"} for key in body):
            return respond({"accepted": False, "reason": "Approval decisions only accept an optional reason; no action data."}, 400)
        return respond(plane.decide(approval_id, "APPROVED", reason=str(body.get("reason", "") or "")))

    @app.post("/api/approvals/<approval_id>/reject")
    def api_reject(approval_id: str):
        if not _valid_identifier(approval_id):
            return respond({"accepted": False, "reason": "Invalid approval identifier."}, 400)
        body = request.get_json(silent=True) or {}
        if any(key not in {"reason"} for key in body):
            return respond({"accepted": False, "reason": "Approval decisions only accept an optional reason; no action data."}, 400)
        return respond(plane.decide(approval_id, "REJECTED", reason=str(body.get("reason", "") or "")))

    @app.get("/api/security")
    def api_security():
        return respond({"security": plane.security_health()})

    @app.get("/api/resources")
    def api_resources():
        return respond({"resources": plane.resource_health()})

    @app.get("/api/audit")
    def api_audit():
        return respond(plane.audit())

    @app.get("/api/tasks")
    def api_tasks():
        return respond(plane.list_tasks(request.args.get("status", "") or None))

    @app.get("/api/tasks/<task_id>")
    def api_task(task_id: str):
        return respond(plane.inspect_task(task_id))

    if web_ui:
        @app.get("/api/health")
        def api_health():
            try:
                health = plane.service.health()
                state = str(plane.service.status().get("state") or "STOPPED").upper()
            except Exception as exc:
                plane._audit("web_health_failed", result="FAILED", reason=str(exc))
                health = {}
                state = "UNAVAILABLE"
            return respond({
                "health": health.get("health", "UNAVAILABLE"),
                "reason": health.get("reason", ""),
                "state": state,
                "queued_events": int(health.get("queued_events") or 0),
                "pending_approvals": int(health.get("pending_approvals") or 0),
                "active_tasks": int(health.get("active_tasks") or 0),
                "last_success_at": health.get("last_success_at", ""),
                "local_only": True,
                "host": WEB_HOST,
            })

        @app.post("/api/tasks")
        def api_submit_task():
            body = request.get_json(silent=True)
            if not isinstance(body, dict):
                return respond({"accepted": False, "reason": "A JSON payload with a natural-language 'request' is required."}, 400)
            unknown = sorted(set(body) - {"request"})
            if unknown:
                return respond({"accepted": False, "reason": "Only a natural-language 'request' field is accepted."}, 400)
            request_text = str(body.get("request") or "").strip()
            if not request_text:
                return respond({"accepted": False, "reason": "A request is required."}, 400)
            if len(request_text) > 2000:
                return respond({"accepted": False, "reason": "Request is too long."}, 400)
            try:
                result = plane.submit(request_text)
            except Exception as exc:
                plane._audit("web_task_submit_failed", target=_bounded_text(request_text, 200), result="FAILED", reason=str(exc))
                return respond({"accepted": False, "reason": "Task submission failed safely."}, 500)
            return respond(result)

        @app.get("/api/activity")
        def api_activity():
            audit = plane.audit(limit=50).get("events", [])
            events = plane.events(limit=10).get("events", [])
            return respond({"accepted": True, "audit": audit, "events": events, "count": len(audit) + len(events)})

        @app.get("/api/workspace")
        def api_workspace():
            return respond({"accepted": True, "workspace": plane.workspace_status()})

        @app.get("/api/git")
        def api_git():
            try:
                git = redact_sensitive_data(inspect_git_repository(str(plane.workspace_root), timeout_seconds=5))
            except Exception as exc:
                plane._audit("web_git_unavailable", result="FAILED", reason=str(exc))
                git = {"status": "UNAVAILABLE", "reason": "Git inspection is not available."}
            return respond({"accepted": True, "git": git})

        @app.get("/api/sections/<application_id>")
        def api_section(application_id: str):
            if not _valid_identifier(application_id, limit=60):
                return respond({"accepted": False, "reason": "Invalid application identifier."}, 400)
            providers = [
                provider for provider in plane.provider_health()
                if str(provider.get("application_id") or "").lower() == application_id.lower()
            ]
            return respond({"accepted": True, "application_id": application_id, "providers": providers})

        @app.post("/api/service/<command>")
        def api_service(command: str):
            normalized = str(command or "").upper()
            if normalized not in LIFECYCLE_COMMANDS or normalized == "STATUS":
                return respond({"accepted": False, "reason": "Service control supports START, STOP, PAUSE, RESUME, RESTART, SHUTDOWN."}, 400)
            return respond(plane.lifecycle(normalized))

    @app.errorhandler(404)
    def api_not_found(_error: Any) -> Any:
        return respond({"accepted": False, "reason": "The requested surface does not exist."}, 404)

    @app.errorhandler(413)
    def api_too_large(_error: Any) -> Any:
        return respond({"accepted": False, "reason": "Request is too large."}, 413)

    @app.errorhandler(500)
    def api_internal_error(_error: Any) -> Any:
        import traceback
        traceback.print_exc()
        return respond({"accepted": False, "reason": "An internal error occurred."}, 500)

    return app


def run_server(host: str = "127.0.0.1", port: int = 8770, control: ControlPlane | None = None) -> None:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("NEXUS control plane only binds to localhost; refusing non-local host.")
    plane = control or ControlPlane()
    current = str(plane.service.status().get("state") or "STOPPED").upper()
    if current != "RUNNING":
        started = plane.lifecycle("START")
        if not started.get("accepted"):
            state = str(started.get("current_state") or current)
            raise RuntimeError(
                f"NEXUS web startup failed: could not auto-start the service (current state: {state}); "
                "requests will be refused until it is running."
            )
    app = create_control_app(plane)
    app.run(host=host, port=int(port), debug=False, use_reloader=False)


__all__ = [
    "ARBITRARY_EXECUTION_HINTS",
    "CONTROL_VERBS",
    "ControlPlane",
    "LEGAL_LIFECYCLE_TRANSITIONS",
    "LIFECYCLE_COMMANDS",
    "create_control_app",
    "run_cli",
    "run_server",
]