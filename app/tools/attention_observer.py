from __future__ import annotations

from typing import Any

from app.agent.approval_authority import list_pending_approvals
from app.attention.service import build_attention_snapshot
from app.calendar.service import provider_observatory as calendar_observatory
from app.comms.service import communication_observatory
from app.email.service import email_observatory
from app.memory.task_ledger import list_recent_tasks
from app.security.security_monitor import SecurityMonitor
from app.security.sensitive_data import redact_sensitive_data
from app.tools.git_inspector import inspect_git_repository
from app.tools.workspace_monitor import detect_workspace_events


def observe_attention(
    *,
    provider_name: str = "fixture",
    capability_context: dict[str, Any] | None = None,
    workspace_path: str = "workspace",
    task_db_path: str | Any = None,
) -> dict[str, Any]:
    """Return a bounded, deterministic, read-only cross-application attention snapshot.

    The snapshot is built only from evidence produced by the existing read-only
    observers (task ledger, calendar observatory, email observatory, comms
    observatory, approvals, security monitor, git inspector, and workspace event
    detector). It never sends, schedules, mutates, or executes anything and never
    reconciles conflicting evidence.
    """
    monitor = SecurityMonitor()
    approvals = list_pending_approvals(db_path=task_db_path)
    security_events = monitor.recent_events(limit=50)
    tasks = list_recent_tasks(limit=100, db_path=task_db_path)
    watch_events = detect_workspace_events(workspace_path)

    git_status: dict[str, Any] = {}
    try:
        git_status = inspect_git_repository(workspace_path)
    except Exception:  # pragma: no cover - defensive read-only guard
        git_status = {}

    return build_attention_snapshot(
        tasks=tasks,
        calendar_observatory=calendar_observatory(provider_name=provider_name),
        email_observatory=email_observatory(provider_name=provider_name),
        comms_observatory=communication_observatory(provider_name="comms"),
        approvals=approvals,
        security_events=security_events,
        git_status=git_status,
        workspace_events=watch_events,
        system_health=monitor.build_health_snapshot(),
        generated_at="",
    )


__all__ = ["observe_attention"]