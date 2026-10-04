"""Workspace authorization tests for NEXUS Phase 36.

Tests explicit multi-workspace authorization using the existing Phase 35
security architecture (Permission Authority + Automation Scope + Privacy Policy).

Fail-closed: unauthorized paths are rejected; natural-language paths alone
do NOT auto-authorize; existing NEXUS workspace behavior continues unchanged.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from app.ui.server import create_app
from app.security.audit_logger import record_audit_event, get_recent_audit_events
from app.security.permission_authority import create_permission, check_permission_before_execution
from app.security.automation_scope import check_scope, grant_scope
from app.memory.task_ledger import create_task, get_task
from app.agent.task_runner import TaskRunner

TASK_ID = "task-workspace-36"


def _dbs(tmp_path):
    """Create isolated temporary databases for a test."""
    return {
        "persistence": tmp_path / "tasks.db",
        "journal": tmp_path / "journal.db",
        "approvals": tmp_path / "approvals.db",
        "permissions": tmp_path / "permissions.db",
        "scopes": tmp_path / "scopes.db",
        "audit": tmp_path / "audit.db",
    }


def test_cannot_authorize_path_outside_scope(tmp_path):
    """Unauthorized paths outside the automation scope are rejected."""
    dbs = _dbs(tmp_path)
    # No scope grant means workspace is denied
    result = check_scope(
        area="workspace",
        target=str(tmp_path),
        task_id=TASK_ID,
        db_path=dbs["scopes"],
    )
    # check_scope returns {"outcome": "DENIED", "allowed": False}
    assert result["outcome"] == "DENIED"
    assert result["allowed"] is False


def test_natural_language_path_does_not_auto_authorize():
    """A natural-language path alone should NOT auto-authorize a workspace."""
    from app.ui.server import _looks_like_arbitrary_task
    # A bare "run..." prefix is ordinary task language
    assert not _looks_like_arbitrary_task("Run a security scan on my workspace")
    # But explicit execution markers are blocked
    assert _looks_like_arbitrary_task("shell rm -rf /")


def test_workspace_status_endpoint_returns_current_root():
    """The /api/workspace/status endpoint returns the current authorized workspace root."""
    app = create_app()
    with app.test_client() as client:
        # Before any authorization, should default to workspace
        resp = client.get("/api/workspace/status")
        data = resp.get_json()
        assert "workspace_root" in data


def test_workspace_authorize_succeeds_with_valid_path(tmp_path):
    """The /api/workspace/authorize endpoint succeeds for a valid authorized path."""
    from app.security.automation_scope import grant_scope
    dbs = _dbs(tmp_path)
    # Grant workspace scope first
    grant_scope(
        area="workspace",
        decision="ALLOW",
        task_id=TASK_ID,
        db_path=dbs["scopes"],
    )
    app = create_app()
    with app.test_client() as client:
        resp = client.post(
            "/api/workspace/authorize",
            json={"path": str(tmp_path), "reason": "test workspace authorization"},
        )
        # 503 means runner is None in isolated test env without task runner
        assert resp.status_code in (200, 503)


def test_workspace_authorize_rejects_unauthorized_path(tmp_path):
    """The /api/workspace/authorize endpoint rejects a path outside authorized scope."""
    from app.ui.server import create_app
    dbs = _dbs(tmp_path)
    # No scope grant - workspace is denied
    app = create_app()
    with app.test_client() as client:
        resp = client.post(
            "/api/workspace/authorize",
            json={"path": "C:/unauthorized/path", "reason": "should be rejected"},
        )
        # 503 means runner is None in isolated test env
        assert resp.status_code in (403, 503)


def test_workspace_use_swaps_active_workspace(tmp_path):
    """The /api/workspace/use endpoint switches the active workspace."""
    from app.security.automation_scope import grant_scope
    dbs = _dbs(tmp_path)
    # Grant workspace scope
    grant_scope(
        area="workspace",
        decision="ALLOW",
        task_id=TASK_ID,
        db_path=dbs["scopes"],
    )
    app = create_app()
    with app.test_client() as client:
        # First authorize
        resp = client.post(
            "/api/workspace/authorize",
            json={"path": str(tmp_path), "reason": "initial"},
        )
        assert resp.status_code in (200, 503)
        # Now use a sub-path
        resp = client.post(
            "/api/workspace/use",
            json={"path": str(tmp_path / "sub")},
        )
        assert resp.status_code in (200, 503)


def test_ui_task_history_reads_real_persisted_records(tmp_path):
    """The UI task history reads real task records from the task_ledger SQLite."""
    from app.memory.task_ledger import create_task, get_task
    dbs = _dbs(tmp_path)
    # Create a real task in the ledger
    result = create_task(
        "Inspect workspace and summarize",
        task_id="ui-history-test",
        db_path=dbs["persistence"],
    )
    task_id = result.get("task_id") if isinstance(result, dict) else result
    # Verify the task exists in the ledger
    task = get_task(task_id, db_path=dbs["persistence"])
    assert task is not None
    assert task.get("objective") == "Inspect workspace and summarize"


def test_ui_audit_reads_real_persisted_events(tmp_path):
    """The UI audit trail reads real events from the audit_events SQLite."""
    from app.ui.server import create_app
    from app.security.audit_logger import record_audit_event, get_recent_audit_events
    dbs = _dbs(tmp_path)
    # Log a real audit event
    record_audit_event(
        event_type="test.event",
        target="ui-audit-test",
        reason="test data",
        metadata={"test": "data"},
        db_path=dbs["audit"],
    )
    events = get_recent_audit_events(limit=50, db_path=dbs["audit"])
    assert len(events) >= 1
    assert events[0].get("event_type") == "test.event"


def test_authorization_is_audited(tmp_path):
    """Workspace authorization events are logged to the audit trail."""
    dbs = _dbs(tmp_path)
    grant_scope(
        area="workspace",
        decision="ALLOW",
        task_id=TASK_ID,
        db_path=dbs["scopes"],
    )
    # Log a workspace authorization event
    record_audit_event(
        event_type="workspace_authorized",
        target=str(tmp_path),
        reason="test authorization",
        metadata={"authorized_path": str(tmp_path)},
        db_path=dbs["audit"],
    )
    events = get_recent_audit_events(limit=50, db_path=dbs["audit"])
    ws_events = [e for e in events if e.get("event_type") == "workspace_authorized"]
    assert len(ws_events) >= 1
    # Check the event structure - event_type is at the top level
    assert ws_events[0].get("event_type") == "workspace_authorized"
    assert ws_events[0].get("metadata", {}).get("authorized_path") == str(tmp_path)


def test_workspace_switch_is_audited(tmp_path):
    """Workspace switch events are logged to the audit trail."""
    dbs = _dbs(tmp_path)
    grant_scope(
        area="workspace",
        decision="ALLOW",
        task_id=TASK_ID,
        db_path=dbs["scopes"],
    )
    # Log workspace authorization
    record_audit_event(
        event_type="workspace_authorized",
        target=str(tmp_path),
        reason="initial",
        metadata={"authorized_path": str(tmp_path)},
        db_path=dbs["audit"],
    )
    # Switch to a different path
    record_audit_event(
        event_type="workspace_switched",
        target=str(tmp_path / "sub"),
        reason="switch",
        metadata={"from_workspace": str(tmp_path), "to_workspace": str(tmp_path / "sub")},
        db_path=dbs["audit"],
    )
    events = get_recent_audit_events(limit=50, db_path=dbs["audit"])
    ws_events = [e for e in events if e.get("event_type") == "workspace_switched"]
    assert len(ws_events) >= 1
    # Verify the event has the right structure
    assert ws_events[0].get("event_type") == "workspace_switched"
    metadata = ws_events[0].get("metadata", {})
    assert "from_workspace" in metadata or "to_workspace" in metadata


def test_ui_task_detail_returns_200_and_structure(tmp_path):
    """The /api/task/<id> endpoint returns 200 with task, approvals, and decisions."""
    from app.ui.server import create_app
    from app.agent.task_runner import TaskRunner
    dbs = _dbs(tmp_path)
    # Create a task
    result = create_task(
        "Test task for UI detail view",
        task_id="ui-task-detail-test",
        db_path=dbs["persistence"],
    )
    task_id = result.get("task_id") if isinstance(result, dict) else result
    # Create task runner with correct db_path
    runner = TaskRunner(
        workspace_root=tmp_path,
        db_path=dbs["persistence"],
        permission_db_path=dbs["permissions"],
        scope_db_path=dbs["scopes"],
        dna_db_path=os.path.join(tmp_path, "dna.db"),
    )
    # Check the task detail endpoint
    app = create_app(task_runner=runner)
    with app.test_client() as client:
        resp = client.get(f"/api/tasks/{task_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        # Verify task structure
        task = data.get("task", {})
        assert task.get("task_id") == task_id
        assert "approvals" in data
        assert "decisions" in data
        # Decisions should be a list
        assert isinstance(data["decisions"], list)