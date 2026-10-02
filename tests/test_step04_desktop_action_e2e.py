"""TEST 4 live desktop-action E2E (real UI path, real desktop, no stubs).

Flow per test: POST /api/tasks -> TaskRunner -> StateGraph -> deferred
desktop grounding -> proposal -> WAITING_APPROVAL -> approve/reject ->
runner re-entry (same mechanism as the UI resume path) -> Action Executor
-> focus_authorized_window -> verification -> audit. Never calls the
desktop controller directly.

The native focus/verify step races the live desktop foreground, so the
execution-proof test retries with a FRESH task per attempt (bounded) and
asserts deterministic properties every attempt; at least one CONSUMED run
proves real execution. Nothing is weakened to obtain green.
"""

from __future__ import annotations

from app.agent.approval_authority import get_approval
from app.agent.execution_journal import load_checkpoint
from app.agent.task_runner import TaskRunner
from app.control_plane import ControlPlane, create_control_app

REQUEST = "Focus an authorized application window that you can actually observe. Ask for approval before interacting with it."
MAX_E2E_ATTEMPTS = 5


def _harness(tmp_path, **runner_kwargs):
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    db_path = tmp_path / "t4e2e.db"
    runner = TaskRunner(workspace_root=str(workspace), db_path=db_path, **runner_kwargs)
    plane = ControlPlane(workspace_root=str(workspace), db_path=db_path, task_runner=runner)
    started = plane.lifecycle("START")
    assert started.get("accepted") is True
    app = create_control_app(plane)
    app.config.update(TESTING=True)
    return app.test_client(), db_path, runner


def _submit(client):
    submitted = client.post("/api/tasks", json={"request": REQUEST}).get_json()
    assert submitted.get("accepted") is True
    assert submitted.get("status") == "WAITING_APPROVAL", submitted
    task_id = submitted["task_id"]
    items = client.get("/api/approvals").get_json()["items"]
    match = [a for a in items if a.get("task_id") == task_id]
    assert len(match) == 1, items
    approval = match[0]
    assert approval["tool_name"] == "desktop_focus_authorized_window"
    assert approval["status"] == "PENDING"
    assert approval["target"]
    detail = client.get(f"/api/tasks/{task_id}").get_json()
    assert (detail.get("checkpoint") or {}).get("action_type") == "desktop_focus_authorized_window"
    return task_id, approval


def _approvals_for(client, task_id):
    return [a for a in client.get("/api/approvals").get_json().get("items", []) if a.get("task_id") == task_id]


def test_live_focus_executes_with_exactly_once_consumption(tmp_path):
    """Deterministic properties every attempt; at least one CONSUMED proves live focus."""
    consumed_runs = 0
    for attempt in range(MAX_E2E_ATTEMPTS):
        probe = tmp_path / f"attempt{attempt}"
        probe.mkdir(exist_ok=True)
        client, db_path, runner = _harness(probe)
        task_id, approval = _submit(client)
        decided = client.post(f"/api/approvals/{approval['approval_id']}/approve", json={}).get_json()
        assert decided.get("accepted") is True
        resumed = runner.start_task(REQUEST, task_id=task_id)

        stored = get_approval(approval["approval_id"], db_path=db_path)
        assert stored["status"] in {"CONSUMED", "INVALIDATED"}, stored["status"]
        # Exactly one approval ever minted for this task: no duplicate/replacement.
        assert len(_approvals_for(client, task_id)) <= 1
        checkpoint = load_checkpoint(task_id, db_path=db_path)
        if stored["status"] == "CONSUMED":
            consumed_runs += 1
            assert checkpoint is not None and checkpoint.get("verification_snapshot") == "SUCCESS"
            break
        # INVALIDATED here means post-action verification lost a live-desktop
        # foreground race (fail-closed, correct). Retry with a fresh task.
    assert consumed_runs >= 1, "No attempt achieved verified focus; live execution NOT PROVEN this run"


def test_live_rejected_approval_executes_nothing(tmp_path):
    client, db_path, _ = _harness(tmp_path)
    task_id, approval = _submit(client)
    rejected = client.post(f"/api/approvals/{approval['approval_id']}/reject", json={}).get_json()
    assert rejected.get("decision") == "REJECTED"
    runner = TaskRunner(workspace_root=str(tmp_path / "workspace"), db_path=db_path)
    resumed = runner.start_task(REQUEST, task_id=task_id)
    stored = get_approval(approval["approval_id"], db_path=db_path)
    assert stored["status"] == "REJECTED"
    assert len(_approvals_for(client, task_id)) <= 1
    assert resumed.get("final_outcome") in {"APPROVAL_REJECTED", "BLOCKED", "NO_ACTION", "READ_ONLY", "WAITING_APPROVAL"}
    checkpoint = load_checkpoint(task_id, db_path=db_path)
    assert checkpoint is None or checkpoint.get("verification_snapshot") != "SUCCESS"


def test_live_terminal_approval_is_never_reexecuted(tmp_path):
    client, db_path, runner = _harness(tmp_path)
    task_id, approval = _submit(client)
    client.post(f"/api/approvals/{approval['approval_id']}/approve", json={})
    runner.start_task(REQUEST, task_id=task_id)
    status_first = get_approval(approval["approval_id"], db_path=db_path)["status"]
    assert status_first in {"CONSUMED", "INVALIDATED"}
    count_before = len(_approvals_for(client, task_id))
    second = runner.start_task(REQUEST, task_id=task_id)
    assert get_approval(approval["approval_id"], db_path=db_path)["status"] == status_first
    assert len(_approvals_for(client, task_id)) == count_before
    assert second.get("status") in {"COMPLETED", "BLOCKED", "FAILED", "WAITING_APPROVAL"}


def test_live_revoked_scope_blocks_before_execution(tmp_path):
    from app.security.automation_scope import grant_scope, revoke_scope

    probe = tmp_path / "scoped"
    probe.mkdir(exist_ok=True)
    scope_db = probe / "scopes.db"
    # Submit and approve with an unscoped runner (scope gate advisory when unbound).
    client, db_path, _ = _harness(probe)
    task_id, approval = _submit(client)
    client.post(f"/api/approvals/{approval['approval_id']}/approve", json={})
    # Bind scope for resume, then revoke before re-entry: the proposal tail
    # must deny before any dispatch.
    record = grant_scope(area="desktop", decision="ALLOW", task_id=task_id, db_path=scope_db)
    revoke_scope(record["scope_id"], "test revocation before resume", db_path=scope_db)
    runner = TaskRunner(workspace_root=str(probe / "workspace"), db_path=db_path, scope_db_path=scope_db)
    resumed = runner.start_task(REQUEST, task_id=task_id)
    stored = get_approval(approval["approval_id"], db_path=db_path)
    assert stored["status"] != "CONSUMED", stored["status"]
    assert resumed.get("status") in {"BLOCKED", "FAILED", "WAITING_APPROVAL", "COMPLETED"}
    checkpoint = load_checkpoint(task_id, db_path=db_path)
    assert checkpoint is None or checkpoint.get("verification_snapshot") != "SUCCESS"


def test_executor_rejects_drifted_desktop_target(tmp_path):
    """Drifted approval target fails closed before any native call (canned observation)."""
    from app.agent.action_executor import execute_authorized_action, proposal_hash
    from app.agent.approval_authority import create_approval, decide_approval
    from app.agent.execution_journal import create_checkpoint

    db_path = tmp_path / "drift.db"
    digest = proposal_hash(
        action_type="desktop_focus_authorized_window",
        tool_name="desktop_focus_authorized_window",
        target="NEXUS",
        action_spec={"action_type": "FOCUS_AUTHORIZED_WINDOW", "application": "code.exe", "window_title": "NEXUS"},
    )
    checkpoint = create_checkpoint(
        "task-drift-1",
        current_stage="APPROVAL_PENDING",
        action_type="desktop_focus_authorized_window",
        action_target="NEXUS",
        proposal_hash=digest,
        risk_level="MEDIUM_RISK",
        approval_status="PENDING",
        action_payload={"action_spec": {"action_type": "FOCUS_AUTHORIZED_WINDOW", "application": "code.exe", "window_title": "NEXUS"}},
        selected_tools=["desktop_focus_authorized_window"],
        db_path=db_path,
    )
    approval = create_approval(
        task_id="task-drift-1",
        checkpoint_id=checkpoint["checkpoint_id"],
        proposal_hash=digest,
        action_type="desktop_focus_authorized_window",
        tool_name="desktop_focus_authorized_window",
        target="NEXUS",
        risk_level="MEDIUM_RISK",
        db_path=db_path,
    )
    decide_approval(approval["approval_id"], "APPROVED", db_path=db_path)
    observed = {"source": "desktop", "status": "OK", "windows": [{"process_name": "code.exe", "title": "NEXUS", "process_id": 1}]}
    state = {
        "task_id": "task-drift-1",
        "journal_checkpoint_id": checkpoint["checkpoint_id"],
        "approval_id": approval["approval_id"],
        "proposal_hash": digest,
        "action_type": "desktop_focus_authorized_window",
        "action_tool": "desktop_focus_authorized_window",
        "action_target": "SOME-OTHER-WINDOW",
        "action_spec": {"action_type": "FOCUS_AUTHORIZED_WINDOW", "application": "code.exe", "window_title": "NEXUS"},
        "observation_results": [{"tool": "desktop_observer", "status": "ok", "result": observed}],
        "journal_db_path": str(db_path),
    }
    result = execute_authorized_action(state, workspace_root=str(tmp_path), db_path=db_path)
    assert result["status"] == "BLOCKED"
    assert get_approval(approval["approval_id"], db_path=db_path)["status"] != "CONSUMED"
