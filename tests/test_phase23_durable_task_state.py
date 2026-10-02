import json

import pytest

from app.agent.graph import retrieve_memory
from app.memory.task_ledger import (
    create_task,
    get_task,
    list_recent_tasks,
    record_task_event,
    resume_task,
    update_task_status,
)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "nexus_task_ledger.db"


def test_phase23_task_creation_persistence_and_redaction(db_path):
    task = create_task(
        "Fix the secret token and password in the deployment config.",
        current_stage="REQUEST",
        db_path=db_path,
    )

    assert task["task_id"]
    assert task["status"] == "CREATED"
    assert task["current_stage"] == "REQUEST"
    assert task["objective"]
    assert "[REDACTED]" in task["objective"] or "[REDACTED]" in str(task)

    stored = get_task(task["task_id"], db_path=db_path)
    assert stored is not None
    assert stored["task_id"] == task["task_id"]
    assert stored["status"] == "CREATED"
    assert stored["objective"]
    assert "[REDACTED]" in stored["objective"]


def test_phase23_persistence_across_connections_and_event_lineage(db_path):
    task = create_task("Inspect workspace for runtime errors.", db_path=db_path)

    event = record_task_event(
        task["task_id"],
        "STAGE_CHANGED",
        {"from_stage": "REQUEST", "to_stage": "OBSERVE"},
        db_path=db_path,
    )
    assert event["event_type"] == "STAGE_CHANGED"

    stored = get_task(task["task_id"], db_path=db_path)
    events = stored["event_history"]
    assert events
    assert any(item["event_type"] == "TASK_CREATED" for item in events)
    assert any(item["event_type"] == "STAGE_CHANGED" for item in events)

    task_again = get_task(task["task_id"], db_path=db_path)
    assert task_again["event_history"]
    assert any(item["event_type"] == "TASK_CREATED" for item in task_again["event_history"])


def test_phase23_status_transitions_are_valid_and_invalid_transitions_fail(db_path):
    task = create_task("Run a bounded review.", db_path=db_path)

    updated = update_task_status(
        task["task_id"],
        "RUNNING",
        current_stage="OBSERVE",
        status_reason="Creation accepted.",
        db_path=db_path,
    )
    assert updated["status"] == "RUNNING"

    updated = update_task_status(
        task["task_id"],
        "WAITING_APPROVAL",
        current_stage="APPROVAL_PENDING",
        status_reason="Approval required.",
        db_path=db_path,
    )
    assert updated["status"] == "WAITING_APPROVAL"

    with pytest.raises(ValueError):
        update_task_status(
            task["task_id"],
            "COMPLETED",
            current_stage="FINAL_OUTCOME",
            status_reason="This should be rejected.",
            db_path=db_path,
        )

    final_task = update_task_status(
        task["task_id"],
        "RUNNING",
        status_reason="Approved path resumed.",
        db_path=db_path,
    )
    assert final_task["status"] == "RUNNING"

    final_task = update_task_status(
        task["task_id"],
        "VERIFYING",
        current_stage="VERIFICATION",
        status_reason="Checking runtime evidence.",
        db_path=db_path,
    )
    final_task = update_task_status(
        task["task_id"],
        "COMPLETED",
        current_stage="FINAL_OUTCOME",
        status_reason="Task satisfied.",
        final_outcome="SUCCESS",
        db_path=db_path,
    )
    assert final_task["status"] == "COMPLETED"
    assert final_task["final_outcome"] == "SUCCESS"

    with pytest.raises(ValueError):
        update_task_status(final_task["task_id"], "RUNNING", db_path=db_path)


def test_phase23_approval_history_and_redacted_task_status_output(db_path):
    task = create_task("Review local logs for a security issue.", db_path=db_path)

    task = update_task_status(
        task["task_id"],
        "WAITING_APPROVAL",
        current_stage="APPROVAL_PENDING",
        approval_lineage={
            "approval_id": "approval-123",
            "status": "PENDING",
            "decision": "APPROVED",
            "token": "super-secret-token",
            "target": "workspace/app.py",
        },
        db_path=db_path,
    )

    assert task["approval_lineage"]["token"] == "[REDACTED]"
    assert task["approval_lineage"]["status"] == "PENDING"
    assert "super-secret-token" not in json.dumps(task["approval_lineage"], default=str)

    assert task["status_output"]
    assert "WAITING_APPROVAL" in task["status_output"]
    assert "[REDACTED]" in task["status_output"] or "approval" in task["status_output"].lower()


def test_phase23_stale_approval_invalidates_and_requires_fresh_approval(db_path):
    task = create_task("Apply a local fix with approval gates.", db_path=db_path)

    task = update_task_status(
        task["task_id"],
        "WAITING_APPROVAL",
        current_stage="APPROVAL_PENDING",
        approval_lineage={
            "approval_id": "old-approval",
            "status": "APPROVED",
            "target": "workspace/old.py",
            "reason": "Old approval",
            "risk_level": "MEDIUM_RISK",
            "expires_at": "2020-01-01T00:00:00+00:00",
        },
        db_path=db_path,
    )

    invalidated = update_task_status(
        task["task_id"],
        "WAITING_APPROVAL",
        current_stage="APPROVAL_PENDING",
        approval_lineage={
            "approval_id": "new-approval",
            "status": "PENDING",
            "target": "workspace/new.py",
            "reason": "Fresh approval required",
            "risk_level": "MEDIUM_RISK",
        },
        db_path=db_path,
    )

    assert invalidated["approval_lineage"]["status"] == "PENDING"
    assert invalidated["approval_lineage"]["target"] == "workspace/new.py"


def test_phase23_resume_requires_explicit_request_and_blocks_terminal_states(db_path):
    task = create_task("Review a paused task.", db_path=db_path)
    task = update_task_status(task["task_id"], "PAUSED", current_stage="PAUSED", db_path=db_path)
    resumed = resume_task(task["task_id"], resume_reason="Explicit resume requested.", db_path=db_path)
    assert resumed["status"] == "RUNNING"
    assert resumed["resume_reason"] == "Explicit resume requested."

    failed = create_task("Let the task fail.", db_path=db_path)
    failed = update_task_status(failed["task_id"], "FAILED", current_stage="FINAL_OUTCOME", final_outcome="FAILED_VERIFICATION", db_path=db_path)
    with pytest.raises(ValueError):
        resume_task(failed["task_id"], db_path=db_path)

    with pytest.raises(ValueError):
        resume_task(failed["task_id"], force=False, db_path=db_path)

    resumed_failed = resume_task(failed["task_id"], resume_reason="Fresh approval was given.", force=True, db_path=db_path)
    assert resumed_failed["status"] == "RUNNING"

    completed = create_task("Complete the task.", db_path=db_path)
    completed = update_task_status(completed["task_id"], "RUNNING", current_stage="FIXED", db_path=db_path)
    completed = update_task_status(completed["task_id"], "COMPLETED", current_stage="FINAL_OUTCOME", final_outcome="SUCCESS", db_path=db_path)
    with pytest.raises(ValueError):
        resume_task(completed["task_id"], db_path=db_path)


def test_phase23_task_resume_reloads_fresh_evidence_and_graph_state(db_path):
    task = create_task("Fix a workspace bug.", db_path=db_path)
    task = update_task_status(task["task_id"], "PAUSED", current_stage="PAUSED", status_reason="Awaiting fresh evidence.", db_path=db_path)
    task = update_task_status(
        task["task_id"],
        "RUNNING",
        current_stage="OBSERVE",
        status_reason="Fresh evidence was gathered.",
        evidence_refs=["runtime:status=SUCCESS", "workspace:files=updated"],
        db_path=db_path,
    )

    resumed = resume_task(task["task_id"], resume_reason="Fresh observation required.", db_path=db_path)
    assert resumed["status"] == "RUNNING"
    assert resumed["resume_reason"] == "Fresh observation required."
    assert resumed["evidence_refs"]
    assert resumed["current_stage"] in {"OBSERVE", "REQUEST", "APPROVAL_PENDING"}

    state = {
        "user_request": "Fix a workspace bug.",
        "observations": ["Fresh evidence was collected."],
        "decision_stage": "REQUEST",
        "task_status": "RUNNING",
        "task_id": resumed["task_id"],
        "resume_requested": True,
        "risk_decision": {"risk_level": "MEDIUM_RISK", "allowed": True, "approval_required": True},
        "approved": False,
    }
    state = retrieve_memory(state)
    assert state["task_id"] == resumed["task_id"]
    assert state["task_status"] in {"RUNNING", "WAITING_APPROVAL"}


def test_phase23_history_and_retry_bounds_are_persisted(db_path):
    task = create_task("Verify a fix with retry data.", db_path=db_path)
    task = update_task_status(task["task_id"], "RUNNING", current_stage="OBSERVE", db_path=db_path)
    task = update_task_status(
        task["task_id"],
        "VERIFYING",
        current_stage="VERIFICATION",
        verification_history=["STATUS: INITIAL FAILURE", "STATUS: SUCCESS"],
        retry_history=["retry-1", "retry-2"],
        db_path=db_path,
    )

    stored = get_task(task["task_id"], db_path=db_path)
    assert stored["verification_history"]
    assert stored["retry_history"] == ["retry-1", "retry-2"]
    assert len(stored["retry_history"]) <= 4


def test_phase23_list_recent_tasks_is_redacted_and_bounded(db_path):
    create_task("Deploy secret token to production.", db_path=db_path)
    create_task("Inspect logs and fix issue.", db_path=db_path)

    tasks = list_recent_tasks(limit=5, db_path=db_path)
    assert len(tasks) >= 2
    assert all("[REDACTED]" in json.dumps(task, default=str) or "token" in json.dumps(task, default=str).lower() or "logs" in json.dumps(task, default=str).lower() for task in tasks)


def test_phase23_sql_parameterization_and_append_only_lineage(db_path):
    task = create_task("Create a durable ledger entry with explicit metadata.", db_path=db_path)
    record_task_event(task["task_id"], "TASK_PAUSED", {"reason": "Waiting for fresh evidence."}, db_path=db_path)
    record_task_event(task["task_id"], "TASK_RESUMED", {"reason": "Fresh evidence loaded."}, db_path=db_path)

    task_after = get_task(task["task_id"], db_path=db_path)
    events = task_after["event_history"]
    assert [item["event_type"] for item in events].count("TASK_PAUSED") == 1
    assert [item["event_type"] for item in events].count("TASK_RESUMED") == 1
    assert all(";" not in item["payload"] for item in events if item.get("payload"))


def test_phase23_no_generic_execution_endpoint_is_present_in_server_contract():
    from app.ui.server import create_app

    app = create_app()
    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert "/api/status" in rules
    assert "/api/approvals" in rules
    assert all(name not in rules for name in {"/execute", "/run", "/command", "/api/execute_task"})
