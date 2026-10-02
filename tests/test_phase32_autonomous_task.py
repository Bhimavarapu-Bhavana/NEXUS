from app.agent.autonomous_policy import MAX_SUB_GOALS_PER_PLAN, MAX_TOTAL_SUBGOALS_PER_TASK, plan_hash, validate_autonomous_plan
from app.agent.graph import nexus_graph
from app.memory.task_ledger import create_task, get_task, update_task_status


def test_task_ledger_tracks_durable_autonomous_plan_metadata():
    task = create_task("Prepare this project for submission.", db_path="data/test_phase32_autonomous_task.db")
    update_task_status(
        task["task_id"],
        "RUNNING",
        current_stage="DECOMPOSE",
        current_sub_goal="inspect_workspace",
        goal_plan=[{"sub_goal_id": "inspect_workspace", "objective": "Inspect the workspace and determine the likely target."}],
        subgoal_statuses={"inspect_workspace": "READY"},
        current_subgoal_id="inspect_workspace",
        plan_version="v1",
        plan_hash=plan_hash([{"sub_goal_id": "inspect_workspace", "objective": "Inspect the workspace and determine the likely target."}]),
        plan_revisions=1,
        task_retry_count=1,
        subgoal_retry_count={"inspect_workspace": 0},
        failure_classifications={"inspect_workspace": "RECOVERABLE"},
        adaptation_history=[{"plan_version": "v1", "reason": "initial"}],
        completion_evidence=["workspace:inspect"],
        db_path="data/test_phase32_autonomous_task.db",
    )
    stored = get_task(task["task_id"], db_path="data/test_phase32_autonomous_task.db")
    assert stored["goal_plan"][0]["sub_goal_id"] == "inspect_workspace"
    assert stored["plan_version"] == "v1"
    assert stored["current_subgoal_id"] == "inspect_workspace"
    assert stored["task_retry_count"] == 1


def test_autonomous_policy_rejects_unbounded_plan_growth():
    plan = [{"sub_goal_id": f"g{i}", "objective": f"Inspect item {i}.", "dependencies": []} for i in range(MAX_SUB_GOALS_PER_PLAN + 1)]
    try:
        validate_autonomous_plan(plan)
        assert False, "Expected unbounded plan to be rejected"
    except ValueError:
        pass


def test_graph_creates_durable_goal_plan_for_high_level_goal():
    state = {
        "user_request": "Prepare this project for submission.",
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
        "monitoring_active": False,
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
        "task_id": "",
        "task_status": "",
        "task_resume_requested": False,
        "task_resume_reason": "",
        "task_context": "",
        "persistence_db_path": "data/test_phase32_autonomous_task.db",
        "journal_db_path": "data/test_phase32_autonomous_task.db",
        "approval_db_path": "data/test_phase32_autonomous_task.db",
        "environment_fingerprint": "phase32-test",
    }
    result = nexus_graph.invoke(state)
    assert isinstance(result.get("goal_plan"), list) and len(result["goal_plan"]) >= 2
    assert result.get("task_id")
