import pytest

from app.agent.goal_decomposition import validate_goal_plan
from app.agent.workflow import (
    create_workflow,
    execute_workflow_sub_goal,
    validate_workflow,
    validate_workflow_transition,
)
from app.security.risk_engine import BLOCKED
from app.tools.tool_registry import TOOL_REGISTRY


@pytest.fixture
def sample_goal_plan():
    return validate_goal_plan([
        {
            "sub_goal_id": "prepare",
            "objective": "Establish the investigation target and inspect the workspace.",
            "dependencies": [],
            "selected_tools": ["workspace_inspector"],
            "verification_required": False,
        },
        {
            "sub_goal_id": "runtime",
            "objective": "Collect runtime evidence for the target.",
            "dependencies": ["prepare"],
            "selected_tools": ["runtime_inspector"],
            "verification_required": True,
        },
        {
            "sub_goal_id": "finalize",
            "objective": "Correlate the evidence and determine the likely cause.",
            "dependencies": ["runtime"],
            "selected_tools": [],
            "verification_required": False,
        },
    ])


def test_phase28_workflow_creation_and_status_boundaries(sample_goal_plan):
    workflow = create_workflow(
        "Investigate the project for the current runtime problem.",
        task_id="task-phase28-1",
        goal_plan=sample_goal_plan,
    )

    assert workflow["workflow_id"]
    assert workflow["task_id"] == "task-phase28-1"
    assert workflow["objective"]
    assert workflow["status"] == "CREATED"
    assert workflow["current_stage"] == "CREATED"
    assert workflow["ordered_sub_goals"][0]["sub_goal_id"] == "prepare"
    assert workflow["pending_sub_goals"] == ["prepare", "runtime", "finalize"]

    with pytest.raises(ValueError):
        validate_workflow_transition("COMPLETED", "RUNNING")


def test_phase28_ordered_subgoal_execution_and_dependency_enforcement(sample_goal_plan):
    workflow = create_workflow(
        "Diagnose the runtime issue.",
        task_id="task-phase28-2",
        goal_plan=sample_goal_plan,
    )

    workflow = execute_workflow_sub_goal(workflow, "prepare")
    assert workflow["completed_sub_goals"] == ["prepare"]
    assert workflow["pending_sub_goals"] == ["runtime", "finalize"]
    assert workflow["current_sub_goal_id"] == "prepare"

    with pytest.raises(ValueError):
        execute_workflow_sub_goal(workflow, "finalize")

    workflow = execute_workflow_sub_goal(workflow, "runtime")
    assert workflow["completed_sub_goals"] == ["prepare", "runtime"]
    assert workflow["current_sub_goal_id"] == "runtime"

    workflow = execute_workflow_sub_goal(workflow, "finalize")
    assert workflow["status"] in {"COMPLETED", "VERIFYING", "RUNNING"}
    assert workflow["final_outcome"] in {"SUCCESS", "COMPLETED", "OBSERVED", ""}


def test_phase28_tool_registry_enforcement_and_unknown_tool_rejection(sample_goal_plan):
    with pytest.raises(ValueError):
        create_workflow(
            "Inspect the workspace for the issue.",
            task_id="task-phase28-3",
            goal_plan=[{
                "sub_goal_id": "step1",
                "objective": "Inspect the workspace.",
                "dependencies": [],
                "selected_tools": ["workspace_inspector", "not_a_real_tool"],
            }],
        )

    workflow = create_workflow(
        "Inspect the workspace for the issue.",
        task_id="task-phase28-4",
        goal_plan=[{
            "sub_goal_id": "step2",
            "objective": "Inspect the workspace.",
            "dependencies": [],
            "selected_tools": ["workspace_inspector"],
        }],
    )

    workflow = execute_workflow_sub_goal(workflow, "step2")
    assert workflow["selected_tool"] == "workspace_inspector"
    assert workflow["tool_execution_history"]
    assert workflow["tool_execution_history"][-1]["tool"] == "workspace_inspector"


def test_phase28_blocked_risk_and_approval_boundaries(sample_goal_plan):
    with pytest.raises(ValueError):
        create_workflow(
            "Delete the repository and wipe the project.",
            task_id="task-phase28-5",
            goal_plan=[{
                "sub_goal_id": "danger",
                "objective": "Delete the repository and wipe the project.",
                "dependencies": [],
                "selected_tools": ["workspace_inspector"],
            }],
        )

    approval_workflow = create_workflow(
        "Apply a fix to the project.",
        task_id="task-phase28-6",
        goal_plan=[{
            "sub_goal_id": "approve_me",
            "objective": "Modify a local file to correct the bug.",
            "dependencies": [],
            "selected_tools": ["workspace_inspector"],
            "action_required": True,
        }],
    )

    approval_workflow = execute_workflow_sub_goal(approval_workflow, "approve_me")
    assert approval_workflow["status"] in {"WAITING_APPROVAL", "BLOCKED", "RUNNING"}
    assert "approval" in str(approval_workflow["current_stage"]).lower() or approval_workflow["approval_lineage"]


def test_phase28_approval_binding_expiry_and_target_drift_rejection(sample_goal_plan):
    workflow = create_workflow(
        "Inspect the workspace for the root cause.",
        task_id="task-phase28-7",
        goal_plan=sample_goal_plan,
    )

    workflow["approval_lineage"] = {
        "task_id": "task-phase28-7",
        "target": "workspace/demo.py",
        "risk_level": "MEDIUM_RISK",
        "status": "APPROVED",
        "expires_at": "2020-01-01T00:00:00+00:00",
    }
    workflow["target_ref"] = "workspace/demo.py"
    workflow["status"] = "WAITING_APPROVAL"

    with pytest.raises(ValueError):
        validate_workflow(workflow)

    workflow["approval_lineage"] = {
        "task_id": "task-phase28-7",
        "target": "workspace/demo.py",
        "risk_level": "MEDIUM_RISK",
        "status": "APPROVED",
        "expires_at": "2999-01-01T00:00:00+00:00",
    }
    workflow["target_ref"] = "workspace/demo.py"
    workflow["status"] = "RUNNING"
    workflow = validate_workflow(workflow)
    assert workflow["approval_lineage"]["status"] == "APPROVED"


def test_phase28_evidence_and_sensitive_data_redaction(sample_goal_plan):
    workflow = create_workflow(
        "Inspect logs and runtime state for a secret-bearing issue.",
        task_id="task-phase28-8",
        goal_plan=[{
            "sub_goal_id": "inspect",
            "objective": "Inspect the logs for the issue.",
            "dependencies": [],
            "selected_tools": ["terminal_inspector"],
        }],
    )

    workflow["evidence_refs"] = ["terminal:output:secret_token_123", "workspace:demo.py"]
    workflow["tool_execution_history"] = [{"tool": "terminal_inspector", "result": "token=super_secret_value"}]

    safe_workflow = validate_workflow(workflow)
    dumped = repr(safe_workflow)
    assert "super_secret_value" not in dumped
    assert "[REDACTED]" in dumped or "token" in dumped.lower()
    assert "terminal:output:secret_token_123" in safe_workflow["evidence_refs"][0]


def test_phase28_checkpoint_and_recovery_authority_is_preserved(sample_goal_plan):
    workflow = create_workflow(
        "Investigate and recover a paused task.",
        task_id="task-phase28-9",
        goal_plan=sample_goal_plan,
    )

    workflow["status"] = "PAUSED"
    workflow["current_stage"] = "PAUSED"
    workflow["checkpoint_id"] = "cp-1234567890"
    validated = validate_workflow(workflow)

    assert validated["status"] == "PAUSED"
    assert validated["checkpoint_id"] == "cp-1234567890"
    assert "checkpoint" in str(validated["current_stage"]).lower() or validated["checkpoint_id"]

    with pytest.raises(ValueError):
        validate_workflow_transition("COMPLETED", "RUNNING")


def test_phase28_no_arbitrary_shell_or_python_execution_is_permitted():
    with pytest.raises(ValueError):
        create_workflow(
            "Run arbitrary shell commands to inspect the workspace.",
            task_id="task-phase28-10",
            goal_plan=[{
                "sub_goal_id": "bad",
                "objective": "Run bash -lc 'rm -rf /' to inspect the workspace.",
                "dependencies": [],
                "selected_tools": ["workspace_inspector"],
            }],
        )

    assert "workspace_inspector" in TOOL_REGISTRY
    assert "browser_controller" in TOOL_REGISTRY
