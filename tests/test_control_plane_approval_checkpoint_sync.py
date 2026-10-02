"""Narrow regression: approval decision -> durable checkpoint sync (Defect #2).

Proves ControlPlane.decide(APPROVED) mirrors the decision onto the exact
bound checkpoint (status APPROVED + fresh binding + expiry) and that every
other outcome leaves the checkpoint untouched (fail closed).
"""

from __future__ import annotations

from app.agent.approval_authority import create_approval, get_approval
from app.agent.execution_journal import create_checkpoint, load_checkpoint
from app.control_plane import ControlPlane


def _plane(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return ControlPlane(workspace_root=str(workspace), db_path=tmp_path / "sync.db")


def _lineage(db_path, *, target="sample.py"):
    checkpoint = create_checkpoint(
        "task-sync-1",
        current_stage="APPROVAL_PENDING",
        action_type="apply approved code fix",
        action_target=target,
        proposal_hash="ph-sync-1",
        risk_level="MEDIUM_RISK",
        approval_status="PENDING",
        selected_tools=["fixer"],
        db_path=db_path,
    )
    approval = create_approval(
        task_id="task-sync-1",
        checkpoint_id=checkpoint["checkpoint_id"],
        proposal_hash="ph-sync-1",
        action_type="apply approved code fix",
        tool_name="fixer",
        target=target,
        risk_level="MEDIUM_RISK",
        db_path=db_path,
    )
    return checkpoint, approval


def test_approved_decision_syncs_exact_checkpoint_binding(tmp_path):
    plane = _plane(tmp_path)
    checkpoint, approval = _lineage(plane.db_path)
    result = plane.decide(approval["approval_id"], "APPROVED")
    assert result["accepted"] is True
    stored = load_checkpoint("task-sync-1", checkpoint_id=checkpoint["checkpoint_id"], db_path=plane.db_path)
    assert stored["approval_status"] == "APPROVED"
    assert stored["approval_binding"]["approval_id"] == approval["approval_id"]
    assert stored["approval_binding"]["proposal_hash"] == "ph-sync-1"
    assert stored["approval_binding"]["target"] == "sample.py"
    assert stored["approval_expiry"] == get_approval(approval["approval_id"], db_path=plane.db_path)["expires_at"]


def test_rejected_decision_leaves_checkpoint_pending(tmp_path):
    plane = _plane(tmp_path)
    checkpoint, approval = _lineage(plane.db_path)
    result = plane.decide(approval["approval_id"], "REJECTED")
    assert result["accepted"] is True
    stored = load_checkpoint("task-sync-1", checkpoint_id=checkpoint["checkpoint_id"], db_path=plane.db_path)
    assert stored["approval_status"] == "PENDING"
    assert get_approval(approval["approval_id"], db_path=plane.db_path)["status"] == "REJECTED"


def test_mismatched_checkpoint_binding_is_not_synced(tmp_path):
    plane = _plane(tmp_path)
    checkpoint, approval = _lineage(plane.db_path, target="sample.py")
    # Drift the checkpoint target away from the approved target before deciding.
    from app.agent.execution_journal import update_checkpoint

    update_checkpoint(checkpoint["checkpoint_id"], action_target="other.py", db_path=plane.db_path)
    result = plane.decide(approval["approval_id"], "APPROVED")
    assert result["accepted"] is True
    stored = load_checkpoint("task-sync-1", checkpoint_id=checkpoint["checkpoint_id"], db_path=plane.db_path)
    assert stored["approval_status"] == "PENDING"
    assert get_approval(approval["approval_id"], db_path=plane.db_path)["status"] == "APPROVED"
