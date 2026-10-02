from datetime import datetime, timedelta, timezone

import pytest

from app.agent.approval_authority import (
    create_approval,
    decide_approval,
    get_approval,
    list_pending_approvals,
    validate_approval,
)


def _approval(db_path, **overrides):
    values = {
        "task_id": "task-31",
        "checkpoint_id": "cp-31",
        "proposal_hash": "proposal-31",
        "action_type": "apply approved code fix",
        "tool_name": "fixer",
        "target": "demo.py",
        "risk_level": "MEDIUM_RISK",
        "db_path": db_path,
    }
    values.update(overrides)
    return create_approval(**values)


def test_approval_is_durable_and_bound_to_lineage(tmp_path):
    db_path = tmp_path / "approvals.db"
    approval = _approval(db_path)
    assert approval["status"] == "PENDING"
    assert approval["task_id"] == "task-31"
    assert get_approval(approval["approval_id"], db_path=db_path)["proposal_hash"] == "proposal-31"
    assert list_pending_approvals(db_path=db_path)[0]["approval_id"] == approval["approval_id"]

    decide_approval(approval["approval_id"], "APPROVED", db_path=db_path)
    validated = validate_approval(approval["approval_id"], task_id="task-31", checkpoint_id="cp-31", proposal_hash="proposal-31", action_type="apply approved code fix", tool_name="fixer", target="demo.py", risk_level="MEDIUM_RISK", db_path=db_path)
    assert validated["status"] == "APPROVED"


def test_cross_task_target_tool_and_proposal_reuse_is_rejected(tmp_path):
    db_path = tmp_path / "approvals.db"
    approval = _approval(db_path)
    decide_approval(approval["approval_id"], "APPROVED", db_path=db_path)
    cases = [
        {"task_id": "other"},
        {"target": "other.py"},
        {"tool_name": "other_tool"},
        {"proposal_hash": "other"},
        {"risk_level": "HIGH_RISK"},
    ]
    for mismatch in cases:
        values = {"task_id": "task-31", "checkpoint_id": "cp-31", "proposal_hash": "proposal-31", "action_type": "apply approved code fix", "tool_name": "fixer", "target": "demo.py", "risk_level": "MEDIUM_RISK", "db_path": db_path}
        values.update(mismatch)
        with pytest.raises(ValueError):
            validate_approval(approval["approval_id"], **values)


def test_expired_approval_cannot_be_decided_or_validated(tmp_path):
    db_path = tmp_path / "approvals.db"
    approval = _approval(db_path, expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
    with pytest.raises(ValueError):
        decide_approval(approval["approval_id"], "APPROVED", db_path=db_path)
    assert get_approval(approval["approval_id"], db_path=db_path)["status"] == "EXPIRED"
