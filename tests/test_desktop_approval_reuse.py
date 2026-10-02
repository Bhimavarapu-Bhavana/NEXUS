"""Narrow regression: desktop approval-lineage reuse (Defect #3).

Deterministic (stubbed desktop observation; no live desktop, no browser).
Proves the desktop counterpart to the browser lineage helper: an APPROVED
desktop approval is reused without minting a replacement, while drifted,
rejected, expired, or absent lineage fails closed or takes the normal path.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

import app.agent.graph as graph_module
from app.agent.action_executor import proposal_hash
from app.agent.approval_authority import create_approval, decide_approval, list_pending_approvals
from app.agent.execution_journal import create_checkpoint
from app.agent.graph import create_action_proposal
from app.memory.task_ledger import create_task, update_task_status

REQUEST = "Focus an authorized application window that you can actually observe. Ask for approval before interacting with it."
WINDOW = {"process_name": "code.exe", "title": "NEXUS", "process_id": 42}
SPEC = {"action_type": "FOCUS_AUTHORIZED_WINDOW", "application": "code.exe", "window_title": "NEXUS"}


def _digest() -> str:
    return proposal_hash(
        action_type="desktop_focus_authorized_window",
        tool_name="desktop_focus_authorized_window",
        target="NEXUS",
        action_spec=SPEC,
    )


def _observe_ok(monkeypatch):
    def fake_execute(tool_names, **kwargs):
        assert tool_names == ["desktop_observer"]
        assert kwargs.get("capability_context") is None
        return [{
            "tool": "desktop_observer",
            "status": "ok",
            "result": {"source": "desktop", "status": "OK", "windows": [dict(WINDOW)]},
        }]

    monkeypatch.setattr(graph_module, "execute_selected_tools", fake_execute)


def _bind_task(db_path, *, task_id, checkpoint_id, approval_id, digest):
    update_task_status(
        task_id,
        "WAITING_APPROVAL",
        current_stage="APPROVAL_PENDING",
        action_lineage={"checkpoint_id": checkpoint_id, "proposal_hash": digest, "action_type": "desktop_focus_authorized_window", "target": "NEXUS"},
        approval_lineage={"approval_id": approval_id},
        db_path=db_path,
    )


def _proposal_state(db_path, task_id):
    return {
        "task_id": task_id,
        "user_request": REQUEST,
        "request_intent": "DESKTOP_ACTION_REQUEST",
        "observation_results": [],
        "persistence_db_path": str(db_path),
        "journal_db_path": str(db_path),
        "approval_db_path": str(db_path),
        "environment_fingerprint": "test",
    }


def _lineage(db_path, task_id, *, digest, target="NEXUS", expires_at=None):
    checkpoint = create_checkpoint(
        task_id,
        current_stage="APPROVAL_PENDING",
        action_type="desktop_focus_authorized_window",
        action_target=target,
        proposal_hash=digest,
        risk_level="MEDIUM_RISK",
        approval_status="PENDING",
        action_payload={"action_spec": dict(SPEC)},
        selected_tools=["desktop_focus_authorized_window"],
        db_path=db_path,
    )
    approval = create_approval(
        task_id=task_id,
        checkpoint_id=checkpoint["checkpoint_id"],
        proposal_hash=digest,
        action_type="desktop_focus_authorized_window",
        tool_name="desktop_focus_authorized_window",
        target=target,
        risk_level="MEDIUM_RISK",
        db_path=db_path,
        **({"expires_at": expires_at} if expires_at else {}),
    )
    return checkpoint, approval


def test_approved_desktop_approval_is_reused_without_new_approval(tmp_path, monkeypatch):
    _observe_ok(monkeypatch)
    db_path = tmp_path / "reuse.db"
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    create_task(REQUEST, task_id=task_id, db_path=db_path)
    digest = _digest()
    checkpoint, approval = _lineage(db_path, task_id, digest=digest)
    decide_approval(approval["approval_id"], "APPROVED", db_path=db_path)
    _bind_task(db_path, task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], approval_id=approval["approval_id"], digest=digest)
    pending_before = len(list_pending_approvals(db_path=db_path))

    result = create_action_proposal(_proposal_state(db_path, task_id))

    assert result["action_tool"] == "desktop_focus_authorized_window"
    assert result["action_target"] == "NEXUS"
    assert result["approval_id"] == approval["approval_id"]
    assert result["journal_checkpoint_id"] == checkpoint["checkpoint_id"]
    assert result["proposal_hash"] == digest
    assert len(list_pending_approvals(db_path=db_path)) == pending_before


def test_mismatched_target_fails_closed_without_replacement(tmp_path, monkeypatch):
    def fake_execute(tool_names, **kwargs):
        return [{
            "tool": "desktop_observer",
            "status": "ok",
            "result": {"source": "desktop", "status": "OK", "windows": [{"process_name": "code.exe", "title": "OTHER", "process_id": 7}]},
        }]

    monkeypatch.setattr(graph_module, "execute_selected_tools", fake_execute)
    db_path = tmp_path / "drift.db"
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    create_task(REQUEST, task_id=task_id, db_path=db_path)
    digest = _digest()
    checkpoint, approval = _lineage(db_path, task_id, digest=digest)
    decide_approval(approval["approval_id"], "APPROVED", db_path=db_path)
    _bind_task(db_path, task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], approval_id=approval["approval_id"], digest=digest)
    pending_before = len(list_pending_approvals(db_path=db_path))

    result = create_action_proposal(_proposal_state(db_path, task_id))

    assert result["final_outcome"] == "BLOCKED"
    assert len(list_pending_approvals(db_path=db_path)) == pending_before


def test_rejected_approval_fails_closed_without_replacement(tmp_path, monkeypatch):
    _observe_ok(monkeypatch)
    db_path = tmp_path / "rejected.db"
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    create_task(REQUEST, task_id=task_id, db_path=db_path)
    digest = _digest()
    checkpoint, approval = _lineage(db_path, task_id, digest=digest)
    decide_approval(approval["approval_id"], "REJECTED", db_path=db_path)
    _bind_task(db_path, task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], approval_id=approval["approval_id"], digest=digest)
    pending_before = len(list_pending_approvals(db_path=db_path))

    result = create_action_proposal(_proposal_state(db_path, task_id))

    assert result["final_outcome"] == "APPROVAL_REJECTED"
    assert len(list_pending_approvals(db_path=db_path)) == pending_before


def test_expired_approval_fails_closed_without_replacement(tmp_path, monkeypatch):
    _observe_ok(monkeypatch)
    db_path = tmp_path / "expired.db"
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    create_task(REQUEST, task_id=task_id, db_path=db_path)
    digest = _digest()
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    checkpoint, approval = _lineage(db_path, task_id, digest=digest, expires_at=past)
    _bind_task(db_path, task_id=task_id, checkpoint_id=checkpoint["checkpoint_id"], approval_id=approval["approval_id"], digest=digest)
    pending_before = len(list_pending_approvals(db_path=db_path))

    result = create_action_proposal(_proposal_state(db_path, task_id))

    assert result["final_outcome"] in {"BLOCKED", "APPROVAL_REJECTED"}
    assert len(list_pending_approvals(db_path=db_path)) == pending_before


def test_missing_lineage_still_mints_normal_approval(tmp_path, monkeypatch):
    _observe_ok(monkeypatch)
    db_path = tmp_path / "fresh.db"
    task_id = f"task-{uuid.uuid4().hex[:12]}"
    create_task(REQUEST, task_id=task_id, db_path=db_path)

    result = create_action_proposal(_proposal_state(db_path, task_id))

    assert result["action_tool"] == "desktop_focus_authorized_window"
    assert result["action_target"] == "NEXUS"
    assert result["approval_required"] is True
    assert result["approved"] is False
    assert result["approval_id"]
