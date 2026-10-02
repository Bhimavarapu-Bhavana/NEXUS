from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.security.audit_logger import get_recent_audit_events
from app.security.permission_authority import (
    check_permission_before_execution,
    create_permission,
    evaluate_permission,
    get_permission,
    list_permissions,
    revoke_permission,
)


def _paths(tmp_path):
    return tmp_path / "permissions.db", tmp_path / "audit.db"


def _create(tmp_path, **overrides):
    perm_db, audit_db = _paths(tmp_path)
    values = {
        "capability": "DOCUMENT_OBSERVE",
        "action_class": "READ",
        "target_scope": "workspace-only",
        "task_id": "task-35",
        "db_path": perm_db,
        "audit_db_path": audit_db,
    }
    values.update(overrides)
    return create_permission(**values), perm_db, audit_db


def _audit_types(audit_db, limit=100):
    return {event["event_type"] for event in get_recent_audit_events(limit=limit, db_path=audit_db)}


def test_create_get_list_round_trip(tmp_path):
    record, perm_db, _ = _create(tmp_path)
    assert record["status"] == "ACTIVE"
    assert record["capability"] == "DOCUMENT_OBSERVE"
    assert record["action_class"] == "READ"
    fetched = get_permission(record["permission_id"], db_path=perm_db)
    assert fetched is not None
    assert fetched["permission_id"] == record["permission_id"]
    listed = list_permissions(task_id="task-35", db_path=perm_db)
    assert [item["permission_id"] for item in listed] == [record["permission_id"]]


def test_revoke_requires_reason(tmp_path):
    record, perm_db, audit_db = _create(tmp_path)
    with pytest.raises(ValueError):
        revoke_permission(record["permission_id"], "", db_path=perm_db, audit_db_path=audit_db)
    with pytest.raises(ValueError):
        revoke_permission(record["permission_id"], "   ", db_path=perm_db, audit_db_path=audit_db)


def test_revoke_and_repeated_revoke(tmp_path):
    record, perm_db, audit_db = _create(tmp_path)
    first = revoke_permission(record["permission_id"], "no longer needed", db_path=perm_db, audit_db_path=audit_db)
    assert first is not None
    assert first["status"] == "REVOKED"
    second = revoke_permission(record["permission_id"], "repeat", db_path=perm_db, audit_db_path=audit_db)
    assert second is not None
    assert second["status"] == "REVOKED"
    assert "permission_revoked" in _audit_types(audit_db)
    assert "permission_revoke_rejected" in _audit_types(audit_db)


def test_revoke_unknown_permission_returns_none(tmp_path):
    perm_db, audit_db = _paths(tmp_path)
    assert revoke_permission("perm-missing", "reason", db_path=perm_db, audit_db_path=audit_db) is None


def test_valid_expiry_is_accepted(tmp_path):
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    record, _, _ = _create(tmp_path, expires_at=future)
    assert record["status"] == "ACTIVE"


def test_malformed_expiry_is_rejected(tmp_path):
    for bad in ("tomorrow", "2026-13-99", "not-a-date", "12345", "2026/01/01"):
        with pytest.raises(ValueError):
            _create(tmp_path, expires_at=bad)


def test_expired_permission_is_terminal(tmp_path):
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    record, perm_db, audit_db = _create(tmp_path, expires_at=past)
    assert get_permission(record["permission_id"], db_path=perm_db)["status"] == "EXPIRED"
    decision = evaluate_permission(
        capability="DOCUMENT_OBSERVE",
        action_class="READ",
        target="notes.txt",
        task_id="task-35",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert decision["outcome"] == "EXPIRED"
    assert decision["allowed"] is False


def test_action_class_normalization(tmp_path):
    lower, perm_db, audit_db = _create(tmp_path, capability="FILE_WRITE", action_class="write", target_scope="global")
    assert lower["action_class"] == "WRITE"
    decision = evaluate_permission(
        capability="FILE_WRITE",
        action_class="write",
        target="notes.txt",
        task_id="task-35",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert decision["outcome"] == "APPROVAL_REQUIRED"


def test_invalid_action_class_rejected(tmp_path):
    with pytest.raises(ValueError):
        _create(tmp_path, action_class="TELEPORT")
    _, perm_db, audit_db = _create(tmp_path)
    with pytest.raises(ValueError):
        evaluate_permission(
            capability="DOCUMENT_OBSERVE",
            action_class="TELEPORT",
            target="notes.txt",
            task_id="task-35",
            db_path=perm_db,
            audit_db_path=audit_db,
        )


def test_capability_matching_is_canonical(tmp_path):
    _, perm_db, audit_db = _create(tmp_path, capability="document_observe")
    decision = evaluate_permission(
        capability="  Document_Observe ",
        action_class="READ",
        target="notes.txt",
        task_id="task-35",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert decision["outcome"] == "ALLOWED"
    assert decision["allowed"] is True


def test_unknown_capability_fails_closed(tmp_path):
    _, perm_db, audit_db = _create(tmp_path)
    decision = evaluate_permission(
        capability="NO_SUCH_CAPABILITY",
        action_class="READ",
        target="notes.txt",
        task_id="task-35",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert decision["outcome"] == "UNKNOWN_CAPABILITY"
    assert decision["allowed"] is False


def test_out_of_scope_on_scope_and_pattern_mismatch(tmp_path):
    _, perm_db, audit_db = _create(tmp_path, target_scope="workspace-only", target_pattern="docs/*.txt")
    scope_miss = evaluate_permission(
        capability="DOCUMENT_OBSERVE",
        action_class="READ",
        target="https://example.com/page",
        task_id="task-35",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert scope_miss["outcome"] == "OUT_OF_SCOPE"
    assert scope_miss["allowed"] is False
    pattern_miss = evaluate_permission(
        capability="DOCUMENT_OBSERVE",
        action_class="READ",
        target="other/file.txt",
        task_id="task-35",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert pattern_miss["outcome"] == "OUT_OF_SCOPE"


def test_target_scope_rejects_traversal_and_remote(tmp_path):
    _, perm_db, audit_db = _create(tmp_path, target_scope="workspace-only")
    for hostile in ("../secret.txt", "..\\secret.txt", "/etc/passwd", "C:\\secret.txt", "file:///secret", "https://example.com/x"):
        decision = evaluate_permission(
            capability="DOCUMENT_OBSERVE",
            action_class="READ",
            target=hostile,
            task_id="task-35",
            db_path=perm_db,
            audit_db_path=audit_db,
        )
        assert decision["outcome"] == "OUT_OF_SCOPE", hostile
    assert evaluate_permission(
        capability="DOCUMENT_OBSERVE",
        action_class="READ",
        target="notes.txt",
        task_id="task-35",
        db_path=perm_db,
        audit_db_path=audit_db,
    )["outcome"] == "ALLOWED"


def test_named_scopes_do_not_match_everything(tmp_path):
    for scope in ("desktop", "email", "calendar", "comms", "security"):
        _, perm_db, audit_db = _create(
            tmp_path, capability=f"SCOPE_{scope.upper()}", target_scope=scope, task_id=f"task-{scope}"
        )
        assert evaluate_permission(
            capability=f"SCOPE_{scope.upper()}",
            action_class="READ",
            target="",
            task_id=f"task-{scope}",
            db_path=perm_db,
            audit_db_path=audit_db,
        )["outcome"] == "OUT_OF_SCOPE"
        assert evaluate_permission(
            capability=f"SCOPE_{scope.upper()}",
            action_class="READ",
            target="https://example.com/evil",
            task_id=f"task-{scope}",
            db_path=perm_db,
            audit_db_path=audit_db,
        )["outcome"] == "OUT_OF_SCOPE"


def test_task_isolation(tmp_path):
    _, perm_db, audit_db = _create(tmp_path, task_id="task-a")
    decision = evaluate_permission(
        capability="DOCUMENT_OBSERVE",
        action_class="READ",
        target="notes.txt",
        task_id="task-b",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert decision["outcome"] == "UNKNOWN_CAPABILITY"
    assert decision["allowed"] is False


def test_global_permission_requires_explicit_opt_in(tmp_path):
    _, perm_db, audit_db = _create(tmp_path, task_id="")
    strict = evaluate_permission(
        capability="DOCUMENT_OBSERVE",
        action_class="READ",
        target="notes.txt",
        task_id="task-other",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert strict["allowed"] is False
    assert strict["outcome"] == "UNKNOWN_CAPABILITY"
    opted_in = evaluate_permission(
        capability="DOCUMENT_OBSERVE",
        action_class="READ",
        target="notes.txt",
        task_id="task-other",
        db_path=perm_db,
        audit_db_path=audit_db,
        allow_global=True,
    )
    assert opted_in["outcome"] == "ALLOWED"
    assert opted_in["allowed"] is True


def test_risk_blocked_override(tmp_path):
    _, perm_db, audit_db = _create(tmp_path)
    decision = check_permission_before_execution(
        capability="DOCUMENT_OBSERVE",
        action_class="READ",
        target="notes.txt",
        task_id="task-35",
        risk_level="BLOCKED",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert decision["outcome"] == "SECURITY_BLOCKED"
    assert decision["allowed"] is False
    assert "permission_blocked" in _audit_types(audit_db)


def test_read_observe_authorization(tmp_path):
    _, perm_db, audit_db = _create(tmp_path, action_class="OBSERVE")
    decision = check_permission_before_execution(
        capability="DOCUMENT_OBSERVE",
        action_class="OBSERVE",
        target="notes.txt",
        task_id="task-35",
        risk_level="READ_ONLY",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert decision["outcome"] == "ALLOWED"
    assert decision["allowed"] is True
    assert decision["metadata"]["requires_approval"] is False


def test_mutating_action_requires_approval_not_executable(tmp_path):
    _, perm_db, audit_db = _create(tmp_path, capability="FILE_WRITE", action_class="WRITE", target_scope="global")
    evaluated = evaluate_permission(
        capability="FILE_WRITE",
        action_class="WRITE",
        target="notes.txt",
        task_id="task-35",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert evaluated["outcome"] == "APPROVAL_REQUIRED"
    assert evaluated["allowed"] is False
    assert evaluated["metadata"]["requires_approval"] is True
    checked = check_permission_before_execution(
        capability="FILE_WRITE",
        action_class="WRITE",
        target="notes.txt",
        task_id="task-35",
        risk_level="MEDIUM_RISK",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert checked["outcome"] == "APPROVAL_REQUIRED"
    assert checked["allowed"] is False


def test_revoked_permission_evaluates_revoked(tmp_path):
    record, perm_db, audit_db = _create(tmp_path)
    revoke_permission(record["permission_id"], "withdrawn", db_path=perm_db, audit_db_path=audit_db)
    decision = evaluate_permission(
        capability="DOCUMENT_OBSERVE",
        action_class="READ",
        target="notes.txt",
        task_id="task-35",
        db_path=perm_db,
        audit_db_path=audit_db,
    )
    assert decision["outcome"] == "REVOKED"
    assert decision["allowed"] is False


def test_check_and_evaluate_are_consistent(tmp_path):
    _, perm_db, audit_db = _create(tmp_path, capability="FILE_WRITE", action_class="WRITE", target_scope="global")
    for action_class in ("READ", "WRITE"):
        capability = "DOCUMENT_OBSERVE" if action_class == "READ" else "FILE_WRITE"
        evaluated = evaluate_permission(
            capability=capability,
            action_class=action_class,
            target="notes.txt",
            task_id="task-35",
            db_path=perm_db,
            audit_db_path=audit_db,
        )
        checked = check_permission_before_execution(
            capability=capability,
            action_class=action_class,
            target="notes.txt",
            task_id="task-35",
            risk_level="READ_ONLY",
            db_path=perm_db,
            audit_db_path=audit_db,
        )
        assert evaluated["outcome"] == checked["outcome"]
        assert evaluated["allowed"] == checked["allowed"]


def test_audit_events_cover_security_outcomes(tmp_path):
    record, perm_db, audit_db = _create(tmp_path)
    evaluate_permission(
        capability="MISSING_CAP", action_class="READ", target="x.txt",
        task_id="task-35", db_path=perm_db, audit_db_path=audit_db,
    )
    evaluate_permission(
        capability="DOCUMENT_OBSERVE", action_class="READ", target="https://example.com/x",
        task_id="task-35", db_path=perm_db, audit_db_path=audit_db,
    )
    revoke_permission(record["permission_id"], "done", db_path=perm_db, audit_db_path=audit_db)
    evaluate_permission(
        capability="DOCUMENT_OBSERVE", action_class="READ", target="notes.txt",
        task_id="task-35", db_path=perm_db, audit_db_path=audit_db,
    )
    types = _audit_types(audit_db)
    assert "permission_created" in types
    assert "permission_evaluated" in types
    assert "permission_revoked" in types


def test_audit_db_remains_separate_from_permission_db(tmp_path):
    record, perm_db, audit_db = _create(tmp_path)
    assert get_permission(record["permission_id"], db_path=perm_db) is not None
    connection = sqlite3.connect(str(perm_db))
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    finally:
        connection.close()
    assert "audit_events" not in tables
    assert get_recent_audit_events(limit=50, db_path=audit_db), "audit events must land in the audit DB"


def test_truncation_collision_is_rejected_not_stored(tmp_path):
    perm_db, audit_db = _paths(tmp_path)
    with pytest.raises(ValueError):
        create_permission(
            capability="A" * 121, action_class="READ", task_id="task-35",
            db_path=perm_db, audit_db_path=audit_db,
        )
    with pytest.raises(ValueError):
        create_permission(
            capability="DOCUMENT_OBSERVE", action_class="READ", task_id="task-35",
            target_pattern="p" * 501, db_path=perm_db, audit_db_path=audit_db,
        )
    with pytest.raises(ValueError):
        create_permission(
            capability="DOCUMENT_OBSERVE", action_class="READ", task_id="t" * 201,
            db_path=perm_db, audit_db_path=audit_db,
        )
    assert list_permissions(db_path=perm_db) == []


def test_unknown_scope_rejected_at_creation(tmp_path):
    with pytest.raises(ValueError):
        _create(tmp_path, target_scope="everywhere")
