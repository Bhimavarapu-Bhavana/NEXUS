import sqlite3

import pytest

from app.security.audit_logger import (
    get_recent_audit_events,
    initialize_audit,
    record_audit_event,
)
from app.security.sensitive_data import REDACTION_MARKER


def test_audit_table_initializes_and_records_structured_event(tmp_path):
    db_path = tmp_path / "audit.db"

    assert record_audit_event(
        "risk_decision",
        actor="risk_engine",
        tool="fixer",
        risk_level="MEDIUM_RISK",
        approval_required=True,
        approved=False,
        target="source.py",
        result="allowed",
        reason="synthetic audit reason",
        metadata={"request": "api_key=synthetic_audit_secret"},
        db_path=db_path,
    ) is True

    events = get_recent_audit_events(db_path=db_path)

    assert len(events) == 1
    assert events[0]["event_type"] == "risk_decision"
    assert events[0]["risk_level"] == "MEDIUM_RISK"
    assert events[0]["approval_required"] is True
    assert events[0]["approved"] is False
    assert REDACTION_MARKER in str(events[0])
    assert "synthetic_audit_secret" not in str(events[0])


def test_audit_persistence_redacts_database_rows(tmp_path):
    db_path = tmp_path / "audit.db"
    secret = "synthetic_database_secret_12345"

    assert record_audit_event(
        "tool_execution",
        result=f"password={secret}",
        metadata={"nested": {"token": secret}},
        db_path=db_path,
    ) is True

    with sqlite3.connect(db_path) as connection:
        row = connection.execute("SELECT result, metadata FROM audit_events").fetchone()

    assert secret not in str(row)
    assert REDACTION_MARKER in str(row)


def test_audit_query_is_bounded_and_newest_first(tmp_path):
    db_path = tmp_path / "audit.db"
    for index in range(5):
        assert record_audit_event(
            "observation",
            result=f"event {index}",
            db_path=db_path,
        ) is True

    events = get_recent_audit_events(limit=2, db_path=db_path)

    assert len(events) == 2
    assert events[0]["id"] > events[1]["id"]
    assert events[0]["result"] == "event 4"


def test_audit_history_rejects_update_and_delete(tmp_path):
    db_path = tmp_path / "audit.db"
    initialize_audit(db_path)
    record_audit_event("observation", result="original", db_path=db_path)

    with sqlite3.connect(db_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE audit_events SET result='changed' WHERE id=1")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM audit_events WHERE id=1")

    assert get_recent_audit_events(db_path=db_path)[0]["result"] == "original"


def test_audit_query_does_not_accept_arbitrary_sql(tmp_path):
    db_path = tmp_path / "audit.db"
    record_audit_event("observation", result="safe", db_path=db_path)

    events = get_recent_audit_events(limit="1 OR 1=1", db_path=db_path)

    assert len(events) == 1
    assert events[0]["event_type"] == "observation"


def test_audit_write_failure_is_explicit(tmp_path):
    invalid_path = tmp_path / "not_a_database_directory"
    invalid_path.mkdir()

    assert record_audit_event("error", result="write failed", db_path=invalid_path) is False


def test_blocked_action_is_audited_and_never_executes(monkeypatch):
    from app.agent import graph

    events = []
    called = []

    def fake_audit(event_type, **payload):
        events.append((event_type, payload))
        return True

    def fake_fix(*args, **kwargs):
        called.append(True)
        return "unexpected"

    monkeypatch.setattr(graph, "record_audit_event", fake_audit)
    monkeypatch.setattr(graph, "fix_python_logic", fake_fix)

    result = graph.execute_action({
        "approved": True,
        "target_file": "../outside.py",
        "old_code": "old",
        "new_code": "new",
        "action_result": "",
    })

    assert called == []
    assert result["risk_decision"]["risk_level"] == "BLOCKED"
    assert any(event[0] == "action_blocked" for event in events)


def test_audit_failure_fail_closes_approved_mutation(monkeypatch):
    from app.agent import graph

    called = []

    monkeypatch.setattr(graph, "record_audit_event", lambda *args, **kwargs: False)
    monkeypatch.setattr(graph, "fix_python_logic", lambda *args, **kwargs: called.append(True))

    result = graph.execute_action({
        "approved": True,
        "target_file": "source.py",
        "old_code": "old",
        "new_code": "new",
        "action_result": "",
    })

    assert called == []
    assert result["approved"] is False
    assert "audit persistence failed" in result["action_result"].lower()
    assert result["audit_error"]


def test_existing_read_only_tools_and_approval_contract_remain_intact():
    from app.tools.tool_registry import TOOL_REGISTRY, validate_tool_plan

    observation_tools = {
        name: info for name, info in TOOL_REGISTRY.items()
        if name not in {
            "browser_navigate_observed",
            "browser_follow_observed_link",
            "desktop_focus_authorized_window",
            "desktop_minimize_authorized_window",
            "desktop_restore_authorized_window",
            "calendar_event_action",
            "email_send_action",
            "comms_send_action",
            "job_application_fill_action",
            "job_application_submit_action",
        }
    }
    assert all(info["read_only"] for info in observation_tools.values())
    assert TOOL_REGISTRY["browser_navigate_observed"]["read_only"] is False
    assert TOOL_REGISTRY["browser_follow_observed_link"]["read_only"] is False
    assert TOOL_REGISTRY["desktop_focus_authorized_window"]["read_only"] is False
    assert TOOL_REGISTRY["desktop_minimize_authorized_window"]["read_only"] is False
    assert TOOL_REGISTRY["desktop_restore_authorized_window"]["read_only"] is False
    assert TOOL_REGISTRY["calendar_event_action"]["read_only"] is False
    assert TOOL_REGISTRY["email_send_action"]["read_only"] is False
    assert TOOL_REGISTRY["comms_send_action"]["read_only"] is False
    assert validate_tool_plan(["fixer", "workspace_inspector"]) == ["workspace_inspector"]
