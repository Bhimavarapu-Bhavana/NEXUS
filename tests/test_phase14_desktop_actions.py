import pytest

from app.security.risk_engine import BLOCKED, MEDIUM_RISK
from app.tools import desktop_actions
from app.tools.desktop_actions import (
    MAX_DESKTOP_ACTIONS,
    _perform_desktop_action,
    focus_authorized_window,
    minimize_authorized_window,
    restore_authorized_window,
)
from app.tools.tool_registry import TOOL_REGISTRY, get_tool_risk, validate_tool_plan


def _observation(title="NEXUS", application="code.exe", process_id=42):
    window = {
        "title": title,
        "process_name": application,
        "process_id": process_id,
        "is_foreground": False,
        "bounds": {"left": 0, "top": 0, "right": 800, "bottom": 600},
    }
    return {"status": "OK", "windows": [window], "active_window": None}


def _action(action_type="FOCUS_AUTHORIZED_WINDOW", title="NEXUS", application="code.exe"):
    return {
        "action_type": action_type,
        "application": application,
        "window_title": title,
        "reason": "synthetic test action",
    }


def _seams(monkeypatch, current=None, verified=True):
    events = []
    executed = []
    monkeypatch.setattr(desktop_actions, "record_audit_event", lambda event_type, **kwargs: events.append(event_type) or True)
    current = current or {"title": "NEXUS", "process_name": "code.exe", "process_id": 42, "_hwnd": 1001}
    return events, executed, (lambda application, title: current), (lambda action_type, hwnd: executed.append((action_type, hwnd))), (lambda action_type, hwnd: verified)


def test_authorized_target_is_considered_and_requires_approval(monkeypatch):
    _, _, resolver, executor, verifier = _seams(monkeypatch)

    result = focus_authorized_window(_action(), _observation(), resolver=resolver, executor=executor, verifier=verifier)

    assert result["status"] == "APPROVAL_REQUIRED"
    assert result["risk_decision"]["risk_level"] == MEDIUM_RISK
    assert result["risk_decision"]["approval_required"] is True


def test_unauthorized_and_unknown_application_rejected(monkeypatch):
    monkeypatch.setattr(desktop_actions, "record_audit_event", lambda *args, **kwargs: True)

    for application in ("notepad.exe", "unknown.exe"):
        result = focus_authorized_window(
            _action(application=application),
            _observation(application=application),
        )
        assert result["status"] == "BLOCKED"


def test_empty_observation_scope_fails_closed(monkeypatch):
    monkeypatch.setattr(desktop_actions, "record_audit_event", lambda *args, **kwargs: True)

    result = focus_authorized_window(_action(), {"status": "OK", "windows": []})

    assert result["status"] == "BLOCKED"


def test_supported_actions_are_explicit(monkeypatch):
    _, executed, resolver, executor, verifier = _seams(monkeypatch)

    for function, action_type in (
        (focus_authorized_window, "FOCUS_AUTHORIZED_WINDOW"),
        (minimize_authorized_window, "MINIMIZE_AUTHORIZED_WINDOW"),
        (restore_authorized_window, "RESTORE_AUTHORIZED_WINDOW"),
    ):
        result = function(_action(), _observation(), approved=True, resolver=resolver, executor=executor, verifier=verifier)
        assert result["status"] == "COMPLETED"
        assert executed[-1][0] == action_type


def test_unknown_and_unsupported_actions_are_blocked(monkeypatch):
    _, _, resolver, executor, verifier = _seams(monkeypatch)

    result = _perform_desktop_action(_action("ARBITRARY_CLICK"), _observation(), approved=True, resolver=resolver, executor=executor, verifier=verifier)

    assert result["status"] == "BLOCKED"
    assert result["risk_decision"]["risk_level"] == BLOCKED


def test_malformed_action_is_blocked(monkeypatch):
    monkeypatch.setattr(desktop_actions, "record_audit_event", lambda *args, **kwargs: True)

    result = focus_authorized_window({}, _observation(), approved=True)

    assert result["status"] == "BLOCKED"


@pytest.mark.parametrize("field", ["coordinates", "x", "y", "keys", "keyboard", "command", "api", "handle", "hwnd"])
def test_arbitrary_control_fields_are_rejected(monkeypatch, field):
    monkeypatch.setattr(desktop_actions, "record_audit_event", lambda *args, **kwargs: True)
    action = _action()
    action[field] = "synthetic-control"

    result = focus_authorized_window(action, _observation(), approved=True)

    assert result["status"] == "BLOCKED"


def test_action_requires_grounding_in_prior_observation(monkeypatch):
    monkeypatch.setattr(desktop_actions, "record_audit_event", lambda *args, **kwargs: True)

    result = focus_authorized_window(_action(title="Invented"), _observation(), approved=True)

    assert result["status"] == "BLOCKED"
    assert "grounded" in result["action_result"]


def test_stale_or_changed_target_is_rejected(monkeypatch):
    _, executed, _, executor, verifier = _seams(
        monkeypatch,
        current={"title": "Changed", "process_name": "code.exe", "process_id": 42, "_hwnd": 1001},
    )

    result = focus_authorized_window(_action(), _observation(), approved=True, resolver=lambda application, title: {"title": "Changed", "process_name": "code.exe", "process_id": 42, "_hwnd": 1001}, executor=executor, verifier=verifier)

    assert result["status"] == "BLOCKED"
    assert executed == []
    assert "Stale" in result["action_result"]


def test_process_identity_change_is_rejected(monkeypatch):
    _, executed, _, executor, verifier = _seams(monkeypatch)
    changed = {"title": "NEXUS", "process_name": "code.exe", "process_id": 99, "_hwnd": 1001}

    result = focus_authorized_window(_action(), _observation(), approved=True, resolver=lambda application, title: changed, executor=executor, verifier=verifier)

    assert result["status"] == "BLOCKED"
    assert executed == []


def test_unapproved_and_denied_actions_do_not_execute(monkeypatch):
    _, executed, resolver, executor, verifier = _seams(monkeypatch)

    result = focus_authorized_window(_action(), _observation(), approved=False, resolver=resolver, executor=executor, verifier=verifier)

    assert result["status"] == "APPROVAL_REQUIRED"
    assert executed == []


def test_planner_risk_text_cannot_lower_risk(monkeypatch):
    _, _, resolver, executor, verifier = _seams(monkeypatch)
    action = _action()
    action["risk_level"] = "READ_ONLY"

    result = focus_authorized_window(action, _observation(), approved=False, resolver=resolver, executor=executor, verifier=verifier)

    assert result["risk_decision"]["risk_level"] == MEDIUM_RISK
    assert get_tool_risk("desktop_focus_authorized_window")["risk_level"] == MEDIUM_RISK


def test_action_count_is_bounded(monkeypatch):
    _, executed, resolver, executor, verifier = _seams(monkeypatch)

    result = focus_authorized_window(_action(), _observation(), approved=True, action_count=MAX_DESKTOP_ACTIONS, resolver=resolver, executor=executor, verifier=verifier)

    assert result["status"] == "BLOCKED"
    assert executed == []


def test_execution_and_successful_verification(monkeypatch):
    events, executed, resolver, executor, verifier = _seams(monkeypatch)

    result = focus_authorized_window(_action(), _observation(), approved=True, resolver=resolver, executor=executor, verifier=verifier)

    assert result["status"] == "COMPLETED"
    assert result["verification"] == "SUCCESS"
    assert executed == [("FOCUS_AUTHORIZED_WINDOW", 1001)]
    assert "desktop_action_executed" in events
    assert "desktop_action_verification" in events


def test_failed_verification_is_not_success_and_is_not_retried(monkeypatch):
    _, executed, resolver, executor, verifier = _seams(monkeypatch, verified=False)

    result = focus_authorized_window(_action(), _observation(), approved=True, resolver=resolver, executor=executor, verifier=verifier)

    assert result["status"] == "VERIFICATION_FAILED"
    assert result["verification"] == "FAILED"
    assert result["retry_allowed"] is False
    assert len(executed) == 1


def test_execution_failure_is_explicit(monkeypatch):
    _, _, resolver, _, verifier = _seams(monkeypatch)

    def fail(action_type, hwnd):
        raise OSError("synthetic execution failure")

    result = focus_authorized_window(_action(), _observation(), approved=True, resolver=resolver, executor=fail, verifier=verifier)

    assert result["status"] == "EXECUTION_FAILED"
    assert result["verification"] == "NOT_RUN"


def test_audit_failure_fails_closed(monkeypatch):
    executed = []
    monkeypatch.setattr(desktop_actions, "record_audit_event", lambda *args, **kwargs: False)

    result = focus_authorized_window(
        _action(), _observation(), approved=True,
        resolver=lambda application, title: {"title": "NEXUS", "process_name": "code.exe", "process_id": 42, "_hwnd": 1001},
        executor=lambda action_type, hwnd: executed.append(True),
        verifier=lambda action_type, hwnd: True,
    )

    assert result["status"] == "BLOCKED"
    assert executed == []


def test_audit_lifecycle_is_recorded(monkeypatch):
    events, _, resolver, executor, verifier = _seams(monkeypatch)

    focus_authorized_window(_action(), _observation(), approved=True, resolver=resolver, executor=executor, verifier=verifier)

    assert "desktop_action_proposed" in events
    assert "desktop_action_risk_evaluated" in events
    assert "desktop_action_approved" in events
    assert "desktop_action_revalidated" in events
    assert "desktop_action_executed" in events
    assert "desktop_action_verification" in events


def test_sensitive_values_are_redacted(monkeypatch):
    monkeypatch.setattr(desktop_actions, "record_audit_event", lambda *args, **kwargs: True)
    action = _action(title="Authorization: Bearer synthetic_action_secret")

    result = focus_authorized_window(action, _observation(title=action["window_title"]), approved=True)

    assert "synthetic_action_secret" not in str(result)


def test_registry_exposes_only_narrow_actions():
    action_tools = {
        "desktop_focus_authorized_window",
        "desktop_minimize_authorized_window",
        "desktop_restore_authorized_window",
    }
    assert action_tools <= TOOL_REGISTRY.keys()
    assert all(TOOL_REGISTRY[name]["read_only"] is False for name in action_tools)
    assert all(TOOL_REGISTRY[name]["requires_approval"] is True for name in action_tools)
    assert "desktop_control" not in TOOL_REGISTRY
    assert "execute_desktop_action" not in TOOL_REGISTRY
    assert "computer_use" not in TOOL_REGISTRY
    assert validate_tool_plan(["desktop_control", "desktop_focus_authorized_window"]) == ["desktop_focus_authorized_window"]
