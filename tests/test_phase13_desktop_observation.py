from app.security.risk_engine import READ_ONLY, evaluate_risk
from app.tools import desktop_observer
from app.tools.desktop_observer import MAX_WINDOWS, observe_active_window, observe_desktop
from app.tools.tool_registry import TOOL_REGISTRY, get_tool_risk, get_trusted_tool_plan


def _snapshot(count=2):
    windows = [
        {
            "title": "NEXUS Editor",
            "process_id": 1000,
            "process_name": "editor.exe",
            "bounds": {"left": 0, "top": 0, "right": 800, "bottom": 600, "width": 800, "height": 600},
            "is_foreground": index == 0,
        }
        for index in range(count)
    ]
    return {"status": "OK", "windows": windows, "active_window": windows[0] if windows else None}


def test_desktop_observation_returns_bounded_structured_metadata(monkeypatch):
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda *args, **kwargs: True)

    result = observe_desktop(collector=lambda: _snapshot(), authorized_applications={"editor.exe"})

    assert result["source"] == "desktop"
    assert result["status"] == "OK"
    assert result["window_count"] == 2
    assert result["active_window"]["title"] == "NEXUS Editor"
    assert result["windows"][0]["bounds"]["width"] == 800
    assert result["observed_at"]


def test_window_count_is_bounded_and_marked_truncated(monkeypatch):
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda *args, **kwargs: True)

    result = observe_desktop(collector=lambda: _snapshot(MAX_WINDOWS + 5), authorized_applications={"editor.exe"})

    assert result["window_count"] == MAX_WINDOWS
    assert len(result["windows"]) == MAX_WINDOWS
    assert result["truncated"] is True


def test_active_window_observation_is_read_only(monkeypatch):
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda *args, **kwargs: True)

    result = observe_active_window(collector=lambda: _snapshot(), authorized_applications={"editor.exe"})

    assert result["status"] == "OK"
    assert result["active_window"]["title"] == "NEXUS Editor"
    assert result["source"] == "desktop"


def test_sensitive_desktop_metadata_is_redacted(monkeypatch):
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda *args, **kwargs: True)
    snapshot = _snapshot()
    snapshot["windows"][0]["title"] = "Authorization: Bearer synthetic_desktop_secret"

    result = observe_desktop(collector=lambda: snapshot, authorized_applications={"editor.exe"})

    assert "synthetic_desktop_secret" not in str(result)
    assert "[REDACTED]" in str(result)


def test_audit_failure_does_not_return_success(monkeypatch):
    called = []
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda *args, **kwargs: False)

    result = observe_desktop(collector=lambda: called.append(True) or _snapshot())

    assert result["status"] == "ERROR"
    assert called == []


def test_observation_events_are_audited(monkeypatch):
    events = []
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda event_type, **kwargs: events.append(event_type) or True)

    observe_desktop(collector=lambda: _snapshot(), authorized_applications={"editor.exe"})

    assert events == ["desktop_observation_requested", "desktop_observation_started", "desktop_observation_authorization", "desktop_observation_completed"]


def test_non_windows_capability_is_safe(monkeypatch):
    monkeypatch.setattr(desktop_observer.os, "name", "posix")
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda *args, **kwargs: True)

    result = observe_desktop()

    assert result["status"] == "UNSUPPORTED"
    assert result["windows"] == []


def test_desktop_observer_is_read_only_and_planner_selectable():
    assert TOOL_REGISTRY["desktop_observer"]["read_only"] is True
    assert TOOL_REGISTRY["desktop_observer"]["requires_approval"] is False
    assert get_tool_risk("desktop_observer")["risk_level"] == READ_ONLY
    assert get_trusted_tool_plan("Observe the active desktop window") == ["desktop_observer"]


def test_unauthorized_and_unknown_applications_are_not_exposed(monkeypatch):
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda *args, **kwargs: True)

    result = observe_desktop(collector=lambda: _snapshot(), authorized_applications={"authorized.exe"})

    assert result["windows"] == []
    assert result["active_window"] is None
    assert result["truncated"] is True


def test_empty_application_allowlist_fails_closed(monkeypatch):
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda *args, **kwargs: True)

    result = observe_desktop(collector=lambda: _snapshot(), authorized_applications=set())

    assert result["status"] == "BLOCKED"
    assert result["windows"] == []


def test_timeout_is_reported_without_expanding_scope(monkeypatch):
    monkeypatch.setattr(desktop_observer, "record_audit_event", lambda *args, **kwargs: True)

    result = observe_desktop(
        collector=lambda: (_ for _ in ()).throw(TimeoutError("synthetic timeout")),
        authorized_applications={"editor.exe"},
    )

    assert result["status"] == "ERROR"
    assert "timeout" in result["error"]


def test_risk_engine_keeps_desktop_observation_read_only():
    decision = evaluate_risk("observe visible desktop application state")

    assert decision["risk_level"] == READ_ONLY
    assert decision["allowed"] is True
    assert decision["approval_required"] is False


def test_no_desktop_control_api_is_exposed():
    forbidden = {
        "click", "double_click", "right_click", "type", "hotkey", "key_press",
        "move_mouse", "drag", "scroll", "launch", "terminate", "resize", "move_window",
    }

    assert forbidden.isdisjoint(set(dir(desktop_observer)))
    assert "desktop_control" not in TOOL_REGISTRY
    assert "desktop_action" not in TOOL_REGISTRY


def test_no_browser_or_shell_control_is_added():
    forbidden = {"execute_browser", "run_javascript", "arbitrary_click", "arbitrary_browser_command", "shell", "subprocess"}

    assert forbidden.isdisjoint(set(dir(desktop_observer)))
