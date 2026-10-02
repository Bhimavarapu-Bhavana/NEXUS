from pathlib import Path

from app.tools.workspace_monitor import WorkspaceMonitor, detect_workspace_events


def test_monitor_creates_baseline_without_false_event(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "tracked.py").write_text("print('base')\n", encoding="utf-8")

    monitor = WorkspaceMonitor(workspace_path=str(workspace))
    monitor.start()

    assert monitor.poll_events() == []


def test_monitor_detects_file_creation(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monitor = WorkspaceMonitor(workspace_path=str(workspace))
    monitor.start()

    path = workspace / "new_file.py"
    path.write_text("print('new')\n", encoding="utf-8")

    events = monitor.poll_events()
    assert any(event["event_type"] == "FILE_CREATED" and event["path"] == "new_file.py" for event in events)


def test_monitor_detects_file_modification(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    path = workspace / "edit.py"
    path.write_text("print('old')\n", encoding="utf-8")

    monitor = WorkspaceMonitor(workspace_path=str(workspace))
    monitor.start()

    path.write_text("print('new')\n", encoding="utf-8")
    events = monitor.poll_events()

    assert any(event["event_type"] == "FILE_MODIFIED" and event["path"] == "edit.py" for event in events)


def test_monitor_detects_file_deletion(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    path = workspace / "delete_me.py"
    path.write_text("print('go')\n", encoding="utf-8")

    monitor = WorkspaceMonitor(workspace_path=str(workspace))
    monitor.start()

    path.unlink()
    events = monitor.poll_events()

    assert any(event["event_type"] == "FILE_DELETED" and event["path"] == "delete_me.py" for event in events)


def test_monitor_ignores_restricted_directory(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    hidden = workspace / ".git"
    hidden.mkdir()
    block = hidden / "secret.py"
    block.write_text("SECRET = 'x'\n", encoding="utf-8")

    monitor = WorkspaceMonitor(workspace_path=str(workspace))
    monitor.start()

    events = monitor.poll_events()
    assert all(".git" not in event["path"] for event in events)


def test_monitor_rejects_outside_workspace_path(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    outside = tmp_path / "outside"
    outside.mkdir()

    try:
        detect_workspace_events(str(workspace), {str(outside.relative_to(workspace)): 1.0})
        raise AssertionError("Expected ValueError for outside workspace path")
    except ValueError:
        pass


def test_monitor_events_contain_no_file_contents(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    path = workspace / "code.py"
    path.write_text("password = 'secret'\n", encoding="utf-8")

    monitor = WorkspaceMonitor(workspace_path=str(workspace))
    monitor.start()
    path.write_text("password = 'another'\n", encoding="utf-8")

    events = monitor.poll_events()
    assert events
    assert all("password" not in event.get("path", "") for event in events)


def test_monitor_bounded_queue(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    for index in range(60):
        path = workspace / f"file_{index}.py"
        path.write_text(f"print({index})\n", encoding="utf-8")

    monitor = WorkspaceMonitor(workspace_path=str(workspace), max_pending_events=10)
    monitor.start()
    events = monitor.poll_events()

    assert len(events) <= 11


def test_monitor_clean_shutdown(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    monitor = WorkspaceMonitor(workspace_path=str(workspace))
    monitor.start()
    monitor.stop()

    assert monitor.poll_events() == []


def test_monitor_event_can_enter_planner_state(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    event = {
        "event_type": "FILE_MODIFIED",
        "path": "tracked.py",
        "timestamp": "2026-01-01T00:00:00Z",
    }

    assert event["event_type"] == "FILE_MODIFIED"
    assert event["path"] == "tracked.py"
