from __future__ import annotations

from pathlib import Path

import pytest

from app.agent.autonomous_service import (
    AutonomousService,
    build_privacy_contract,
    normalize_workspace_event,
)
from app.agent.task_runner import TaskRunner
from app.memory.task_ledger import get_task


class RepeatingMonitor:
    def __init__(self, **_kwargs):
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def poll_events(self):
        if not self.running:
            return []
        return [{"event_type": "FILE_MODIFIED", "path": "changed.py", "timestamp": "2026-09-21T00:00:00Z"}]


class FailingMonitor(RepeatingMonitor):
    def poll_events(self):
        raise RuntimeError("safe monitor failure")


def _runner(workspace: Path, db: Path) -> TaskRunner:
    return TaskRunner(
        workspace_root=workspace,
        db_path=db,
        graph_runner=lambda state: {**state, "task_status": "COMPLETED", "final_outcome": "READ_ONLY"},
    )


def test_phase34_event_normalization_is_bounded_and_rejects_traversal():
    event = normalize_workspace_event({"event_type": "FILE_MODIFIED", "path": "src\\safe.py", "timestamp": "now"})
    assert event["path"] == "src/safe.py"
    assert event["fingerprint"]
    with pytest.raises(ValueError):
        normalize_workspace_event({"event_type": "FILE_MODIFIED", "path": "../secret.py"})
    with pytest.raises(ValueError):
        normalize_workspace_event({"event_type": "COMMAND", "path": "safe.py"})


def test_phase34_service_lifecycle_is_durable(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db = tmp_path / "service.db"
    service = AutonomousService(workspace, db_path=db, task_runner=_runner(workspace, db))

    assert service.start()["state"] == "RUNNING"
    assert service.pause()["state"] == "PAUSED"
    assert service.resume()["state"] == "RUNNING"
    assert service.stop()["state"] == "STOPPED"
    assert service.shutdown()["state"] == "SHUTDOWN"
    assert AutonomousService(workspace, db_path=db, task_runner=_runner(workspace, db)).status()["state"] == "SHUTDOWN"


def test_phase34_real_monitor_event_creates_durable_task(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db = tmp_path / "service.db"
    service = AutonomousService(workspace, db_path=db, task_runner=_runner(workspace, db), poll_interval_seconds=0.1)
    service.start()
    (workspace / "changed.py").write_text("print('changed')\n", encoding="utf-8")

    result = service.run_once()

    assert result["status"] == "RUNNING"
    assert result["events"][0]["path"] == "changed.py"
    assert result["tasks"][0]["status"] == "COMPLETED"
    task = get_task(result["tasks"][0]["task_id"], db_path=db)
    assert task is not None
    assert any(event["event_type"] == "AUTONOMOUS_EVENT_RECEIVED" for event in task["event_history"])
    assert "changed.py" in str(task["event_history"])


def test_phase34_event_deduplication_is_idempotent(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db = tmp_path / "service.db"
    service = AutonomousService(workspace, db_path=db, monitor_factory=RepeatingMonitor, task_runner=_runner(workspace, db))
    service.start()

    first = service.run_once()
    second = service.run_once()

    assert first["tasks"]
    assert second["tasks"] == []
    assert second["events"][0]["path"] == "changed.py"


def test_phase34_run_forever_is_bounded(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db = tmp_path / "service.db"
    service = AutonomousService(workspace, db_path=db, monitor_factory=RepeatingMonitor, task_runner=_runner(workspace, db), poll_interval_seconds=0.1)
    service.start()
    status = service.run_forever(max_cycles=2)
    assert status["state"] == "RUNNING"
    assert status["loop_count"] == 2


def test_phase34_monitor_failure_enters_degraded_state(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db = tmp_path / "service.db"
    service = AutonomousService(workspace, db_path=db, monitor_factory=FailingMonitor, max_recovery_failures=2, task_runner=_runner(workspace, db))
    service.start()
    assert service.run_once()["status"] == "DEGRADED"
    assert service.status()["state"] == "DEGRADED"
    assert service.run_once()["status"] == "RESTRICTED"
    assert service.status()["state"] == "RESTRICTED"


def test_phase34_privacy_contract_is_explicit_and_disabled():
    contract = build_privacy_contract(
        capability="FILE_OBSERVATION",
        target="workspace/sample.txt",
        purpose="inspect project metadata",
        scope="one authorized file",
        privacy_classification="project",
    )
    assert contract["explicit_authorization_required"] is True
    assert contract["enabled"] is False
    with pytest.raises(ValueError):
        build_privacy_contract(capability="FILE_OBSERVATION", target="", purpose="p", scope="s", privacy_classification="private")


def test_phase34_concurrent_task_limit_is_fail_closed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db = tmp_path / "service.db"
    service = AutonomousService(workspace, db_path=db, monitor_factory=RepeatingMonitor, max_concurrent_tasks=1, task_runner=_runner(workspace, db))
    service.start()
    service._active_task_ids.add("task-already-active")

    result = service.run_once()

    assert result["tasks"][0]["status"] == "WAITING_RESOURCE"
