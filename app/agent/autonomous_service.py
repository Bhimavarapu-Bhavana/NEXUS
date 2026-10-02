from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
import uuid
import argparse
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.agent.task_runner import TERMINAL_TASKS, TaskRunner
from app.memory.task_ledger import get_task, list_recent_tasks, record_task_event
from app.agent.approval_authority import list_pending_approvals
from app.security.audit_logger import record_audit_event
from app.security.security_monitor import SecurityMonitor
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.tools.workspace_monitor import WorkspaceMonitor

SERVICE_STATES = {"STOPPED", "RUNNING", "PAUSED", "SHUTDOWN", "DEGRADED", "RESTRICTED", "HUMAN_REQUIRED"}
RELEVANT_EVENT_TYPES = {"FILE_CREATED", "FILE_MODIFIED", "FILE_DELETED"}
MAX_EVENT_PATH_CHARS = 500
DEFAULT_POLL_INTERVAL_SECONDS = 1.0
DEFAULT_MAX_EVENTS_PER_CYCLE = 10
DEFAULT_MAX_CONCURRENT_TASKS = 1
DEFAULT_MAX_TASKS_PER_CYCLE = 1
DEFAULT_MAX_RECOVERY_FAILURES = 3
INSTANCE_LEASE_SECONDS = 15
EVENT_DEDUP_WINDOW_SECONDS = 5
DEFAULT_MAX_TASK_RUNTIME_SECONDS = 300
DEFAULT_MAX_TASK_RETRIES = 3
DEFAULT_MAX_TOOL_CALLS = 25


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fingerprint(event: dict[str, Any]) -> str:
    stable = {
        "event_type": str(event.get("event_type") or ""),
        "path": str(event.get("path") or ""),
    }
    return hashlib.sha256(json.dumps(stable, sort_keys=True, ensure_ascii=True).encode("utf-8")).hexdigest()


def event_priority(event: dict[str, Any]) -> str:
    event_type = str(event.get("event_type") or "").upper()
    if event_type in {"SECURITY_BLOCKED", "AUTHORIZATION_FAILURE"}:
        return "CRITICAL"
    if event_type in {"FILE_DELETED", "SERVICE_FAILURE"}:
        return "HIGH"
    if event_type in {"FILE_MODIFIED", "FILE_CREATED"}:
        return "NORMAL"
    return "LOW"


def normalize_workspace_event(event: dict[str, Any]) -> dict[str, Any]:
    """Convert monitor output into bounded, redacted data before it can affect a task."""
    if not isinstance(event, dict):
        raise ValueError("Workspace events must be dictionaries.")
    event_type = str(event.get("event_type") or "").upper().strip()
    path = str(event.get("path") or "").replace("\\", "/").strip()
    if event_type not in RELEVANT_EVENT_TYPES:
        raise ValueError("Unsupported workspace event type.")
    if not path or path.startswith("/") or ".." in Path(path).parts:
        raise ValueError("Workspace event path is not authorized.")
    safe = redact_sensitive_data({
        "event_id": f"event-{uuid.uuid4().hex[:12]}",
        "event_type": event_type,
        "path": redact_text(path)[:MAX_EVENT_PATH_CHARS],
        "timestamp": redact_text(str(event.get("timestamp") or _now_iso()))[:64],
        "source": "workspace_monitor",
        "authorization_scope": "workspace-only",
        "target": redact_text(path)[:MAX_EVENT_PATH_CHARS],
        "priority": event_priority({"event_type": event_type}),
        "fingerprint": _fingerprint({"event_type": event_type, "path": path}),
    })
    return safe


def build_privacy_contract(*, capability: str, target: str, purpose: str, scope: str, privacy_classification: str) -> dict[str, Any]:
    """Describe future sensitive observation capabilities without granting access."""
    allowed = {"PHOTO_OBSERVATION", "FILE_OBSERVATION", "PERSONAL_DATA_OBSERVATION"}
    capability_name = str(capability or "").upper()
    if capability_name not in allowed:
        raise ValueError("Unsupported privacy capability.")
    if not all(str(value or "").strip() for value in (target, purpose, scope, privacy_classification)):
        raise ValueError("Privacy contracts require target, purpose, scope, and classification.")
    return redact_sensitive_data({
        "capability": capability_name,
        "target": target,
        "purpose": purpose,
        "scope": scope,
        "privacy_classification": privacy_classification,
        "explicit_authorization_required": True,
        "redaction_policy": "metadata_first_and_secret_redaction",
        "audit_required": True,
        "enabled": False,
    })


class AutonomousService:
    """Bounded local observer that delegates task execution to the existing StateGraph."""

    def __init__(
        self,
        workspace_root: str | Path = "workspace",
        *,
        db_path: str | Path | None = None,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        max_events_per_cycle: int = DEFAULT_MAX_EVENTS_PER_CYCLE,
        max_concurrent_tasks: int = DEFAULT_MAX_CONCURRENT_TASKS,
        max_tasks_per_cycle: int = DEFAULT_MAX_TASKS_PER_CYCLE,
        max_recovery_failures: int = DEFAULT_MAX_RECOVERY_FAILURES,
        monitor_factory: Callable[..., WorkspaceMonitor] = WorkspaceMonitor,
        task_runner: TaskRunner | None = None,
        security_monitor: SecurityMonitor | None = None,
        resource_provider: Callable[[], dict[str, float]] | None = None,
        cpu_threshold_percent: float = 85.0,
        memory_threshold_bytes: int = 512 * 1024 * 1024,
        max_task_runtime_seconds: int = DEFAULT_MAX_TASK_RUNTIME_SECONDS,
        max_task_retries: int = DEFAULT_MAX_TASK_RETRIES,
        max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.db_path = Path(db_path) if db_path is not None else self.workspace_root.parent / "data" / "nexus_service.db"
        self.poll_interval_seconds = max(0.1, min(float(poll_interval_seconds), 60.0))
        self.max_events_per_cycle = max(1, min(int(max_events_per_cycle), 100))
        self.max_concurrent_tasks = max(1, min(int(max_concurrent_tasks), 4))
        self.max_tasks_per_cycle = max(1, min(int(max_tasks_per_cycle), self.max_concurrent_tasks))
        self.max_recovery_failures = max(1, min(int(max_recovery_failures), 10))
        self.monitor_factory = monitor_factory
        self.task_runner = task_runner or TaskRunner(workspace_root=self.workspace_root, db_path=self.db_path)
        self.security_monitor = security_monitor or SecurityMonitor()
        self.resource_provider = resource_provider or (lambda: {"cpu_percent": 0.0, "memory_bytes": 0.0})
        self.cpu_threshold_percent = max(1.0, float(cpu_threshold_percent))
        self.memory_threshold_bytes = max(1, int(memory_threshold_bytes))
        self.max_task_runtime_seconds = max(1, int(max_task_runtime_seconds))
        self.max_task_retries = max(1, int(max_task_retries))
        self.max_tool_calls = max(1, int(max_tool_calls))
        self._resource_snapshot: dict[str, float] = {"cpu_percent": 0.0, "memory_bytes": 0.0}
        self._supervision_events: list[dict[str, Any]] = []
        self.monitor: WorkspaceMonitor | None = None
        self._state_lock = threading.RLock()
        self._stop_event = threading.Event()
        self._active_task_ids: set[str] = set()
        self._recovery_failures = 0
        self._instance_id = f"instance-{uuid.uuid4().hex[:16]}"
        self._lease_owned = False
        self._ensure_store()

    def _ensure_store(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.db_path))
        try:
            connection.execute("CREATE TABLE IF NOT EXISTS nexus_service_state (id INTEGER PRIMARY KEY CHECK (id = 1), state TEXT NOT NULL, updated_at TEXT NOT NULL, loop_count INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '', active_task_id TEXT NOT NULL DEFAULT '', recovery_failures INTEGER NOT NULL DEFAULT 0, owner_id TEXT NOT NULL DEFAULT '', owner_heartbeat TEXT NOT NULL DEFAULT '', started_at TEXT NOT NULL DEFAULT '', last_success_at TEXT NOT NULL DEFAULT '')")
            connection.execute("CREATE TABLE IF NOT EXISTS nexus_service_events (fingerprint TEXT PRIMARY KEY, event_json TEXT NOT NULL, task_id TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, occurrence_count INTEGER NOT NULL DEFAULT 1)")
            connection.execute("INSERT OR IGNORE INTO nexus_service_state (id, state, updated_at) VALUES (1, 'STOPPED', ?)", (_now_iso(),))
            connection.commit()
        finally:
            connection.close()

    def _load_state(self) -> dict[str, Any]:
        self._ensure_store()
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute("SELECT * FROM nexus_service_state WHERE id = 1").fetchone()
        finally:
            connection.close()
        return dict(row) if row else {"state": "STOPPED", "loop_count": 0, "recovery_failures": 0}

    def _set_state(self, state: str, *, error: str = "", active_task_id: str = "") -> dict[str, Any]:
        normalized = str(state or "").upper()
        if normalized not in SERVICE_STATES:
            raise ValueError("Invalid autonomous service state.")
        current = self._load_state()
        connection = sqlite3.connect(str(self.db_path))
        try:
            connection.execute("UPDATE nexus_service_state SET state = ?, updated_at = ?, loop_count = ?, last_error = ?, active_task_id = ?, recovery_failures = ?, owner_id = ?, owner_heartbeat = ? WHERE id = 1", (normalized, _now_iso(), int(current.get("loop_count", 0) or 0), redact_text(error)[:1000], active_task_id, int(self._recovery_failures), self._instance_id if self._lease_owned else "", _now_iso() if self._lease_owned else ""))
            connection.commit()
        finally:
            connection.close()
        return self.status()

    def status(self) -> dict[str, Any]:
        state = self._load_state()
        return redact_sensitive_data({
            "state": state.get("state", "STOPPED"),
            "updated_at": state.get("updated_at", ""),
            "loop_count": int(state.get("loop_count", 0) or 0),
            "last_error": state.get("last_error", ""),
            "active_task_id": state.get("active_task_id", ""),
            "recovery_failures": int(state.get("recovery_failures", 0) or 0),
            "owner_id": state.get("owner_id", ""),
            "started_at": state.get("started_at", ""),
            "last_success_at": state.get("last_success_at", ""),
            "workspace_root": str(self.workspace_root),
            "poll_interval_seconds": self.poll_interval_seconds,
            "max_concurrent_tasks": self.max_concurrent_tasks,
        })

    def _acquire_lease(self) -> None:
        connection = sqlite3.connect(str(self.db_path), timeout=5)
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT state, owner_id, owner_heartbeat FROM nexus_service_state WHERE id = 1").fetchone()
            now = datetime.now(timezone.utc)
            heartbeat = str(row[2] or "") if row else ""
            stale = True
            if heartbeat:
                try:
                    stale = (now - datetime.fromisoformat(heartbeat.replace("Z", "+00:00"))).total_seconds() > INSTANCE_LEASE_SECONDS
                except ValueError:
                    stale = True
            if row and row[0] == "RUNNING" and row[1] and row[1] != self._instance_id and not stale:
                connection.rollback()
                raise RuntimeError("Another NEXUS service instance owns this workspace.")
            connection.execute("UPDATE nexus_service_state SET owner_id = ?, owner_heartbeat = ?, started_at = CASE WHEN started_at = '' OR ? THEN ? ELSE started_at END WHERE id = 1", (self._instance_id, _now_iso(), stale, _now_iso()))
            connection.commit()
            self._lease_owned = True
        finally:
            connection.close()

    def _release_lease(self) -> None:
        connection = sqlite3.connect(str(self.db_path))
        try:
            connection.execute("UPDATE nexus_service_state SET owner_id = '', owner_heartbeat = '' WHERE id = 1 AND owner_id = ?", (self._instance_id,))
            connection.commit()
        finally:
            connection.close()
        self._lease_owned = False

    def start(self) -> dict[str, Any]:
        with self._state_lock:
            persisted = self._load_state()
            current = persisted.get("state", "STOPPED")
            if current == "RUNNING" and persisted.get("owner_id") == self._instance_id:
                self._lease_owned = True
                return self.status()
            self._acquire_lease()
            self.monitor = self.monitor_factory(workspace_path=str(self.workspace_root), max_pending_events=self.max_events_per_cycle)
            self.monitor.start()
            self._stop_event.clear()
            try:
                self.task_runner.startup_recovery()
                self._recovery_failures = 0
            except Exception as exc:
                self._recovery_failures += 1
                if self._recovery_failures >= self.max_recovery_failures:
                    return self._set_state("RESTRICTED", error=f"Startup recovery failed: {exc}")
                return self._set_state("DEGRADED", error=f"Startup recovery failed: {exc}")
            record_audit_event("autonomous_service_started", actor="autonomous_service", tool="workspace_monitor", target=str(self.workspace_root), result="RUNNING", metadata={"poll_interval_seconds": self.poll_interval_seconds}, db_path=self.db_path)
            return self._set_state("RUNNING")

    def stop(self) -> dict[str, Any]:
        with self._state_lock:
            if self.monitor is not None:
                self.monitor.stop()
            self._stop_event.set()
            record_audit_event("autonomous_service_stopped", actor="autonomous_service", tool="workspace_monitor", target=str(self.workspace_root), result="STOPPED", db_path=self.db_path)
            self._set_state("STOPPED")
            self._release_lease()
            return self.status()

    def pause(self) -> dict[str, Any]:
        with self._state_lock:
            if self.monitor is not None:
                self.monitor.stop()
            return self._set_state("PAUSED")

    def resume(self) -> dict[str, Any]:
        with self._state_lock:
            if not self._lease_owned:
                self._acquire_lease()
            if self.monitor is None:
                self.monitor = self.monitor_factory(workspace_path=str(self.workspace_root), max_pending_events=self.max_events_per_cycle)
            self.monitor.start()
            self._stop_event.clear()
            return self._set_state("RUNNING")

    def shutdown(self) -> dict[str, Any]:
        with self._state_lock:
            if self.monitor is not None:
                self.monitor.stop()
            self._stop_event.set()
            record_audit_event("autonomous_service_shutdown", actor="autonomous_service", tool="workspace_monitor", target=str(self.workspace_root), result="SHUTDOWN", db_path=self.db_path)
            self._set_state("SHUTDOWN")
            self._release_lease()
            return self.status()

    def restart(self) -> dict[str, Any]:
        with self._state_lock:
            if self._load_state().get("state") in {"RUNNING", "PAUSED", "DEGRADED", "RESTRICTED"}:
                self.stop()
            return self.start()

    def health(self) -> dict[str, Any]:
        state = self.status()
        resource = self._sample_resources()
        health_state = "HEALTHY" if state["state"] == "RUNNING" and not state["last_error"] else "STOPPED" if state["state"] in {"STOPPED", "SHUTDOWN"} else "DEGRADED"
        if resource["cpu_percent"] >= self.cpu_threshold_percent or resource["memory_bytes"] >= self.memory_threshold_bytes:
            health_state = "RESTRICTED"
        recent_security = self.security_monitor.recent_events(20)
        if any(str(item.get("severity") or "").upper() == "CRITICAL" for item in recent_security):
            health_state = "BLOCKED"
        elif any(str(item.get("severity") or "").upper() == "HIGH" for item in recent_security) and health_state == "HEALTHY":
            health_state = "RESTRICTED"
        if state["recovery_failures"] >= self.max_recovery_failures:
            health_state = "RESTRICTED"
        return {"health": health_state, "reason": state["last_error"] or "Service health is determined from persisted state.", "state": state["state"], "active_tasks": len(self._active_task_ids), "queued_events": self._queued_event_count(), "resource": resource, "supervision_events": list(self._supervision_events[-20:]), "pending_approvals": len(self.approvals()), "last_success_at": state.get("last_success_at", ""), "updated_at": state.get("updated_at", "")}

    def _sample_resources(self) -> dict[str, float]:
        try:
            raw = self.resource_provider() or {}
            self._resource_snapshot = {"cpu_percent": max(0.0, float(raw.get("cpu_percent", 0.0))), "memory_bytes": max(0.0, float(raw.get("memory_bytes", 0.0)))}
        except (TypeError, ValueError, OSError) as exc:
            self._supervision_events.append({"type": "RESOURCE_SAMPLE_FAILED", "reason": redact_text(exc)})
        return dict(self._resource_snapshot)

    def _supervise_tasks(self) -> None:
        now = datetime.now(timezone.utc)
        for task in self.tasks(100):
            if str(task.get("status") or "").upper() in TERMINAL_TASKS:
                continue
            try:
                updated = datetime.fromisoformat(str(task.get("updated_at") or task.get("created_at")).replace("Z", "+00:00"))
                runtime = (now - updated).total_seconds()
            except (TypeError, ValueError):
                runtime = self.max_task_runtime_seconds + 1
            retries = int(task.get("task_retry_count") or 0)
            tool_calls = len(task.get("selected_tools") or []) + len(task.get("verification_history") or [])
            reason = ""
            if runtime > self.max_task_runtime_seconds:
                reason = "Task runtime exceeded the bounded supervision limit."
            elif retries > self.max_task_retries:
                reason = "Task retry count exceeded the bounded supervision limit."
            elif tool_calls > self.max_tool_calls:
                reason = "Task tool-call count exceeded the bounded supervision limit."
            if reason:
                self._supervision_events.append({"type": "TASK_SUPERVISION_LIMIT", "task_id": task.get("task_id", ""), "reason": reason})
                try:
                    self.task_runner.pause_task(task["task_id"], reason)
                except (ValueError, RuntimeError):
                    pass

    def _ingest_security_events(self) -> None:
        for event in self.security_monitor.recent_events(20):
            fingerprint = hashlib.sha256(json.dumps({"type": event.get("event_type"), "target": event.get("target"), "task": event.get("task_id")}, sort_keys=True).encode("utf-8")).hexdigest()
            normalized = {"event_id": event.get("event_id", f"security-{uuid.uuid4().hex[:12]}"), "event_type": "SECURITY_EVENT", "path": str(event.get("target") or "security"), "timestamp": event.get("detected_at", _now_iso()), "source": event.get("source", "security_monitor"), "priority": "CRITICAL" if event.get("severity") == "CRITICAL" else "HIGH", "fingerprint": fingerprint, "authorization_scope": "service-security"}
            try:
                seen, _ = self._event_seen(normalized)
                if not seen:
                    self._mark_event(normalized, status="SECURITY_EVENT")
            except sqlite3.Error:
                continue

    def _queued_event_count(self) -> int:
        connection = sqlite3.connect(str(self.db_path))
        try:
            return int(connection.execute("SELECT COUNT(*) FROM nexus_service_events WHERE status IN ('RECEIVED', 'WAITING_RESOURCE')").fetchone()[0])
        finally:
            connection.close()

    def _event_seen(self, event: dict[str, Any]) -> tuple[bool, str]:
        fingerprint = str(event["fingerprint"])
        connection = sqlite3.connect(str(self.db_path))
        try:
            row = connection.execute("SELECT status, task_id, occurrence_count, last_seen_at FROM nexus_service_events WHERE fingerprint = ?", (fingerprint,)).fetchone()
            within_window = False
            if row is None:
                connection.execute("INSERT INTO nexus_service_events (fingerprint, event_json, status, first_seen_at, last_seen_at) VALUES (?, ?, 'RECEIVED', ?, ?)", (fingerprint, json.dumps(event, ensure_ascii=True, separators=(",", ":")), _now_iso(), _now_iso()))
            else:
                try:
                    last_seen = datetime.fromisoformat(str(row[3]).replace("Z", "+00:00"))
                    within_window = (datetime.now(timezone.utc) - last_seen).total_seconds() <= EVENT_DEDUP_WINDOW_SECONDS
                except (TypeError, ValueError):
                    within_window = True
                connection.execute("UPDATE nexus_service_events SET last_seen_at = ?, occurrence_count = occurrence_count + 1 WHERE fingerprint = ?", (_now_iso(), fingerprint))
            connection.commit()
            if row is None:
                return False, ""
            return within_window and str(row[0]) in {"RECEIVED", "TASK_CREATED", "DUPLICATE", "IGNORED", "SECURITY_EVENT"}, str(row[1]) if row else ""
        finally:
            connection.close()

    def _mark_event(self, event: dict[str, Any], *, status: str, task_id: str = "") -> None:
        connection = sqlite3.connect(str(self.db_path))
        try:
            connection.execute("UPDATE nexus_service_events SET status = ?, task_id = ?, last_seen_at = ? WHERE fingerprint = ?", (status, task_id, _now_iso(), event["fingerprint"]))
            connection.commit()
        finally:
            connection.close()

    def _event_request(self, event: dict[str, Any]) -> str:
        path = str(event["path"])
        if path.lower().endswith(".py"):
            return f"Inspect the changed authorized workspace Python file {path}, collect syntax and relevant evidence, and explain any issue. Do not modify anything."
        return f"Inspect the changed authorized workspace file {path}, collect bounded evidence, and report whether follow-up is needed. Do not modify anything."

    def _create_task_for_event(self, event: dict[str, Any]) -> dict[str, Any]:
        if len(self._active_task_ids) >= self.max_concurrent_tasks:
            self._mark_event(event, status="WAITING_RESOURCE")
            return {"status": "WAITING_RESOURCE", "event": event}
        task_result = self.task_runner.start_task(self._event_request(event))
        task_id = str(task_result.get("task_id") or "")
        if task_id:
            self._active_task_ids.add(task_id)
            record_task_event(task_id, "AUTONOMOUS_EVENT_RECEIVED", {"source_event": event, "trigger": "workspace_monitor"}, db_path=self.db_path)
            record_task_event(task_id, "AUTONOMOUS_TASK_CREATED", {"source_event": event, "goal": task_result.get("objective", self._event_request(event)), "verification_required": True}, db_path=self.db_path)
            self._mark_event(event, status="TASK_CREATED", task_id=task_id)
            if str(task_result.get("status") or "").upper() in TERMINAL_TASKS:
                self._active_task_ids.discard(task_id)
        return task_result

    def run_once(self) -> dict[str, Any]:
        with self._state_lock:
            if self._load_state().get("state") not in {"RUNNING", "DEGRADED"}:
                return {"status": "NOT_RUNNING", "events": [], "tasks": []}
            if self.monitor is None:
                degraded = self._set_state("DEGRADED", error="Monitor is not initialized.")
                return {"status": degraded["state"], "events": [], "tasks": []}
            try:
                self._sample_resources()
                self._supervise_tasks()
                self._ingest_security_events()
                resource = self._resource_snapshot
                if resource["cpu_percent"] >= self.cpu_threshold_percent or resource["memory_bytes"] >= self.memory_threshold_bytes:
                    return {"status": "RESTRICTED", "events": [], "tasks": []}
                raw_events = sorted(self.monitor.poll_events(), key=lambda item: {"CRITICAL": 0, "HIGH": 1, "NORMAL": 2, "LOW": 3}.get(event_priority(item), 3))[: self.max_events_per_cycle]
                tasks: list[dict[str, Any]] = []
                normalized_events: list[dict[str, Any]] = []
                for raw_event in raw_events:
                    try:
                        event = normalize_workspace_event(raw_event)
                    except ValueError:
                        self.security_monitor.record_event({
                            "event_type": "invalid_workspace_event",
                            "source": "autonomous_service",
                            "reason": "Workspace monitor emitted an event outside the bounded event contract.",
                            "recommended_containment": "RESTRICT",
                        })
                        continue
                    normalized_events.append(event)
                    seen, _ = self._event_seen(event)
                    if seen:
                        self._mark_event(event, status="DUPLICATE")
                        continue
                    if len(tasks) >= self.max_tasks_per_cycle:
                        self._mark_event(event, status="WAITING_RESOURCE")
                        continue
                    tasks.append(self._create_task_for_event(event))
                current = self._load_state()
                connection = sqlite3.connect(str(self.db_path))
                try:
                    connection.execute("UPDATE nexus_service_state SET loop_count = ?, updated_at = ?, active_task_id = ?, last_success_at = ? WHERE id = 1", (int(current.get("loop_count", 0) or 0) + 1, _now_iso(), next(iter(self._active_task_ids), ""), _now_iso()))
                    connection.commit()
                finally:
                    connection.close()
                return {"status": "RUNNING", "events": normalized_events, "tasks": tasks, "active_task_ids": sorted(self._active_task_ids)}
            except Exception as exc:
                self._recovery_failures += 1
                self.security_monitor.record_event({
                    "event_type": "autonomous_service_cycle_failure",
                    "source": "autonomous_service",
                    "reason": str(exc),
                    "recommended_containment": "RESTRICT" if self._recovery_failures < self.max_recovery_failures else "BLOCK",
                })
                state = "RESTRICTED" if self._recovery_failures >= self.max_recovery_failures else "DEGRADED"
                contained = self._set_state(state, error=f"Observation cycle failed: {exc}")
                return {"status": contained["state"], "events": [], "tasks": []}

    def tasks(self, limit: int = 20) -> list[dict[str, Any]]:
        return list_recent_tasks(limit=max(1, min(int(limit), 100)), db_path=self.db_path)

    def events(self, limit: int = 20) -> list[dict[str, Any]]:
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("SELECT event_json, status, task_id, last_seen_at, occurrence_count FROM nexus_service_events ORDER BY last_seen_at DESC LIMIT ?", (max(1, min(int(limit), 100)),)).fetchall()
        finally:
            connection.close()
        return [redact_sensitive_data({**json.loads(row[0]), "status": row[1], "task_id": row[2], "last_seen_at": row[3], "occurrence_count": row[4]}) for row in rows]

    def approvals(self) -> list[dict[str, Any]]:
        return list_pending_approvals(db_path=self.db_path)

    def run_forever(self, *, max_cycles: int | None = None) -> dict[str, Any]:
        cycles = 0
        while not self._stop_event.is_set():
            if max_cycles is not None and cycles >= max(0, int(max_cycles)):
                break
            self.run_once()
            cycles += 1
            if self._stop_event.wait(self.poll_interval_seconds):
                break
        return self.status()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the bounded local NEXUS autonomous observer.")
    parser.add_argument("command", choices=("start", "stop", "pause", "resume", "restart", "status", "health", "tasks", "events", "approvals", "shutdown", "run"))
    parser.add_argument("--workspace", default="workspace")
    parser.add_argument("--db", default="data/nexus_service.db")
    parser.add_argument("--cycles", type=int, default=None)
    args = parser.parse_args(argv)
    service = AutonomousService(args.workspace, db_path=args.db)
    if args.command == "start":
        result = service.start()
    elif args.command == "stop":
        result = service.stop()
    elif args.command == "pause":
        result = service.pause()
    elif args.command == "resume":
        result = service.resume()
    elif args.command == "shutdown":
        result = service.shutdown()
    elif args.command == "restart":
        result = service.restart()
    elif args.command == "health":
        result = service.health()
    elif args.command == "tasks":
        result = service.tasks()
    elif args.command == "events":
        result = service.events()
    elif args.command == "approvals":
        result = service.approvals()
    elif args.command == "run":
        service.start()
        result = service.run_forever(max_cycles=args.cycles)
    else:
        result = service.status()
    print(json.dumps(result, ensure_ascii=True, indent=2, default=str))
    return 0


__all__ = ["AutonomousService", "SERVICE_STATES", "normalize_workspace_event", "build_privacy_contract", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
