from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from app.security.permissions import is_authorized_path

IGNORED_DIRECTORIES = {
    ".env",
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
}

RELEVANT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".c",
    ".cpp",
    ".h",
    ".json",
    ".md",
    ".html",
    ".css",
    ".txt",
}

DEFAULT_MAX_PENDING_EVENTS = 50
DEFAULT_DEBOUNCE_SECONDS = 1.0


def _is_restricted(relative_path: Path) -> bool:
    return any(part in IGNORED_DIRECTORIES for part in relative_path.parts)


def _is_relevant(relative_path: Path) -> bool:
    if relative_path.name.startswith("."):
        return False
    return relative_path.suffix.lower() in RELEVANT_EXTENSIONS or relative_path.name.lower() in {"readme", "requirements.txt"}


def _normalize_path(root: Path, candidate: str | os.PathLike[str]) -> str:
    requested = Path(candidate).resolve()
    if not is_authorized_path(str(requested)):
        raise ValueError("Requested path is outside the authorized workspace.")
    relative = requested.relative_to(root)
    return str(relative).replace("\\", "/")


def _snapshot_workspace(workspace_path: str) -> dict[str, tuple[int, int, int]]:
    root = Path(workspace_path).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Workspace does not exist: {workspace_path}")

    snapshot: dict[str, tuple[int, int]] = {}
    for file_path in root.rglob("*"):
        if file_path.is_dir():
            continue
        if any(part in IGNORED_DIRECTORIES for part in file_path.relative_to(root).parts):
            continue
        if not _is_relevant(file_path.relative_to(root)):
            continue
        stat_result = file_path.stat()
        snapshot[str(file_path.relative_to(root)).replace("\\", "/")] = (int(stat_result.st_mtime_ns), int(stat_result.st_ctime_ns), int(stat_result.st_size))
    return snapshot


class WorkspaceMonitor:
    """Read-only workspace monitor with a bounded snapshot-diff approach."""

    def __init__(
        self,
        workspace_path: str = "workspace",
        max_pending_events: int = DEFAULT_MAX_PENDING_EVENTS,
        debounce_seconds: float = DEFAULT_DEBOUNCE_SECONDS,
    ):
        self.workspace_path = workspace_path
        self.root = Path(workspace_path).resolve()
        self.max_pending_events = max_pending_events
        self.debounce_seconds = debounce_seconds
        self._running = False
        self._baseline = _snapshot_workspace(self.workspace_path)
        self._coalesced_keys: dict[tuple[str, str], float] = {}

    def start(self) -> None:
        self._running = True
        self._baseline = _snapshot_workspace(self.workspace_path)
        self._coalesced_keys = {}

    def stop(self) -> None:
        self._running = False

    def poll_events(self) -> list[dict[str, str]]:
        if not self._running:
            return []

        current = _snapshot_workspace(self.workspace_path)
        events: list[dict[str, str]] = []

        for relative_path, modified_at in current.items():
            previous = self._baseline.get(relative_path)
            if previous is None:
                events.append({
                    "event_type": "FILE_CREATED",
                    "path": relative_path,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })

        for relative_path, previous_at in self._baseline.items():
            current_at = current.get(relative_path)
            if current_at is None:
                events.append({
                    "event_type": "FILE_DELETED",
                    "path": relative_path,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
            elif current_at != previous_at:
                events.append({
                    "event_type": "FILE_MODIFIED",
                    "path": relative_path,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })

        coalesced: list[dict[str, str]] = []
        for event in events:
            key = (event["path"], event["event_type"])
            last_seen = self._coalesced_keys.get(key)
            now = time.time()
            if last_seen is not None and (now - last_seen) < self.debounce_seconds:
                self._coalesced_keys[key] = now
                continue
            self._coalesced_keys[key] = now
            coalesced.append(event)

        self._baseline = current

        if len(coalesced) > self.max_pending_events:
            coalesced = coalesced[: self.max_pending_events]
            coalesced.append({
                "event_type": "QUEUE_LIMIT_REACHED",
                "path": "",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

        return coalesced


def detect_workspace_events(workspace_path: str, baseline_snapshot: dict[str, float] | None = None) -> list[dict[str, str]]:
    """Return relevant, read-only filesystem events for the authorized workspace."""

    root = Path(workspace_path).resolve()
    if not is_authorized_path(str(root)):
        raise ValueError("Workspace must stay inside the authorized workspace.")

    current = _snapshot_workspace(workspace_path)
    if baseline_snapshot is None:
        return []

    events: list[dict[str, str]] = []

    for relative_path, modified_at in current.items():
        previous = baseline_snapshot.get(relative_path)
        if previous is None:
            events.append({
                "event_type": "FILE_CREATED",
                "path": relative_path,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

    for relative_path, previous_at in baseline_snapshot.items():
        current_at = current.get(relative_path)
        if current_at is None:
            events.append({
                "event_type": "FILE_DELETED",
                "path": relative_path,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
        elif current_at != previous_at:
            events.append({
                "event_type": "FILE_MODIFIED",
                "path": relative_path,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })

    deduped: dict[tuple[str, str], dict[str, str]] = {}
    for event in events:
        key = (event["path"], event["event_type"])
        deduped[key] = event

    return list(deduped.values())[:DEFAULT_MAX_PENDING_EVENTS]
