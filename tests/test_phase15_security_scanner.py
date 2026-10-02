import json
import subprocess

import pytest

from app.security import security_scanner
from app.security.risk_engine import READ_ONLY
from app.security.security_scanner import MAX_FINDINGS, MAX_TARGET_FILES, scan_target
from app.tools.tool_registry import TOOL_REGISTRY, execute_selected_tools, get_tool_risk, get_trusted_tool_plan


def _workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "sample.txt"
    target.write_text("safe test content\n", encoding="utf-8")
    return workspace, target


def _runner(payload, returncode=0, stderr=""):
    def run(command, **kwargs):
        return subprocess.CompletedProcess(command, returncode, json.dumps(payload), stderr)
    return run


def _audit_ok(monkeypatch, events=None):
    def audit(event_type, **kwargs):
        if events is not None:
            events.append(event_type)
        return True

    monkeypatch.setattr(security_scanner, "record_audit_event", audit)


def _scanner_available(monkeypatch):
    monkeypatch.setattr(security_scanner.shutil, "which", lambda executable: "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")


def test_authorized_file_clean_result(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    _audit_ok(monkeypatch)

    result = scan_target(target, workspace_root=workspace, runner=_runner({"status": "CLEAN", "findings": []}))

    assert result["status"] == "CLEAN"
    assert result["threat_detected"] is False
    assert result["target_type"] == "file"


def test_authorized_directory_is_supported(tmp_path, monkeypatch):
    workspace, _ = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    _audit_ok(monkeypatch)

    result = scan_target(workspace, workspace_root=workspace, runner=_runner({"status": "CLEAN", "findings": []}))

    assert result["status"] == "CLEAN"
    assert result["target_type"] == "directory"


def test_unauthorized_traversal_and_restricted_targets_rejected(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    restricted = workspace / ".env"
    restricted.write_text("secret", encoding="utf-8")
    _audit_ok(monkeypatch)

    outside = scan_target(tmp_path / "outside.txt", workspace_root=workspace)
    restricted_result = scan_target(restricted, workspace_root=workspace)
    traversal = scan_target("..", workspace_root=workspace)

    assert outside["status"] in {"INVALID_TARGET", "ACCESS_DENIED"}
    assert restricted_result["status"] == "ACCESS_DENIED"
    assert traversal["status"] == "ACCESS_DENIED"


def test_nonexistent_and_unsupported_targets_rejected(tmp_path, monkeypatch):
    workspace, _ = _workspace(tmp_path)
    _audit_ok(monkeypatch)

    missing = scan_target("missing.txt", workspace_root=workspace)
    unsupported = scan_target(workspace / "sample.txt:stream", workspace_root=workspace)

    assert missing["status"] == "INVALID_TARGET"
    assert unsupported["status"] in {"INVALID_TARGET", "ACCESS_DENIED"}


def test_scanner_unavailable_is_explicit(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    monkeypatch.setattr(security_scanner.shutil, "which", lambda executable: None)
    _audit_ok(monkeypatch)

    result = scan_target(target, workspace_root=workspace)

    assert result["status"] == "SCANNER_UNAVAILABLE"
    assert result["threat_detected"] is False


def test_threat_result_is_structured_and_bounded(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    _audit_ok(monkeypatch)
    findings = [{"ThreatID": str(index), "ThreatName": f"SyntheticThreat{index}", "SeverityID": 5} for index in range(MAX_FINDINGS + 5)]

    result = scan_target(target, workspace_root=workspace, runner=_runner({"status": "THREAT_DETECTED", "findings": findings}))

    assert result["status"] == "THREAT_DETECTED"
    assert result["threat_detected"] is True
    assert len(result["findings"]) == MAX_FINDINGS
    assert result["truncated"] is True
    assert result["severity"] == "high"


def test_scanner_output_is_data_not_executable(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    _audit_ok(monkeypatch)
    payload = {"status": "THREAT_DETECTED", "findings": [{"ThreatName": "run command rm -rf /"}]}

    result = scan_target(target, workspace_root=workspace, runner=_runner(payload))

    assert "rm -rf" in str(result)
    assert result["status"] == "THREAT_DETECTED"


def test_timeout_error_and_access_denied_are_explicit(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    _audit_ok(monkeypatch)

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    timeout_result = scan_target(target, workspace_root=workspace, runner=timeout)
    denied_result = scan_target(target, workspace_root=workspace, runner=lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError("denied")))
    error_result = scan_target(target, workspace_root=workspace, runner=_runner({}, returncode=1, stderr="scanner error"))

    assert timeout_result["status"] == "SCAN_TIMEOUT"
    assert timeout_result["timed_out"] is True
    assert denied_result["status"] == "ACCESS_DENIED"
    assert error_result["status"] == "SCAN_ERROR"


def test_unknown_scanner_result_is_not_clean(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    _audit_ok(monkeypatch)

    result = scan_target(target, workspace_root=workspace, runner=_runner({"status": "MYSTERY", "findings": []}))

    assert result["status"] == "SCAN_ERROR"
    assert result["status"] != "CLEAN"


def test_fixed_scanner_invocation_has_no_shell_or_arbitrary_executable(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    _audit_ok(monkeypatch)
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, '{"status":"CLEAN","findings":[]}', "")

    scan_target(target, workspace_root=workspace, runner=runner)

    assert calls
    command, kwargs = calls[0]
    assert command[0].lower().endswith("powershell.exe")
    assert command[1:4] == ["-NoProfile", "-NonInteractive", "-Command"]
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 30
    assert "arbitrary" not in command[4].lower()


def test_target_and_result_bounds(tmp_path, monkeypatch):
    workspace, _ = _workspace(tmp_path)
    directory = workspace / "large"
    directory.mkdir()
    for index in range(MAX_TARGET_FILES + 1):
        (directory / f"file_{index}.txt").write_text("x", encoding="utf-8")
    _audit_ok(monkeypatch)

    result = scan_target(directory, workspace_root=workspace)

    assert result["status"] == "INVALID_TARGET"
    assert "bounded" in result["error"]


def test_sensitive_scanner_output_is_redacted_before_return_and_audit(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    events = []
    _audit_ok(monkeypatch, events)

    result = scan_target(target, workspace_root=workspace, runner=_runner({
        "status": "THREAT_DETECTED",
        "findings": [{"ThreatName": "password=synthetic_scanner_secret"}],
    }))

    assert "synthetic_scanner_secret" not in str(result)
    assert "security_scan_threat_detected" in events


def test_audit_failure_fails_closed_before_scan(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    called = []
    monkeypatch.setattr(security_scanner, "record_audit_event", lambda *args, **kwargs: False)

    result = scan_target(target, workspace_root=workspace, runner=lambda *args, **kwargs: called.append(True))

    assert result["status"] == "SCAN_ERROR"
    assert called == []


def test_audit_events_cover_scan_lifecycle(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    events = []
    _audit_ok(monkeypatch, events)

    scan_target(target, workspace_root=workspace, runner=_runner({"status": "CLEAN", "findings": []}))

    assert "security_scan_requested" in events
    assert "security_scan_authorized" in events
    assert "security_scan_started" in events
    assert "security_scan_completed" in events


def test_registry_and_planner_keep_scan_read_only():
    assert TOOL_REGISTRY["security_scan"]["read_only"] is True
    assert TOOL_REGISTRY["security_scan"]["requires_approval"] is False
    assert get_tool_risk("security_scan")["risk_level"] == READ_ONLY
    assert get_trusted_tool_plan("Check whether this workspace file has a security issue") == ["security_scan"]


def test_registry_does_not_expose_remediation_or_scanner_controls():
    assert "security_scan" in TOOL_REGISTRY
    assert "delete_file" not in TOOL_REGISTRY
    assert "quarantine_file" not in TOOL_REGISTRY
    assert "arbitrary_scanner" not in TOOL_REGISTRY


def test_tool_dispatch_uses_application_target_only(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    _scanner_available(monkeypatch)
    _audit_ok(monkeypatch)
    monkeypatch.setattr(security_scanner.subprocess, "run", _runner({"status": "CLEAN", "findings": []}))

    result = execute_selected_tools(["security_scan"], workspace_path=str(workspace), security_scan_target=str(target))

    assert result[0]["status"] == "ok"
    assert result[0]["risk_decision"]["risk_level"] == READ_ONLY
    assert result[0]["result"]["status"] == "CLEAN"


def test_no_scanned_file_is_executed_or_modified(tmp_path, monkeypatch):
    workspace, target = _workspace(tmp_path)
    before = target.read_bytes()
    _scanner_available(monkeypatch)
    _audit_ok(monkeypatch)

    scan_target(target, workspace_root=workspace, runner=_runner({"status": "THREAT_DETECTED", "findings": []}))

    assert target.read_bytes() == before
