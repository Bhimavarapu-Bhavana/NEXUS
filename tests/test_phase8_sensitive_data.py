import sqlite3
import subprocess

import pytest

from app.memory.sqlite_memory import search_memory, store_memory
from app.security.sensitive_data import (
    REDACTION_MARKER,
    contains_sensitive_data,
    redact_sensitive_data,
)
from app.tools.git_inspector import inspect_git_repository
from app.tools.log_inspector import inspect_log_file
from app.tools.terminal_inspector import analyze_terminal_output
from app.tools.tool_registry import TOOL_REGISTRY, execute_selected_tools, validate_tool_plan


def _git(workspace, *arguments):
    return subprocess.run(
        ["git", *arguments],
        cwd=str(workspace),
        check=True,
        capture_output=True,
        text=True,
    )


def _repository(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.email", "nexus@example.test")
    _git(workspace, "config", "user.name", "NEXUS Test")
    (workspace / "tracked.py").write_text("print('base')\n", encoding="utf-8")
    _git(workspace, "add", "tracked.py")
    _git(workspace, "commit", "-q", "-m", "initial commit")
    return workspace


def test_common_credentials_are_redacted():
    text = (
        "api_key=synthetic_api_value_12345 "
        "Authorization: Bearer synthetic_bearer_value "
        "password=synthetic_password_value"
    )

    protected = redact_sensitive_data(text)

    assert REDACTION_MARKER in protected
    assert "synthetic_api_value_12345" not in protected
    assert "synthetic_bearer_value" not in protected
    assert "synthetic_password_value" not in protected


def test_private_key_and_connection_password_are_redacted():
    text = (
        "-----BEGIN PRIVATE KEY-----\nsynthetic_private_material\n"
        "-----END PRIVATE KEY-----\n"
        "postgresql://user:synthetic_db_password@localhost/app"
    )

    protected = redact_sensitive_data(text)

    assert "synthetic_private_material" not in protected
    assert "synthetic_db_password" not in protected
    assert "localhost/app" in protected


def test_nested_structures_are_protected_without_mutating_input():
    original = {
        "safe": "keep this",
        "credentials": {
            "token": "synthetic_nested_token",
            "items": ["synthetic_list_secret_value", {"password": "synthetic_nested_password"}],
        },
    }

    protected = redact_sensitive_data(original)

    assert original["credentials"]["token"] == "synthetic_nested_token"
    assert protected["safe"] == "keep this"
    assert protected["credentials"]["token"] == REDACTION_MARKER
    assert protected["credentials"]["items"][0] == REDACTION_MARKER
    assert protected["credentials"]["items"][1]["password"] == REDACTION_MARKER
    assert contains_sensitive_data(original) is True
    assert contains_sensitive_data("ordinary documentation") is False


def test_placeholders_and_non_sensitive_text_are_preserved():
    text = 'password = "hello"; documentation says password fields exist'

    protected = redact_sensitive_data(text)

    assert protected == text


def test_multiple_secrets_and_cloud_formats_are_redacted():
    text = "AKIA1234567890ABCDEF ghp_synthetic_token_value_123456 sk-synthetic_key_value_12345"

    protected = redact_sensitive_data(text)

    assert protected.count(REDACTION_MARKER) == 3
    assert "AKIA1234567890ABCDEF" not in protected
    assert "ghp_synthetic_token_value_123456" not in protected
    assert "sk-synthetic_key_value_12345" not in protected


def test_memory_redacts_before_sqlite_persistence_and_search(tmp_path):
    db_path = tmp_path / "memory.db"
    secret = "synthetic_memory_secret_12345"
    assert store_memory(
        {
            "user_request": f"api_key={secret}",
            "target_file": "config.py",
            "diagnosis": f"password={secret}",
            "proposed_change": f"token={secret}",
            "action_result": secret,
            "verification_result": secret,
            "memory_context": secret,
        },
        db_path,
    ) is True

    with sqlite3.connect(db_path) as connection:
        row = connection.execute("SELECT * FROM memory_events").fetchone()

    assert secret not in str(row)
    assert REDACTION_MARKER in str(row)
    assert secret not in search_memory(secret, db_path=db_path)


def test_terminal_evidence_is_redacted():
    result = analyze_terminal_output("Authorization: Bearer synthetic_terminal_token")

    assert "synthetic_terminal_token" not in str(result)
    assert REDACTION_MARKER in result["stderr"] or REDACTION_MARKER in result["stdout"]


def test_log_evidence_is_redacted(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.log").write_text("password=synthetic_log_password\n", encoding="utf-8")

    result = inspect_log_file(str(workspace), "app.log")

    assert "synthetic_log_password" not in result["content"]
    assert REDACTION_MARKER in result["content"]


def test_git_evidence_is_redacted(tmp_path):
    workspace = _repository(tmp_path)
    _git(workspace, "commit", "--allow-empty", "-q", "-m", "api_key=synthetic_git_secret")

    result = inspect_git_repository(str(workspace))

    assert "synthetic_git_secret" not in str(result)
    assert REDACTION_MARKER in str(result)


def test_registry_protects_structured_tool_results(monkeypatch):
    def fake_tool(**kwargs):
        return {"nested": [{"secret": "synthetic_tool_secret"}], "safe": "visible"}

    monkeypatch.setitem(TOOL_REGISTRY, "workspace_inspector", {
        "function": fake_tool,
        "description": "test",
        "read_only": True,
        "requires_approval": False,
        "allowed": True,
    })

    result = execute_selected_tools(["workspace_inspector"])[0]["result"]

    assert result["nested"][0]["secret"] == REDACTION_MARKER
    assert result["safe"] == "visible"


def test_diagnosis_boundary_redacts_request_and_evidence(monkeypatch):
    from app.tools import diagnoser

    captured = []

    class Response:
        content = "DIAGNOSIS:\nNo secret returned."

    def fake_invoke(messages):
        captured.extend(messages)
        return Response()

    class FakeLLM:
        invoke = staticmethod(fake_invoke)

    monkeypatch.setattr(diagnoser, "llm", FakeLLM())
    diagnoser.diagnose_problem(
        "Investigate api_key=synthetic_diagnosis_secret",
        "terminal output: token=synthetic_diagnosis_secret",
    )

    message_text = str(captured)
    assert "synthetic_diagnosis_secret" not in message_text
    assert REDACTION_MARKER in message_text


def test_detection_does_not_execute_values(monkeypatch):
    class DangerousValue:
        def __str__(self):
            raise AssertionError("value was unexpectedly serialized")

    value = DangerousValue()
    assert redact_sensitive_data(value) is value

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("sensitive-data detection executed a command")
    ))
    assert redact_sensitive_data("token=synthetic_value") == f"token={REDACTION_MARKER}"


def test_restricted_paths_and_approval_remain_intact(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    restricted = workspace / ".git"
    restricted.mkdir()
    (restricted / "secrets.log").write_text("token=synthetic", encoding="utf-8")

    with pytest.raises(ValueError):
        inspect_log_file(str(workspace), ".git/secrets.log")

    assert validate_tool_plan(["fixer", "terminal_inspector"]) == ["terminal_inspector"]
