from app.agent.runtime_containment import execute_contained_python, validate_runtime_source
from app.tools.runtime_inspector import run_python_file


def test_runtime_policy_denies_network_and_child_process_capabilities(tmp_path):
    network = tmp_path / "network.py"
    network.write_text("import socket\nsocket.socket()\n", encoding="utf-8")
    allowed, reason = validate_runtime_source(network)
    assert allowed is False
    assert "denied" in reason.lower()

    child = tmp_path / "child.py"
    child.write_text("import subprocess\nsubprocess.run([])\n", encoding="utf-8")
    allowed, reason = validate_runtime_source(child)
    assert allowed is False
    assert "denied" in reason.lower()


def test_runtime_stays_confined_and_reports_structured_containment(tmp_path):
    target = tmp_path / "safe.py"
    target.write_text("print('contained')\n", encoding="utf-8")
    result = run_python_file(str(tmp_path), "safe.py", timeout_seconds=5)
    assert "FILE: safe.py" in result
    assert any(status in result for status in ("STATUS: SUCCESS", "STATUS: RUNTIME_CONTAINMENT_UNAVAILABLE"))


def test_runtime_escape_target_is_rejected(tmp_path):
    result = run_python_file(str(tmp_path), "..\\outside.py")
    assert "outside the authorized workspace" in result
