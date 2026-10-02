from app.agent.graph import verify_result


def test_verify_result_uses_runtime_evidence(monkeypatch, tmp_path):
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    target_file = workspace_dir / "broken_fix.py"
    target_file.write_text(
        "print('new behavior')\nraise RuntimeError('still broken')\n",
        encoding="utf-8",
    )

    monkeypatch.chdir(tmp_path)

    state = {
        "approved": True,
        "target_file": "broken_fix.py",
        "old_code": "print('old behavior')",
        "new_code": "print('new behavior')",
        "verification": "",
    }

    verify_result(state)

    assert "STATUS: RUNTIME ERROR" in state["verification"]
    assert "still broken" in state["verification"]
