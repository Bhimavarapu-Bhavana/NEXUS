from app.agent.graph import MAX_RETRIES, evaluate_verification, should_retry_verification


def test_successful_first_attempt(monkeypatch, tmp_path):
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    target_file = workspace_dir / "fix_ok.py"
    target_file.write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)

    state = {
        "approved": True,
        "target_file": "fix_ok.py",
        "retry_count": 0,
        "verification_history": [],
        "last_verification": "",
        "verification": "",
    }

    outcome = evaluate_verification(state)

    assert outcome == "success"
    assert state["retry_count"] == 0
    assert "STATUS: SUCCESS" in state["last_verification"].upper()


def test_first_attempt_fails_then_retries(monkeypatch, tmp_path):
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    target_file = workspace_dir / "fix_retry.py"
    target_file.write_text("raise RuntimeError('still broken')\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)

    state = {
        "approved": True,
        "target_file": "fix_retry.py",
        "retry_count": 0,
        "verification_history": [],
        "last_verification": "",
        "verification": "",
    }

    outcome = evaluate_verification(state)

    assert outcome == "retry"
    assert state["retry_count"] == 1
    assert len(state["verification_history"]) == 1
    assert "STATUS: RUNTIME ERROR" in state["last_verification"].upper()


def test_retry_eventually_succeeds(monkeypatch, tmp_path):
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    target_file = workspace_dir / "fix_retry_then_success.py"
    target_file.write_text("raise RuntimeError('still broken')\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)

    state = {
        "approved": True,
        "target_file": "fix_retry_then_success.py",
        "retry_count": 0,
        "verification_history": [],
        "last_verification": "",
        "verification": "",
    }

    assert evaluate_verification(state) == "retry"
    state["approved"] = True
    target_file.write_text("print('fixed')\n", encoding="utf-8")

    next_outcome = evaluate_verification(state)

    assert next_outcome == "success"
    assert state["retry_count"] == 1
    assert len(state["verification_history"]) == 2
    assert "STATUS: SUCCESS" in state["last_verification"].upper()


def test_retry_limit_stops_further_attempts(monkeypatch, tmp_path):
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()

    target_file = workspace_dir / "limit_reached.py"
    target_file.write_text("raise RuntimeError('still broken')\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)

    state = {
        "approved": True,
        "target_file": "limit_reached.py",
        "retry_count": MAX_RETRIES,
        "verification_history": ["old failure"],
        "last_verification": "old failure",
        "verification": "",
    }

    route = should_retry_verification(state)

    assert route == "stop"
    assert state["retry_count"] == MAX_RETRIES
