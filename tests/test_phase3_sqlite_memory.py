import sqlite3

from app.memory.sqlite_memory import initialize_memory, search_memory, store_memory


def test_database_initialization(tmp_path):
    db_path = tmp_path / "nexus_memory.db"
    initialize_memory(db_path)

    with sqlite3.connect(db_path) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='memory_events'"
        ).fetchall()

    assert tables == [("memory_events",)]


def test_store_and_retrieve_memory(tmp_path):
    db_path = tmp_path / "nexus_memory.db"
    record = {
        "user_request": "billing bug in shop project",
        "target_file": "shop_project.py",
        "diagnosis": "discount formula was wrong",
        "proposed_change": "change discount application",
        "verification_result": "STATUS: SUCCESS",
        "retry_count": 0,
        "success": True,
    }

    assert store_memory(record, db_path) is True

    result = search_memory("billing bug", 5, db_path)
    assert "billing bug" in result
    assert "shop_project.py" in result
    assert "STATUS: SUCCESS" in result


def test_persistence_across_runs(tmp_path):
    db_path = tmp_path / "nexus_memory.db"

    store_memory({
        "user_request": "persistent bug",
        "target_file": "demo_error.py",
        "verification_result": "STATUS: SUCCESS",
        "success": True,
    }, db_path)

    result = search_memory("persistent bug", 5, db_path)
    assert "persistent bug" in result


def test_sensitive_data_redaction(tmp_path):
    db_path = tmp_path / "nexus_memory.db"
    record = {
        "user_request": "password=supersecret and api_key=sk-ABC123456789",
        "target_file": "config.py",
        "memory_context": "token=abc123",
        "verification_result": "secret token should be redacted",
    }

    assert store_memory(record, db_path) is True

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT user_request, memory_context, verification_result FROM memory_events ORDER BY id DESC LIMIT 1"
        ).fetchone()

    assert "[REDACTED]" in row[0]
    assert "[REDACTED]" in row[1]
    assert "[REDACTED]" in row[2]


def test_parameterized_search_safely_handles_unusual_input(tmp_path):
    db_path = tmp_path / "nexus_memory.db"
    store_memory({
        "user_request": "odd request with % and _ characters",
        "target_file": "test.py",
        "verification_result": "STATUS: SUCCESS",
        "success": True,
    }, db_path)

    result = search_memory("% OR 1=1 --", 5, db_path)
    assert result == ""


def test_store_memory_fails_safely_for_invalid_database_path(tmp_path):
    db_path = tmp_path / "not_a_db_directory"
    db_path.mkdir()

    assert store_memory({"user_request": "should fail"}, db_path) is False
