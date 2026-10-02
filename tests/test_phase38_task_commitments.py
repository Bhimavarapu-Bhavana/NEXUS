from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.agent.task_commitments import deadline_conflicts, deadline_state, dependency_state, normalize_commitment_metadata, validate_deadline
from app.memory.task_ledger import create_task, get_task, update_task_commitments


def test_phase38_deadline_requires_provenance_and_confidence():
    deadline = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    evidence = [{"source": "document", "reference": "report.txt", "observed_at": "2026-09-22T00:00:00+00:00"}]
    result = validate_deadline(deadline=deadline, source="document", evidence=evidence, confidence="HIGH")
    assert result["confidence"] == "HIGH"
    assert result["evidence"] == evidence
    with pytest.raises(ValueError):
        validate_deadline(deadline=deadline, source="", evidence=evidence, confidence="HIGH")
    with pytest.raises(ValueError):
        validate_deadline(deadline=deadline, source="document", evidence=[], confidence="HIGH")


def test_phase38_deadline_states_are_deterministic():
    now = datetime(2026, 9, 22, tzinfo=timezone.utc)
    assert deadline_state(None, now=now) == "NONE"
    assert deadline_state("2026-09-21T00:00:00+00:00", now=now) == "OVERDUE"
    assert deadline_state("2026-09-22T12:00:00+00:00", now=now) == "DUE_SOON"
    assert deadline_state("2026-10-01T00:00:00+00:00", now=now) == "UPCOMING"
    assert deadline_state("invalid", now=now) == "INVALID"


def test_phase38_dependencies_and_conflicts():
    assert dependency_state(dependencies=["a", "b"], task_statuses={"a": "COMPLETED", "b": "RUNNING"}) == {"blocked": True, "blocked_by": ["b"], "dependencies": ["a", "b"]}
    tasks = [{"task_id": "a", "deadline": "2026-09-22T10:00:00+00:00"}, {"task_id": "b", "deadline": "2026-09-22T10:30:00+00:00"}]
    assert deadline_conflicts(tasks)


def test_phase38_durable_commitment_metadata_is_redacted_and_persistent(tmp_path):
    db = tmp_path / "tasks.db"
    task = create_task("Finish project report", parent_goal="Complete project", source="document", source_reference="report.txt", priority="HIGH", commitment="Submit before review", completion_criteria=["report exists", "verification passed"], db_path=db)
    deadline = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    evidence = [{"source": "document", "reference": "report.txt"}]
    updated = update_task_commitments(task["task_id"], deadline=deadline, deadline_confidence="HIGH", deadline_evidence=evidence, dependencies=["research"], associated_files=["report.txt"], db_path=db)
    assert updated["priority"] == "HIGH"
    assert updated["deadline_confidence"] == "HIGH"
    assert updated["dependencies"] == ["research"]
    assert updated["source_reference"] == "report.txt"
    assert get_task(task["task_id"], db_path=db)["deadline"] == deadline


def test_phase38_cross_task_isolation_and_invalid_priority(tmp_path):
    db = tmp_path / "tasks.db"
    first = create_task("First", db_path=db)
    second = create_task("Second", db_path=db)
    with pytest.raises(ValueError):
        update_task_commitments(first["task_id"], priority="UNSAFE", db_path=db)
    update_task_commitments(first["task_id"], source_reference="first.txt", db_path=db)
    assert get_task(second["task_id"], db_path=db)["source_reference"] == ""


def test_phase38_commitment_metadata_uses_existing_redaction():
    metadata = normalize_commitment_metadata(priority="HIGH", commitment="token=secret-value", associated_files=["passwords.txt"])
    assert metadata["priority"] == "HIGH"
    assert "secret-value" not in str(metadata)
