from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.agent.evidence import SOURCE_SEMANTICS, correlate_evidence, normalize_tool_results
from app.agent.graph import _classify_request_intent, nexus_graph, should_create_proposal
from app.calendar.actions import calendar_event_action, parse_calendar_request
from app.calendar.fixtures import build_default_fixture_events
from app.calendar.models import CalendarEvent, normalize_calendar_event, parse_calendar_datetime
from app.calendar.providers import FixtureCalendarProvider, PROVIDER_REGISTRY, get_provider, get_provider_names
from app.calendar.service import (
    attach_calendar_deadline_to_task,
    build_calendar_evidence_list,
    calendar_deadline_state,
    calendar_event_evidence,
    calendar_operation_read_only,
    classify_calendar_operation,
    create_task_from_calendar_event,
    deadline_candidates,
    deadline_conflicts_with_tasks,
    detect_upcoming_events,
    get_calendar_event,
    list_calendar_events,
    overlapping_events,
    provider_observatory,
)
from app.memory.task_ledger import create_task, get_task
from app.security.risk_engine import BLOCKED, MEDIUM_RISK, READ_ONLY, evaluate_risk
from app.security.sensitive_data import redact_sensitive_data
from app.tools.tool_registry import (
    ALLOWED_MODIFICATION_TOOLS,
    TOOL_REGISTRY,
    execute_selected_tools,
    get_trusted_tool_plan,
    validate_tool_plan,
)

RETRO_TITLE = "Retro Phase 40"
RETRO_START = "2030-06-15T10:00:00+00:00"


FIXTURE_NOW = datetime(2026, 9, 22, 10, 15, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _reset_fixture_provider():
    PROVIDER_REGISTRY.register(FixtureCalendarProvider(now=FIXTURE_NOW))
    yield
    PROVIDER_REGISTRY.register(FixtureCalendarProvider(now=FIXTURE_NOW))


def _provider():
    return get_provider("fixture")


def _deadline_event() -> dict:
    return _provider().get_event("fixture-event-0001").to_dict()


def _daytime(now: datetime) -> datetime:
    return now.replace(hour=10, minute=15, second=0, microsecond=0)


# ----------------------------------------------------------------------
# Provider-independent event normalization
# ----------------------------------------------------------------------


def test_normalize_valid_calendar_event():
    event = normalize_calendar_event(
        {
            "event_id": "x-1",
            "title": "Quarterly review",
            "start_time": "2031-01-05T09:00:00-05:00",
            "end_time": "2031-01-05T10:30:00-05:00",
            "timezone": "America/New_York",
            "confidence": "HIGH",
            "status": "CONFIRMED",
        },
        provider="fixture",
    )
    assert event.event_id == "x-1"
    assert event.start_time.tzinfo is not None
    assert event.start_time == datetime(2031, 1, 5, 14, 0, tzinfo=timezone.utc)
    assert event.provenance["origin"] == "calendar_event"
    assert event.provenance["provider"] == "fixture"
    assert event.provenance["extraction_method"] == "provider_normalized_event"


def test_normalize_invalid_events_fail_closed():
    with pytest.raises(ValueError):
        normalize_calendar_event({"event_id": "x", "title": "", "start_time": "2031-01-05T09:00:00+00:00"}, provider="fixture")
    with pytest.raises(ValueError):
        normalize_calendar_event({"event_id": "x", "title": "x", "start_time": "not-a-time"}, provider="fixture")
    with pytest.raises(ValueError):
        normalize_calendar_event({"event_id": "x", "title": "x", "start_time": "2031-01-05T09:00:00+00:00", "end_time": "2031-01-05T08:00:00+00:00"}, provider="fixture")


def test_missing_end_time_is_tolerated_without_invented_data():
    event = normalize_calendar_event({"event_id": "x-2", "title": "Reminder", "start_time": "2031-01-05T09:00:00+00:00"}, provider="fixture")
    assert event.end_time is None
    assert event.summary == ""


def test_timestamp_parser_accepts_iso_and_space_forms():
    a = parse_calendar_datetime("2031-02-02T09:30:00+00:00")
    b = parse_calendar_datetime("2031-02-02T09:30:00Z")
    c = parse_calendar_datetime("2031-02-02 09:30:00+05:30")
    d = parse_calendar_datetime("2031-02-02 09:30:00")
    assert a == b
    assert c == datetime(2031, 2, 2, 4, 0, tzinfo=timezone.utc)
    assert d == a


# ----------------------------------------------------------------------
# Provider isolation, determinism, dedupe, malformed data
# ----------------------------------------------------------------------


def test_fixture_provider_is_deterministic_and_dedupes():
    events = build_default_fixture_events()
    provider = FixtureCalendarProvider(events)
    listed = provider.list_events()
    ids = [event.event_id for event in listed]
    assert len(ids) == len(set(ids))
    assert all(event.status != "CANCELLED" for event in listed)
    provider2 = FixtureCalendarProvider(build_default_fixture_events())
    assert [e.event_id for e in listed] == [e.event_id for e in provider2.list_events()]


def test_malformed_and_hostile_fixture_entries_are_recorded_not_trusted():
    provider = FixtureCalendarProvider(build_default_fixture_events())
    assert provider.errors()
    hostile = [e for e in provider.list_events() if e.event_id == "fixture-event-0004"]
    assert len(hostile) == 1
    assert hostile[0].untrusted is True
    assert hostile[0].description
    assert "delete-everything" in hostile[0].description


def test_fixture_provider_never_requires_or_stores_credentials():
    info = _provider().credentials_info()
    assert info["requires_credentials"] is False
    assert info["stores_credentials"] is False
    assert info["oauth"] is False
    assert info["external_connection"] is False
    assert "sk-test" not in json.dumps(info)


# ----------------------------------------------------------------------
# Read-only service capabilities with provenance
# ----------------------------------------------------------------------


def test_list_events_returns_redacted_sorted_events_with_provenance():
    events = list_calendar_events(now=_daytime(datetime(2026, 9, 22, tzinfo=timezone.utc)))
    assert events
    assert events == sorted(events, key=lambda e: (e["start_time"], e["event_id"]))
    assert all(event["provenance"]["origin"] == "calendar_event" for event in events)
    assert "sk-test" not in json.dumps(events)


def test_read_paths_do_not_mutate_calendar_state():
    provider = get_provider("fixture")
    before = {e.event_id: e.snapshot() for e in provider.list_events()}
    list_calendar_events(now=datetime(2026, 9, 22, tzinfo=timezone.utc))
    assert get_calendar_event("fixture", "fixture-event-0001") is not None
    detect_upcoming_events(now=datetime(2026, 9, 22, tzinfo=timezone.utc))
    deadline_candidates(now=datetime(2026, 9, 22, tzinfo=timezone.utc))
    after = {e.event_id: e.snapshot() for e in provider.list_events()}
    assert before == after


def test_upcoming_events_window_and_deadline_only_filter():
    now = _daytime(datetime(2026, 9, 22, tzinfo=timezone.utc))
    upcoming = detect_upcoming_events(now=now, window_hours=24 * 7)
    past_event_ids = {"fixture-event-0008"}
    assert not (past_event_ids & {e["event_id"] for e in upcoming})
    deadline_only = detect_upcoming_events(now=now, window_hours=24 * 14, deadline_only=True)
    assert {e["event_id"] for e in deadline_only} <= {"fixture-event-0001", "fixture-event-0005"}
    assert all(e["is_deadline"] for e in deadline_only)


def test_deadline_candidates_retain_provenance():
    now = _daytime(datetime(2026, 9, 22, tzinfo=timezone.utc))
    candidates = deadline_candidates(now=now)
    assert candidates
    assert all(entry["is_deadline"] for entry in candidates)
    assert all(entry["provenance"]["origin"] == "calendar_event" for entry in candidates)


def test_provider_observatory_single_bounded_snapshot():
    obs = provider_observatory(now=_daytime(datetime(2026, 9, 22, tzinfo=timezone.utc)))
    assert obs["status"] == "OK"
    assert obs["provider"] == "fixture"
    assert obs["provenance"]["read_only"] is True
    assert obs["event_count"] == len(obs["events"])
    assert isinstance(obs["conflicts"], list)
    assert "sk-test" not in json.dumps(obs)


# ----------------------------------------------------------------------
# Deterministic conflict detection
# ----------------------------------------------------------------------


def test_overlapping_events_detected_only_when_verified():
    now = _daytime(datetime(2026, 9, 22, tzinfo=timezone.utc))
    events = list_calendar_events(now=now)
    conflicts = overlapping_events(events, now=now)
    pair = {(c["left_event_id"], c["right_event_id"]) for c in conflicts}
    assert ("fixture-event-0002", "fixture-event-0003") in pair
    assert all(c["basis"] == "verified_interval_only" for c in conflicts)
    assert all(c["relationship"] == "overlap" for c in conflicts)


def test_events_without_end_time_are_excluded_from_interval_conflicts():
    now = _daytime(datetime(2026, 9, 22, tzinfo=timezone.utc))
    events = list_calendar_events(now=now)
    reminders = [e for e in events if not e["end_time"]]
    assert reminders
    combined = overlapping_events(reminders, now=now)
    assert combined == []


def test_deadline_conflicts_with_tasks_uses_ledger_timestamps():
    now = _daytime(datetime(2026, 9, 22, tzinfo=timezone.utc))
    event = _deadline_event()
    near = {"task_id": "t-near", "deadline": event["start_time"]}
    far = {"task_id": "t-far", "deadline": "2031-05-01T09:00:00+00:00"}
    conflicts = deadline_conflicts_with_tasks([event], [near, far])
    assert {c["task_id"] for c in conflicts} == {"t-near"}
    assert all(c["basis"] == "deadline_evidence_timestamps" for c in conflicts)


# ----------------------------------------------------------------------
# Read vs mutation classification
# ----------------------------------------------------------------------


def test_read_operations_classify_clean():
    for operation in ("read", "list", "get"):
        decision = classify_calendar_operation(operation)
        assert decision["read_only"] is True
        assert decision["allowed"] is True
        assert decision["approval_required"] is False
        assert calendar_operation_read_only(operation) is True


def test_mutations_classify_as_approval_required():
    for operation in ("create", "update", "delete", "cancel"):
        decision = classify_calendar_operation(operation)
        assert decision["read_only"] is False
        assert decision["approval_required"] is True
        assert decision["risk_level"] == MEDIUM_RISK


def test_unknown_operations_fail_closed():
    decision = classify_calendar_operation("drop_table")
    assert decision["allowed"] is False
    assert decision["risk_level"] == BLOCKED
    assert calendar_operation_read_only("drop_table") is False


# ----------------------------------------------------------------------
# Security: risk engine, evidence semantics, redaction
# ----------------------------------------------------------------------


def test_calendar_observer_is_read_only_evidence():
    decision = evaluate_risk("observe the calendar", tool_name="calendar_observer")
    assert decision["risk_level"] == READ_ONLY
    assert decision["allowed"] is True
    assert decision["approval_required"] is False


def test_calendar_event_action_requires_approval():
    decision = evaluate_risk("execute calendar_event_action", tool_name="calendar_event_action")
    assert decision["risk_level"] == MEDIUM_RISK
    assert decision["allowed"] is True
    assert decision["approval_required"] is True
    assert decision.get("category") == "CALENDAR_ACTION"


def test_calendar_evidence_is_data_not_instructions():
    assert "calendar_observer" in SOURCE_SEMANTICS
    assert "cal_event" not in SOURCE_SEMANTICS.get("calendar_observer", "").lower() or "not an instruction" in SOURCE_SEMANTICS["calendar_observer"]
    assert "untrusted" in SOURCE_SEMANTICS["calendar_observer"]


def test_calendar_observer_tool_result_normalizes_as_calendar_category():
    results = execute_selected_tools(["calendar_observer"], calendar_provider="fixture")
    assert results[0]["risk_decision"]["risk_level"] == READ_ONLY
    normalized = normalize_tool_results(results)
    assert normalized
    assert normalized[0]["category"] == "calendar"
    correlated = correlate_evidence(normalized)
    assert len(correlated["correlations"]) >= 1
    assert "data, never instructions" in normalized[0]["source_semantics"]
    assert "sk-test" not in json.dumps(normalized)


def test_events_evidence_redacts_secrets_not_content_shape():
    event = _provider().get_event("fixture-event-0005").to_dict()
    evidence = calendar_event_evidence(event)
    assert "sk-test" not in json.dumps(evidence)
    assert evidence["source_type"] == "calendar"
    assert evidence["observation_type"] == "CALENDAR_EVENT"
    assert evidence["correlation_key"].startswith("calendar:")
    built = build_calendar_evidence_list([event])
    assert len(built) == 1


# ----------------------------------------------------------------------
# Mutations are bounded and approval-gated
# ----------------------------------------------------------------------


def test_mutation_tool_demands_structured_spec():
    blocked = calendar_event_action(None, approved=True)
    assert blocked["status"] == "BLOCKED"
    assert blocked["verification"] == "NOT_RUN"


def test_unknown_operation_is_blocked():
    blocked = calendar_event_action({"operation": "drop_table", "title": "x"}, approved=True)
    assert blocked["status"] == "BLOCKED"


def test_read_operations_never_route_through_mutation_tool():
    for operation in ("read", "list", "get"):
        blocked = calendar_event_action({"operation": operation}, approved=True)
        assert blocked["status"] == "BLOCKED"


def test_create_requires_approval():
    spec = {"operation": "create", "title": RETRO_TITLE, "start_time": RETRO_START}
    result = calendar_event_action(spec, approved=False)
    assert result["status"] == "APPROVAL_REQUIRED"
    assert result["verification"] == "NOT_RUN"
    assert all(e.title != RETRO_TITLE for e in _provider().list_events())


def test_create_fails_closed_without_title_or_time():
    assert calendar_event_action({"operation": "create", "start_time": RETRO_START}, approved=True)["status"] == "BLOCKED"
    assert calendar_event_action({"operation": "create", "title": "x"}, approved=True)["status"] == "BLOCKED"


def test_approved_create_is_completed_and_persisted():
    before = {e.event_id for e in _provider().list_events()}
    spec = {"operation": "create", "title": RETRO_TITLE, "start_time": RETRO_START}
    result = calendar_event_action(spec, approved=True)
    assert result["status"] == "COMPLETED"
    assert result["verification"] == "SUCCESS"
    assert result["event_id"] not in before
    assert "sk-test" not in json.dumps(result)
    created = _provider().get_event(result["event_id"])
    assert created.title == RETRO_TITLE
    assert created.start_time == parse_calendar_datetime(RETRO_START)


def test_update_requires_matching_observation_snapshot():
    event = _provider().get_event("fixture-event-0001")
    stale = {
        "operation": "update",
        "event_id": event.event_id,
        "grounded_snapshot": {
            "event_id": event.event_id,
            "title": "Wrong title",
            "start_time": "2030-01-01T00:00:00+00:00",
        },
        "start_time": "2031-03-03T09:00:00+00:00",
    }
    result = calendar_event_action(stale, approved=True)
    assert result["status"] == "BLOCKED"
    assert "changed before execution" in result["action_result"].lower()


def test_cancel_and_delete_require_observed_event():
    never = {"operation": "cancel", "event_id": "ghost-event", "grounded_snapshot": {"event_id": "ghost-event", "title": "Ghost", "start_time": "2031-01-01T00:00:00+00:00"}}
    assert calendar_event_action(never, approved=True)["status"] == "BLOCKED"
    target = _provider().get_event("fixture-event-0002")
    good = {"operation": "cancel", "event_id": target.event_id, "grounded_snapshot": target.snapshot()}
    result = calendar_event_action(good, approved=True)
    assert result["status"] == "COMPLETED"
    assert _provider().get_event(target.event_id).status == "CANCELLED"
    delete_target = _provider().get_event("fixture-event-0006")
    result = calendar_event_action({"operation": "delete", "event_id": delete_target.event_id, "grounded_snapshot": delete_target.snapshot()}, approved=True)
    assert result["status"] == "COMPLETED"
    assert _provider().get_event(delete_target.event_id) is None


def test_approved_update_reschedules_preserving_duration():
    event = _provider().get_event("fixture-event-0001")
    spec = {
        "operation": "update",
        "event_id": event.event_id,
        "grounded_snapshot": event.snapshot(),
        "start_time": "2031-01-01T09:00:00+00:00",
    }
    result = calendar_event_action(spec, approved=True)
    assert result["status"] == "COMPLETED"
    updated = _provider().get_event(event.event_id)
    assert updated.start_time == datetime(2031, 1, 1, 9, 0, tzinfo=timezone.utc)
    assert updated.end_time - updated.start_time == event.end_time - event.start_time


# ----------------------------------------------------------------------
# Deterministic request grounding (fail closed)
# ----------------------------------------------------------------------


def test_parse_create_requires_explicit_time_and_title():
    assert parse_calendar_request("Add a meeting tomorrow at 3pm", []) is None
    assert parse_calendar_request("Add an event titled Party tonight", []) is None
    spec = parse_calendar_request(f"Add a calendar event titled {RETRO_TITLE} on 2030-06-15 at 10:00:00+00:00", [])
    assert spec["operation"] == "create"
    assert spec["title"] == RETRO_TITLE
    assert spec["start_time"] == "2030-06-15T10:00:00+00:00"


def test_parse_update_requires_grounded_observed_event():
    observed = [_provider().get_event("fixture-event-0001").to_dict()]
    spec = parse_calendar_request("Update the event Project report due to 2031-01-01T09:00:00+00:00", observed)
    assert spec["operation"] == "update"
    assert spec["event_id"] == "fixture-event-0001"
    assert spec["grounded_snapshot"]["title"] == "Project report due"
    assert parse_calendar_request("Update the event Never seen to 2031-01-01T09:00:00+00:00", observed) is None
    assert parse_calendar_request("Not a calendar request at all", observed) is None


# ----------------------------------------------------------------------
# Phase 38 task ledger integration with distinguishable provenance
# ----------------------------------------------------------------------


def test_create_task_from_calendar_deadline_event(tmp_path):
    db = os.path.join(str(tmp_path), "ledger.db")
    event = _deadline_event()
    task = create_task_from_calendar_event(event, db_path=db)
    assert task["source"] == "calendar"
    assert task["source_reference"].startswith("calendar:fixture:")
    assert task["deadline"] == event["start_time"]
    assert task["deadline_confidence"] == event["confidence"]
    evidence = task["deadline_evidence"]
    assert evidence
    assert evidence[0]["origin"] == "calendar_event"
    assert evidence[0]["evidence_type"] == "calendar_derived_deadline"
    assert evidence[0]["event_id"] == event["event_id"]
    persisted = get_task(task["task_id"], db_path=db)
    assert persisted["deadline"] == event["start_time"]


def test_attach_calendar_deadline_preserves_existing_commitments(tmp_path):
    db = os.path.join(str(tmp_path), "ledger.db")
    task = create_task("Prepare release notes", source="user", priority="NORMAL", commitment="Draft notes before cut-off", db_path=db)
    event = _provider().get_event("fixture-event-0005").to_dict()
    updated = attach_calendar_deadline_to_task(task["task_id"], event, db_path=db)
    assert updated["deadline"] == event["start_time"]
    assert updated["commitment"] == "Draft notes before cut-off"
    assert any(item.get("evidence_type") == "calendar_derived_deadline" for item in updated["deadline_evidence"])
    assert calendar_deadline_state(event) in {"OVERDUE", "DUE_SOON", "UPCOMING"}


def test_attach_deadline_rejects_missing_task(tmp_path):
    db = os.path.join(str(tmp_path), "ledger.db")
    with pytest.raises(ValueError):
        attach_calendar_deadline_to_task("nope", _deadline_event(), db_path=db)


# ----------------------------------------------------------------------
# Tool registration and plan selection
# ----------------------------------------------------------------------


def test_calendar_tools_registered_with_read_mutation_split():
    observer = TOOL_REGISTRY["calendar_observer"]
    action = TOOL_REGISTRY["calendar_event_action"]
    assert observer["read_only"] is True
    assert observer["requires_approval"] is False
    assert observer["capability"] == "CALENDAR_OBSERVE"
    assert action["read_only"] is False
    assert action["requires_approval"] is True
    assert action["capability"] == "CALENDAR_MUTATE"
    assert "calendar_event_action" in ALLOWED_MODIFICATION_TOOLS


def test_calendar_requests_plan_to_read_only_observer():
    assert get_trusted_tool_plan("What events do I have this week? Upcoming deadlines") == ["calendar_observer"]
    assert get_trusted_tool_plan("Delete the event Client reminder from the calendar") == ["calendar_observer"]
    plan = validate_tool_plan(["calendar_observer"])
    assert plan == ["calendar_observer"]


# ----------------------------------------------------------------------
# StateGraph integration
# ----------------------------------------------------------------------


def test_intent_classifier_and_proposal_routing():
    mutation = _classify_request_intent("Add a meeting on my calendar for tomorrow at 3pm")
    assert mutation == "CALENDAR_ACTION_REQUEST"
    state = {"request_intent": mutation, "user_constraints": {"do_not_modify": False, "do_not_propose_fixes": False}}
    assert should_create_proposal(state) == "create_action_proposal"
    read_only = _classify_request_intent("Show me the upcoming events and deadlines")
    assert read_only != "CALENDAR_ACTION_REQUEST"


def _graph_state(db: str) -> dict:
    return {
        "user_request": "",
        "observations": [], "priority": "", "selected_tool": "", "investigation": [], "plan": [],
        "target_file": "", "old_code": "", "new_code": "", "approval_required": False, "approved": True,
        "approval_override": "APPROVED", "action_result": "", "verification": "", "retry_count": 0,
        "verification_history": [], "last_verification": "", "memory_context": "", "selected_tools": [],
        "tool_results": [], "workspace_event": "", "monitoring_active": True, "decision_stage": "REQUEST",
        "decision_reason": "", "final_outcome": "", "risk_decision": {}, "audit_error": "", "browser_url": "",
        "normalized_evidence": [], "evidence_correlations": [], "evidence_conflicts": [], "reasoning_context": "",
        "goal_plan": [], "goal_error": "", "task_id": "", "task_status": "", "task_resume_requested": False,
        "task_resume_reason": "", "task_context": "",
        "persistence_db_path": db, "approval_db_path": db, "journal_db_path": db,
    }


def test_graph_end_to_end_approved_calendar_create(tmp_path):
    db = os.path.join(str(tmp_path), "ledger.db")
    title = f"GraphRetro {uuid.uuid4().hex[:8]}"
    state = _graph_state(db)
    state["user_request"] = f"Add a calendar event titled {title} on 2030-06-15 at 10:00:00+00:00"
    result = nexus_graph.invoke(state)
    assert result["action_tool"] == "calendar_event_action"
    assert result["risk_decision"]["risk_level"] == MEDIUM_RISK
    assert result["approved"] is True
    assert str(result["verification"]) == "SUCCESS"
    assert result["action_result"].get("status") == "COMPLETED" if isinstance(result["action_result"], dict) else True
    assert any(event.title == title for event in _provider().list_events())


def test_graph_end_to_end_rejected_calendar_create_does_nothing(tmp_path):
    db = os.path.join(str(tmp_path), "ledger.db")
    title = f"GraphReject {uuid.uuid4().hex[:8]}"
    state = _graph_state(db)
    state["user_request"] = f"Add a calendar event titled {title} on 2030-06-15 at 10:00:00+00:00"
    state["approval_override"] = "REJECTED"
    result = nexus_graph.invoke(state)
    assert result["action_tool"] == "calendar_event_action"
    assert result["final_outcome"] != "SUCCESS"
    assert all(event.title != title for event in _provider().list_events())


def test_graph_with_unspected_relative_request_fails_closed(tmp_path):
    db = os.path.join(str(tmp_path), "ledger.db")
    state = _graph_state(db)
    state["user_request"] = "Add a meeting tomorrow at 3pm"
    result = nexus_graph.invoke(state)
    assert result["final_outcome"] == "NO_ACTION"
    assert all(event.title != "meeting" for event in _provider().list_events())