from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.attention.correlation import (
    MAX_CORRELATION_GROUPS,
    correlate_attention_items,
)
from app.attention.models import (
    MAX_ATTENTION_ITEMS,
    attention_snapshot,
    build_attention_item,
    validate_attention_item,
)
from app.attention.rules import (
    DEADLINE_STATE_PRIORITY,
    approval_attention_state,
    calendar_event_attention_state,
    deadline_attention_state,
    max_priority,
    security_attention_state,
    task_attention_state,
)
from app.agent.capability_context import build_capability_context
from app.agent.evidence import SOURCE_SEMANTICS, _category
from app.agent.graph import (
    _classify_request_intent,
    should_create_proposal,
)
from app.security.risk_engine import (
    BLOCKED,
    READ_ONLY,
    evaluate_tool_risk,
)
from app.tools.attention_observer import observe_attention

STABLE_ISO = "2031-04-23T11:00:00+00:00"
STABLE_NOW = datetime(2031, 4, 23, 11, 0, 0, tzinfo=timezone.utc)
NOW = "2031-04-23T11:00:00+00:00"


def _item(**kw: object) -> dict:
    defaults = {
        "attention_id": "attn-0001",
        "category": "task",
        "title": "Ship final review",
        "summary": "Final review is overdue",
        "priority": "HIGH",
        "urgency": "TODAY",
        "confidence": "HIGH",
        "status": "OPEN",
        "source": "task_ledger",
        "source_reference": "task-0001",
        "deadline": "2031-04-20T00:00:00+00:00",
        "deadline_state": "OVERDUE",
    }
    defaults.update(kw)
    return build_attention_item(**defaults)


def test_build_attention_item_defaults_and_validation_round_trip():
    item = _item()
    assert item["category"] == "task"
    assert item["priority"] == "HIGH"
    assert item["requires_user_attention"] is True
    assert validate_attention_item(item)["attention_id"] == "attn-0001"


def test_build_attention_item_rejects_unknown_priority():
    with pytest.raises(ValueError):
        _item(priority="WHATEVER")


def test_attention_snapshot_is_bounded_and_provenance_linked() -> None:
    snap = None
    items = [_item()] * 200
    snap = attention_snapshot(items=items)
    assert snap["item_count"] <= MAX_ATTENTION_ITEMS
    assert snap["provenance"]["origin"] == "attention_engine"


def test_task_attention_state_escalates_blocked_and_overdue():
    priority, urgency, reason, explanation, requires = task_attention_state(
        priority="LOW",
        status="BLOCKED",
        deadline="2031-04-20T00:00:00+00:00",
        deadline_state="OVERDUE",
        confidence="MEDIUM",
        blocked=True,
        needs_user_attention=True,
        now=STABLE_NOW,
    )
    assert priority in {"HIGH", "CRITICAL"}
    assert urgency in {"TODAY", "IMMEDIATE"}
    assert reason
    assert requires is True


def test_max_priority_is_deterministic_and_bounded():
    assert max_priority("HIGH", "CRITICAL", "LOW") == "CRITICAL"
    assert max_priority("LOW", "LOW") == "LOW"


def test_security_attention_state_maps_severity():
    priority, urgency = security_attention_state("CRITICAL")
    assert priority == "CRITICAL"
    assert urgency == "IMMEDIATE"


def test_approval_attention_state_maps_risk_level():
    priority, urgency = approval_attention_state("HIGH_RISK")
    assert priority == "HIGH"
    assert urgency == "TODAY"


def test_calendar_event_attention_state_deadline_is_high():
    priority, urgency = calendar_event_attention_state(
        {
            "title": "Board review",
            "start_time": "2031-04-20T00:00:00+00:00",
            "is_deadline": True,
            "confidence": "HIGH",
        },
        now=STABLE_NOW,
    )
    assert priority in {"HIGH", "CRITICAL"}
    assert urgency in {"TODAY", "IMMEDIATE"}


def test_deadline_attention_state_overdue_is_critical():
    deadline_state_priority, _ = deadline_attention_state(
        "2031-04-20T00:00:00+00:00",
        "HIGH",
        now=STABLE_NOW,
    )
    assert deadline_state_priority == "OVERDUE"
    assert DEADLINE_STATE_PRIORITY[deadline_state_priority] == "CRITICAL"


def test_correlate_attention_items_is_bounded_and_deterministic():
    items = [_item()] * 200
    grouped = correlate_attention_items(items)
    assert grouped["group_count"] <= MAX_CORRELATION_GROUPS


# ----------------------------------------------------------------------
# Evidence semantics (attention is evidence, never instructions)
# ----------------------------------------------------------------------


def test_attention_source_semantics_present_in_evidence():
    assert "attention_observer" in SOURCE_SEMANTICS


def test_attention_category_includes_bounded_attention_sources():
    assert "attention_observer" in SOURCE_SEMANTICS


# ----------------------------------------------------------------------
# Risk engine: read-only, deterministic evaluation
# ----------------------------------------------------------------------


def test_attention_observer_is_read_only_allowed_in_risk_engine():
    decision = evaluate_tool_risk("attention_observer")
    assert decision["risk_level"] == READ_ONLY
    assert decision["allowed"] is True
    assert decision["approval_required"] is False
    assert "read-only" in str(decision.get("reason", "")).lower()


def test_attention_observer_is_not_blocked_even_at_high_volume():
    # Deterministic bounded evaluation regardless of item density.
    decision = evaluate_tool_risk("attention_observer")
    assert decision["allowed"] is True
    assert decision["risk_level"] not in {BLOCKED, "HIGH_RISK"}


# ----------------------------------------------------------------------
# Capability context (cross-application, bounded)
# ----------------------------------------------------------------------


def test_attention_capability_context_is_bounded_and_consistent():
    ctx = build_capability_context(
        application_id="attention",
        capability_id="attention-observe",
        tool_name="attention_observer",
        task_id="task-test",
        subgoal_id="observe_attention_snapshot",
        environment_fingerprint="workspace",
    )
    assert ctx["application_id"] == "attention"
    assert ctx["capability_id"]
    assert ctx["tool_name"] == "attention_observer"


# ----------------------------------------------------------------------
# Intent routing (read-only -> create plan, no mutation proposal)
# ----------------------------------------------------------------------


def test_attention_intent_does_not_require_mutation_proposal():
    intent = _classify_request_intent(
        "What needs my attention right now? Any overdue tasks?",
    )
    assert intent == "ATTENTION_REQUEST"
    assert should_create_proposal({"user_request": "What needs my attention?"}) == "create_plan"


def test_observe_attention_is_bounded_read_only_smoke() -> None:
    snap = observe_attention(provider_name="fixture", capability_context={"application_id": "attention", "capability_id": "cap-attention", "tool_name": "attention_observer", "application_name": "attention", "workspace_context": "workspace", "intent": "ATTENTION_REQUEST"})
    assert snap["item_count"] <= MAX_ATTENTION_ITEMS
    assert snap["status"] == "OK"
    assert snap["reports"][0]["_category"] == "attention"
