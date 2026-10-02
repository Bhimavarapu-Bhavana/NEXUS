from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatControl:
    threat_id: str
    name: str
    control: str
    failure_state: str


THREAT_CONTROLS = {
    key: ThreatControl(key, name, control, failure_state)
    for key, name, control, failure_state in (
        ("A", "prompt injection", "evidence provenance and instruction/data separation", "RESTRICTED"),
        ("B", "tool abuse", "allowlisted Tool Registry metadata and argument validation", "BLOCKED"),
        ("C", "approval bypass", "Action Executor requires durable approval and checkpoint", "BLOCKED"),
        ("D", "stale approval", "expiry and binding validation", "REVALIDATE"),
        ("E", "approval replay", "atomic EXECUTING claim and CONSUMED terminal state", "BLOCKED"),
        ("F", "target substitution", "checkpoint target and target-hash validation", "BLOCKED"),
        ("G", "proposal substitution", "proposal hash binding", "BLOCKED"),
        ("H", "cross-task contamination", "task-bound capability contexts and evidence scopes", "BLOCKED"),
        ("I", "cross-subgoal contamination", "subgoal-bound contexts and lineage", "BLOCKED"),
        ("J", "cross-application confusion", "application-specific context validation", "BLOCKED"),
        ("K", "browser grounding replay", "fresh page grounding TTL and page identity", "BLOCKED"),
        ("L", "desktop grounding replay", "fresh allowlisted window revalidation", "BLOCKED"),
        ("M", "evidence poisoning", "redaction, provenance, and untrusted semantics", "RESTRICTED"),
        ("N", "secret leakage", "defense-in-depth sensitive data redaction", "BLOCKED"),
        ("O", "memory poisoning", "historical memory separation and bounded persistence", "RESTRICTED"),
        ("P", "path traversal", "authorized-root containment", "BLOCKED"),
        ("Q", "unauthorized filesystem access", "deterministic authorization roots", "BLOCKED"),
        ("R", "resource exhaustion", "bounded queues, evidence, tools, files, and retries", "BLOCKED"),
        ("S", "infinite task loops", "StateGraph loop limit and terminal invariants", "FAILED"),
        ("T", "infinite retry loops", "bounded retry classification", "FAILED"),
        ("U", "process escape", "Windows Job Object containment", "UNAVAILABLE"),
        ("V", "runtime timeout bypass", "bounded communicate timeout and tree termination", "TIMEOUT"),
        ("W", "recovery replay", "checkpoint and approval revalidation", "REVALIDATE"),
        ("X", "concurrent execution races", "atomic approval claim", "BLOCKED"),
        ("Y", "audit tampering", "append-only SQLite triggers", "BLOCKED"),
        ("Z", "environment drift", "checkpoint environment fingerprint", "BLOCKED"),
    )
}


def get_threat_control(threat_id: str) -> ThreatControl:
    try:
        return THREAT_CONTROLS[str(threat_id).upper()]
    except KeyError as exc:
        raise ValueError("Unknown threat identifier.") from exc


__all__ = ["THREAT_CONTROLS", "ThreatControl", "get_threat_control"]
