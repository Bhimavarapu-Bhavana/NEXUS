from __future__ import annotations

import fnmatch
import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "nexus_permissions.db"

PERMISSION_OUTCOMES = {
    "ALLOWED",
    "APPROVAL_REQUIRED",
    "DENIED",
    "EXPIRED",
    "REVOKED",
    "SECURITY_BLOCKED",
    "OUT_OF_SCOPE",
    "UNKNOWN_CAPABILITY",
}

ACTION_CLASSES = {
    "OBSERVE",
    "READ",
    "WRITE",
    "MODIFY",
    "EXECUTE",
    "DELETE",
    "SEND",
    "SUBMIT",
    "ADMIN",
}

# Action classes that may execute without human approval once permitted.
# Every other action class authorizes at most APPROVAL_REQUIRED: the permission
# existing must never read as "may execute now".
READ_ONLY_ACTION_CLASSES = {"OBSERVE", "READ"}

VALID_STATUSES = {"ACTIVE", "EXPIRED", "REVOKED", "PENDING"}

# Bounded storage limits. Authorization-critical fields are validated against
# these limits and rejected when overlong instead of being silently truncated,
# so distinct capabilities/targets can never collapse into one record.
MAX_CAPABILITY_CHARS = 120
MAX_ACTION_CLASS_CHARS = 40
MAX_TASK_ID_CHARS = 200
MAX_SCOPE_CHARS = 500
MAX_PATTERN_CHARS = 500
MAX_EXPIRY_CHARS = 80
MAX_TARGET_CHARS = 2000
MAX_METADATA_CHARS = 8000

KNOWN_TARGET_SCOPES = frozenset(
    {
        "workspace-only",
        "project-only",
        "authorized-personal-folder",
        "authorized-image-folder",
        "browser",
        "desktop",
        "email",
        "calendar",
        "comms",
        "security",
        "global",
    }
)

_CAPABILITY_RE = re.compile(r"[A-Z0-9][A-Z0-9_.\-]*")

_PERSONAL_DOCUMENT_EXTENSIONS = {".txt", ".md", ".pdf", ".docx", ".csv", ".json"}
_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat(timespec="seconds")


def _safe(value: Any, limit: int = 2000) -> str:
    return redact_text(value)[:limit]


def _bounded_or_raise(value: Any, limit: int, field: str) -> str:
    text = redact_text(value)
    if len(text) > limit:
        raise ValueError(f"Permission {field} exceeds the bounded length of {limit}.")
    return text


def _canonical_action_class(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not text:
        raise ValueError("Permission requires capability and action_class.")
    if len(text) > MAX_ACTION_CLASS_CHARS:
        raise ValueError("Permission action_class exceeds the bounded length.")
    if text not in ACTION_CLASSES:
        raise ValueError(f"Invalid action_class: {value}")
    return text


def _canonical_capability(value: Any) -> str:
    # Canonical form only: no second registry is introduced. Stored values and
    # query values go through this same function so "read"-vs-"READ" style
    # case mismatches cannot change an authorization decision.
    text = str(value or "").strip().upper()
    if not text:
        raise ValueError("Permission requires capability and action_class.")
    if len(text) > MAX_CAPABILITY_CHARS:
        raise ValueError(
            f"Permission capability exceeds the bounded length of {MAX_CAPABILITY_CHARS}."
        )
    if _CAPABILITY_RE.fullmatch(text) is None:
        raise ValueError(f"Invalid capability identifier: {value}")
    return text


def _canonical_task_id(value: Any) -> str:
    text = redact_text(value).strip()
    if len(text) > MAX_TASK_ID_CHARS:
        raise ValueError(
            f"Permission task_id exceeds the bounded length of {MAX_TASK_ID_CHARS}."
        )
    return text


def _canonical_scope(value: Any) -> str:
    text = redact_text(value).strip().lower()
    if not text:
        return ""
    if len(text) > MAX_SCOPE_CHARS:
        raise ValueError(
            f"Permission target_scope exceeds the bounded length of {MAX_SCOPE_CHARS}."
        )
    if text not in KNOWN_TARGET_SCOPES:
        raise ValueError(f"Unknown target_scope: {value}")
    return text


def _canonical_pattern(value: Any) -> str:
    text = redact_text(value).strip()
    if len(text) > MAX_PATTERN_CHARS:
        raise ValueError(
            f"Permission target_pattern exceeds the bounded length of {MAX_PATTERN_CHARS}."
        )
    return text


def _parse_expiry(value: str | None) -> str:
    """Accept only valid ISO-8601 timestamps; never store malformed values."""
    if value is None:
        return _iso(_now() + timedelta(days=30))
    text = str(value).strip()
    if not text:
        raise ValueError("Permission expires_at must be a valid ISO timestamp.")
    if len(text) > MAX_EXPIRY_CHARS:
        raise ValueError("Permission expires_at exceeds the bounded length.")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Permission expires_at must be a valid ISO timestamp.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat(timespec="seconds")


def _audit(
    event_type: str,
    *,
    audit_db_path: str | Path | None = None,
    **payload: Any,
) -> None:
    # Audit failures must never break or change an authorization decision.
    # NOTE: audit_db_path defaults to the audit store default, never to the
    # permission DB. Callers must not pass the permission db_path here.
    try:
        record_audit_event(event_type, db_path=audit_db_path, mirror_central=True, **payload)
    except Exception:
        pass


def _db_path(db_path: str | Path | None = None) -> Path:
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(str(_db_path(db_path)))
    connection.row_factory = sqlite3.Row
    return connection


def initialize_permission_store(db_path: str | Path | None = None) -> Path:
    path = _db_path(db_path)
    connection = _connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS permissions (
                permission_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL DEFAULT '',
                capability TEXT NOT NULL,
                action_class TEXT NOT NULL,
                target_scope TEXT NOT NULL DEFAULT '',
                target_pattern TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL DEFAULT '',
                revoked_at TEXT NOT NULL DEFAULT '',
                revoked_reason TEXT NOT NULL DEFAULT '',
                metadata TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_permissions_task ON permissions(task_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_permissions_capability ON permissions(capability)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_permissions_status ON permissions(status)")
        connection.commit()
    finally:
        connection.close()
    return path


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    return redact_sensitive_data(result)


def _expire_locked(connection: sqlite3.Connection) -> None:
    # All stored expiries are canonical ISO with timezone, so the lexicographic
    # comparison is chronological. Legacy malformed rows are failed closed at
    # evaluation time instead.
    connection.execute(
        "UPDATE permissions SET status = 'EXPIRED', revoked_at = ?, revoked_reason = 'Permission expired.' WHERE status = 'ACTIVE' AND expires_at != '' AND expires_at <= ?",
        (_iso(), _iso()),
    )


def _task_matches(permission_task_id: str, request_task_id: str, *, allow_global: bool) -> bool:
    """Explicit task-isolation semantics.

    - A task-bound permission (task_id set) authorizes only that exact task.
    - A global permission (task_id '') authorizes a task-bound request only
      when the caller explicitly passes allow_global=True.
    - A global request (task_id '') matches only global permissions.
    - There is no silent empty-task wildcard.
    """
    stored = str(permission_task_id or "")
    requested = str(request_task_id or "")
    if not requested:
        return stored == ""
    if stored == requested:
        return True
    if stored == "" and allow_global:
        return True
    return False


def create_permission(
    *,
    capability: str,
    action_class: str,
    target_scope: str = "",
    target_pattern: str = "",
    task_id: str = "",
    expires_at: str | None = None,
    metadata: dict[str, Any] | None = None,
    db_path: str | Path | None = None,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any]:
    canon_capability = _canonical_capability(capability)
    canon_action = _canonical_action_class(action_class)
    canon_task = _canonical_task_id(task_id)
    canon_scope = _canonical_scope(target_scope)
    canon_pattern = _canonical_pattern(target_pattern)
    expiry = _parse_expiry(expires_at)
    packed_metadata = json.dumps(
        redact_sensitive_data(metadata or {}), sort_keys=True, ensure_ascii=True
    )
    if len(packed_metadata) > MAX_METADATA_CHARS:
        raise ValueError("Permission metadata exceeds the bounded size.")
    initialize_permission_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        permission_id = f"perm-{uuid.uuid4().hex[:16]}"
        connection.execute(
            "INSERT INTO permissions (permission_id, task_id, capability, action_class, target_scope, target_pattern, status, created_at, expires_at, metadata) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)",
            (
                permission_id,
                canon_task,
                canon_capability,
                canon_action,
                canon_scope,
                canon_pattern,
                _iso(),
                expiry,
                packed_metadata,
            ),
        )
        connection.commit()
        record = _row(connection.execute("SELECT * FROM permissions WHERE permission_id = ?", (permission_id,)).fetchone())
    finally:
        connection.close()
    _audit(
        "permission_created",
        audit_db_path=audit_db_path,
        actor="permission_authority",
        tool="permission_authority",
        target=canon_pattern or canon_scope or "global",
        result="ACTIVE",
        reason=f"Permission granted for {canon_capability}:{canon_action}",
        metadata={"permission_id": permission_id, "task_id": canon_task, "capability": canon_capability, "action_class": canon_action},
    )
    return record or {}


def get_permission(permission_id: str, *, db_path: str | Path | None = None) -> dict[str, Any] | None:
    if not permission_id:
        return None
    initialize_permission_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        return _row(connection.execute("SELECT * FROM permissions WHERE permission_id = ?", (permission_id,)).fetchone())
    finally:
        connection.close()


def list_permissions(
    *,
    task_id: str | None = None,
    capability: str | None = None,
    status: str | None = None,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    initialize_permission_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()
        query = "SELECT * FROM permissions WHERE 1=1"
        params: list[Any] = []
        if task_id:
            query += " AND task_id = ?"
            params.append(_canonical_task_id(task_id))
        if capability:
            query += " AND capability = ?"
            params.append(_canonical_capability(capability))
        if status:
            normalized = str(status or "").strip().upper()
            if normalized not in VALID_STATUSES:
                raise ValueError(f"Invalid permission status: {status}")
            query += " AND status = ?"
            params.append(normalized)
        query += " ORDER BY created_at DESC"
        return [_row(row) for row in connection.execute(query, params).fetchall()]
    finally:
        connection.close()


def revoke_permission(
    permission_id: str,
    reason: str,
    *,
    db_path: str | Path | None = None,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any] | None:
    if not reason or not reason.strip():
        raise ValueError("Revocation reason is required.")
    initialize_permission_store(db_path)
    connection = _connect(db_path)
    try:
        cursor = connection.execute(
            "UPDATE permissions SET status = 'REVOKED', revoked_at = ?, revoked_reason = ? WHERE permission_id = ? AND status = 'ACTIVE'",
            (_iso(), _safe(reason), permission_id),
        )
        revoked_now = cursor.rowcount == 1
        connection.commit()
        record = _row(connection.execute("SELECT * FROM permissions WHERE permission_id = ?", (permission_id,)).fetchone())
    finally:
        connection.close()
    if record is None:
        _audit(
            "permission_revoke_rejected",
            audit_db_path=audit_db_path,
            actor="permission_authority",
            tool="permission_authority",
            target=str(permission_id or ""),
            result="NOT_FOUND",
            reason="Revocation target does not exist.",
            metadata={"permission_id": str(permission_id or "")},
        )
        return None
    if revoked_now:
        _audit(
            "permission_revoked",
            audit_db_path=audit_db_path,
            actor="permission_authority",
            tool="permission_authority",
            target=str(record.get("target_pattern") or record.get("target_scope") or "global"),
            result="REVOKED",
            reason=redact_text(reason)[:500],
            metadata={"permission_id": str(record.get("permission_id") or ""), "task_id": str(record.get("task_id") or "")},
        )
    else:
        _audit(
            "permission_revoke_rejected",
            audit_db_path=audit_db_path,
            actor="permission_authority",
            tool="permission_authority",
            target=str(record.get("target_pattern") or record.get("target_scope") or "global"),
            result=str(record.get("status") or "UNKNOWN"),
            reason="Permission was not ACTIVE and could not be revoked.",
            metadata={"permission_id": str(record.get("permission_id") or "")},
        )
    return record


def _path_segments(value: str) -> list[str]:
    return str(value).replace("\\", "/").split("/")


def _is_local_relative_path(target: str) -> bool:
    if "//" in target and "://" in target:
        return False
    lowered = target.lower()
    if lowered.startswith(("http://", "https://", "file://")):
        return False
    if "://" in target:
        return False
    if target.startswith(("/", "\\")):
        return False
    if re.match(r"^[A-Za-z]:[\\/]", target) is not None:
        return False
    if re.match(r"^[A-Za-z]:$", target) is not None:
        return False
    if any(segment == ".." for segment in _path_segments(target)):
        return False
    return True


def _matches_scope(target: str, scope: str) -> bool:
    """Conservative scope matching. Empty targets never match.

    Scope checks are syntactic form checks only; secret, SSRF, and workspace
    containment enforcement stay with the Risk Engine, observers, and
    permissions.is_authorized_path. Unknown scopes fail closed.
    """
    normalized_scope = str(scope or "").strip().lower()
    text = str(target or "")
    if not text or not text.strip() or "\x00" in text:
        return False
    candidate = text.strip()
    if len(candidate) > MAX_TARGET_CHARS:
        return False

    if normalized_scope in {"workspace-only", "project-only"}:
        return _is_local_relative_path(candidate)

    if normalized_scope in {"authorized-personal-folder", "authorized-image-folder"}:
        if not _is_local_relative_path(candidate):
            return False
        suffix = Path(candidate).suffix.lower()
        if normalized_scope == "authorized-personal-folder":
            return suffix in _PERSONAL_DOCUMENT_EXTENSIONS
        return suffix in _IMAGE_EXTENSIONS

    if normalized_scope == "browser":
        lowered = candidate.lower()
        if not lowered.startswith(("http://", "https://")):
            return False
        if any(char.isspace() for char in candidate):
            return False
        try:
            parts = urlsplit(candidate)
        except ValueError:
            return False
        if not parts.hostname:
            return False
        if parts.username or parts.password:
            return False
        return True

    if normalized_scope in {"desktop", "email", "calendar", "comms", "security"}:
        # Named-identity scopes: require a bounded non-empty identity and
        # reject URL/path forms rather than matching every target blindly.
        if "://" in candidate:
            return False
        if any(segment == ".." for segment in _path_segments(candidate)):
            return False
        return 0 < len(candidate) <= 1000

    if normalized_scope == "global":
        # Explicit global semantics: any bounded non-empty target. Capability,
        # action-class, task binding, and target_pattern (when set) still apply.
        return 0 < len(candidate) <= MAX_TARGET_CHARS

    return False


def _matches_pattern(target: str, pattern: str) -> bool:
    text = str(target or "")
    expression = str(pattern or "")
    if not expression:
        return True
    if len(text) > MAX_TARGET_CHARS or len(expression) > MAX_PATTERN_CHARS:
        return False
    return fnmatch.fnmatchcase(text, expression)


def _decision(outcome: str, allowed: bool, reason: str, metadata: dict[str, Any]) -> dict[str, Any]:
    return {
        "outcome": outcome,
        "allowed": allowed,
        "reason": reason,
        "metadata": redact_sensitive_data(metadata),
    }


def _audited_decision(
    outcome: str,
    allowed: bool,
    reason: str,
    metadata: dict[str, Any],
    *,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any]:
    decision = _decision(outcome, allowed, reason, metadata)
    event = "permission_evaluated"
    if outcome in {"EXPIRED"}:
        event = "permission_expired"
    _audit(
        event,
        audit_db_path=audit_db_path,
        actor="permission_authority",
        tool="permission_authority",
        target=str(metadata.get("target") or metadata.get("permission_id") or ""),
        result=outcome,
        reason=reason,
        metadata=metadata,
    )
    return decision


def evaluate_permission(
    *,
    capability: str,
    action_class: str,
    target: str,
    task_id: str = "",
    db_path: str | Path | None = None,
    audit_db_path: str | Path | None = None,
    allow_global: bool = False,
) -> dict[str, Any]:
    """
    Evaluate whether a capability/action/target combination is permitted.

    Authorization semantics (fail closed throughout):

    - ``allowed=True`` means the action may proceed subject only to the
      remaining security chain (Risk Engine, Approval Authority, executor).
      Only read-only action classes (OBSERVE, READ) can return ALLOWED.
    - Mutating action classes return APPROVAL_REQUIRED with ``allowed=False``
      and ``requires_approval=True``: the permission exists, but a human
      approval is still required before anything executes.
    - Unknown capabilities fail closed (UNKNOWN_CAPABILITY).
    - Expired/revoked permissions cannot be reused.
    - Task-bound permissions authorize only their exact task unless the
      caller explicitly passes allow_global=True for global permissions.
    """
    canon_capability = _canonical_capability(capability)
    canon_action = _canonical_action_class(action_class)
    request_task = _canonical_task_id(task_id)
    target_text = str(target or "")
    base_metadata = {
        "capability": canon_capability,
        "action_class": canon_action,
        "target": target_text,
        "task_id": request_task,
    }
    initialize_permission_store(db_path)
    connection = _connect(db_path)
    try:
        _expire_locked(connection)
        connection.commit()

        rows = connection.execute(
            "SELECT * FROM permissions WHERE capability = ? ORDER BY created_at DESC",
            (canon_capability,),
        ).fetchall()

        task_rows = [
            dict(row)
            for row in rows
            if _task_matches(str(dict(row).get("task_id") or ""), request_task, allow_global=allow_global)
        ]
        active_rows = [perm for perm in task_rows if perm.get("status") == "ACTIVE"]

        if not active_rows:
            if any(perm.get("status") == "REVOKED" for perm in task_rows):
                revoked = next(perm for perm in task_rows if perm.get("status") == "REVOKED")
                return _audited_decision(
                    "REVOKED",
                    False,
                    f"Permission {revoked.get('permission_id')} was revoked and cannot be reused",
                    {**base_metadata, "permission_id": str(revoked.get("permission_id") or "")},
                    audit_db_path=audit_db_path,
                )
            if any(perm.get("status") == "EXPIRED" for perm in task_rows):
                expired = next(perm for perm in task_rows if perm.get("status") == "EXPIRED")
                return _audited_decision(
                    "EXPIRED",
                    False,
                    f"Permission {expired.get('permission_id')} has expired",
                    {**base_metadata, "permission_id": str(expired.get("permission_id") or "")},
                    audit_db_path=audit_db_path,
                )
            return _audited_decision(
                "UNKNOWN_CAPABILITY",
                False,
                f"No active permission found for capability: {canon_capability}",
                base_metadata,
                audit_db_path=audit_db_path,
            )

        for perm in active_rows:
            if str(perm.get("action_class") or "") != canon_action:
                continue

            target_scope = str(perm.get("target_scope") or "")
            target_pattern = str(perm.get("target_pattern") or "")

            if target_scope and not _matches_scope(target_text, target_scope):
                continue

            if target_pattern and not _matches_pattern(target_text, target_pattern):
                continue

            expires_at = str(perm.get("expires_at") or "")
            if expires_at:
                try:
                    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                except ValueError:
                    # Legacy or corrupt rows without a valid expiry fail
                    # closed instead of staying ACTIVE forever.
                    return _audited_decision(
                        "EXPIRED",
                        False,
                        f"Permission {perm.get('permission_id')} has an invalid expiry and cannot be used",
                        {**base_metadata, "permission_id": str(perm.get("permission_id") or "")},
                        audit_db_path=audit_db_path,
                    )
                if expiry <= _now():
                    return _audited_decision(
                        "EXPIRED",
                        False,
                        f"Permission {perm.get('permission_id')} has expired",
                        {**base_metadata, "permission_id": str(perm.get("permission_id") or "")},
                        audit_db_path=audit_db_path,
                    )

            if canon_action in READ_ONLY_ACTION_CLASSES:
                return _audited_decision(
                    "ALLOWED",
                    True,
                    f"Permission {perm.get('permission_id')} allows {canon_capability}:{canon_action}",
                    {
                        **base_metadata,
                        "permission_id": str(perm.get("permission_id") or ""),
                        "requires_approval": False,
                    },
                    audit_db_path=audit_db_path,
                )
            return _audited_decision(
                "APPROVAL_REQUIRED",
                False,
                f"Permission {perm.get('permission_id')} authorizes {canon_capability}:{canon_action} pending human approval",
                {
                    **base_metadata,
                    "permission_id": str(perm.get("permission_id") or ""),
                    "requires_approval": True,
                },
                audit_db_path=audit_db_path,
            )

        return _audited_decision(
            "OUT_OF_SCOPE",
            False,
            f"No matching permission scope for {canon_capability}:{canon_action} on target {target_text}",
            base_metadata,
            audit_db_path=audit_db_path,
        )
    finally:
        connection.close()


def check_permission_before_execution(
    *,
    capability: str,
    action_class: str,
    target: str,
    task_id: str = "",
    risk_level: str = "",
    db_path: str | Path | None = None,
    audit_db_path: str | Path | None = None,
    allow_global: bool = False,
) -> dict[str, Any]:
    """Final permission check before execution.

    INTEGRATION BOUNDARY (for the later StateGraph/Action Executor step, not
    this step): call this function fresh, immediately before execution, after
    Risk Engine evaluation and Approval Authority validation/claim. Never cache
    its result across stages. It performs no execution itself and creates no
    orchestrator; it only reads the current permission store state.

    TOCTOU note: this check alone does not make execution atomic. Atomicity
    stays with the Approval Authority single-claim plus the executor's
    re-validation; the permission decision must be re-read here (it always
    opens a fresh connection) and treated as valid only at call time.

    Risk Engine SECURITY_BLOCKED cannot be overridden by any permission.
    Return shape matches evaluate_permission exactly: only outcome ALLOWED
    carries allowed=True.
    """
    normalized_risk = str(risk_level or "").strip().upper()
    if normalized_risk == "BLOCKED":
        decision = _decision(
            "SECURITY_BLOCKED",
            False,
            "Action blocked by Risk Engine policy",
            {"capability": _safe(capability, 120), "action_class": _safe(action_class, 40), "target": _safe(target), "risk_level": normalized_risk},
        )
        _audit(
            "permission_blocked",
            audit_db_path=audit_db_path,
            actor="permission_authority",
            tool="permission_authority",
            target=_safe(target, 1000),
            result="SECURITY_BLOCKED",
            reason="Action blocked by Risk Engine policy",
            metadata={"capability": _safe(capability, 120), "action_class": _safe(action_class, 40), "task_id": _safe(task_id, 200)},
        )
        return decision

    # evaluate_permission is the single source of gating semantics; its
    # decision is returned unchanged so the two functions cannot disagree.
    return evaluate_permission(
        capability=capability,
        action_class=action_class,
        target=target,
        task_id=task_id,
        db_path=db_path,
        audit_db_path=audit_db_path,
        allow_global=allow_global,
    )


__all__ = [
    "ACTION_CLASSES",
    "DEFAULT_DB_PATH",
    "KNOWN_TARGET_SCOPES",
    "PERMISSION_OUTCOMES",
    "READ_ONLY_ACTION_CLASSES",
    "VALID_STATUSES",
    "check_permission_before_execution",
    "create_permission",
    "evaluate_permission",
    "get_permission",
    "initialize_permission_store",
    "list_permissions",
    "revoke_permission",
]
