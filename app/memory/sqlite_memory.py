import datetime
import sqlite3
from pathlib import Path
from typing import Any

from app.security.sensitive_data import redact_text

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "nexus_memory.db"

# Default retention window for working-memory rows, aligned with the privacy
# policy's most permissive (PUBLIC/INTERNAL) window. Memory rows carry no
# category label, so the conservative choice is bounded turnover, never
# unbounded accumulation. Audit, task, approval, and checkpoint records are
# never touched by retention enforcement.
DEFAULT_RETENTION_DAYS = 365
MAX_PURGE_ROWS = 1000


def _redact_sensitive(value: Any) -> str:
    return redact_text(value)


def initialize_memory(db_path: str | Path | None = None) -> Path:
    resolved_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    resolved_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(resolved_path))
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                user_request TEXT,
                target_file TEXT,
                diagnosis TEXT,
                proposed_change TEXT,
                action_result TEXT,
                verification_result TEXT,
                retry_count INTEGER DEFAULT 0,
                success INTEGER DEFAULT 0,
                memory_context TEXT
            )
            """
        )
        connection.commit()
    finally:
        connection.close()

    return resolved_path


def store_memory(record: dict[str, Any], db_path: str | Path | None = None) -> bool:
    try:
        safe_record = {
            key: _redact_sensitive(value)
            for key, value in record.items()
        }

        target_path = initialize_memory(db_path)
        connection = sqlite3.connect(str(target_path))
        try:
            connection.execute(
                """
                INSERT INTO memory_events (
                    timestamp,
                    user_request,
                    target_file,
                    diagnosis,
                    proposed_change,
                    action_result,
                    verification_result,
                    retry_count,
                    success,
                    memory_context
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    safe_record.get("timestamp") or datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
                    safe_record.get("user_request", ""),
                    safe_record.get("target_file", ""),
                    safe_record.get("diagnosis", ""),
                    safe_record.get("proposed_change", ""),
                    safe_record.get("action_result", ""),
                    safe_record.get("verification_result", ""),
                    safe_record.get("retry_count", 0),
                    1 if safe_record.get("success") else 0,
                    safe_record.get("memory_context", ""),
                ),
            )
            connection.commit()
            return True
        finally:
            connection.close()
    except sqlite3.Error:
        return False


def search_memory(query: str, limit: int = 5, db_path: str | Path | None = None) -> str:
    if not query or not query.strip():
        return ""

    try:
        target_path = initialize_memory(db_path)
        connection = sqlite3.connect(str(target_path))
        try:
            pattern = f"%{query.strip()}%"
            rows = connection.execute(
                """
                SELECT user_request, target_file, diagnosis, proposed_change, verification_result, retry_count, success
                FROM memory_events
                WHERE user_request LIKE ?
                   OR target_file LIKE ?
                   OR diagnosis LIKE ?
                   OR proposed_change LIKE ?
                   OR action_result LIKE ?
                   OR verification_result LIKE ?
                   OR memory_context LIKE ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (pattern, pattern, pattern, pattern, pattern, pattern, pattern, limit),
            ).fetchall()
        finally:
            connection.close()

        if not rows:
            return ""

        lines: list[str] = []
        for index, row in enumerate(rows, start=1):
            user_request, target_file, diagnosis, proposed_change, verification_result, retry_count, success = row
            lines.append(
                f"{index}. Request: {user_request or 'N/A'}\n"
                f"   Target: {target_file or 'N/A'}\n"
                f"   Diagnosis: {diagnosis or 'N/A'}\n"
                f"   Verification: {verification_result or 'N/A'}\n"
                f"   Retry count: {retry_count}\n"
                f"   Success: {'YES' if success else 'NO'}"
            )

        return "PREVIOUS MEMORY:\n" + "\n\n".join(lines)
    except sqlite3.Error:
        return ""


def enforce_memory_retention(
    *,
    db_path: str | Path | None = None,
    max_age_days: int = DEFAULT_RETENTION_DAYS,
    limit: int = MAX_PURGE_ROWS,
    now: datetime.datetime | None = None,
    audit_db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Delete working-memory rows older than the retention window.

    Targets ONLY the ``memory_events`` table: audit, task, approval, and
    checkpoint records are never deleted by retention enforcement. Bounded
    (oldest-first, row-capped) and fail-safe: database errors yield a zero
    purge instead of raising; invalid configuration raises ValueError.
    Timestamps compare lexicographically, which is chronological for both
    ISO-8601 and SQLite CURRENT_TIMESTAMP shapes.
    """
    try:
        window = int(max_age_days)
        cap = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("Retention window and purge limit must be integers.") from exc
    if window <= 0:
        raise ValueError("Retention window must be a positive number of days.")
    cap = max(1, min(cap, MAX_PURGE_ROWS))
    current = now or datetime.datetime.now(datetime.UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=datetime.UTC)
    cutoff = (current - datetime.timedelta(days=window)).isoformat(timespec="seconds")
    try:
        target_path = initialize_memory(db_path)
        connection = sqlite3.connect(str(target_path))
        try:
            cursor = connection.execute(
                """
                DELETE FROM memory_events
                WHERE id IN (
                    SELECT id FROM memory_events
                    WHERE timestamp < ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                )
                """,
                (cutoff, cap),
            )
            purged = int(cursor.rowcount or 0)
            connection.commit()
        finally:
            connection.close()
    except sqlite3.Error:
        return {"purged": 0, "retention_days": window, "cutoff": cutoff, "error": "Retention purge failed safely."}
    try:
        from app.security.audit_logger import record_audit_event

        record_audit_event(
            "memory_retention_enforced",
            actor="retention_enforcement",
            tool="sqlite_memory",
            result=f"{purged} expired row(s) purged.",
            reason=f"Working-memory retention window is {window} days.",
            metadata={"purged": purged, "retention_days": window},
            db_path=audit_db_path if audit_db_path is not None else db_path,
        )
    except Exception:
        pass
    return {"purged": purged, "retention_days": window, "cutoff": cutoff}
