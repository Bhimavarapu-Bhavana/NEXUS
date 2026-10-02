from __future__ import annotations

import difflib
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.agent.task_commitments import validate_deadline
from app.memory.task_ledger import create_task
from app.security.audit_logger import record_audit_event
from app.security.permissions import is_authorized_path
from app.security.sensitive_data import redact_sensitive_data, redact_text
from app.tools.personal_data_observer import MAX_FILE_BYTES, RESTRICTED_PARTS

SUPPORTED_DOCUMENTS = {".txt", ".md", ".pdf", ".docx", ".csv", ".json"}
MAX_DOCUMENT_CHARS = 20000
MAX_FACTS = 50


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _audit(event: str, **payload: Any) -> None:
    record_audit_event(event, actor="document_intelligence", tool="document_observer", **payload)


def _safe_target(target: str | Path, authorization_root: str | Path) -> tuple[Path | None, str]:
    root = Path(authorization_root).resolve()
    candidate = Path(target)
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return None, "Target is outside the authorized scope."
    if not is_authorized_path(str(resolved), root) or any(part.lower() in RESTRICTED_PARTS for part in relative.parts):
        return None, "Target is outside the authorized scope."
    if not resolved.is_file():
        return None, "Target does not exist or is not a file."
    if resolved.stat().st_size > MAX_FILE_BYTES:
        return None, "Target exceeds the bounded document size limit."
    if resolved.suffix.lower() not in SUPPORTED_DOCUMENTS:
        return None, "Unsupported document format."
    return resolved, ""


def _pdf_text(path: Path) -> tuple[str, int, str]:
    raw = path.read_bytes()
    if not raw.startswith(b"%PDF-") or b"%%EOF" not in raw[-1024:]:
        return "", 0, "Malformed or unreadable PDF."
    pages = max(1, raw.count(b"/Type /Page"))
    chunks: list[str] = []
    for stream in re.findall(rb"stream\s*(.*?)\s*endstream", raw, flags=re.DOTALL):
        for match in re.findall(rb"\(([^()]*)\)\s*Tj", stream):
            chunks.append(match.decode("latin-1", errors="replace"))
        for array in re.findall(rb"\[(.*?)\]\s*TJ", stream, flags=re.DOTALL):
            chunks.extend(item.decode("latin-1", errors="replace") for item in re.findall(rb"\(([^()]*)\)", array))
    text = " ".join(chunks)
    if not text:
        return "", pages, "PDF contains no safely extractable text streams."
    return text[:MAX_DOCUMENT_CHARS], pages, ""


def _docx_text(path: Path) -> tuple[str, str]:
    import zipfile
    try:
        with zipfile.ZipFile(path) as archive:
            xml = archive.read("word/document.xml").decode("utf-8", errors="replace")
    except (OSError, KeyError, zipfile.BadZipFile):
        return "", "Malformed or unreadable DOCX."
    text = re.sub(r"<[^>]+>", " ", xml)
    return " ".join(text.split())[:MAX_DOCUMENT_CHARS], ""


def _read_text(path: Path) -> tuple[str, int, str]:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        text, pages, error = _pdf_text(path)
        return text, pages, error
    if suffix == ".docx":
        text, error = _docx_text(path)
        return text, 0, error
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:MAX_DOCUMENT_CHARS], 0, ""
    except OSError as exc:
        return "", 0, redact_text(exc)


def _facts(text: str, *, target: str, pages: int, observed_at: str) -> dict[str, Any]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    headings = [line for line in lines if line.endswith(":") or (len(line) < 100 and line.isupper())][:MAX_FACTS]
    requirement_lines = [line for line in lines if re.search(r"\b(must|required|requirements?|shall|needs to)\b", line, re.I)][:MAX_FACTS]
    action_lines = [line for line in lines if re.search(r"\b(todo|action item|please|submit|complete|send|review)\b", line, re.I)][:MAX_FACTS]
    deadline_lines = [line for line in lines if re.search(r"\b(deadline|due|by (monday|tuesday|wednesday|thursday|friday|saturday|sunday)|202\d[-/]\d\d[-/]\d\d)\b", line, re.I)][:MAX_FACTS]
    commitment_lines = [line for line in lines if re.search(r"\b(commit|committed|promise|will)\b", line, re.I)][:MAX_FACTS]
    provenance = {"source_document": redact_text(target), "location": {"pages": pages or None, "line_based": True}, "observed_at": observed_at, "extraction_method": "bounded_local_text_patterns", "confidence": "medium"}
    return redact_sensitive_data({"headings": headings, "requirements": [{"text": item, "provenance": provenance} for item in requirement_lines], "action_items": [{"text": item, "provenance": provenance} for item in action_lines], "deadlines": [{"text": item, "provenance": provenance} for item in deadline_lines], "commitments": [{"text": item, "provenance": provenance} for item in commitment_lines]})


def observe_document(target: str | Path, *, authorization_root: str | Path, capability_context: dict[str, Any], task_db_path: str | Path | None = None) -> dict[str, Any]:
    path, error = _safe_target(target, authorization_root)
    if path is None:
        _audit("document_observation_blocked", target=str(target), result="BLOCKED", reason=error)
        return {"source": "document_observer", "status": "BLOCKED", "target": redact_text(target), "error": error}
    try:
        if Path(capability_context.get("target", "")).resolve() != path or capability_context.get("application_id") != "personal_data":
            raise ValueError("Document capability context does not match the authorized target.")
    except (TypeError, ValueError) as exc:
        return {"source": "document_observer", "status": "BLOCKED", "target": redact_text(path), "error": redact_text(exc)}
    text, pages, parse_error = _read_text(path)
    if parse_error:
        status = "UNAVAILABLE" if path.suffix.lower() == ".pdf" and "no safely" in parse_error.lower() else "REJECTED"
        return {"source": "document_observer", "status": status, "target": redact_text(path), "error": parse_error, "pages": pages}
    observed_at = _now_iso()
    result = {"source": "document_observer", "status": "OK", "target": redact_text(path), "format": path.suffix.lower().lstrip("."), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "text": redact_sensitive_data(text), "facts": _facts(text, target=str(path), pages=pages, observed_at=observed_at), "provenance": {"source_document": redact_text(path), "pages": pages or None, "observed_at": observed_at, "extraction_method": "bounded_local_text_patterns"}, "ocr": {"status": "UNAVAILABLE", "reason": "No local OCR dependency is installed."}}
    _audit("document_observation_completed", target=str(path), result="OK", metadata={"format": result["format"], "pages": pages})
    return redact_sensitive_data(result)


def compare_documents(left: str | Path, right: str | Path, *, authorization_root: str | Path, capability_contexts: tuple[dict[str, Any], dict[str, Any]]) -> dict[str, Any]:
    left_path, left_error = _safe_target(left, authorization_root)
    right_path, right_error = _safe_target(right, authorization_root)
    if left_path is None or right_path is None:
        return {"source": "document_comparison", "status": "BLOCKED", "error": left_error or right_error}
    left_text, _, left_parse_error = _read_text(left_path)
    right_text, _, right_parse_error = _read_text(right_path)
    if left_parse_error or right_parse_error:
        return {"source": "document_comparison", "status": "UNAVAILABLE", "error": left_parse_error or right_parse_error}
    diff = list(difflib.unified_diff(left_text.splitlines(), right_text.splitlines(), lineterm=""))[:200]
    left_lines, right_lines = set(left_text.splitlines()), set(right_text.splitlines())
    return redact_sensitive_data({"source": "document_comparison", "status": "OK", "left": str(left_path), "right": str(right_path), "additions": sorted(right_lines - left_lines)[:MAX_FACTS], "removals": sorted(left_lines - right_lines)[:MAX_FACTS], "changed_sections": diff, "provenance": {"left": str(left_path), "right": str(right_path), "observed_at": _now_iso(), "extraction_method": "bounded_local_diff"}})


def create_task_from_document_facts(observation: dict[str, Any], *, db_path: str | Path | None = None) -> dict[str, Any]:
    if observation.get("status") != "OK":
        raise ValueError("Only verified document observations can create task evidence.")
    facts = observation.get("facts") or {}
    criteria = [item["text"] for item in facts.get("requirements", [])[:20] if isinstance(item, dict) and item.get("text")]
    actions = [item["text"] for item in facts.get("action_items", [])[:20] if isinstance(item, dict) and item.get("text")]
    deadline = ""
    deadline_evidence: list[dict[str, Any]] = []
    for item in facts.get("deadlines", [])[:20]:
        text = str(item.get("text") if isinstance(item, dict) else "")
        match = re.search(r"\b(20\d\d[-/]\d\d[-/]\d\d)\b", text)
        if match:
            deadline = match.group(1).replace("/", "-") + "T23:59:59+00:00"
            deadline_evidence.append(item.get("provenance", {}) if isinstance(item, dict) else {})
            break
    return create_task("Document-derived action items", source="document", source_reference=str(observation.get("target", "")), associated_files=[str(observation.get("target", ""))], completion_criteria=criteria, commitment="; ".join(actions), deadline=deadline, deadline_confidence="MEDIUM" if deadline else "", deadline_evidence=deadline_evidence, db_path=db_path)


__all__ = ["compare_documents", "create_task_from_document_facts", "observe_document"]
