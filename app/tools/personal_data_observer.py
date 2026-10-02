from __future__ import annotations

import csv
import hashlib
import json
import struct
import zipfile
from pathlib import Path
from typing import Any

from app.agent.personal_capabilities import build_personal_capability_context, validate_personal_capability_context, classify_data
from app.security.audit_logger import record_audit_event
from app.security.permissions import is_authorized_path
from app.security.sensitive_data import redact_sensitive_data, redact_text

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_TEXT_CHARS = 12000
MAX_ROWS = 100
SUPPORTED_DOCUMENTS = {".txt", ".md", ".pdf", ".docx", ".csv", ".json"}
SUPPORTED_IMAGES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}
RESTRICTED_PARTS = {".env", ".git", ".venv", "__pycache__", "node_modules"}


def _audit(event: str, **payload: Any) -> None:
    record_audit_event(event, actor="personal_data_observer", tool="personal_file_observer", **payload)


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
    if not resolved.exists() or not resolved.is_file():
        return None, "Target does not exist or is not a file."
    if resolved.stat().st_size > MAX_FILE_BYTES:
        return None, "Target exceeds the bounded file size limit."
    return resolved, ""


def _image_properties(path: Path) -> dict[str, Any]:
    data = path.read_bytes()[:64]
    suffix = path.suffix.lower()
    width = height = None
    if suffix == ".png" and data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        width, height = struct.unpack(">II", data[16:24])
    elif suffix in {".gif"} and len(data) >= 10 and data[:3] == b"GIF":
        width, height = struct.unpack("<HH", data[6:10])
    elif suffix in {".jpg", ".jpeg"}:
        raw = path.read_bytes()[:MAX_FILE_BYTES]
        index = 2
        while index + 9 < len(raw):
            if raw[index] != 0xFF:
                index += 1
                continue
            marker = raw[index + 1]
            index += 2
            if marker in {0xD8, 0xD9}:
                continue
            length = int.from_bytes(raw[index:index + 2], "big")
            if marker in range(0xC0, 0xC4) and index + 7 < len(raw):
                height = int.from_bytes(raw[index + 3:index + 5], "big")
                width = int.from_bytes(raw[index + 5:index + 7], "big")
                break
            index += max(length, 2)
    return {"format": suffix.lstrip("."), "width": width, "height": height, "byte_size": path.stat().st_size}


def _document_content(path: Path) -> tuple[str, str]:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".md", ".csv", ".json"}:
        raw = path.read_text(encoding="utf-8", errors="replace")[:MAX_TEXT_CHARS]
        if suffix == ".json":
            try:
                raw = json.dumps(json.loads(raw), ensure_ascii=True, sort_keys=True)[:MAX_TEXT_CHARS]
            except json.JSONDecodeError:
                return "", "Malformed JSON document."
        if suffix == ".csv":
            rows = list(csv.reader(raw.splitlines()))[:MAX_ROWS]
            raw = "\n".join(",".join(row) for row in rows)[:MAX_TEXT_CHARS]
        return raw, ""
    if suffix == ".docx":
        with zipfile.ZipFile(path) as archive:
            xml = archive.read("word/document.xml").decode("utf-8", errors="replace")
        return redact_text(xml.replace("><", "> <"))[:MAX_TEXT_CHARS], ""
    if suffix == ".pdf":
        return "", "PDF text extraction is unavailable in the bounded local adapter."
    return "", "Unsupported document format."


def observe_personal_file(target: str | Path, *, authorization_root: str | Path, capability_context: dict[str, Any]) -> dict[str, Any]:
    path, error = _safe_target(target, authorization_root)
    if path is None:
        _audit("personal_observation_blocked", target=str(target), result="BLOCKED", reason=error)
        return {"source": "personal_data", "status": "BLOCKED", "target": redact_text(target), "error": error}
    suffix = path.suffix.lower()
    capability_id = "IMAGE_OBSERVE" if suffix in SUPPORTED_IMAGES else "DOCUMENT_OBSERVE" if suffix in SUPPORTED_DOCUMENTS else "FILE_OBSERVE"
    try:
        context = validate_personal_capability_context(capability_context)
        if Path(context["target"]).resolve() != path:
            raise ValueError("Personal capability target does not match the observed file.")
        expected_capability = "IMAGE_OBSERVE" if suffix in SUPPORTED_IMAGES else "DOCUMENT_OBSERVE" if suffix in SUPPORTED_DOCUMENTS else "FILE_OBSERVE"
        if context["capability_id"] != expected_capability:
            raise ValueError("Personal capability does not match the target format.")
    except ValueError as exc:
        return {"source": "personal_data", "status": "BLOCKED", "target": redact_text(path), "error": redact_text(exc)}
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if suffix in SUPPORTED_IMAGES:
        result = {"source": "personal_data", "status": "OK", "target": str(path), "classification": classify_data(target=path.name), "properties": _image_properties(path), "sha256": digest, "content": "Image content retained locally; no visual inference performed."}
    elif suffix in SUPPORTED_DOCUMENTS:
        content, parse_error = _document_content(path)
        if parse_error and suffix == ".pdf":
            return {"source": "personal_data", "status": "UNAVAILABLE", "target": str(path), "error": parse_error, "classification": classify_data(target=path.name), "sha256": digest}
        if parse_error:
            return {"source": "personal_data", "status": "REJECTED", "target": str(path), "error": parse_error}
        classification = classify_data(target=path.name, content=content)
        if classification in {"SECRET", "CREDENTIAL"}:
            return {"source": "personal_data", "status": "BLOCKED", "target": str(path), "classification": classification, "error": "Secret and credential content is blocked from observation."}
        result = {"source": "personal_data", "status": "OK", "target": str(path), "classification": classification, "content": redact_sensitive_data(content), "sha256": digest, "byte_size": path.stat().st_size}
    else:
        return {"source": "personal_data", "status": "UNAVAILABLE", "target": str(path), "error": "Unsupported file format."}
    _audit("personal_observation_completed", target=str(path), result=result["status"], metadata={"classification": result.get("classification", ""), "byte_size": path.stat().st_size})
    return redact_sensitive_data(result)


__all__ = ["MAX_FILE_BYTES", "observe_personal_file"]
