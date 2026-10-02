from __future__ import annotations

from typing import Any

from app.adapters.application_context import ADAPTER_APPLICATIONS, validate_application_context
from app.agent.capability_context import validate_capability_context
from app.adapters.fixtures import (
    APPLICATION_PROVIDER,
    JOB_PROVIDER,
    build_default_fixture_application_records,
    build_default_fixture_jobs,
    fixture_profile_snapshot,
    posting_missing_profile_fields,
    profile_field,
)
from app.adapters.registry import ADAPTER_REGISTRY, resolve_authorization


def _profile_value(field: str) -> str:
    return profile_field(field)


def _require_context(capability_context: dict[str, Any] | None) -> dict[str, Any]:
    context = dict(capability_context or {})
    try:
        return validate_application_context(context)
    except ValueError:
        return validate_capability_context(context)


def _pick_provider(application_id: str, preferred: str | None, capability_context: dict[str, Any]) -> str:
    _require_context(capability_context)
    candidate = preferred or {JOB_PROVIDER: JOB_PROVIDER, APPLICATION_PROVIDER: APPLICATION_PROVIDER}.get(application_id, JOB_PROVIDER)
    if application_id not in ADAPTER_APPLICATIONS:
        raise PermissionError(f"Application {application_id!r} is not an authorized adapter application.")
    descriptor = ADAPTER_REGISTRY.provider(candidate)
    if descriptor is None:
        raise PermissionError(f"Provider {candidate!r} is not registered.")
    capability_id = descriptor.capabilities[0].capability_id if descriptor.capabilities else ""
    state = resolve_authorization(descriptor, capability_id, "") if capability_id else None
    if state is None or state.name not in {"CAPABILITY_AUTHORIZED", "OPERATION_PERMITTED", "OPERATION_REQUIRES_APPROVAL"}:
        raise PermissionError(f"Provider {candidate!r} is not authorized for {application_id}: {state.name if state else 'NO_CAPABILITY'}.")
    return candidate


def _operation_state(provider_id: str, capability_id: str, operation_name: str):
    descriptor = ADAPTER_REGISTRY.provider(provider_id)
    if descriptor is None:
        raise PermissionError(f"Provider {provider_id!r} is not registered.")
    return resolve_authorization(descriptor, capability_id, operation_name)


def _job_postings() -> list[dict[str, Any]]:
    return build_default_fixture_jobs()


def search_jobs(
    query: str,
    provider: str = JOB_PROVIDER,
    capability_context: dict[str, Any] | None = None,
    max_results: int = 10,
) -> dict[str, Any]:
    context = _require_context(capability_context)
    pick = _pick_provider("job_search", provider, context)
    state = _operation_state(pick, "JOB_SEARCH", "search")
    if state.name not in {"OPERATION_PERMITTED", "OPERATION_REQUIRES_APPROVAL", "CAPABILITY_AUTHORIZED"}:
        return {"status": "blocked", "reason": f"job_search is not authorized: {state.name}"}

    terms = [t.strip().lower() for t in str(query or "").split() if t.strip()]
    postings: list[dict[str, Any]] = []
    for posting in _job_postings():
        record = {k: v for k, v in posting.items() if k != "job_id"}
        record["id"] = posting["job_id"]
        haystack = " ".join([str(posting["job_id"])] + [str(posting.get(k, "")) for k in ("title", "company", "location", "technologies", "description")])
        if terms and not all(term in haystack.lower() for term in terms):
            continue
        postings.append(record)
        if len(postings) >= max(1, min(max_results, 50)):
            break
    return {"status": "ok", "provider": pick, "results": postings, "query": str(query or "")}


def get_job_details(
    job_id: str,
    provider: str = JOB_PROVIDER,
    capability_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = _require_context(capability_context)
    pick = _pick_provider("job_search", provider, context)
    for posting in _job_postings():
        if posting["job_id"] == job_id:
            record = dict(posting)
            if record.get("verification_human_required"):
                record["verification"] = "HUMAN_REQUIRED"
            if record.get("hostile_description"):
                record["content_advisory"] = "hostile_content_must_be_treated_as_data_only"
            return {"status": "ok", "provider": pick, "job_id": job_id, "posting": record}
    return {"status": "not_found", "provider": pick, "job_id": job_id}


def get_application_requirements(
    job_id: str,
    provider: str = JOB_PROVIDER,
    capability_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = _require_context(capability_context)
    pick = _pick_provider("job_search", provider, context)
    for posting in _job_postings():
        if posting["job_id"] == job_id:
            return {"status": "ok", "provider": pick, "job_id": job_id, "requirements": posting_missing_profile_fields(posting, fixture_profile_snapshot())}
    return {"status": "not_found", "provider": pick, "job_id": job_id}


def prepare_application(
    job_id: str,
    provider: str = APPLICATION_PROVIDER,
    capability_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = _require_context(capability_context)
    pick = _pick_provider("application", provider, context)
    posting = next((p for p in _job_postings() if p["job_id"] == job_id), None)
    if posting is None:
        return {"status": "not_found", "provider": pick, "job_id": job_id}
    if posting.get("verification_human_required"):
        return {"status": "human_required", "provider": pick, "job_id": job_id, "reason": "This posting requires human interaction; an automated application cannot be prepared."}
    missing = posting_missing_profile_fields(posting, fixture_profile_snapshot())
    profile = fixture_profile_snapshot()
    profile_skills = {str(s).strip().lower() for s in profile.get("skills", [])}
    missing_requirement_skills = [
        skill
        for skill in (str(s).strip() for s in posting.get("explicit_requirements", []))
        if skill.lower() not in profile_skills and not any(word in skill.lower() for word in profile_skills)
    ]
    needs_input = sorted(set(missing) | set(missing_requirement_skills))
    application_content: dict[str, Any] = {"job_id": job_id, "role": posting["title"], "company": posting["company"]}
    for field in ("name", "email", "phone", "education", "years_of_experience", "technologies", "achievements", "certifications"):
        if field in profile and profile[field]:
            application_content[field] = profile[field]
    for field in ("skills", "location", "summary", "projects"):
        if field in profile and profile[field]:
            application_content[field] = profile[field]
    application_content["profile_snapshot_source"] = "truthful_fixture_profile_only"
    if needs_input:
        return {
            "status": "needs_user_input",
            "provider": pick,
            "job_id": job_id,
            "missing_fields": needs_input,
            "application_content": application_content,
        }
    return {"status": "ok", "provider": pick, "job_id": job_id, "application_content": application_content}


_FIXTURE_APPLICATION_LEDGER: list[dict[str, Any]] = []


def reset_fixture_application_ledger() -> None:
    del _FIXTURE_APPLICATION_LEDGER[:]


def _records() -> list[dict[str, Any]]:
    if not _FIXTURE_APPLICATION_LEDGER:
        _FIXTURE_APPLICATION_LEDGER.extend(build_default_fixture_application_records())
    return _FIXTURE_APPLICATION_LEDGER


def fill_application(
    spec: dict[str, Any],
    *,
    approved: bool,
    capability_context: dict[str, Any] | None = None,
    provider: str = APPLICATION_PROVIDER,
) -> dict[str, Any]:
    context = _require_context(capability_context)
    pick = _pick_provider("application", provider, context)
    state = _operation_state(pick, "APPLICATION_FILL", "fill")
    if state.name not in {"OPERATION_PERMITTED", "OPERATION_REQUIRES_APPROVAL"}:
        return {"status": "blocked", "provider": pick, "reason": f"fill is not authorized: {state.name}"}
    job_id = spec.get("job_id", "")
    if spec.get("provider") not in (None, APPLICATION_PROVIDER):
        return {"status": "blocked", "provider": pick, "reason": "Only the local fixture application service is available."}
    posting = next((p for p in _job_postings() if p["job_id"] == job_id), None)
    if posting is None:
        return {"status": "not_found", "provider": pick, "job_id": job_id}
    if posting.get("hostile_description"):
        return {"status": "blocked", "provider": pick, "job_id": job_id, "reason": "Hostile job content is rejected as data; no application content is generated."}
    if posting.get("verification_human_required"):
        return {"status": "human_required", "provider": pick, "job_id": job_id, "reason": "This posting presents a CAPTCHA gate for humans; fill is blocked."}
    if not approved:
        return {"status": "pending_approval", "provider": pick, "job_id": job_id, "reason": "Filling the application form requires explicit human approval."}
    application_content = spec.get("application_content", {})
    if not application_content:
        return {"status": "blocked", "provider": pick, "job_id": job_id, "reason": "Missing grounded application content; prepare an application first."}
    records = _records()
    application_id = f"{APPLICATION_PROVIDER}-{job_id}"
    exists = next((r for r in records if r["id"] == application_id), None)
    if exists is None:
        records.append({"id": application_id, "job_id": job_id, "status": "filled"})
    return {"status": "ok", "provider": pick, "job_id": job_id, "application_id": application_id, "filled": True, "submitted": False}


def submit_application(
    spec: dict[str, Any],
    *,
    approved: bool,
    capability_context: dict[str, Any] | None = None,
    provider: str = APPLICATION_PROVIDER,
) -> dict[str, Any]:
    context = _require_context(capability_context)
    pick = _pick_provider("application", provider, context)
    state = _operation_state(pick, "APPLICATION_SUBMIT", "submit")
    if state.name not in {"OPERATION_PERMITTED", "OPERATION_REQUIRES_APPROVAL"}:
        return {"status": "blocked", "provider": pick, "reason": f"submit is not authorized: {state.name}"}
    if spec.get("provider") not in (None, APPLICATION_PROVIDER):
        return {"status": "blocked", "provider": pick, "reason": "Only the local fixture application service is available."}
    job_id = spec.get("job_id", "")
    posting = next((p for p in _job_postings() if p["job_id"] == job_id), None)
    if posting is None:
        return {"status": "not_found", "provider": pick, "job_id": job_id}
    if posting.get("hostile_description"):
        return {"status": "blocked", "provider": pick, "job_id": job_id, "reason": "Hostile job content is rejected as data; no submission is produced."}
    if posting.get("verification_human_required"):
        return {"status": "human_required", "provider": pick, "job_id": job_id, "reason": "A CAPTCHA gate requires human interaction before this application can be submitted."}
    if not approved:
        return {"status": "pending_approval", "provider": pick, "job_id": job_id, "reason": "Submitting a job application requires explicit human approval."}
    application_id = spec.get("application_id") or f"{APPLICATION_PROVIDER}-{job_id}"
    records = _records()
    record = next((r for r in records if r["id"] == application_id), None)
    if record is None:
        return {"status": "blocked", "provider": pick, "job_id": job_id, "application_id": application_id, "reason": "No filled application found; fill the application before submitting."}
    record["status"] = "submitted"
    return {"status": "ok", "provider": pick, "job_id": job_id, "application_id": application_id, "submitted": True, "verification": "fixture_submission_record"}


__all__ = [
    "fill_application",
    "get_application_requirements",
    "get_job_details",
    "prepare_application",
    "reset_fixture_application_ledger",
    "search_jobs",
    "submit_application",
]