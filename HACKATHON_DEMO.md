# NEXUS — Hackathon Demo Guide

Final development phase: **Phase 48**. Phases 1–46 are complete; Phase 47 proved
real browser execution; Phase 48 hardened and documented the demo.

---

## 1. What NEXUS is

NEXUS is a **local, bounded autonomous computer-intelligence agent**. You give it
a natural-language goal. NEXUS decomposes the goal into bounded subgoals,
observes the real environment through an allowlisted tool registry, executes only
what is authorized, verifies the result with real evidence, and persists a final
audited outcome.

NEXUS is not a chatbot, not a shell, and not a cloud service. It runs on your
machine, binds only to `127.0.0.1`, and enforces risk, approval, and verification
gates before anything consequential happens.

The architecture is a single `StateGraph` driven by a single `TaskRunner`. There
is no second orchestrator, no second browser stack, and no second backend.

## 2. What the demonstrated workflow does

The primary demo is a single safe, read-only task:

> Open https://example.com, read the page, and tell me the page title and main
> text. Do not modify anything.

It exercises the full intended loop through the real architecture:

```
Natural-language request
  -> POST /api/tasks  (validation only; no tool selection by the caller)
  -> TaskRunner        (durable task, ledger, journal)
  -> StateGraph        (understand -> prioritize -> select tool -> diagnose -> plan)
  -> goal decomposition (2 bounded subgoals)
  -> browser_observer  (REAL outbound HTTPS GET to the requested URL)
  -> evidence normalization + correlation
  -> verification      (evidence must be present and fresh)
  -> durable persistence (ledger, subgoal lineage, evidence hash)
  -> final answer
```

Six stages are visible through the existing API: natural-language submission,
goal/subgoal processing, browser observation, real webpage evidence,
verification, and the final answer.

## 3. How to start NEXUS locally

```powershell
# from the repository root
.\.venv\Scripts\python.exe -m app.web
```

Then open `http://127.0.0.1:8770/`.

The alternate dashboard is:

```powershell
.\.venv\Scripts\python.exe -m app.ui.server   # http://127.0.0.1:8765/
```

Both bind to `127.0.0.1` only. Non-localhost hosts are rejected at startup.

## 4. How to run the real-browser demo

**Automated (deterministic, recommended for the hackathon):**

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_real_browser_execution.py -q
.\.venv\Scripts\python.exe -m pytest tests\test_phase48_hackathon_demo.py -q
```

The first file proves real network execution. The second drives the same demo
through the real HTTP surface and asserts the security boundary.

**Interactive (through the running server):**

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8770/api/tasks `
  -ContentType 'application/json' `
  -Body '{"request":"Open https://example.com, read the page, and tell me the page title and main text. Do not modify anything."}'
```

Then retrieve the result:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8770/api/tasks/<task_id>
```

The `task_answer` field contains the real observed title and page text.

**This demo requires live outbound HTTPS to `https://example.com`.** If the
network is unavailable the tests fail loudly; they never substitute fixture
evidence.

## 5. What is genuinely verified

These were executed and observed during this push:

| Capability | Evidence |
|---|---|
| Real HTTPS page fetch | Live `https://example.com` retrieved; HTTP 200 |
| Real title extraction | `Title: Example Domain` |
| Real page text extraction | "This domain is for use in documentation examples without needing permission. Avoid use in operations. Learn more" |
| Real link discovery | `https://iana.org/domains/example` |
| Real observation timestamp | Fresh, within the run window |
| Evidence reaches verification | `verification_history` holds the real evidence |
| Evidence is hashed and bound to the subgoal | `evidence_hash` in persisted lineage |
| Durable persistence | Task, goal plan, statuses, and answer survive process exit |
| Terminal state | `COMPLETED`, `final_outcome: READ_ONLY` |
| Read-only guarantee | No action tool planned, no approval, no checkpoint created |
| No repository mutation | Source/workspace SHA-256 snapshot identical before and after |
| Approval boundary intact | `browser_controller` returns `APPROVAL_REQUIRED` |
| Full regression suite | 792 passed, 0 failed, 0 skipped |

## 6. Security boundaries

- **No arbitrary execution.** There is no `/execute`, `/run-command`,
  `/run-python`, or arbitrary tool-invocation endpoint. The only POST routes are
  `/api/tasks`, `/api/service/<command>`, and approval decisions.
- **Task submission is natural-language only.** Unknown fields are rejected with
  HTTP 400; requests are length-capped and routed through `TaskRunner` ->
  `StateGraph`. Callers never select tools.
- **Service control is lifecycle-only** (`START/STOP/PAUSE/RESUME/RESTART/
  SHUTDOWN`) and validated against a legal transition table.
- **Read-only vs. action is enforced.** `browser_observer` is read-only and needs
  no approval. Every browser *action* tool (`browser_navigate_observed`,
  `browser_follow_observed_link`, `browser_controller`) is non-read-only and
  requires approval; `browser_controller` and `fixer` are hidden from the
  read-only registry view entirely.
- **SSRF protection.** Browser targets are DNS-resolved and rejected if private,
  loopback, link-local, reserved, multicast, credential-embedded, or a non-HTTP(S)
  scheme. Redirects are re-validated. Page size, text, heading, and link counts
  are bounded.
- **Local-only binding.** Enforced in `app/web/__main__.py`, `app/control_plane.py`,
  and `app/ui/server.py`.
- **Redaction and audit.** Sensitive data is redacted on ingest, answers, and API
  responses; every observation, tool call, decision, and lifecycle change is
  audited.
- **No secrets, no credentials, no cloud, no unrestricted MCP invocation.**

## 7. Capability honesty

### REAL / VERIFIED

- **Read-only web observation** (`browser_observer`): real DNS resolution, real
  outbound HTTPS GET, real HTML parsing. Proven end-to-end against live
  `https://example.com`.
- **Local task architecture**: StateGraph, TaskRunner, goal decomposition,
  evidence normalization/correlation, verification, durable task ledger,
  execution journal, audit log, approval authority, recovery manager,
  lifecycle service, control plane, localhost UI.
- **Local inspection tools**: workspace, Git status, runtime, terminal, log,
  logic/error, document, and security inspection (bounded, `shell=False`).

### SIMULATED / FIXTURE (catalogued, not real integrations)

These providers are declared in the adapter catalog and are **not** live services:

- `fixture_*` and `mock_*` providers for **calendar, email, comms, job search,
  and job application**.
- Personal-data, attention, and desktop/section summaries.
- The default calendar battery used by the Phase 40 tests is a fixture.

### DECLARED REAL BUT NOT RUNTIME-VERIFIED

`gmail_real`, `slack_real`, `chrome_real`, `google_calendar_real`,
`linkedin_real`, and `internshala_real` are **catalog declarations only**. No
credentials are configured and none were exercised. Do not present these as
working integrations.

`playwright` (1.63.0) is installed, so `chrome_real` has its driver present, but
the browser *action* path is approval-gated and was deliberately **not** exercised
in the demo.

### NOT CURRENTLY AVAILABLE

- **IBM Bob — see section 8.**
- Real email send, real calendar mutation, real job application submission.
- Cloud services, deployment infrastructure, LLM reasoning architecture.

## 8. IBM Bob limitation

**LIVE IBM BOB RUNTIME VERIFICATION: NOT AVAILABLE.**

There is **no IBM Bob integration in this codebase** — no adapter, no client, no
configuration. A repository-wide search for `ibm bob`, `watsonx`, and `com.ibm`
returns zero matches. Nothing in this project can demonstrate Bob activity, and
no Bob activity is claimed.

NEXUS demonstrates its value independently through the verified real-browser
workflow in section 5.

## 9. Regression demonstration — status

The previously described "intentionally failing migration candidate" regression
scenario (**Verification FAIL -> Decision REJECT -> rollback -> baseline
verification PASS -> COMPLETED**) **does not exist in this repository.** There is
no migration test and no such rollback scenario. Nothing was fabricated to stand
in for it, and no existing test was modified.

The related real, tested machinery does exist and is preserved: approval
rejection (`APPROVAL_REJECTED`), failed verification (`FAILED_VERIFICATION`),
durable checkpoint recovery (`recovery_manager`), and bounded retry limits.

The semantic distinction the demo requires — *COMPLETED after rollback means the
verified baseline was restored, not that the change succeeded* — is preserved by
construction: `final_outcome` remains distinct from `task_status`, and a
`FAILED_VERIFICATION` outcome maps to a `FAILED` ledger status, never `COMPLETED`.
