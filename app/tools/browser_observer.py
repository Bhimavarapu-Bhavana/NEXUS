from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from app.security.audit_logger import record_audit_event
from app.security.sensitive_data import redact_sensitive_data, redact_text

MAX_URL_CHARS = 2048
MAX_PAGE_BYTES = 250_000
MAX_TEXT_CHARS = 20_000
MAX_HEADINGS = 50
MAX_LINKS = 100
MAX_REDIRECTS = 3
OBSERVATION_TIMEOUT_SECONDS = 10
ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain"}


class _BoundedPageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.headings: list[str] = []
        self.links: list[dict[str, str]] = []
        self._title_depth = 0
        self._heading_tag = ""
        self._heading_parts: list[str] = []
        self._skip_depth = 0
        self.truncated = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        if lowered in {"script", "style", "noscript", "template"}:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if lowered == "title":
            self._title_depth += 1
        if lowered in {"h1", "h2", "h3", "h4", "h5", "h6"} and len(self.headings) < MAX_HEADINGS:
            self._heading_tag = lowered
            self._heading_parts = []
        if lowered == "a" and len(self.links) < MAX_LINKS:
            attributes = dict(attrs)
            href = attributes.get("href") or ""
            parsed = urlparse(urljoin(self.base_url, href))
            if parsed.scheme in ALLOWED_SCHEMES and parsed.netloc and len(parsed.geturl()) <= MAX_URL_CHARS:
                self.links.append({"text": "", "url": parsed.geturl()})

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in {"script", "style", "noscript", "template"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if lowered == "title" and self._title_depth:
            self._title_depth -= 1
        if lowered == self._heading_tag:
            heading = " ".join("".join(self._heading_parts).split())
            if heading and len(self.headings) < MAX_HEADINGS:
                self.headings.append(heading[:MAX_TEXT_CHARS])
            self._heading_tag = ""
            self._heading_parts = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        cleaned = " ".join(data.split())
        if not cleaned:
            return
        if self._title_depth:
            self.title_parts.append(cleaned)
        if self._heading_tag:
            self._heading_parts.append(cleaned)
        if sum(len(part) for part in self.text_parts) < MAX_TEXT_CHARS:
            self.text_parts.append(cleaned)
        elif not self.truncated:
            self.truncated = True
        if self.links and self.links[-1]["text"] == "":
            self.links[-1]["text"] = cleaned[:500]


def _audit(event_type: str, **payload: Any) -> bool:
    return record_audit_event(event_type, **payload)


def _resolved_addresses(hostname: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        raise ValueError("Browser target hostname could not be resolved.") from exc


def _resolution_snapshot(url: str) -> frozenset[str]:
    """Best-effort snapshot of a URL's resolved addresses for rebinding checks."""
    try:
        hostname = urlparse(url).hostname or ""
        if not hostname:
            return frozenset()
        return frozenset(_resolved_addresses(hostname))
    except (ValueError, OSError):
        return frozenset()


def _resolution_drifted(before: frozenset[str], after: frozenset[str]) -> bool:
    """Detect DNS resolution changes between validation and fetch.

    Empty snapshots are inconclusive (never a drift verdict). A post-fetch
    resolution that no longer overlaps the validated set indicates the name
    now points elsewhere, so the fetched bytes cannot be attributed to the
    validated target.
    """
    if not before or not after:
        return False
    return before.isdisjoint(after)


def validate_browser_url(url: str) -> str:
    """Validate an explicit public HTTP(S) target and return its normalized URL."""

    candidate = str(url or "").strip()
    if len(candidate) > MAX_URL_CHARS:
        raise ValueError("Browser URL exceeds the maximum allowed length.")
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Only HTTP and HTTPS browser targets are allowed.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Browser URL must contain a hostname and no embedded credentials.")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in BLOCKED_HOSTNAMES or hostname.endswith(".local") or hostname.endswith(".internal"):
        raise ValueError("Local and internal browser targets are not authorized.")
    try:
        addresses = _resolved_addresses(hostname)
    except ValueError:
        raise
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if any((ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_reserved, ip.is_multicast, ip.is_unspecified)):
            raise ValueError("Private or local network browser targets are not authorized.")
    normalized = parsed._replace(scheme=parsed.scheme.lower(), fragment="").geturl()
    return normalized


class _SafeRedirectHandler(HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS
    max_repeats = MAX_REDIRECTS

    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Request | None:
        validate_browser_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_page(url: str, timeout_seconds: int) -> tuple[str, str, int]:
    request = Request(url, headers={"User-Agent": "NEXUS-Observer/1.0", "Accept": "text/html,text/plain;q=0.8"}, method="GET")
    opener = build_opener(_SafeRedirectHandler())
    with opener.open(request, timeout=timeout_seconds) as response:
        body = response.read(MAX_PAGE_BYTES + 1)
        content_type = response.headers.get_content_charset() or "utf-8"
        return body[:MAX_PAGE_BYTES].decode(content_type, errors="replace"), response.geturl(), len(body) > MAX_PAGE_BYTES


def observe_browser_page(
    url: str,
    *,
    timeout_seconds: int = OBSERVATION_TIMEOUT_SECONDS,
    fetcher: Callable[[str, int], tuple[str, str, int]] | None = None,
) -> dict[str, Any]:
    """Observe bounded HTML evidence from one explicitly authorized HTTP(S) URL."""

    requested_url = str(url or "")[:MAX_URL_CHARS]
    if not _audit("browser_observation_requested", actor="nexus", tool="browser_observer", target=requested_url, result="Observation requested."):
        return {"source": "browser", "status": "ERROR", "error": "Audit persistence failed before browser observation."}

    try:
        normalized_url = validate_browser_url(url)
    except ValueError as exc:
        _audit("browser_observation_blocked", actor="risk_engine", tool="browser_observer", target=requested_url, risk_level="BLOCKED", approved=False, result="Blocked", reason=str(exc))
        raise

    if not _audit("browser_observation_started", actor="nexus", tool="browser_observer", target=normalized_url, risk_level="READ_ONLY", result="Observation started."):
        return {"source": "browser", "url": normalized_url, "status": "ERROR", "error": "Audit persistence failed before browser observation."}

    timeout = max(1, min(int(timeout_seconds), OBSERVATION_TIMEOUT_SECONDS))
    pre_resolution = _resolution_snapshot(normalized_url)
    try:
        fetch = fetcher or _fetch_page
        html, final_url, page_truncated = fetch(normalized_url, timeout)
        final_url = validate_browser_url(final_url)
        if _resolution_drifted(pre_resolution, _resolution_snapshot(normalized_url)):
            result = {"source": "browser", "url": normalized_url, "status": "ERROR", "error": "Browser target resolution changed during observation; possible DNS rebinding.", "truncated": False}
            _audit("browser_observation_failed", actor="risk_engine", tool="browser_observer", target=normalized_url, risk_level="BLOCKED", approved=False, result=result["status"], reason=result["error"])
            return redact_sensitive_data(result)
        parser = _BoundedPageParser(final_url)
        parser.feed(html[:MAX_PAGE_BYTES])
        evidence = redact_sensitive_data({
            "source": "browser",
            "url": normalized_url,
            "final_url": final_url,
            "title": " ".join(parser.title_parts)[:MAX_TEXT_CHARS],
            "visible_text": " ".join(parser.text_parts)[:MAX_TEXT_CHARS],
            "headings": parser.headings[:MAX_HEADINGS],
            "links": parser.links[:MAX_LINKS],
            "page_structure": {"heading_count": len(parser.headings), "link_count": len(parser.links)},
            "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "status": "OK",
            "truncated": bool(page_truncated or parser.truncated),
        })
        if not _audit("browser_observation_completed", actor="nexus", tool="browser_observer", target=normalized_url, risk_level="READ_ONLY", result="Observation completed.", metadata={"truncated": evidence["truncated"]}):
            return {"source": "browser", "url": normalized_url, "status": "ERROR", "error": "Audit persistence failed after browser observation."}
        return evidence
    except TimeoutError:
        result = {"source": "browser", "url": normalized_url, "status": "TIMEOUT", "error": "Browser observation timed out.", "truncated": False}
    except (HTTPError, URLError, OSError, ValueError) as exc:
        result = {"source": "browser", "url": normalized_url, "status": "ERROR", "error": redact_text(str(exc)), "truncated": False}
    _audit("browser_observation_failed", actor="nexus", tool="browser_observer", target=normalized_url, risk_level="READ_ONLY", result=result["status"], reason=result["error"])
    return redact_sensitive_data(result)


def extract_requested_url(text: str) -> str:
    candidate_text = str(text or "")
    for match in re.finditer(r"https?://[^\s\]\)\}>\"']+", candidate_text, flags=re.IGNORECASE):
        candidate = match.group(0).rstrip(".,;:)]}\"'")
        if candidate:
            try:
                normalized = validate_browser_url(candidate)
                return normalized[:MAX_URL_CHARS]
            except ValueError:
                continue

    for token in candidate_text.split():
        if token.lower().startswith(("http://", "https://")):
            return token.rstrip(".,);]>")[:MAX_URL_CHARS]
    return ""
