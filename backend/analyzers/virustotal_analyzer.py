import base64
import os
from urllib.parse import urlparse

import httpx

from backend.analyzers import vt_rate
from backend.analyzers.allowlist import is_allowlisted
from backend.models.email_request import AttachmentMeta, Signal

_VT_URL = "https://www.virustotal.com/api/v3/files/{hash}"
_VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{id}"
_TIMEOUT = 5  # seconds — fail fast if VT is slow
_MAX_URL_LOOKUPS = 3  # protect the free 4/min quota, shared with file + domain lookups


def analyze_with_virustotal(attachments: list[AttachmentMeta]) -> tuple[int, list[Signal]]:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return 0, []

    hashes = [(a, a.sha256) for a in attachments if a.sha256]
    if not hashes:
        return 0, []

    score = 0
    signals = []

    for attachment, sha256 in hashes:
        result = _lookup(sha256, api_key)
        if result is None:
            continue

        stats = result.get("stats", {})
        engines = result.get("engines", [])
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 3:
            score += 50
            engine_sample = ", ".join(engines[:3])
            signals.append(Signal(
                type="virustotal_malicious",
                severity="high",
                description=f"'{attachment.name}' flagged as malicious by {malicious} antivirus engines on VirusTotal (e.g. {engine_sample}).",
            ))
        elif malicious >= 1 or suspicious >= 3:
            score += 25
            engine_sample = ", ".join(engines[:3]) if engines else ""
            detail = f" (e.g. {engine_sample})" if engine_sample else ""
            signals.append(Signal(
                type="virustotal_suspicious",
                severity="medium",
                description=f"'{attachment.name}' flagged as suspicious by {malicious + suspicious} antivirus engines on VirusTotal{detail}.",
            ))

    return min(score, 100), signals


def analyze_urls_with_virustotal(urls: list[str]) -> tuple[int, list[Signal]]:
    """Look up URLs on VirusTotal (read-only — never submits new URLs).

    Complements the per-domain report in reputation_analyzer: a URL-level
    detection catches a specific malicious page even on otherwise-clean shared
    hosting. Only untrusted hosts are queried, capped to protect the free quota.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key or not urls:
        return 0, []

    candidates = [u for u in urls if not is_allowlisted(_host(u))][:_MAX_URL_LOOKUPS]
    score = 0
    signals = []

    for url in candidates:
        result = _lookup_url(_url_id(url), api_key)
        if result is None:
            continue

        stats = result.get("stats", {})
        engines = result.get("engines", [])
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        shown = _host(url) or url

        if malicious >= 2:
            score += 50
            sample = ", ".join(engines[:3])
            signals.append(Signal(
                type="vt_url_malicious",
                severity="high",
                description=f"Link '{shown}' flagged as malicious by {malicious} engines on VirusTotal (e.g. {sample}).",
            ))
        elif malicious >= 1 or suspicious >= 2:
            score += 25
            sample = ", ".join(engines[:3]) if engines else ""
            detail = f" (e.g. {sample})" if sample else ""
            signals.append(Signal(
                type="vt_url_suspicious",
                severity="medium",
                description=f"Link '{shown}' flagged by {malicious + suspicious} engine(s) on VirusTotal{detail}.",
            ))

    return min(score, 100), signals


def _url_id(url: str) -> str:
    # VT's URL identifier is the unpadded base64url of the raw URL.
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _host(url: str) -> str | None:
    try:
        return urlparse(url).netloc or None
    except Exception:
        return None


def _lookup_url(url_id: str, api_key: str) -> dict | None:
    try:
        vt_rate.wait_turn()
        response = httpx.get(
            _VT_URL_ENDPOINT.format(id=url_id),
            headers={"x-apikey": api_key},
            timeout=_TIMEOUT,
        )
        if response.status_code == 404:
            return None  # URL not in VT database — unknown, not malicious
        if response.status_code != 200:
            return None

        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        malicious_engines = sorted([
            engine for engine, r in results.items()
            if r.get("category") == "malicious"
        ])
        return {"stats": stats, "engines": malicious_engines}

    except Exception as e:
        print(f"VT URL lookup error: {e}")
        return None


def _lookup(sha256: str, api_key: str) -> dict | None:
    try:
        vt_rate.wait_turn()
        response = httpx.get(
            _VT_URL.format(hash=sha256),
            headers={"x-apikey": api_key},
            timeout=_TIMEOUT,
        )
        if response.status_code == 404:
            return None  # File not in VT database — unknown, not malicious
        if response.status_code != 200:
            return None

        attributes = response.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})
        malicious_engines = sorted([
            engine for engine, r in results.items()
            if r.get("category") == "malicious"
        ])
        return {"stats": stats, "engines": malicious_engines}

    except Exception as e:
        print(f"VT lookup error: {e}")
        return None
