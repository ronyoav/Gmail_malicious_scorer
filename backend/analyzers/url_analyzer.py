import re
import httpx
from urllib.parse import urlparse
from backend.models.email_request import Signal
from backend.analyzers.allowlist import is_allowlisted

_UNSHORTEN_TIMEOUT = 4  # seconds — fail fast

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rb.gy", "cutt.ly", "short.io", "is.gd", "buff.ly",
}

# Genuinely abused free/cheap TLDs. Intentionally excludes .co and .cc, which
# are heavily used by legitimate companies and were a major false-positive source.
_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".work", ".gq",
    ".ml", ".cf", ".tk", ".pw", ".su",
}

_IP_URL_RE = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")


def analyze_urls(urls: list[str], link_mismatches: list[dict] | None = None,
                 has_base64_payload: bool = False) -> tuple[int, list[Signal]]:
    # Only concrete URL evidence is scored. Weak structural hints (http://, long
    # URLs, redirect params, keyword-in-domain, external domain) were removed:
    # they fire constantly on legitimate newsletters and tracking links.
    score = 0
    signals = []

    if urls:
        # Expand shortened URLs via HEAD request before all other checks
        expanded = [_unshorten(u) if _is_shortener(u) else u for u in urls]

        # Links on trusted infrastructure (identity providers, banks, ESP tracking
        # links...) are not checked for suspicious TLDs. Strong signals (IP,
        # link mismatch) still apply to every URL.
        untrusted = [u for u in expanded if not is_allowlisted(_host_of(u))]

        # A shortener is only a concern when its real destination isn't trusted.
        shortener_hidden = [
            e for u, e in zip(urls, expanded)
            if _is_shortener(u) and not is_allowlisted(_host_of(e))
        ]
        if shortener_hidden:
            score += 10
            dest = next((e for u, e in zip(urls, expanded) if _is_shortener(u) and e != u), None)
            dest_hint = f" → {dest}" if dest else ""
            signals.append(Signal(type="url_shortener", severity="medium", description=f"{len(shortener_hidden)} shortened URL(s) hiding an untrusted destination{dest_hint}."))

        suspicious_tld_urls = [u for u in untrusted if _has_suspicious_tld(u)]
        if suspicious_tld_urls:
            score += 20
            signals.append(Signal(type="suspicious_tld", severity="high", description=f"URLs with suspicious TLDs detected: {', '.join(suspicious_tld_urls[:2])}."))

        ip_urls = [u for u in expanded if _IP_URL_RE.match(u)]
        if ip_urls:
            score += 25
            signals.append(Signal(type="ip_url", severity="high", description="URL points directly to an IP address — no legitimate domain."))

    if has_base64_payload:
        score += 30
        signals.append(Signal(
            type="base64_payload",
            severity="high",
            description="HTML contains suspicious base64-encoded content — a technique used to hide malicious scripts from filters.",
        ))

    if link_mismatches:
        score += 30
        example = link_mismatches[0]
        signals.append(Signal(
            type="link_text_mismatch",
            severity="high",
            description=(
                f"Link displays '{example['display']}' but points to '{example['actual']}' "
                f"({len(link_mismatches)} mismatch(es) found)."
            ),
        ))

    return min(score, 100), signals


def _is_shortener(url: str) -> bool:
    return _extract_domain(url) in _SHORTENERS


def _has_suspicious_tld(url: str) -> bool:
    try:
        host = urlparse(url).netloc.lower()
        return any(host.endswith(tld) for tld in _SUSPICIOUS_TLDS)
    except Exception:
        return False


def _extract_domain(url: str) -> str | None:
    try:
        return urlparse(url).netloc.lower().removeprefix("www.") or None
    except Exception:
        return None


def _host_of(url: str) -> str | None:
    try:
        return urlparse(url).netloc or None
    except Exception:
        return None


def _unshorten(url: str) -> str:
    """Follow redirects via HEAD request and return the final destination URL."""
    try:
        r = httpx.head(url, follow_redirects=True, timeout=_UNSHORTEN_TIMEOUT)
        final = str(r.url)
        return final if final != url else url
    except Exception:
        return url
