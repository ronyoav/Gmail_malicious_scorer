import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

_URL_LIKE = re.compile(r"^https?://|^www\.", re.IGNORECASE)

# Security gateways rewrite the href (wrapping the original URL), which makes the
# visible text differ from the href even for legitimate mail. A mismatch where the
# href points to one of these is the rewriter, not a phishing trick, so it's ignored.
_URL_REWRITERS = ("safelinks", "urldefense", "mimecast", "protection.outlook",
                  "proofpoint", "barracuda", "cudasvc", "clean.mx", "linkprotect")

# Inline images/fonts (data: URIs) are legitimate base64 and must be excluded,
# otherwise every email with an embedded logo looks suspicious.
_DATA_URI_RE = re.compile(r"data:[^,\s;]*(;base64)?,[A-Za-z0-9+/=]+", re.IGNORECASE)
# After stripping those, a very long raw base64 blob (likely a hidden script
# payload) is what we actually care about. Threshold raised from 100 to 300.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{300,}={0,2}")


def _root_domain(domain: str) -> str:
    """Return the last two parts of a domain — 'jobs.intel.com' → 'intel.com'."""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def clean_html(html: str) -> str:
    """Strip scripts, styles, tracking pixels and return plain text."""
    soup = BeautifulSoup(html, "lxml")

    for tag in soup.find_all(["script", "style", "noscript", "iframe", "object", "embed"]):
        tag.decompose()

    for img in soup.find_all("img"):
        width = img.get("width", "")
        height = img.get("height", "")
        if str(width) == "1" or str(height) == "1":
            img.decompose()

    return soup.get_text(separator=" ", strip=True)


def detect_base64_payload(html: str) -> bool:
    """
    Returns True if the raw HTML contains suspiciously long base64 strings
    — a technique used to hide malicious JavaScript from content filters.
    Runs on raw HTML before sanitization so script tags are still present.
    """
    if not html:
        return False
    # Remove legitimate inline images/fonts first, then look for a long raw blob.
    stripped = _DATA_URI_RE.sub("", html)
    return bool(_BASE64_RE.search(stripped))


def extract_link_mismatches(html: str) -> list[dict]:
    """
    Return anchor tags where the visible text looks like a URL but the
    actual href points to a different domain — a classic phishing trick.
    e.g. <a href="evil.xyz">paypal.com</a>
    """
    if not html:
        return []

    soup = BeautifulSoup(html, "lxml")
    mismatches = []

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        text = a.get_text(strip=True)

        if not href.startswith("http") or not _URL_LIKE.match(text):
            continue

        try:
            href_domain = urlparse(href).netloc.lower().lstrip("www.")
            text_domain = urlparse(text if text.startswith("http") else "http://" + text).netloc.lower().lstrip("www.")
        except Exception:
            continue

        # Skip rewritten links (Safe Links / Proofpoint / Mimecast wrappers): the
        # href is the gateway, not a deceptive destination.
        if any(marker in href_domain for marker in _URL_REWRITERS):
            continue

        if href_domain and text_domain and _root_domain(href_domain) != _root_domain(text_domain):
            mismatches.append({"display": text_domain, "actual": href_domain})

    return mismatches
