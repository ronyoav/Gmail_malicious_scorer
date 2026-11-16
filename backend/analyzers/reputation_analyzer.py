"""Domain reputation for the sender domain and every URL domain:
  1. Domain age via RDAP (free, no key) — newly registered domains are a strong phishing signal.
     Falls back to VirusTotal's whois creation_date when RDAP has no data for the TLD.
  2. VirusTotal domain report (/api/v3/domains/{d}) — how many engines flag the domain.
     A domain report is used instead of a per-URL lookup because phishing URLs carry unique
     tracking parameters and are usually unknown to VT, while the domain usually isn't.
Results are cached per domain, so a batch run never looks the same domain up twice.
"""
import os
import re
from datetime import date, datetime, timezone

import httpx

from backend.analyzers import vt_rate
from backend.models.email_request import Signal

_TIMEOUT = 6
_MAX_DOMAINS = 6  # per email — protects the 4/min VT quota

_RDAP_URL = "https://rdap.org/domain/{d}"
_VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{d}"

# Second-level public suffixes, so "shop.example.co.il" -> "example.co.il"
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.il", "org.il", "ac.il", "gov.il", "net.il",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.in", "com.br", "com.mx", "com.tr",
    "co.za", "com.cn", "com.sg", "com.hk", "re.kr", "co.kr", "or.kr",
}

# Huge, well-known infrastructure: age/reputation lookups add nothing and burn quota.
# Abuse of these (Google Forms, SharePoint) must be judged by content, not domain reputation.
_SKIP = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "youtube.com",
    "microsoft.com", "office.com", "outlook.com", "live.com", "sharepoint.com", "onmicrosoft.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com", "amazonses.com", "cloudfront.net",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "imgur.com",
    "w3.org", "gmail.com", "yahoo.com", "hotmail.com",
}

_cache: dict[str, dict] = {}


def registrable_domain(host: str | None) -> str | None:
    if not host:
        return None
    host = host.lower().strip(".").split(":")[0]
    if re.fullmatch(r"[\d.]+", host):
        return None  # bare IP — handled by url_analyzer
    parts = host.split(".")
    if len(parts) < 2:
        return None
    n = 3 if ".".join(parts[-2:]) in _MULTI_SUFFIX and len(parts) >= 3 else 2
    return ".".join(parts[-n:])


def _host(url: str) -> str | None:
    m = re.match(r"https?://([^/:?#]+)", url, re.I)
    return m.group(1) if m else None


def _rdap_created(domain: str) -> datetime | None:
    if os.environ.get("RDAP_ENABLED", "1") == "0":
        return None
    try:
        r = httpx.get(_RDAP_URL.format(d=domain), follow_redirects=True, timeout=_TIMEOUT)
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                return datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
    except Exception:
        pass
    return None


def _vt_domain(domain: str) -> dict | None:
    key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return None
    try:
        vt_rate.wait_turn()
        r = httpx.get(_VT_DOMAIN_URL.format(d=domain), headers={"x-apikey": key}, timeout=_TIMEOUT)
        if r.status_code == 404:
            return {"stats": {}, "created": None, "known": False}
        if r.status_code != 200:
            print(f"VT domain lookup {domain}: HTTP {r.status_code}")
            return None
        a = r.json().get("data", {}).get("attributes", {})
        created = a.get("creation_date")
        return {
            "stats": a.get("last_analysis_stats", {}),
            "created": datetime.fromtimestamp(created, tz=timezone.utc) if created else None,
            "known": True,
        }
    except Exception as e:
        print(f"VT domain lookup error: {e}")
        return None


def lookup(domain: str) -> dict:
    """Cached per-domain facts: age_days, created, vt_malicious, vt_suspicious."""
    if domain in _cache:
        return _cache[domain]
    created = _rdap_created(domain)
    vt = _vt_domain(domain)
    if not created and vt:
        created = vt["created"]
    info = {
        "domain": domain,
        "created": created.date().isoformat() if created else None,
        "age_days": (datetime.now(timezone.utc) - created).days if created else None,
        "vt_malicious": (vt or {}).get("stats", {}).get("malicious") if vt else None,
        "vt_suspicious": (vt or {}).get("stats", {}).get("suspicious") if vt else None,
    }
    _cache[domain] = info
    return info


def domains_for(sender_domain: str | None, urls: list[str]) -> list[str]:
    seen = []
    for d in [registrable_domain(sender_domain)] + [registrable_domain(_host(u)) for u in urls]:
        if d and d not in _SKIP and d not in seen:
            seen.append(d)
    return seen[:_MAX_DOMAINS]


def _age_days(created_iso: str | None, as_of: datetime) -> int | None:
    """Age in days of a domain at the time `as_of`, from its registration date."""
    if not created_iso:
        return None
    try:
        created = date.fromisoformat(created_iso)
    except ValueError:
        return None
    return (as_of.date() - created).days


def analyze_reputation(sender_domain: str | None, urls: list[str],
                       as_of: datetime | None = None) -> tuple[int, list[Signal]]:
    # Age is measured at the time the email was sent (as_of) when known, so triaging
    # an old email reflects how new the domain was *then*, not today.
    as_of = as_of or datetime.now(timezone.utc)
    score, signals = 0, []
    for d in domains_for(sender_domain, urls):
        info = lookup(d)
        role = "Sender domain" if d == registrable_domain(sender_domain) else "Link domain"
        age = _age_days(info["created"], as_of)
        if age is not None and age < 30:
            score += 30
            signals.append(Signal(type="new_domain", severity="high",
                                  description=f"{role} '{d}' was registered {age} days before the email ({info['created']})."))
        elif age is not None and age < 180:
            score += 15
            signals.append(Signal(type="young_domain", severity="medium",
                                  description=f"{role} '{d}' was only {age} days old when the email was sent ({info['created']})."))
        elif age is not None and age < 365:
            score += 8
            signals.append(Signal(type="young_domain", severity="low",
                                  description=f"{role} '{d}' was under a year old when the email was sent ({age} days, {info['created']})."))
        mal, sus = info["vt_malicious"] or 0, info["vt_suspicious"] or 0
        if mal >= 3:
            score += 40
            signals.append(Signal(type="vt_domain_malicious", severity="high",
                                  description=f"{role} '{d}' is flagged malicious by {mal} engines on VirusTotal."))
        elif mal >= 1 or sus >= 2:
            score += 15
            signals.append(Signal(type="vt_domain_suspicious", severity="medium",
                                  description=f"{role} '{d}' is flagged by {mal + sus} engine(s) on VirusTotal."))
    return min(score, 100), signals
