"""Whole-email result cache (ElastiCache, shared across instances).

The LLM analyzer already caches its own API calls, but every other analyzer and
the rule engine still ran on a repeat email. This caches the *final*
EmailAnalysisResponse keyed by the email content, so an email seen before — from
the web UI (raw -> parsed) or the Gmail add-on (structured payload) — returns
immediately and skips the entire pipeline.

Key: SHA-256 of the request's canonical JSON, excluding `message_id` (a per-send
identifier) so the same email with a different id is still a hit.

Best-effort: if REDIS_URL is unset or ElastiCache is unreachable, caching is silently
disabled and analysis proceeds normally.
"""
import hashlib
import json
import os

import redis

from backend.models.email_request import EmailAnalysisRequest

RESULT_TTL = 3600  # seconds (1 hour) — matches the LLM cache TTL

_CACHE: redis.Redis | None = None
_TRIED = False


def get_cache() -> redis.Redis | None:
    global _CACHE, _TRIED
    if _TRIED:
        return _CACHE
    _TRIED = True
    url = os.environ.get("REDIS_URL")
    if url:
        try:
            _CACHE = redis.Redis.from_url(url, decode_responses=True, socket_connect_timeout=2)
            _CACHE.ping()
        except Exception:
            _CACHE = None
    return _CACHE


def ping() -> str:
    """Cache (ElastiCache) reachability for the /health readiness check.

    "ok"       -> reachable
    "down"     -> REDIS_URL is set but the node cannot be reached
    "disabled" -> no REDIS_URL (local dev / tests) — caching is off by design
    """
    if not os.environ.get("REDIS_URL"):
        return "disabled"
    r = get_cache()
    if r is None:
        return "down"
    try:
        r.ping()
        return "ok"
    except Exception:
        return "down"


def result_key(request: EmailAnalysisRequest) -> str:
    """Stable cache key from the email's *identity* only.

    The same email blasted to many recipients carries different per-delivery
    headers (Received chain, SPF/DKIM/DMARC results, message_id) and a different
    reply_to can appear too. Keying on those would give every recipient a unique
    key and never hit. So the key is an allowlist of content that identifies the
    email itself: sender, subject, body, links, and attachment hashes. URLs and
    attachments are sorted so delivery-order noise doesn't change the key.
    """
    identity = {
        "from": request.headers.from_address,
        "subject": request.subject,
        "body_text": request.body_text,
        "body_html": request.body_html,
        "urls": sorted(request.urls),
        "attachments": sorted(
            (a.sha256 or f"{a.name}|{a.mime_type}") for a in request.attachments
        ),
    }
    canonical = json.dumps(identity, sort_keys=True, ensure_ascii=False)
    return "email:" + hashlib.sha256(canonical.encode()).hexdigest()
