import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.models.email_request import EmailAnalysisRequest, EmailAnalysisResponse
from backend.storage import history
from backend.ingest import parse_raw_email
from backend import cache


class RawEmail(BaseModel):
    raw: str
from backend.sanitizer.pipeline import sanitize
from backend.analyzers.header_analyzer import analyze_headers
from backend.analyzers.content_analyzer import analyze_content
from backend.analyzers.url_analyzer import analyze_urls
from backend.analyzers.attachment_analyzer import analyze_attachments
from backend.analyzers.virustotal_analyzer import analyze_with_virustotal, analyze_urls_with_virustotal
from backend.analyzers.llm_analyzer import analyze_with_llm
from backend.analyzers.reputation_analyzer import analyze_reputation
from backend.scoring.aggregator import aggregate

app = FastAPI(title="Malicious Email Scorer", version="1.0.0")

# Allow all origins for dev; restrict in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


_INDEX_HTML = Path(__file__).parent / "web" / "index.html"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    """Simple web UI to paste an email and see its score."""
    return FileResponse(_INDEX_HTML)


@app.get("/api/v1/history")
def scan_history(limit: int = 50):
    """Recent scans, newest first (empty if no database is configured)."""
    return history.recent_scans(limit)


@app.post("/api/v1/analyze-raw", response_model=EmailAnalysisResponse)
def analyze_raw(payload: RawEmail) -> EmailAnalysisResponse:
    """Analyze a raw RFC-822 email (Gmail 'Show original' / .eml). Unlike the
    field form, this carries the real headers, so SPF/DKIM/DMARC and relay
    detection run."""
    return analyze_email(parse_raw_email(payload.raw))


def _record_history(subject, sender, response: EmailAnalysisResponse) -> None:
    """Persist a scan to RDS on a daemon thread (fire-and-forget, never blocks the
    response). Used on both a fresh analysis and a cache hit."""
    threading.Thread(
        target=history.record_scan,
        kwargs=dict(
            subject=subject,
            sender=sender,
            score=response.score,
            verdict=response.verdict,
            verdict_label=response.verdict_label,
            explanation=response.explanation,
            signals=[s.model_dump() for s in response.signals],
        ),
        daemon=True,
    ).start()


@app.post("/api/v1/analyze", response_model=EmailAnalysisResponse)
def analyze_email(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    # Whole-email cache: an identical email seen within the TTL skips the entire
    # pipeline (every analyzer + the rule engine), not just the LLM call. Keyed by
    # email content (message_id excluded), so it hits across both API entry points.
    cache_key = cache.result_key(request)
    r = cache.get_redis()
    if r:
        try:
            hit = r.get(cache_key)
            if hit:
                cached_response = EmailAnalysisResponse.model_validate_json(hit)
                _record_history(request.subject, request.headers.from_address, cached_response)
                return cached_response
        except Exception:
            pass

    # Run sanitization and VirusTotal in parallel — both are independent of each other
    with ThreadPoolExecutor(max_workers=2) as ex:
        sanitize_f = ex.submit(sanitize, request)
        vt_f = ex.submit(analyze_with_virustotal, request.attachments)
    sanitized = sanitize_f.result()
    vt_score, vt_signals = vt_f.result()

    # Extract sender domain for URL cross-referencing (e.g. link spoofing detection)
    sender_domain = None
    if sanitized["headers"].from_address:
        match = re.search(r"@([\w.\-]+)", sanitized["headers"].from_address)
        sender_domain = match.group(1).lower() if match else None

    # Measure domain age relative to when the email was sent, when the date is known.
    as_of = None
    if sanitized["headers"].sent_date:
        try:
            as_of = parsedate_to_datetime(sanitized["headers"].sent_date)
        except (TypeError, ValueError):
            as_of = None

    # Run all analyzers concurrently; LLM runs alongside rule-based checks
    with ThreadPoolExecutor(max_workers=7) as ex:
        header_f = ex.submit(analyze_headers, sanitized["headers"])
        content_f = ex.submit(analyze_content, sanitized["body"], sanitized["subject"])
        url_f = ex.submit(analyze_urls, sanitized["urls"], sanitized["link_mismatches"], sanitized["has_base64_payload"], sender_domain)
        attachment_f = ex.submit(analyze_attachments, sanitized["attachments"])
        llm_f = ex.submit(analyze_with_llm, sanitized)
        rep_f = ex.submit(analyze_reputation, sender_domain, sanitized["urls"], as_of)
        vt_url_f = ex.submit(analyze_urls_with_virustotal, sanitized["urls"])

    header_score, header_signals = header_f.result()
    content_score, content_signals = content_f.result()
    url_score, url_signals = url_f.result()
    attachment_score, attachment_signals = attachment_f.result()
    llm_score, explanation, llm_signals = llm_f.result()
    rep_score, rep_signals = rep_f.result()
    vt_url_score, vt_url_signals = vt_url_f.result()

    # Cap rule-based score at 100 before blending with LLM score
    rule_score = min(header_score + content_score + url_score + attachment_score + vt_score + rep_score + vt_url_score, 100)
    all_rule_signals = header_signals + content_signals + url_signals + attachment_signals + vt_signals + rep_signals + vt_url_signals

    all_signals = all_rule_signals + llm_signals
    # Pass the full signal set (incl. the LLM's legitimate/impersonation reads) so the
    # aggregator can let a confident "legitimate" verdict dampen weak structural noise.
    final_score, verdict, verdict_label = aggregate(rule_score, llm_score, all_signals)

    # A VirusTotal malicious verdict (file or link) is a hard override — always dangerous
    if any(s.type == "virustotal_malicious" for s in vt_signals) or \
       any(s.type == "vt_url_malicious" for s in vt_url_signals):
        final_score = 100
        verdict = "dangerous"
        verdict_label = "Likely Phishing"

    response = EmailAnalysisResponse(
        score=final_score,
        verdict=verdict,
        verdict_label=verdict_label,
        explanation=explanation,
        signals=all_signals,
    )

    # Cache the full result so a repeat of this exact email skips the pipeline.
    if r:
        try:
            r.setex(cache_key, cache.RESULT_TTL, response.model_dump_json())
        except Exception:
            pass

    # Persist the scan to RDS (the "History Of Actions" indicator). Fire-and-forget
    # on a daemon thread so it never adds latency to, or fails, the response.
    _record_history(sanitized["subject"], sanitized["headers"].from_address, response)

    return response
