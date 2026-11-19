import json
import os
import queue
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
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
    """Deep readiness check used by the ALB target group. Reports each dependency
    and returns 503 when a *configured* dependency (DATABASE_URL / REDIS_URL set)
    is unreachable, so a half-broken instance is pulled from rotation and the
    unhealthy-host alarm fires. A dependency that is intentionally off (no URL,
    e.g. local dev) reports "disabled" and stays healthy."""
    components = {
        "database": history.ping(),
        "elasticache": cache.ping(),
    }
    down = [name for name, status in components.items() if status == "down"]
    body = {"status": "degraded" if down else "ok", "components": components}
    if down:
        return JSONResponse(status_code=503, content=body)
    return body


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


@app.post("/api/v1/analyze-raw/stream")
def analyze_raw_stream(payload: RawEmail) -> StreamingResponse:
    """Same as /analyze-raw, but streams NDJSON progress for the web UI: one
    `signals` event per deterministic analyzer as soon as it finishes, an `llm`
    event when the AI step starts, then a final `result` event with the score."""
    request = parse_raw_email(payload.raw)
    events: queue.Queue = queue.Queue()

    def worker():
        try:
            response = _analyze(request, events.put)
            events.put({"type": "result", **response.model_dump()})
        except Exception as e:
            print(f"Streaming analysis error: {e}")
            events.put({"type": "error", "message": "Analysis failed."})
        finally:
            events.put(None)  # end-of-stream sentinel

    threading.Thread(target=worker, daemon=True).start()

    def lines():
        while (event := events.get()) is not None:
            yield json.dumps(event) + "\n"

    return StreamingResponse(lines(), media_type="application/x-ndjson")


@app.post("/api/v1/analyze", response_model=EmailAnalysisResponse)
def analyze_email(request: EmailAnalysisRequest) -> EmailAnalysisResponse:
    return _analyze(request)


def _analyze(request: EmailAnalysisRequest, emit=None) -> EmailAnalysisResponse:
    """Full pipeline. `emit`, when given, receives progress events (thread-safe
    callable) so the streaming endpoint can show deterministic results early."""
    def emit_signals(source, signals):
        if emit and signals:
            emit({"type": "signals", "source": source, "signals": [s.model_dump() for s in signals]})

    def stream(source, future):
        # Emit an analyzer's signals the moment its future completes.
        future.add_done_callback(
            lambda f: emit_signals(source, f.result()[1]) if not f.exception() else None)
        return future

    # Whole-email cache: an identical email seen within the TTL skips the entire
    # pipeline (every analyzer + the rule engine), not just the LLM call. Keyed by
    # email content (message_id excluded), so it hits across both API entry points.
    cache_key = cache.result_key(request)
    r = cache.get_cache()
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
    emit_signals("virustotal_files", vt_signals)

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

    # Rule analyzers start immediately. The LLM is gated on VirusTotal: a malicious
    # VT verdict (file or link) already decides the email, so the LLM call — the
    # slowest and only paid step — is skipped entirely in that case.
    with ThreadPoolExecutor(max_workers=7) as ex:
        #TODO: make sure check spf,dkim, dmarc
        header_f = stream("headers", ex.submit(analyze_headers, sanitized["headers"]))
        #url shortener, suspicious tld, ip url, base64 payload, link text mismatch
        url_f = stream("urls", ex.submit(analyze_urls, sanitized["urls"], sanitized["link_mismatches"], sanitized["has_base64_payload"]))
        attachment_f = stream("attachments", ex.submit(analyze_attachments, sanitized["attachments"]))
        #domain age - API call to external service
        rep_f = stream("reputation", ex.submit(analyze_reputation, sender_domain, sanitized["urls"], as_of))

        # File VT verdict is already known — only look up links if it was clean.
        vt_malicious = any(s.type == "virustotal_malicious" for s in vt_signals)
        vt_url_score, vt_url_signals = 0, []
        if not vt_malicious:
            vt_url_score, vt_url_signals = analyze_urls_with_virustotal(sanitized["urls"])
            emit_signals("virustotal_urls", vt_url_signals)
            vt_malicious = any(s.type == "vt_url_malicious" for s in vt_url_signals)

        llm_f = None
        if not vt_malicious:
            # LLM judges subject + body only (fewer tokens); links/sender are rule-engine checks
            llm_f = ex.submit(analyze_with_llm, sanitized["subject"], sanitized["body"])
            if emit:
                emit({"type": "llm", "status": "started"})

    header_score, header_signals = header_f.result()
    url_score, url_signals = url_f.result()
    attachment_score, attachment_signals = attachment_f.result()
    rep_score, rep_signals = rep_f.result()

    if llm_f is not None:
        llm_score, explanation, llm_signals = llm_f.result()
        # The regex content analyzer is only a fallback: it runs when the LLM returned
        # no usable result, so content is never judged twice. It is fast (regex only).
        llm_available = not explanation.startswith("AI analysis unavailable")
    else:
        llm_score, llm_signals, llm_available = 0, [], False
        explanation = "VirusTotal flagged this email as malicious — AI content analysis was skipped."

    if llm_available or vt_malicious:
        content_score, content_signals = 0, []
    else:
        content_score, content_signals = analyze_content(sanitized["body"], sanitized["subject"])
        emit_signals("content", content_signals)

    # Cap rule-based score at 100 before blending with LLM score
    rule_score = min(header_score + content_score + url_score + attachment_score + vt_score + rep_score + vt_url_score, 100)
    all_rule_signals = header_signals + content_signals + url_signals + attachment_signals + vt_signals + rep_signals + vt_url_signals

    all_signals = all_rule_signals + llm_signals

    if vt_malicious:
        # A VirusTotal malicious verdict (file or link) is a hard override — always dangerous
        final_score, verdict, verdict_label = 100, "dangerous", "Likely Phishing"
    else:
        # When the LLM returned no usable score, fall back to a fully deterministic
        # rule-engine verdict instead of blending in a zero LLM share.
        # A high-severity llm_intent signal (credential harvesting / financial fraud /
        # malware delivery) is a confirmed malicious intent — floor it out of Safe.
        definitive_malicious_intent = any(
            s.type == "llm_intent" and s.severity == "high" for s in llm_signals
        )
        final_score, verdict, verdict_label = aggregate(
            rule_score, llm_score, llm_available, definitive_malicious_intent
        )

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
