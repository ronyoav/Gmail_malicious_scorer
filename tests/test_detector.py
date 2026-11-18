"""Deterministic detector tests — no external APIs (no Claude / VirusTotal / RDAP)
and no API keys. They pin the logic that makes a verdict trustworthy:

- authentication parsing from the raw headers,
- the score-only aggregator (no signal-based floors or caps),
- the 100%-deterministic fallback when the LLM is unavailable,
- lookalike/typosquat detection,
- per-finding source tagging (rule vs llm).

They import only pure modules (never backend.main / FastAPI), so CI needs no running
server and no secrets.
"""
from backend.ingest import parse_raw_email
from backend.analyzers.header_analyzer import analyze_headers, _is_lookalike
from backend.analyzers.llm_analyzer import _score_features, _LLMOutput
from backend.scoring.aggregator import aggregate
from backend.models.email_request import Signal

# A fully authenticated, benign email (SPF+DKIM+DMARC all pass). No real brand.
AUTHED_LEGIT = """From: Reports <notify@mail.example-corp.test>
Subject: Your weekly report is ready
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=mail.example-corp.test; dkim=pass header.d=mail.example-corp.test; dmarc=pass header.from=mail.example-corp.test
To: user@example.test
Content-Type: text/plain

Hi, your weekly report is ready. Open it from your dashboard when you have a moment.
"""


def _authenticated(req) -> bool:
    pw = lambda v: (v or "").lower() == "pass"
    h = req.headers
    return pw(h.spf) and pw(h.dkim) and pw(h.dmarc)


def test_parse_extracts_authentication():
    req = parse_raw_email(AUTHED_LEGIT)
    assert (req.headers.spf, req.headers.dkim, req.headers.dmarc) == ("pass", "pass", "pass")


def test_authenticated_legit_adds_no_header_points():
    req = parse_raw_email(AUTHED_LEGIT)
    assert _authenticated(req) is True
    score, _ = analyze_headers(req.headers)
    assert score == 0


def test_llm_has_no_authority_of_its_own():
    # No "LLM says legitimate -> lower the score" branch exists: a real rule score
    # is not pulled down, and the LLM share is just the 40% blend.
    score, verdict, _ = aggregate(rule_score=70, llm_score=0)
    assert score == 42 and verdict == "suspicious"


def test_llm_unavailable_is_fully_deterministic():
    blended = aggregate(70, 0, llm_available=True)[0]
    deterministic = aggregate(70, 0, llm_available=False)[0]
    assert deterministic == 70          # rule engine at full weight
    assert deterministic > blended      # not diluted by the missing LLM share


def test_verdict_comes_from_score_only():
    assert aggregate(0, 0)[1] == "safe"
    assert aggregate(100, 100)[1] == "dangerous"


def test_lookalike_detection():
    assert _is_lookalike("paypa1.com") is True
    assert _is_lookalike("g00gle.com") is True
    assert _is_lookalike("mail.example-corp.test") is False


def test_findings_carry_their_source():
    assert Signal(type="x", severity="low", description="d").source == "rule"
    _, sigs = _score_features(_LLMOutput(
        intent="credential_harvesting", urgency_level=2, tone="urgent",
        suspicious_elements=["a link"], explanation="e",
    ))
    assert sigs and all(s.source == "llm" for s in sigs)


def test_link_mismatch_compares_domain_to_domain():
    from backend.sanitizer.html_cleaner import extract_link_mismatches as lm
    a = lambda href, text: f'<a href="{href}">{text}</a>'
    # Text isn't a domain -> never compared.
    assert lm(a("https://evil.xyz", "click here")) == []
    assert lm(a("https://evil.xyz", "לחץ כאן")) == []
    # Exact same domain (www ignored) -> fine.
    assert lm(a("https://www.intel.com/x", "intel.com")) == []
    # Different domain, even a subdomain -> mismatch (strict domain vs domain).
    assert lm(a("https://jobs.intel.com", "https://intel.com")) == [{"display": "intel.com", "actual": "jobs.intel.com"}]
    # Bare domain text (no www/http) pointing elsewhere -> mismatch.
    assert lm(a("https://evil.xyz/login", "paypal.com")) == [{"display": "paypal.com", "actual": "evil.xyz"}]
    # Same public suffix (co.il) is not the same site.
    assert lm(a("https://evil.co.il", "bank.co.il")) == [{"display": "bank.co.il", "actual": "evil.co.il"}]
