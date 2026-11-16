"""Deterministic detector tests — no external APIs (no Claude / VirusTotal / RDAP)
and no API keys. They pin the logic that makes a verdict trustworthy:

- authentication parsing from the raw headers,
- the authentication-anchored aggregator (an authenticated sender can't be flagged
  on soft signals; concrete evidence still overrides),
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


def test_authenticated_legit_stays_safe_even_if_llm_screams():
    req = parse_raw_email(AUTHED_LEGIT)
    assert _authenticated(req) is True
    # LLM pushed the content score to 90; with no hard rule evidence, an
    # authenticated sender must still land Safe.
    _, verdict, _ = aggregate(rule_score=0, llm_score=90, all_signals=[], authenticated=True)
    assert verdict == "safe"


def test_llm_has_no_authority_of_its_own():
    # No "LLM says legitimate -> lower the score" branch exists: a real rule score
    # is not pulled down, and the LLM share is just the 40% blend.
    score, verdict, _ = aggregate(rule_score=70, llm_score=0, all_signals=[], authenticated=False)
    assert score == 42 and verdict == "suspicious"


def test_llm_unavailable_is_fully_deterministic():
    blended = aggregate(70, 0, [], llm_available=True)[0]
    deterministic = aggregate(70, 0, [], llm_available=False)[0]
    assert deterministic == 70          # rule engine at full weight
    assert deterministic > blended      # not diluted by the missing LLM share


def test_concrete_evidence_overrides_authenticated_cap():
    sig = Signal(type="lookalike_domain", severity="high", description="looks like a brand")
    score, _, _ = aggregate(rule_score=0, llm_score=0, all_signals=[sig], authenticated=True)
    assert score >= 40                  # concrete evidence floor beats the Safe cap


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
