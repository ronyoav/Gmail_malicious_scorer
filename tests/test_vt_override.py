"""VirusTotal hard override: a malicious VT verdict (attachment or link) must force
score 100 / dangerous and the LLM must never be called (no tokens spent).

External analyzers are mocked — no API keys, no network, no cache/DB.
"""
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend import main
from backend.ingest import parse_raw_email
from backend.models.email_request import Signal

RAW = """From: Billing <billing@pay-portal.test>
To: user@example.test
Subject: Invoice attached
Content-Type: text/plain

Please review the invoice at http://pay-portal.test/invoice before Friday.
"""

FILE_MALICIOUS = (50, [Signal(type="virustotal_malicious", severity="high", description="bad file")])
URL_MALICIOUS = (50, [Signal(type="vt_url_malicious", severity="high", description="bad link")])
CLEAN = (0, [])


class Calls:
    def __init__(self):
        self.llm = 0
        self.vt_urls = 0


@pytest.fixture
def pipeline():
    """Patch every external/stateful dependency; yield a factory that sets VT results."""
    calls = Calls()

    def run(vt_files=CLEAN, vt_urls=CLEAN):
        def fake_llm(subject, body):
            calls.llm += 1
            return 10, "AI says fine", []

        def fake_vt_urls(urls):
            calls.vt_urls += 1
            return vt_urls

        patches = [
            patch.object(main, "analyze_with_virustotal", lambda atts: vt_files),
            patch.object(main, "analyze_urls_with_virustotal", fake_vt_urls),
            patch.object(main, "analyze_with_llm", fake_llm),
            patch.object(main, "analyze_reputation", lambda *a: (0, [])),
            patch.object(main.cache, "get_cache", lambda: None),
            patch.object(main, "_record_history", lambda *a, **k: None),
        ]
        for p in patches:
            p.start()
        return calls, patches

    started = []

    def factory(**kw):
        calls, patches = run(**kw)
        started.extend(patches)
        return calls

    yield factory
    for p in started:
        p.stop()


def test_malicious_attachment_returns_100_and_skips_llm(pipeline):
    calls = pipeline(vt_files=FILE_MALICIOUS)
    resp = main._analyze(parse_raw_email(RAW))
    assert resp.score == 100
    assert resp.verdict == "dangerous"
    assert calls.llm == 0
    assert calls.vt_urls == 0  # file verdict already decided — no link lookups either


def test_malicious_link_returns_100_and_skips_llm(pipeline):
    calls = pipeline(vt_urls=URL_MALICIOUS)
    resp = main._analyze(parse_raw_email(RAW))
    assert resp.score == 100
    assert resp.verdict == "dangerous"
    assert calls.llm == 0
    assert any(s.type == "vt_url_malicious" for s in resp.signals)


def test_clean_vt_still_calls_llm(pipeline):
    # Guards the two tests above: proves the LLM mock does register real calls.
    calls = pipeline()
    resp = main._analyze(parse_raw_email(RAW))
    assert calls.llm == 1
    assert resp.score < 100


def test_stream_endpoint_skips_llm_on_malicious_link(pipeline):
    calls = pipeline(vt_urls=URL_MALICIOUS)
    with TestClient(main.app) as client:
        r = client.post("/api/v1/analyze-raw/stream", json={"raw": RAW})
    events = [json.loads(line) for line in r.text.splitlines() if line]
    assert not any(e["type"] == "llm" for e in events)
    result = events[-1]
    assert result["type"] == "result"
    assert result["score"] == 100
    assert calls.llm == 0
