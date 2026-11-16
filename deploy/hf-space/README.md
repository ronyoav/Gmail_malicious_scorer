---
title: Email Security Scorer
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# Email Security Scorer — API

FastAPI backend for a Gmail add-on that scores incoming email for phishing risk.

- `GET /health` — liveness probe, also used by the add-on to warm the container.
- `POST /api/v1/analyze` — returns a 0-100 risk score, verdict, explanation and signals.

Source: https://github.com/ronyoav/Gmail_malicious_scorer

## Required secrets

Set these under **Settings → Variables and secrets**:

| Name | Required | Purpose |
| --- | --- | --- |
| `API_KEY_CLAUDE` | yes | Anthropic API key used by the LLM analyzer |
| `VIRUSTOTAL_API_KEY` | no | Attachment hash lookups; skipped when unset |
| `REDIS_URL` | no | LLM response cache; skipped when unreachable |
