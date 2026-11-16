# Deploying the backend to Hugging Face Spaces (free tier)

The Gmail add-on runs on Google's servers, so it needs a publicly reachable HTTPS
endpoint — `localhost` is not an option. A Docker Space on the free CPU tier gives a
permanent URL with no credit card attached.

## 1. Create the Space

1. Sign in at https://huggingface.co and open https://huggingface.co/new-space
2. Owner: your account. Space name: `email-security-scorer`
3. SDK: **Docker** → *Blank*. Hardware: **CPU basic (free)**. Visibility: **Public**
4. Create.

## 2. Add the secrets

In the Space: **Settings → Variables and secrets → New secret**

| Name | Required | Notes |
| --- | --- | --- |
| `API_KEY_CLAUDE` | yes | Anthropic API key (same value as the local `.env`) |
| `VIRUSTOTAL_API_KEY` | no | Attachment lookups are skipped when unset |
| `REDIS_URL` | no | LLM cache; the app falls back to no cache when unreachable |

## 3. Push the code

```powershell
./deploy/hf-space/sync.ps1 -Space <your-username>/email-security-scorer
```

Git prompts once for credentials: username is your Hugging Face username, password is a
**write** access token from https://huggingface.co/settings/tokens

The build takes a few minutes. When it turns green:

```bash
curl https://<your-username>-email-security-scorer.hf.space/health
```

## 4. Point the add-on at the Space

In [`addon/Code.gs`](../../addon/Code.gs) set:

```javascript
var BACKEND_BASE_URL = "https://<your-username>-email-security-scorer.hf.space";
```

Paste the updated file into the Apps Script editor, save, and reload Gmail.

## Notes

- A free Space sleeps after ~48h without traffic and cold-starts on the next request.
  The add-on already pings `/health` first and retries three times with backoff, which
  covers the wake-up delay.
- The endpoint is unauthenticated and public. Anyone who learns the URL can spend your
  Anthropic quota — keep the URL out of the README if that matters, or put a shared
  secret header in front of `/api/v1/analyze`.
