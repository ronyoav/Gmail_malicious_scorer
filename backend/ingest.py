"""Parse a raw RFC-822 email (what Gmail's 'Show original' / a .eml file gives)
into an EmailAnalysisRequest — including the authentication headers (SPF, DKIM,
DMARC), the Received chain and Authentication-Results, so the header-based
checks (auth, relay detection, impersonation) actually run.

This mirrors the .eml parsing in triage.py; it is kept standalone so the
validated triage pipeline is untouched. (Candidate for later unification.)
"""
import hashlib
import re
from email import policy
from email.parser import BytesParser

from backend.models.email_request import AttachmentMeta, EmailAnalysisRequest, EmailHeaders

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_HREF_RE = re.compile(r"""href\s*=\s*["']?(https?://[^"'\s>]+)""", re.I)
_PIXEL_RE = re.compile(r"<img[^>]*(width=[\"']?1[\"']?|height=[\"']?1[\"']?)[^>]*/?>", re.I)
_MAX_URLS = 30


def _auth_value(auth_results: str, protocol: str) -> str | None:
    m = re.search(protocol + r"=(\w+)", auth_results, re.I)
    return m.group(1).lower() if m else None


def _decode_part(part) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def _walk(msg):
    """Collect plain-text bodies, HTML bodies, and attachments (name/mime/sha256)."""
    text, html, attachments = [], [], []
    for part in msg.iter_parts() if msg.is_multipart() else [msg]:
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        filename = part.get_filename()

        if ctype == "message/rfc822":
            inner = part.get_payload(0) if isinstance(part.get_payload(), list) else None
            raw = inner.as_bytes() if inner is not None else b""
            attachments.append({
                "name": filename or "embedded.eml",
                "mime_type": ctype,
                "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
            })
            continue

        if part.is_multipart():
            t, h, a = _walk(part)
            text += t; html += h; attachments += a
            continue

        if disp == "attachment" or (filename and disp != "inline") or (filename and not ctype.startswith("text/")):
            data = part.get_payload(decode=True) or b""
            attachments.append({
                "name": filename or "unnamed",
                "mime_type": ctype,
                "sha256": hashlib.sha256(data).hexdigest() if data else None,
            })
        elif ctype == "text/plain":
            text.append(_decode_part(part))
        elif ctype == "text/html":
            html.append(_decode_part(part))
    return text, html, attachments


def build_request(msg) -> EmailAnalysisRequest:
    """Build an EmailAnalysisRequest from a parsed email.message.Message."""
    auth_list = msg.get_all("Authentication-Results") or msg.get_all("ARC-Authentication-Results") or []
    auth = str(auth_list[0]) if auth_list else ""
    auth_blob = "\n".join(
        f"{h}: {v}"
        for h in ("Authentication-Results", "Authentication-Results-Original", "ARC-Authentication-Results")
        for v in (msg.get_all(h) or [])
    )
    received = [str(r) for r in (msg.get_all("Received") or [])]

    text_parts, html_parts, att = _walk(msg)
    body_text = "\n".join(text_parts)
    body_html = _PIXEL_RE.sub("", "\n".join(html_parts))

    urls = list(dict.fromkeys(_HREF_RE.findall(body_html) + _URL_RE.findall(body_html or body_text)))
    urls = [u.rstrip(".,;") for u in urls][:_MAX_URLS]

    return EmailAnalysisRequest(
        message_id=str(msg.get("Message-ID", "raw-email")),
        subject=str(msg.get("Subject", "") or ""),
        headers=EmailHeaders(
            spf=_auth_value(auth, "spf"),
            dkim=_auth_value(auth, "dkim"),
            dmarc=_auth_value(auth, "dmarc"),
            from_address=str(msg.get("From", "") or "") or None,
            received_from=received[-1] if received else None,
            reply_to=str(msg.get("Reply-To", "") or "") or None,
            received_chain="\n".join(received) or None,
            auth_results=auth_blob or None,
            sent_date=str(msg.get("Date", "") or "") or None,
        ),
        body_text=body_text or None,
        body_html=body_html or None,
        urls=urls,
        attachments=[AttachmentMeta(name=a["name"], mime_type=a["mime_type"], sha256=a["sha256"]) for a in att],
    )


def parse_raw_email(raw: str | bytes) -> EmailAnalysisRequest:
    raw_bytes = raw.encode("utf-8", errors="replace") if isinstance(raw, str) else raw
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    return build_request(msg)
