import re

# Upper bound on the body text handed to the analyzers / LLM. 2000 chars (~500
# tokens) was too small — it silently dropped most of a normal-length email, so a
# lure or link past the cutoff was never analyzed. 16000 chars (~4k tokens) covers
# realistic emails; anything longer keeps the head and the tail (see minimize()).
MAX_BODY_CHARS = 16000
_TAIL_CHARS = 4000  # of the budget, reserve this much for the end of a long email

# Common signature delimiters
_SIGNATURE_PATTERNS = [
    r"--\s*\n",
    r"^(Best regards|Kind regards|Regards|Thanks|Thank you|Cheers|Sincerely),?\s*$",
    r"^Sent from my (iPhone|Android|iPad|Samsung)",
]
_SIGNATURE_RE = re.compile("|".join(_SIGNATURE_PATTERNS), re.IGNORECASE | re.MULTILINE)


def minimize(text: str) -> str:
    """Trim signature and cap length, keeping only phishing-relevant content."""
    match = _SIGNATURE_RE.search(text)
    if match:
        text = text[: match.start()]

    text = text.strip()
    if len(text) <= MAX_BODY_CHARS:
        return text

    # Long email: keep the head (the lure/greeting) and the tail (closing call to
    # action, links, footer) so content at the end isn't lost to truncation.
    head = text[: MAX_BODY_CHARS - _TAIL_CHARS]
    tail = text[-_TAIL_CHARS:]
    return f"{head}\n[... trimmed ...]\n{tail}"
