import re
from backend.models.email_request import EmailHeaders, Signal
from backend.analyzers.allowlist import is_allowlisted
from backend.analyzers.reputation_analyzer import registrable_domain

# Security gateways/relays that sit in front of a mailbox and rewrite messages.
# Their rewriting legitimately breaks SPF/DKIM/DMARC for genuine mail, so an auth
# failure when one of these is in the path is NOT evidence of spoofing.
_RELAY_MARKERS = (
    "mimecast", "proofpoint", "pphosted", "barracuda", "ironport",
    "messagelabs", "symanteccloud", "mailcontrol", "fireeye", "trendmicro",
    "forcepoint", "mailmarshal", "mxlogic", "safelinks", "ppe-hosted",
    # Vendor-agnostic fingerprint: a relay that rewrote the body preserves the
    # pre-relay result in an "Authentication-Results-Original" header (Mimecast).
    "authentication-results-original",
)


def _via_security_relay(headers: EmailHeaders) -> bool:
    """True if a known security relay/gateway appears in the delivery path."""
    blob = " ".join(filter(None, [
        headers.received_chain, headers.auth_results, headers.received_from,
    ])).lower()
    return any(marker in blob for marker in _RELAY_MARKERS)


def analyze_headers(headers: EmailHeaders) -> tuple[int, list[Signal]]:
    score = 0
    signals = []

    relay = _via_security_relay(headers)

    # Authentication checks (SPF / DKIM / DMARC). A hard "fail" is normally strong
    # evidence — EXCEPT when a security relay in the path rewrote the message, which
    # routinely breaks these checks for genuine mail. In that case we record a single
    # low-severity note and add no points, so a legitimate relayed email is not
    # mislabeled as spoofed.
    auth_fails = []  # (check_name, signal_type, points, description)

    # SPF fail is a weak signal: it breaks on ordinary forwarding (the forwarder is
    # not an authorized sender). A MISSING SPF record is worse — the domain owner never
    # set up authentication at all. DKIM survives forwarding and DMARC checks the From
    # domain the user actually sees, so those two carry the weight.
    spf = (headers.spf or "").lower()
    if headers.spf and "fail" in spf:
        auth_fails.append(("SPF", "spf_fail", 5, "SPF check failed — sending server not authorized (common with forwarding)."))
    # Only an explicit "spf=none" means the domain has no SPF record. A missing
    # Authentication-Results header (e.g. a pasted email) means SPF was never
    # checked, so it adds no points.
    elif spf == "none":
        score += 15
        signals.append(Signal(type="spf_missing", severity="medium", description="No SPF record found for sender domain."))

    dkim = (headers.dkim or "").lower()
    if headers.dkim and "fail" in dkim:
        auth_fails.append(("DKIM", "dkim_fail", 30, "DKIM signature invalid — email may have been tampered with."))
    elif dkim == "none":  # explicit "dkim=none" only — absent header = not checked
        score += 8
        signals.append(Signal(type="dkim_missing", severity="low", description="No DKIM signature found."))

    dmarc = (headers.dmarc or "").lower()
    if headers.dmarc and "fail" in dmarc:
        auth_fails.append(("DMARC", "dmarc_fail", 30, "DMARC policy failed — domain alignment check failed."))

    if auth_fails:
        if relay:
            names = ", ".join(n for n, _, _, _ in auth_fails)
            signals.append(Signal(
                type="auth_fail_via_relay",
                severity="low",
                description=(
                    f"{names} failed, but a security relay (e.g. Mimecast) in the delivery path "
                    f"rewrites messages and routinely breaks these checks — treated as a weak "
                    f"signal, not proof of spoofing."
                ),
            ))
        else:
            for _, stype, pts, desc in auth_fails:
                score += pts
                severity = "low" if stype == "spf_fail" else "high"
                signals.append(Signal(type=stype, severity=severity, description=desc))

    # Reply-To mismatch. This is a WEAK signal: legitimate mail sent via a service
    # (newsletters, transactional mail) routinely routes replies to a different
    # mailbox. It only matters when the From domain is not authenticated.
    if headers.from_address and headers.reply_to:
        from_reg = registrable_domain(_extract_domain(headers.from_address))
        reply_reg = registrable_domain(_extract_domain(headers.reply_to))
        if from_reg and reply_reg and from_reg != reply_reg:
            dmarc_pass = bool(headers.dmarc and "pass" in headers.dmarc.lower())
            if dmarc_pass:
                signals.append(Signal(
                    type="reply_to_mismatch",
                    severity="low",
                    description=f"Reply-To domain ({reply_reg}) differs from the authenticated From domain ({from_reg}) — common for mail sent via a service.",
                ))
            else:
                score += 10
                signals.append(Signal(
                    type="reply_to_mismatch",
                    severity="medium",
                    description=f"Reply-To domain ({reply_reg}) differs from From domain ({from_reg}).",
                ))

    # Lookalike / homoglyph domain check
    if headers.from_address:
        domain = _extract_domain(headers.from_address)
        if domain and _is_lookalike(domain):
            score += 30
            signals.append(Signal(
                type="lookalike_domain",
                severity="high",
                description=f"Sender domain '{domain}' resembles a well-known brand (possible homoglyph or typosquat).",
            ))

    return min(score, 100), signals


def _extract_domain(address: str) -> str | None:
    match = re.search(r"@([\w\.\-]+)", address)
    return match.group(1).lower() if match else None


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


# Reference set for LOOKALIKE / typosquat detection only (NOT display-name
# matching). Detecting that a domain *resembles* a well-known brand is impossible
# without knowing the brands, so a small anchor list of major targets is inherent
# to the check — it is the ground truth "paypa1.com" is measured against, not a
# generic impersonation table.
_BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "linkedin": "linkedin.com",
}

# Unicode homoglyphs (Cyrillic/Greek) → the ASCII letter they imitate.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",  # Cyrillic
    "ο": "o", "ν": "v",                                            # Greek
})
# Visual substitutions: rn→m, vv→w, cl→d, 1→l, 0→o
_VISUAL = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("1", "l"), ("0", "o"))


def _variants(token: str) -> set[str]:
    normalized = token.translate(_HOMOGLYPHS)
    visual = normalized
    for src, dst in _VISUAL:
        visual = visual.replace(src, dst)
    return {normalized, visual}


def _is_lookalike(domain: str) -> bool:
    """True if a WHOLE word of the domain (split on '.' and '-') imitates a brand.

    Whole-word matching avoids substring false positives like purchase.com
    ("chase") or applebees.com ("apple"), while still catching paypa1.com,
    rnicrosoft.com, linkedln.com, paypal-login.com and paypal.evil.ru.
    """
    # Skip the real brand domains and their subdomains (accounts.google.com).
    reg = registrable_domain(domain)
    if domain in _BRAND_DOMAINS.values() or (reg and reg in _BRAND_DOMAINS.values()):
        return False
    if is_allowlisted(domain):
        return False

    labels = domain.lower().split(".")[:-1]  # drop the TLD
    tokens = [t for label in labels for t in label.split("-") if t]
    for token in tokens:
        for v in _variants(token):
            for brand in _BRAND_DOMAINS:
                if v == brand:
                    return True
                # One-letter typo of a longer brand: linkedln → linkedin
                if len(brand) >= 6 and _levenshtein(v, brand) <= 1:
                    return True
    return False
