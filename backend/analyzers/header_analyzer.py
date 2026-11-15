import re
from backend.models.email_request import EmailHeaders, Signal
from backend.analyzers.allowlist import is_allowlisted
from backend.analyzers.reputation_analyzer import registrable_domain

# Known legitimate third-party email senders (ATS, marketing platforms)
_TRUSTED_THIRD_PARTY_DOMAINS = {
    # ATS / HR platforms
    "comeet-notifications.com", "comeet.co",
    "sparkhire.com", "spark-hire.com",
    "greenhouse.io", "greenhouse-mail.io",
    "lever.co", "levermail.com",
    "jobvite.com",
    "workable.com", "workablemail.com",
    "bamboohr.com",
    "smartrecruiters.com",
    "myworkday.com", "workday.com",
    "icims.com",
    "taleo.net",
    "successfactors.com", "successfactors.eu",
    "sap.com",
    "oracle.com",
    # Email marketing & transactional
    "sendgrid.net", "sendgrid.com",
    "mailchimp.com", "mandrillapp.com",
    "hubspotemail.net", "hubspot.com",
    "brevo.com", "sendinblue.com",
    "activecampaign.com",
    "mailgun.org", "mailgun.net",
    "amazonses.com",
    "sparkpostmail.com",
    "postmarkapp.com",
    "customer.io",
    "klaviyo.com",
    "constantcontact.com",
    "campaignmonitor.com",
    # Calendar & notifications
    "calendar-server.bounces.google.com",
    "notifications.google.com",
    "zoom.us",
    "calendly.com",
    # E-commerce & payments
    "shopify.com", "mail.shopify.com",
    "stripe.com",
    "paypal.com",
    # LinkedIn & social
    "linkedin.com", "e.linkedin.com",
    # Cloud providers
    "notifications.aws.amazon.com",
    "azure.com",
}


def _is_trusted_sender(headers: EmailHeaders) -> bool:
    """Returns True if the email is sent via a known legitimate third-party service."""
    for field in [headers.from_address, headers.received_from]:
        if not field:
            continue
        domain = _extract_domain(field) or field.lower()
        for trusted in _TRUSTED_THIRD_PARTY_DOMAINS:
            if domain.endswith(trusted):
                return True
    return False


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

    trusted = _is_trusted_sender(headers)
    relay = _via_security_relay(headers)

    # Authentication checks (SPF / DKIM / DMARC). A hard "fail" is normally strong
    # evidence — EXCEPT when a security relay in the path rewrote the message, which
    # routinely breaks these checks for genuine mail. In that case we record a single
    # low-severity note and add no points, so a legitimate relayed email is not
    # mislabeled as spoofed.
    auth_fails = []  # (check_name, signal_type, points, description)

    spf = (headers.spf or "").lower()
    if headers.spf and "fail" in spf:
        auth_fails.append(("SPF", "spf_fail", 25, "SPF check failed — sender domain not authorized."))
    elif not headers.spf or spf in ("none", "neutral"):
        if not trusted:
            score += 10
            signals.append(Signal(type="spf_missing", severity="medium", description="No SPF record found for sender domain."))
        else:
            signals.append(Signal(type="spf_missing", severity="low", description="No SPF record — sent via trusted third-party service (expected)."))

    dkim = (headers.dkim or "").lower()
    if headers.dkim and "fail" in dkim:
        auth_fails.append(("DKIM", "dkim_fail", 20, "DKIM signature invalid — email may have been tampered with."))
    elif not headers.dkim or dkim in ("none", "neutral"):
        if not trusted:
            score += 8
            signals.append(Signal(type="dkim_missing", severity="low", description="No DKIM signature found."))
        else:
            signals.append(Signal(type="dkim_missing", severity="low", description="No DKIM on original domain — signed by trusted third-party service (expected)."))

    dmarc = (headers.dmarc or "").lower()
    if headers.dmarc and "fail" in dmarc:
        auth_fails.append(("DMARC", "dmarc_fail", 20, "DMARC policy failed — domain alignment check failed."))

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
                signals.append(Signal(type=stype, severity="high", description=desc))

    # Reply-To mismatch
    if headers.from_address and headers.reply_to:
        from_domain = _extract_domain(headers.from_address)
        reply_domain = _extract_domain(headers.reply_to)
        if from_domain and reply_domain and from_domain != reply_domain:
            score += 20
            signals.append(Signal(
                type="reply_to_mismatch",
                severity="high",
                description=f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}).",
            ))

    # Display name spoofing: "PayPal <attacker@gmail.com>"
    if headers.from_address:
        display_name = _extract_display_name(headers.from_address)
        actual_domain = _extract_domain(headers.from_address)
        if display_name and actual_domain:
            spoofed_brand = _spoofed_brand(display_name, actual_domain)
            if spoofed_brand:
                score += 35
                signals.append(Signal(
                    type="display_name_spoofing",
                    severity="high",
                    description=f"Display name claims to be '{spoofed_brand}' but email is sent from '{actual_domain}'.",
                ))
            else:
                # Generalized impersonation (any org identity, not just the fixed brand list)
                generic = _generic_impersonation(headers)
                if generic:
                    score += 20
                    signals.append(Signal(type="impersonation_generic", severity="medium", description=generic))

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


def _extract_display_name(address: str) -> str | None:
    """Extract the human-readable name from 'Name <email@domain.com>'."""
    match = re.match(r'^"?([^"<]+)"?\s*<', address.strip())
    return match.group(1).strip().lower() if match else None


# Known brands: display-name keyword → legitimate sending domain
_KNOWN_BRANDS = {
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
    "bank of america": "bankofamerica.com",
    "linkedin": "linkedin.com",
}


def _spoofed_brand(display_name: str, actual_domain: str) -> str | None:
    """Return brand name if display name claims a known brand but domain doesn't match."""
    for brand, legit_domain in _KNOWN_BRANDS.items():
        if brand in display_name and not actual_domain.endswith(legit_domain):
            return brand
    return None


# Words in a display name that are generic/role labels, not a brand or person's
# name. Used to decide whether a display name presents an *organizational* identity.
_ROLE_WORDS = {
    "the", "team", "support", "notification", "notifications", "noreply", "no-reply",
    "donotreply", "do-not-reply", "service", "services", "admin", "info", "account",
    "accounts", "security", "billing", "help", "helpdesk", "customer", "care", "mail",
    "email", "alert", "alerts", "update", "updates", "department", "dept", "office",
    "payroll", "benefits", "hr", "it", "sales", "marketing", "news", "newsletter",
    "inc", "llc", "ltd", "corp", "co", "group", "via", "and", "for",
}
# A subset whose presence signals the sender claims to be an ORGANISATION (not a
# person). Personal-name senders ("John Smith") have none of these, so we don't
# flag them — this keeps false positives down.
_ORG_INDICATORS = {
    "hr", "team", "support", "notification", "notifications", "department", "dept",
    "payroll", "benefits", "helpdesk", "service", "services", "billing", "admin",
    "it", "sales", "marketing", "office", "inc", "llc", "ltd", "corp", "group",
}
# ESP / relay sending domains: when the From domain is one of these, it is sending
# infrastructure, not a claimed brand identity, so the impersonation check is skipped.
_ESP_SENDER_DOMAINS = {
    "amazonses.com", "sendgrid.net", "mailgun.org", "mailchimp.com", "mcsv.net",
    "sparkpostmail.com", "sendinblue.com", "brevo.com", "mandrillapp.com",
    "postmarkapp.com", "customer.io", "klaviyo.com", "list-manage.com",
}


def _generic_impersonation(headers: EmailHeaders) -> str | None:
    """Detect impersonation without a fixed brand list: a display name that presents
    an organisational identity whose brand word is not reflected in the sending
    domain (e.g. 'Yellowtail EVP HR' <...@mfbcpa.com>).

    Exclusions: trusted sender domains (allow-list) and ESP/relay sending domains,
    since those are not a claimed brand. DKIM alignment is deliberately NOT an
    exclusion — a phisher can validly sign from their own throwaway domain.
    """
    if not headers.from_address:
        return None
    display = _extract_display_name(headers.from_address)
    from_domain = _extract_domain(headers.from_address)
    if not display or not from_domain:
        return None

    from_reg = registrable_domain(from_domain) or from_domain
    if is_allowlisted(from_domain) or from_reg in _ESP_SENDER_DOMAINS:
        return None

    words = re.findall(r"[a-z0-9]{2,}", display.lower())
    if not any(w in _ORG_INDICATORS for w in words):
        return None  # looks like a personal name, not an org identity

    from_label = from_reg.split(".")[0]
    # "Brand" words in the display name that are not reflected in the From domain.
    orphans = [
        w for w in words
        if len(w) >= 3 and w not in _ROLE_WORDS
        and w not in from_domain and w not in from_label and from_label not in w
    ]
    if orphans:
        return (f"Display name '{display}' presents an organisational identity "
                f"('{orphans[0]}') not reflected in the sender domain '{from_reg}'.")
    return None


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


def _is_lookalike(domain: str) -> bool:
    # Skip exact legitimate domains and any subdomain of a known-good brand
    # (e.g. accounts.google.com -> google.com). Without this, legitimate brand
    # subdomains are flagged as impersonating their own brand.
    if domain in _KNOWN_BRANDS.values():
        return False
    reg = registrable_domain(domain)
    if is_allowlisted(domain) or (reg and reg in _KNOWN_BRANDS.values()):
        return False

    # Normalize unicode homoglyphs (Cyrillic/Greek → ASCII lookalikes)
    normalized = (
        domain
        .replace("а", "a").replace("е", "e").replace("о", "o")   # Cyrillic
        .replace("р", "p").replace("с", "c").replace("х", "x")
        .replace("ο", "o").replace("ν", "v")                      # Greek
    )
    # Normalize multi-character visual substitutions: rn→m, vv→w, cl→d, li→li(1→l)
    visual = (
        normalized
        .replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .replace("1", "l")
        .replace("0", "o")
    )
    for brand, legit in _KNOWN_BRANDS.items():
        brand_word = brand.split()[0]
        for candidate in (normalized, visual):
            if brand_word in candidate and domain != legit:
                return True
    # Digit-substitution typosquats — only fire if NOT a legit domain
    for candidate in (normalized, visual):
        if re.search(r"(pay[p\d]a[l1]|g[o0]{2}gle|micr[o0]s[o0]ft|app[l1]e|amaz[o0]n)", candidate):
            if domain not in _KNOWN_BRANDS.values():
                return True
    # Edit distance: catches omissions/substitutions like linkedln.com → linkedin
    hostname = domain.split(".")[0]
    for brand, legit in _KNOWN_BRANDS.items():
        brand_word = brand.split()[0]
        if len(brand_word) >= 6 and hostname != brand_word and _levenshtein(hostname, brand_word) <= 1:
            return True
    return False
