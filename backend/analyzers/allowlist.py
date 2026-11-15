"""Shared allow-list of well-known, high-reputation registrable domains.

The rule engine produces many *structural* signals (external link, redirect
parameter, long URL, keyword-in-domain, etc.) that fire on perfectly normal
mail — newsletters, SaaS notifications, identity providers. When a URL's
registrable domain is on this list we suppress those weak structural penalties:
the domain itself is trusted infrastructure, so its link structure is not
evidence of phishing. Content- and header-based signals still apply.

This is intentionally a small, conservative list of global providers — NOT a
substitute for the live reputation / VirusTotal checks in reputation_analyzer.
"""
from backend.analyzers.reputation_analyzer import registrable_domain

# Registrable domains (eTLD+1) that are trusted infrastructure. A match here
# means: do not raise structural URL penalties for links on this domain or any
# of its subdomains (accounts.google.com, login.microsoftonline.com, ...).
KNOWN_GOOD: set[str] = {
    # Google
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "youtube.com", "goo.gl", "withgoogle.com", "google.co.il",
    # Microsoft
    "microsoft.com", "microsoftonline.com", "office.com", "office365.com",
    "outlook.com", "live.com", "sharepoint.com", "onmicrosoft.com",
    "windows.net", "azure.com", "msftconnecttest.com",
    # Apple
    "apple.com", "icloud.com", "me.com",
    # Amazon / AWS — brand & docs only. NOT amazonaws.com / amazonses.com /
    # cloudfront.net: those are shared infrastructure anyone can send or host
    # from (including phishers), so they are not trusted *destinations*.
    "amazon.com", "aws.amazon.com", "awsstatic.com",
    # Social / productivity
    "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "licdn.com", "github.com", "githubusercontent.com",
    "gitlab.com", "atlassian.com", "atlassian.net", "slack.com",
    "zoom.us", "dropbox.com", "notion.so", "figma.com",
    # Payments / commerce
    "paypal.com", "stripe.com", "shopify.com", "ebay.com",
    # NOTE: email service providers / relays (SendGrid, Mailchimp, list-manage,
    # Amazon SES, Mailgun, Constant Contact, HubSpot mail, ...) are deliberately
    # NOT allowlisted. They send and host links on behalf of anyone, legit or
    # not, so a tracked link through them must be judged by its real destination
    # (and by VirusTotal / domain reputation), never trusted by the relay alone.
    # Israeli providers / banks (common in this user's inbox)
    "gov.il", "leumi.co.il", "bankhapoalim.co.il", "mizrahi-tefahot.co.il",
    "discountbank.co.il", "cal-online.co.il", "max.co.il", "isracard.co.il",
}


def is_allowlisted(domain: str | None) -> bool:
    """True when `domain` (any host) resolves to a known-good registrable domain."""
    reg = registrable_domain(domain)
    return reg in KNOWN_GOOD if reg else False
