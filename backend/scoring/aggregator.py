from backend.models.email_request import Signal

# Rule engine and LLM are blended. The rule engine stays the larger share because
# it is deterministic and explainable, but the LLM — which understands context —
# is weighted more heavily than before (was 70/30) to reduce false positives on
# benign mail that merely *looks* structurally unusual.
_RULE_WEIGHT = 0.60
_LLM_WEIGHT = 0.40

# Hard upper bound applied when the sender is authenticated (SPF+DKIM+DMARC pass)
# and no hard rule evidence fired: soft signals alone must not label an
# authenticated email suspicious. Keeps it in the "Safe" band.
_LEGITIMATE_CAP = 25

# Rule signal types that are strong, standalone evidence of phishing. If any of
# these fired, the LLM's "legitimate" read is overridden and no dampening applies.
# These are TECHNICAL facts the LLM cannot assess from the email text alone
# (authentication, domain reputation, URL/attachment reputation, impersonation),
# plus the two extreme content categories. Softer content-wording signals
# (credential/threat/financial phrasing) are intentionally NOT here — legitimate
# security and billing emails use the same phrasing, so a confident LLM
# "legitimate" verdict is allowed to override them.
_STRONG_EVIDENCE = {
    "known_bad_domain", "ip_url", "link_text_mismatch", "base64_payload",
    "suspicious_tld", "virustotal_malicious", "virustotal_suspicious",
    "vt_url_malicious", "vt_domain_malicious", "new_domain",
    "spf_fail", "dkim_fail", "dmarc_fail",
    "display_name_spoofing", "lookalike_domain",
    "ransomware", "sextortion",
}

# Fact-based detectors that justify at least a "Suspicious" verdict on their own —
# even if the LLM reads the email as legitimate. These are observations the LLM
# cannot make from the sanitized text (domain reputation/age, impersonation by
# domain mismatch, URL/attachment reputation). Gated to high/medium severity so a
# weak low note (e.g. a domain under a year old) does not raise the score by itself.
_CONCRETE_EVIDENCE = _STRONG_EVIDENCE | {"impersonation_generic", "young_domain"}
_EVIDENCE_FLOOR = 40  # Suspicious band


def aggregate(rule_score: int, llm_score: int, all_signals: list[Signal],
              authenticated: bool = False, llm_available: bool = True) -> tuple[int, str, str]:
    """Returns (final_score, verdict, verdict_label).

    `authenticated` is True when SPF, DKIM and DMARC all pass — the From domain is
    cryptographically proven to be who it says (not spoofed at the domain level).

    `llm_available` is False when the LLM returned no usable score. The verdict then
    falls back to the rule engine alone, at full weight — a 100% deterministic
    result, never silently dampened by a missing LLM share.
    """
    if llm_available:
        final = int(rule_score * _RULE_WEIGHT + llm_score * _LLM_WEIGHT)
    else:
        final = rule_score
    final = max(0, min(final, 100))

    concrete = any(s.type in _CONCRETE_EVIDENCE and s.severity in ("high", "medium")
                   for s in all_signals)

    if concrete:
        # A fact-based detector fired — don't let a lenient LLM pull it to Safe.
        final = max(final, _EVIDENCE_FLOOR)
    elif authenticated:
        # SPF+DKIM+DMARC all pass and no hard rule evidence fired. The domain is
        # not spoofed, so the only remaining flags are soft LLM guesses — chiefly
        # "brand impersonation", which the LLM asserts with no ground truth of the
        # brand's official domain (a known false-positive source on legitimate
        # third-party senders like recruiting/ESP platforms). Don't let those push
        # an authenticated sender into Suspicious. Malicious *content* is unaffected:
        # a bad URL, VT hit, attachment or lookalike domain is concrete evidence and
        # takes the branch above instead.
        final = min(final, _LEGITIMATE_CAP)
    # NOTE: there is deliberately no "LLM says legitimate -> lower the score" branch.
    # The LLM may not pull a score DOWN on its own say-so any more than it may push
    # one up — only deterministic, verifiable facts (authentication, rule evidence)
    # move the verdict. The LLM is a feature extractor, not an authority.

    if final <= 30:
        return final, "safe", "Safe"
    elif final <= 60:
        return final, "suspicious", "Suspicious"
    else:
        return final, "dangerous", "Likely Phishing"
