from backend.models.email_request import Signal

# Rule engine and LLM are blended. The rule engine stays the larger share because
# it is deterministic and explainable, but the LLM — which understands context —
# is weighted more heavily than before (was 70/30) to reduce false positives on
# benign mail that merely *looks* structurally unusual.
_RULE_WEIGHT = 0.60
_LLM_WEIGHT = 0.40

# When the LLM is confident the email is legitimate and no *hard* rule evidence
# contradicts it, cap the final score here (keeps it in the "Safe" band). Weak,
# structural signals alone must not label a legitimate email as suspicious.
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
    "spf_fail", "dkim_fail", "dmarc_fail", "reply_to_mismatch",
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


def aggregate(rule_score: int, llm_score: int, all_signals: list[Signal]) -> tuple[int, str, str]:
    """Returns (final_score, verdict, verdict_label)."""
    final = int(rule_score * _RULE_WEIGHT + llm_score * _LLM_WEIGHT)
    final = max(0, min(final, 100))

    concrete = any(s.type in _CONCRETE_EVIDENCE and s.severity in ("high", "medium")
                   for s in all_signals)
    llm_says_legit = any(s.type == "llm_legitimate" for s in all_signals)

    if concrete:
        # A fact-based detector fired — don't let a lenient LLM pull it to Safe.
        final = max(final, _EVIDENCE_FLOOR)
    elif llm_says_legit:
        # LLM is confident it's legitimate and nothing concrete contradicts it.
        final = min(final, _LEGITIMATE_CAP)

    if final <= 30:
        return final, "safe", "Safe"
    elif final <= 60:
        return final, "suspicious", "Suspicious"
    else:
        return final, "dangerous", "Likely Phishing"
