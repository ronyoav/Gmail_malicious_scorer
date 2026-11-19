# Rule engine and LLM are blended. The rule engine stays the larger share because
# it is deterministic and explainable.
_RULE_WEIGHT = 0.60
_LLM_WEIGHT = 0.40

# A confirmed malicious intent from the LLM (credential harvesting, financial fraud,
# malware delivery) is categorical, not additive — a weighted average must not be able
# to dampen it into "Safe". When present, the final score is floored to the bottom of
# the Suspicious band so a human reviews it, but NOT higher: the deterministic rule
# engine stays the sole authority for the most severe "Likely Phishing" verdict.
_MALICIOUS_INTENT_FLOOR = 45


def aggregate(rule_score: int, llm_score: int,
              llm_available: bool = True,
              definitive_malicious_intent: bool = False) -> tuple[int, str, str]:
    """Returns (final_score, verdict, verdict_label).

    The verdict comes from the score. The one exception is `definitive_malicious_intent`:
    when the LLM names a concrete malicious goal, the score is floored to the Suspicious
    band so a confident detection can never be averaged down into Safe (it is never
    floored past Suspicious — the rule engine owns the "Likely Phishing" verdict).

    `llm_available` is False when the LLM returned no usable score. The verdict then
    falls back to the rule engine alone, at full weight — a 100% deterministic
    result, never silently dampened by a missing LLM share.
    """
    if llm_available:
        final = int(rule_score * _RULE_WEIGHT + llm_score * _LLM_WEIGHT)
    else:
        final = rule_score
    final = max(0, min(final, 100))

    # A confirmed malicious intent cannot land in Safe (see _MALICIOUS_INTENT_FLOOR).
    if llm_available and definitive_malicious_intent:
        final = max(final, _MALICIOUS_INTENT_FLOOR)

    if final <= 30:
        return final, "safe", "Safe"
    elif final <= 60:
        return final, "suspicious", "Suspicious"
    else:
        return final, "dangerous", "Likely Phishing"
