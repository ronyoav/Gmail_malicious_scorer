# Rule engine and LLM are blended. The rule engine stays the larger share because
# it is deterministic and explainable.
_RULE_WEIGHT = 0.60
_LLM_WEIGHT = 0.40


def aggregate(rule_score: int, llm_score: int,
              llm_available: bool = True) -> tuple[int, str, str]:
    """Returns (final_score, verdict, verdict_label).

    The verdict comes from the score alone — no signal-based floors or caps.
    Each check's weight is expressed in the points it adds.

    `llm_available` is False when the LLM returned no usable score. The verdict then
    falls back to the rule engine alone, at full weight — a 100% deterministic
    result, never silently dampened by a missing LLM share.
    """
    if llm_available:
        final = int(rule_score * _RULE_WEIGHT + llm_score * _LLM_WEIGHT)
    else:
        final = rule_score
    final = max(0, min(final, 100))

    if final <= 30:
        return final, "safe", "Safe"
    elif final <= 60:
        return final, "suspicious", "Suspicious"
    else:
        return final, "dangerous", "Likely Phishing"
