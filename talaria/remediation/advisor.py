SUGGESTIONS = {
    "python-eval": (
        "Avoid eval() on untrusted input. "
        "Prefer explicit parsing or a safe, constrained expression parser."
    ),
    "possible-hardcoded-secret": (
        "Move credentials to a secret manager or environment injection; "
        "rotate any real exposed credential."
    ),
}


def advise(rule_id: str) -> str:
    return SUGGESTIONS.get(
        rule_id,
        "Review the finding manually and apply the relevant secure-coding guidance.",
    )
