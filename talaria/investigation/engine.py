def investigate(finding: dict) -> dict:
    return {
        "triage": "manual_review_required",
        "rationale": "Pattern match only; validate reachability, context, and data flow.",
        "confidence": "low",
    }
