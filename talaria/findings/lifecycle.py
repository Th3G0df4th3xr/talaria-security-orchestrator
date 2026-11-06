"""Finding lifecycle states and permitted transitions."""

from enum import StrEnum


class FindingStatus(StrEnum):
    OPEN = "open"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    REOPENED = "reopened"


ALLOWED_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.OPEN: {
        FindingStatus.NEEDS_REVIEW,
        FindingStatus.CONFIRMED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
    },
    FindingStatus.NEEDS_REVIEW: {
        FindingStatus.OPEN,
        FindingStatus.CONFIRMED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
    },
    FindingStatus.CONFIRMED: {
        FindingStatus.NEEDS_REVIEW,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
        FindingStatus.FIXED,
    },
    FindingStatus.FALSE_POSITIVE: {
        FindingStatus.OPEN,
        FindingStatus.REOPENED,
    },
    FindingStatus.ACCEPTED_RISK: {
        FindingStatus.OPEN,
        FindingStatus.REOPENED,
    },
    FindingStatus.FIXED: {
        FindingStatus.REOPENED,
    },
    FindingStatus.REOPENED: {
        FindingStatus.NEEDS_REVIEW,
        FindingStatus.CONFIRMED,
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.ACCEPTED_RISK,
    },
}


def can_transition(
    current: FindingStatus,
    target: FindingStatus,
) -> bool:
    """Check whether a finding status transition is permitted."""
    return target in ALLOWED_TRANSITIONS[current]
