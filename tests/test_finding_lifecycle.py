import pytest

from talaria.findings.lifecycle import (
    ALLOWED_TRANSITIONS,
    FindingStatus,
    can_transition,
)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (FindingStatus.OPEN, FindingStatus.CONFIRMED),
        (FindingStatus.OPEN, FindingStatus.NEEDS_REVIEW),
        (FindingStatus.OPEN, FindingStatus.FALSE_POSITIVE),
        (FindingStatus.NEEDS_REVIEW, FindingStatus.ACCEPTED_RISK),
        (FindingStatus.CONFIRMED, FindingStatus.FIXED),
        (FindingStatus.FALSE_POSITIVE, FindingStatus.REOPENED),
        (FindingStatus.ACCEPTED_RISK, FindingStatus.REOPENED),
        (FindingStatus.FIXED, FindingStatus.REOPENED),
        (FindingStatus.REOPENED, FindingStatus.CONFIRMED),
    ],
)
def test_allowed_transitions(current, target):
    assert can_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (FindingStatus.OPEN, FindingStatus.FIXED),
        (FindingStatus.FIXED, FindingStatus.CONFIRMED),
        (FindingStatus.FIXED, FindingStatus.ACCEPTED_RISK),
        (FindingStatus.FALSE_POSITIVE, FindingStatus.FIXED),
        (FindingStatus.ACCEPTED_RISK, FindingStatus.FIXED),
    ],
)
def test_rejected_transitions(current, target):
    assert not can_transition(current, target)


def test_every_status_has_transition_definition():
    assert set(ALLOWED_TRANSITIONS) == set(FindingStatus)
