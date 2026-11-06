from talaria.remediation.advisor import advise


def test_remediation_is_advisory():
    assert "eval" in advise("python-eval")
