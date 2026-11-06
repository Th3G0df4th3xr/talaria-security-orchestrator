from talaria.findings.normalizer import fingerprint


def test_fingerprint_is_stable():
    args = ("python-eval", "app.py", 4, "eval(value)")
    assert fingerprint(*args) == fingerprint(*args)


def test_fingerprint_changes_with_location():
    assert fingerprint("r", "a.py", 1, "x") != fingerprint("r", "a.py", 2, "x")
