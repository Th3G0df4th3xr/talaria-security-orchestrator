from talaria.hunters.profiles import load_profile


def test_baseline_profile_loads():
    profile = load_profile()
    assert profile["name"] == "baseline"
    assert {item["id"] for item in profile["checks"]} >= {
        "python-eval",
        "possible-hardcoded-secret",
    }
