"""Credential-bearing HTTP clients must not follow redirects."""

from urllib.error import HTTPError
from urllib.request import Request

import pytest

from talaria.security.http import NoRedirectHandler, urlopen_no_redirect


def test_no_redirect_handler_rejects_redirect_to_another_origin():
    request = Request(
        "https://trusted.example/api", headers={"Authorization": "Bearer secret"}
    )

    with pytest.raises(HTTPError) as error:
        NoRedirectHandler().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://attacker.example/collect",
        )

    assert error.value.code == 302
    assert error.value.url == "https://trusted.example/api"
    assert "attacker.example" not in str(error.value)


def test_urlopen_no_redirect_installs_redirect_rejection(monkeypatch):
    request = Request("https://trusted.example/api")
    captured = {}

    class FakeOpener:
        def open(self, received_request, *, timeout):
            captured["request"] = received_request
            captured["timeout"] = timeout
            return "response"

    def fake_build_opener(*handlers):
        captured["handlers"] = handlers
        return FakeOpener()

    monkeypatch.setattr("talaria.security.http.build_opener", fake_build_opener)

    assert urlopen_no_redirect(request, timeout=3.5) == "response"
    assert len(captured["handlers"]) == 1
    assert isinstance(captured["handlers"][0], NoRedirectHandler)
    assert captured["request"] is request
    assert captured["timeout"] == 3.5
