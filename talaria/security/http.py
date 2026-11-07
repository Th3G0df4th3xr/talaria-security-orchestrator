"""HTTP helpers that keep credential-bearing requests on their configured URL."""

from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirectHandler(HTTPRedirectHandler):
    """Reject redirects so authorization headers cannot reach another origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "HTTP redirects are disabled.", headers, fp)


def urlopen_no_redirect(request: Request, *, timeout: float):
    """Open one HTTP request without following any redirect response."""
    opener = build_opener(NoRedirectHandler())
    return opener.open(request, timeout=timeout)
