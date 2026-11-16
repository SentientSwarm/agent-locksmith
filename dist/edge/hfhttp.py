"""HTTP and token handling for install_model.py.

The operator's token comes from a 0600 file or a hidden prompt and is
checked without ever being echoed. It travels only as an unredirected
header, re-added on a redirect only when the new URL has the endpoint's
own origin, so the CDN a download redirects to never sees it.
"""

from __future__ import annotations

import urllib.parse
import urllib.request
from pathlib import Path

from catalog import InstallError


def read_token_file(path: Path) -> str:
    info = path.stat()
    if info.st_mode & 0o077:
        raise InstallError(
            f"{path} must not be readable by group or others (chmod 600)"
        )
    return check_token(path.read_text(encoding="utf-8"), str(path))


def check_token(raw: str, source: str) -> str:
    """One printable token, or an error that never repeats it."""
    token = raw.strip()
    if not token or any(c.isspace() or not c.isprintable() for c in token):
        raise InstallError(f"{source} must contain one token")
    return token


def redirect_allowed(old: str, new: str) -> bool:
    old_scheme, new_scheme = (
        urllib.parse.urlsplit(old).scheme,
        urllib.parse.urlsplit(new).scheme,
    )
    return new_scheme == "https" or (old_scheme == new_scheme == "http")


DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(url: str) -> tuple[str, str, int | None]:
    """Scheme, lowercased host and port, with the default port made explicit."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    return (
        scheme,
        (parts.hostname or "").lower(),
        parts.port or DEFAULT_PORTS.get(scheme),
    )


class _Redirects(urllib.request.HTTPRedirectHandler):
    """Carry the token across a redirect only back to the endpoint's own
    origin (HF's resolve cache); never to the CDN or any other host."""

    def __init__(self, endpoint: str, token: str | None):
        super().__init__()
        self._endpoint = _origin(endpoint)
        self._token = token

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not redirect_allowed(req.full_url, newurl):
            raise InstallError("refusing a redirect that downgrades from https")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and self._token and _origin(new.full_url) == self._endpoint:
            new.add_unredirected_header("Authorization", f"Bearer {self._token}")
        return new
