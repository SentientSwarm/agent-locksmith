"""Owner-bound consent setup for the OAU cases: a declared custom-oauth-v1
contract against the local fake IdP, following docs/user/operator/custom-oauth.md
and custom-oauth-workflow.md with invented origins, scopes and identities.

Nothing here opens a browser: ``authorize`` fetches the authorization URL with
urllib exactly as a browser would and follows the IdP's redirect to the TLS
callback listener. Authorization URLs, states and codes never reach evidence:
the URL is registered as a canary by ``cli_private`` and the redirect location
is only ever held in memory.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode

from fakes.oau_admin import cli_private
from fakes.oau_provider import USER, WORKSPACE, FakeProvider
from fakes.pki import CA
from harness.target import LocalTarget, free_port

NAME = "customer"
PROFILE = "customer"
REDIRECT = "qa"
SCOPES = ["catalog:inspect", "records:read"]
DEFINITION = "local.qa-oau"


def sealing_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


@dataclass
class Consent:
    """One fake IdP, one CA and the matching ``oauth_consent`` overlay."""

    pki_dir: Path
    ca: CA = field(default_factory=lambda: CA.create("qa-oau-ca"))
    _fake: FakeProvider | None = None
    callback_port: int = 0
    client_secret: str = ""

    def start(self, on_secret) -> Consent:
        server = self.ca.server(("127.0.0.1",))
        self.pki_dir.mkdir(parents=True, exist_ok=True)
        (self.pki_dir / "idp.pem").write_bytes(server.cert_pem())
        key = self.pki_dir / "idp.key"
        key.write_bytes(server.key_pem())
        key.chmod(0o600)
        (self.pki_dir / "ca.pem").write_bytes(self.ca.cert_pem())
        self._fake = FakeProvider(
            on_secret=on_secret, tls=(self.pki_dir / "idp.pem", key)
        ).start()
        self.callback_port = free_port()
        self.client_secret = f"qa-oau-client-secret-{secrets.token_urlsafe(18)}"
        on_secret(self.client_secret, "oau-client-secret")
        self.fake.client_id = "qa-oau-client"
        self.fake.client_secret = self.client_secret
        self.fake.resource = f"{self.fake.origin}/resource"
        return self

    @property
    def fake(self) -> FakeProvider:
        assert self._fake is not None, "start() first"
        return self._fake

    @property
    def callback_origin(self) -> str:
        return f"https://127.0.0.1:{self.callback_port}"

    def profile(self, ca_path: str) -> dict:
        origin = self.fake.origin
        return {
            "id": PROFILE,
            "kind": "custom-oauth-v1",
            "client_id": "qa-oau-client",
            "client_generation": 1,
            "issuer": origin,
            "authorization_endpoint": f"{origin}/authorize",
            "token_endpoint": f"{origin}/token",
            "resource": f"{origin}/resource",
            "redirect_profile_id": REDIRECT,
            "redirect_uri": f"{self.callback_origin}/oauth/callback/custom/{REDIRECT}",
            "ca_path": ca_path,
            "contract": {
                "version": 1,
                "grant": "authorization_code_s256",
                "registration": "pre_registered",
                "client_auth": "client_secret_post",
                "approved_origins": [origin],
                "mcp_endpoint": f"{origin}/mcp",
                "callback": "distinct_redirect",
                "scope": {
                    "required": SCOPES,
                    "request_separator": "space",
                    "response_separator": "space",
                },
                "token_response": "oauth2-bearer-v1",
                "identity": {
                    "endpoint": f"{origin}/whoami",
                    "method": "get",
                    "response": "workspace-user-v1",
                },
                "subject": {
                    "kind": "user_workspace",
                    "workspace_id": WORKSPACE,
                    "user_id": USER,
                },
            },
        }

    def overlay(self, work: Path) -> dict:
        """Config overlay: callback listener TLS files plus the declared profile."""
        callback = self.ca.server(("127.0.0.1", "localhost"))
        (work / "oau-ca.pem").write_bytes(self.ca.cert_pem())
        (work / "oau-callback.pem").write_bytes(callback.cert_pem())
        key = work / "oau-callback.key"
        key.write_bytes(callback.key_pem())
        key.chmod(0o600)
        return {
            "oauth_consent": {
                "callback": {
                    "address": f"127.0.0.1:{self.callback_port}",
                    "cert_path": str(work / "oau-callback.pem"),
                    "key_path": str(key),
                },
                "profiles": [self.profile(str(work / "oau-ca.pem"))],
            }
        }

    def tls(self) -> ssl.SSLContext:
        return ssl.create_default_context(cafile=str(self.pki_dir / "ca.pem"))


def definition() -> dict:
    return {
        "schema_version": 1,
        "id": DEFINITION,
        "revision": 1,
        "name": "QA OAU declared service",
        "summary": "Descriptive fixture only",
        "protocol_profiles": ["mcp_streamable_http"],
        "auth_profiles": [
            {
                "id": "controlled",
                "mechanism": "oauth_provider",
                "setup": "Activate with the configured declared profile",
                "required_scopes": SCOPES,
            }
        ],
        "workflows": [
            {
                "id": "read",
                "summary": "Read a record",
                "operations": ["read_record"],
                "effect": "read",
            }
        ],
        "setup": "Author a disabled connection; no provider call",
        "limits": ["No live verification"],
        "verification": {
            "level": "candidate",
            "evidence_ref": "local fixture draft",
            "verified_at": None,
            "source_revision": None,
        },
    }


def connect(t: LocalTarget, label: str, generation: int = 1):
    """``oauth connect`` with the current config_revision; returns the CLI result."""
    status = t.cli("oauth", "account-status", NAME, "--label", label)
    assert status.code == 0, status.err
    return cli_private(
        t,
        "oauth",
        "connect",
        NAME,
        "--label",
        label,
        "--profile",
        PROFILE,
        "--client-generation",
        str(generation),
        "--redirect-profile",
        REDIRECT,
        "--expected-config-revision",
        str(status.json["config_revision"]),
        "--scopes",
        ",".join(SCOPES),
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def consent_redirect(c: Consent, authorization_url: str) -> str:
    """Approve at the fake IdP; return the callback location without following it."""
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=c.tls()), _NoRedirect()
    )
    try:
        opener.open(authorization_url, timeout=30)
    except urllib.error.HTTPError as err:
        assert err.code == 302, f"IdP answered {err.code}"
        location = err.headers["Location"]
        return location
    raise AssertionError("IdP did not redirect")


def deliver(
    c: Consent, location: str, host: str | None = None, url: str | None = None
) -> tuple[int, str]:
    """GET a callback URL on the TLS callback listener (optionally with a Host override)."""
    request = urllib.request.Request(url or location)
    if host is not None:
        request.add_unredirected_header("Host", host)
    try:
        with urllib.request.urlopen(request, context=c.tls(), timeout=60) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode(errors="replace")


def callback_url(c: Consent, **params: str) -> str:
    return f"{c.callback_origin}/oauth/callback/custom/{REDIRECT}?{urlencode(params)}"


def attempt(t: LocalTarget, attempt_id: str) -> dict:
    result = t.cli("oauth", "attempt-status", NAME, attempt_id)
    assert result.code == 0, result.err
    return result.json


def account(t: LocalTarget, label: str) -> dict:
    result = t.cli("oauth", "account-status", NAME, "--label", label)
    assert result.code == 0, result.err
    return result.json


def json_file(t: LocalTarget, name: str, value: dict) -> str:
    return str(t.write_file(name, json.dumps(value)))
