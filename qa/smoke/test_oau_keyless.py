"""A daemon started without LOCKSMITH_OAUTH_SEALING_KEY (docs/user/concepts/oauth-flow.md:101-110,
docs/user/operator/oauth-consent.md:20-23)."""

import socket
import tempfile
from pathlib import Path

import pytest

from fakes.oau_admin import admin
from fakes.oau_consent import Consent
from fakes.oau_provider import LEGACY_NAME as NAME
from fakes.oau_provider import FakeProvider, legacy_registration

case = pytest.mark.case


@pytest.fixture(scope="module")
def nk(target_factory):
    holder = {}
    fake = FakeProvider(
        on_secret=lambda v, label: holder["t"].canaries.add(v, label)
    ).start()
    t = target_factory(label="oau-keyless", upstream=False)
    holder["t"] = t
    put = admin(t, "PUT", f"/admin/operator/tools/{NAME}", legacy_registration(fake))
    assert put.status == 200, put.text
    yield t, fake
    fake.stop()


@case(
    "SMK-OAU-040",
    area="OAU",
    kind="refusal",
    covers=["agent.ANY./api/{tool_name}/{*path}"],
    codes=["oauth_sealing_key_unset"],
)
def test_oauth_call_without_sealing_key(nk):
    """oauth-flow.md:108-110 and 311: without the sealing key, proxy calls to OAuth
    registrations return 503 oauth_sealing_key_unset, with no provider or upstream request."""
    t, fake = nk
    reg = t.cli("agent", "register", "--name", "oau-keyless", "--allowlist", NAME)
    assert reg.code == 0, reg.err
    bind = t.cli(
        "agent",
        "set-credential",
        reg.json["public_id"],
        NAME,
        "--oauth-session",
        "default",
    )
    assert bind.code == 0, bind.err
    response = t.http("GET", f"/api/{NAME}/records", token=reg.json["token"])
    assert response.status == 503
    assert response.code == "oauth_sealing_key_unset"
    assert sum(fake.counts.values()) == 0, "a refused call reached the provider"


@case(
    "SMK-OAU-041",
    area="OAU",
    kind="corner",
    covers=["admin.GET./admin/operator/oauth", "cli.oauth.list"],
)
def test_oauth_admin_routes_not_mounted_without_key(nk):
    """oauth-flow.md:108-109: if the key is not set, the OAuth admin routes are not mounted."""
    t, _ = nk
    listed = t.cli("oauth", "list")
    assert listed.code == 4, "CLI must report the missing route"
    assert admin(t, "GET", "/admin/operator/oauth").status == 404
    assert admin(t, "GET", f"/admin/operator/oauth/{NAME}").status == 404


@case(
    "SMK-OAU-042",
    area="OAU",
    kind="corner",
    covers=[
        "callback.ANY./oauth/callback{,/slack,/custom/{redirect_profile_id}}",
        "beh.config.validation",
    ],
)
def test_consent_config_requires_sealing_key(target_factory):
    """oauth-consent.md:20-23: consent requires a valid LOCKSMITH_OAUTH_SEALING_KEY at
    startup; configuring `oauth_consent` without it refuses to start (no callback listener)."""
    holder: list = []
    consent = Consent(Path(tempfile.mkdtemp(prefix="oau-pki-"))).start(
        lambda v, label: holder.append((v, label))
    )
    t = target_factory(
        start=False, config=consent.overlay, label="oau-consent-nokey", upstream=False
    )
    for value, label in holder:
        t.canaries.add(value, label)
    try:
        proc = t.run_daemon_once()
        assert proc.returncode != 0
        assert "sealing key" in (proc.stdout + proc.stderr).lower()
        with socket.socket() as probe:
            probe.settimeout(0.5)
            listening = probe.connect_ex(("127.0.0.1", consent.callback_port)) == 0
        assert not listening, "callback listener left running"
    finally:
        consent.fake.stop()
