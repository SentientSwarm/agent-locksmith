"""OAuth token calls take the route's egress (AGENT-269).

Docs: docs/concepts/egress-and-inspection.md "Egress modes", docs/concepts/oauth-flow.md
"Refresh task". A `proxied` OAuth route's bootstrap exchange goes through
`egress_proxy`, and with no egress configured bootstrap fails closed before any session
row is written. The policy's token-host listing is covered by tests/egress_policy_test.rs.
The fake provider is local; no real provider is contacted.
"""

import pytest

from fakes.agt_upstream import EgressProxy
from fakes.oau_admin import admin
from fakes.oau_consent import sealing_key
from fakes.oau_provider import FakeProvider, device_registration, legacy_registration

case = pytest.mark.case
BOOT = "admin.POST./admin/operator/oauth/{name}/bootstrap"
DEVICE = "admin.POST./admin/operator/oauth/{name}/device-login"
DEVICE_NAME = "qa-oauth-device-proxied"
MODE = "beh.egress.enforcement"
NAME = "qa-oauth-proxied"


@pytest.fixture(scope="module")
def oe(target_factory):
    holder = {}
    fake = FakeProvider(on_secret=lambda v, label: holder["canaries"](v, label)).start()
    proxy = EgressProxy()
    targets = {}
    for label, config in (
        ("oau-egress-piped", {"egress_proxy": proxy.url}),
        ("oau-egress-none", None),
    ):
        t = target_factory(
            env={"LOCKSMITH_OAUTH_SEALING_KEY": sealing_key()},
            label=label,
            upstream=False,
            **({"config": config} if config else {}),
        )
        for path, body in (
            (f"/admin/operator/tools/{NAME}", legacy_registration(fake)),
            (f"/admin/operator/models/{DEVICE_NAME}", device_registration(fake)),
        ):
            put = admin(t, "PUT", path, body | {"egress": "proxied"})
            assert put.status == 200, put.text
        targets[label] = t
    holder["canaries"] = lambda v, label: [
        t.canaries.add(v, label) for t in targets.values()
    ]
    yield targets, fake, proxy
    fake.stop()
    proxy.close()


def bootstrap(t, fake):
    return t.cli(
        "oauth",
        "bootstrap",
        NAME,
        "--refresh-token-stdin",
        stdin=fake.mint_refresh_token() + "\n",
    )


@case(
    "SMK-OAU-051",
    area="OAU",
    kind="positive",
    covers=[BOOT, MODE, "cli.oauth.bootstrap"],
)
def test_proxied_oauth_bootstrap_goes_through_the_egress_proxy(oe):
    """egress-and-inspection.md "Egress modes": a proxied OAuth route's token call goes
    through egress_proxy."""
    targets, fake, proxy = oe
    t = targets["oau-egress-piped"]
    before = fake.counts["refresh"]
    boot = bootstrap(t, fake)
    assert boot.code == 0, boot.err
    assert fake.counts["refresh"] == before + 1
    assert any(
        method == "POST" and target.endswith("/token") for method, target in proxy.seen
    ), "the token exchange must go through the egress proxy"


@case(
    "SMK-OAU-052",
    area="OAU",
    kind="refusal",
    covers=[BOOT, MODE, "cli.oauth.bootstrap"],
    codes=["egress_proxy_unconfigured"],
)
def test_proxied_oauth_bootstrap_without_egress_fails_closed(oe):
    """oauth-flow.md "Refresh task": with no usable egress, bootstrap answers 503
    egress_proxy_unconfigured before any session row is written, and the provider is
    never contacted."""
    targets, fake, _proxy = oe
    t = targets["oau-egress-none"]
    before = fake.counts["refresh"]
    boot = admin(
        t,
        "POST",
        f"/admin/operator/oauth/{NAME}/bootstrap",
        {"refresh_token": fake.mint_refresh_token()},
    )
    assert boot.status == 503 and boot.code == "egress_proxy_unconfigured", boot.text
    assert fake.counts["refresh"] == before, "the provider must not be contacted"
    status = t.cli("oauth", "status", NAME)
    assert status.code == 0, status.err
    assert status.json["present"] is False, "no session row may be written"


@case(
    "SMK-OAU-053",
    area="OAU",
    kind="refusal",
    covers=[DEVICE, MODE],
    codes=["egress_proxy_unconfigured"],
)
def test_proxied_device_login_without_egress_fails_closed(oe):
    """egress-and-inspection.md "Egress modes": a proxied route's device login takes
    the route's egress, so with none configured it answers 503
    egress_proxy_unconfigured before the provider is asked for a user code."""
    targets, fake, _proxy = oe
    t = targets["oau-egress-none"]
    before = fake.counts["device-code"]
    start = admin(t, "POST", f"/admin/operator/oauth/{DEVICE_NAME}/device-login", {})
    assert start.status == 503 and start.code == "egress_proxy_unconfigured", start.text
    assert fake.counts["device-code"] == before, "the provider must not be contacted"
