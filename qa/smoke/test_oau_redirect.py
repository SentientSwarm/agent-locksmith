"""OAuth token calls never follow a redirect (AGENT-243).

Docs: docs/concepts/oauth-flow.md#refresh-task ("Token calls never follow a
redirect"). Each path that POSTs a refresh token or code to a token endpoint
(bootstrap, inline refresh, background refresh and device login) is pointed at
a fake provider whose token endpoint answers 307 to a second listener. That
listener must see no connection at all, so no refresh token or client secret
can reach it, whether the redirect stays on the provider's host or names
another. The owner-bound consent paths are in test_oau_consent.py. The fake
provider is local; no real provider is contacted.
"""

import time

import pytest

from fakes.oau_admin import admin
from fakes.oau_consent import sealing_key
from fakes.oau_provider import (
    DEVICE_NAME,
    LEGACY_NAME,
    FakeProvider,
    RedirectSink,
    device_registration,
    legacy_registration,
)

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
BOOT = "admin.POST./admin/operator/oauth/{name}/bootstrap"
POLL = "admin.GET./admin/operator/oauth/{name}/device-login/{attempt}"
START = "admin.POST./admin/operator/oauth/{name}/device-login"
STATUS = "admin.GET./admin/operator/oauth/{name}"
TASK = "beh.oauth.refresh-task"


@pytest.fixture(scope="module")
def rd(target_factory):
    holder = {}
    fake = FakeProvider(
        on_secret=lambda v, label: holder["t"].canaries.add(v, label)
    ).start()
    t = target_factory(
        env={"LOCKSMITH_OAUTH_SEALING_KEY": sealing_key()},
        label="oau-redirect",
        upstream=False,
    )
    holder["t"] = t
    for path, body in (
        (f"/admin/operator/tools/{LEGACY_NAME}", legacy_registration(fake)),
        (f"/admin/operator/models/{DEVICE_NAME}", device_registration(fake)),
    ):
        put = admin(t, "PUT", path, body)
        assert put.status == 200, put.text
    sinks = {"same-host": RedirectSink(), "cross-host": RedirectSink.cross_host()}
    yield t, fake, sinks
    fake.token_redirect = None
    fake.stop()
    for sink in sinks.values():
        sink.close()


class redirected:
    """Point the fake's token endpoint at ``sink`` for the block."""

    def __init__(self, fake, sink):
        self.fake, self.sink = fake, sink

    def __enter__(self):
        self.before = self.fake.counts["token-redirected"]
        self.fake.token_redirect = self.sink.url
        return self

    def __exit__(self, *exc):
        self.fake.token_redirect = None

    @property
    def answered(self) -> int:
        return self.fake.counts["token-redirected"] - self.before


def assert_not_followed(sink):
    # A followed redirect connects within milliseconds; give a slow one a moment.
    time.sleep(0.3)
    assert sink.connections == 0, "the redirect target was contacted"
    assert sink.secrets_seen == 0, "a refresh token or client secret reached it"


def bootstrap(t, fake, label, expires_in=3600):
    fake.expires_in = expires_in
    try:
        return t.cli(
            "oauth",
            "bootstrap",
            LEGACY_NAME,
            "--label",
            label,
            "--refresh-token-stdin",
            stdin=fake.mint_refresh_token() + "\n",
        )
    finally:
        fake.expires_in = 3600


def bind(t, label):
    reg = t.cli(
        "agent",
        "register",
        "--name",
        f"oau-redirect-{label}",
        "--allowlist",
        LEGACY_NAME,
    )
    assert reg.code == 0, reg.err
    sel = t.cli(
        "agent",
        "set-credential",
        reg.json["public_id"],
        LEGACY_NAME,
        "--oauth-session",
        label,
    )
    assert sel.code == 0, sel.err
    return reg.json


def status(t, label, name=LEGACY_NAME):
    result = t.cli("oauth", "status", name, "--label", label)
    assert result.code == 0, result.err
    return result.json


def refresh_failure_logged(t, label) -> bool:
    return any(
        e.get("fields", {}).get("cause") == "token_redirect"
        and e.get("fields", {}).get("session_label") == label
        for e in t.log_events()
    )


@case(
    "SMK-OAU-054",
    area="OAU",
    kind="refusal",
    covers=[BOOT, STATUS, "cli.oauth.bootstrap"],
    codes=["oauth_bootstrap_failed"],
)
def test_bootstrap_does_not_follow_a_token_redirect(rd):
    """docs/concepts/oauth-flow.md#refresh-task: token calls never follow a redirect. A bootstrap
    whose token endpoint answers 307, to the same host or another, fails with 502
    oauth_bootstrap_failed saying so, and the redirect target sees nothing. The
    exchange had been claimed, so the row is kept as uncertain custody that needs a
    reconnect, as docs/operator/oauth-recovery.md#diagnose-and-reconnect-deliberately
    describes for any failed bootstrap."""
    t, fake, sinks = rd
    for where, sink in sinks.items():
        label = f"boot-{where}"
        with redirected(fake, sink) as r:
            refused = admin(
                t,
                "POST",
                f"/admin/operator/oauth/{LEGACY_NAME}/bootstrap?label={label}",
                {"refresh_token": fake.mint_refresh_token()},
            )
        assert refused.status == 502, refused.text
        assert refused.code == "oauth_bootstrap_failed", refused.text
        assert "redirect" in refused.text and "token_url" in refused.text, refused.text
        assert r.answered == 1, "the token endpoint must be asked once"
        assert_not_followed(sink)
        view = status(t, label)
        assert view["present"] is True and view["reconnect_required"] is True, view


@case(
    "SMK-OAU-055",
    area="OAU",
    kind="refusal",
    covers=[API, STATUS],
    codes=["oauth_refresh_failed"],
)
def test_inline_refresh_does_not_follow_a_token_redirect(rd):
    """docs/concepts/oauth-flow.md#refresh-task and
    docs/concepts/oauth-flow.md#refresh-failure: an expired session's inline
    refresh whose token endpoint answers 307 to another host fails the call with 503
    oauth_refresh_failed, logs cause token_redirect, and leaves the session needing
    a reconnect; the redirect target sees nothing."""
    t, fake, sinks = rd
    sink = sinks["cross-host"]
    assert bootstrap(t, fake, "inline", expires_in=2).code == 0
    agent = bind(t, "inline")
    time.sleep(2.5)
    with redirected(fake, sink) as r:
        response = t.http("GET", f"/api/{LEGACY_NAME}/records", token=agent["token"])
    assert response.status == 503, response.text
    assert response.code == "oauth_refresh_failed", response.text
    assert r.answered == 1
    assert_not_followed(sink)
    assert refresh_failure_logged(t, "inline"), "the log must name token_redirect"
    assert status(t, "inline")["reconnect_required"] is True
    assert fake.counts["resource"] == 0, "nothing may be dispatched upstream"


@case("SMK-OAU-056", area="OAU", kind="refusal", covers=[TASK, STATUS])
def test_background_refresh_does_not_follow_a_token_redirect(rd):
    """docs/concepts/oauth-flow.md#refresh-task: the background task's refresh, through the token
    client the daemon builds at startup, does not follow a 307 to another host; it
    logs cause token_redirect and the session needs a reconnect. The redirect is set
    before an agent selects the label, so the first background refresh meets it."""
    t, fake, sinks = rd
    sink = sinks["cross-host"]
    assert bootstrap(t, fake, "background", expires_in=120).code == 0
    with redirected(fake, sink) as r:
        bind(t, "background")
        deadline = time.monotonic() + 45
        while r.answered == 0 and time.monotonic() < deadline:
            time.sleep(0.5)
        assert r.answered == 1, "no background refresh within 45s"
        deadline = time.monotonic() + 5
        while (
            not refresh_failure_logged(t, "background") and time.monotonic() < deadline
        ):
            time.sleep(0.2)
    assert_not_followed(sink)
    assert refresh_failure_logged(t, "background"), "the log must name token_redirect"
    assert status(t, "background")["reconnect_required"] is True


@case(
    "SMK-OAU-057",
    area="OAU",
    kind="refusal",
    covers=[START, POLL],
    codes=["device_login_failed"],
)
def test_device_login_does_not_follow_a_token_redirect(rd):
    """docs/concepts/oauth-flow.md#refresh-task: device login's code exchange does not follow a
    307 to another host. The attempt ends 502 device_login_failed naming the redirect,
    no session is created, and the redirect target sees nothing."""
    t, fake, sinks = rd
    sink = sinks["cross-host"]
    started = admin(
        t, "POST", f"/admin/operator/oauth/{DEVICE_NAME}/device-login?label=device", {}
    )
    assert started.status == 202, started.text
    attempt = started.json["attempt"]
    path = f"/admin/operator/oauth/{DEVICE_NAME}/device-login/{attempt}"
    with redirected(fake, sink) as r:
        deadline = time.monotonic() + 30
        polled = admin(t, "GET", path)
        while polled.status == 200 and polled.json["status"] == "pending":
            assert time.monotonic() < deadline, "the login never left pending"
            time.sleep(1)
            polled = admin(t, "GET", path)
    assert polled.status == 502, polled.text
    assert polled.code == "device_login_failed", polled.text
    assert "307" in polled.text and "redirect" in polled.text, polled.text
    assert r.answered == 1, "the code exchange must reach the token endpoint once"
    assert_not_followed(sink)
    assert status(t, "device", DEVICE_NAME)["present"] is False
