"""Operator device login for ChatGPT-plan sessions (#138): `locksmith oauth
device-login` and its admin routes (docs/user/cli-reference.md, the `oauth`
section; docs/user/concepts/oauth-flow.md, codex), against the local fake
provider's OpenAI device-authorization dialect in qa/fakes/oau_provider.py.
No real provider is contacted."""

import pytest

from fakes.oau_admin import admin
from fakes.oau_consent import sealing_key
from fakes.oau_provider import (
    DEVICE_CLIENT,
    LEGACY_NAME,
    FakeProvider,
    device_registration,
    legacy_registration,
)
from fakes.oau_provider import DEVICE_NAME as NAME

case = pytest.mark.case
START = "admin.POST./admin/operator/oauth/{name}/device-login"
POLL = "admin.GET./admin/operator/oauth/{name}/device-login/{attempt}"
STATUS = "admin.GET./admin/operator/oauth/{name}"
CLI = "cli.oauth.device-login"


@pytest.fixture(scope="module")
def dl(target_factory):
    holder = {}
    fake = FakeProvider(
        on_secret=lambda v, label: holder["t"].canaries.add(v, label)
    ).start()
    fake.client_id = DEVICE_CLIENT
    t = target_factory(
        env={"LOCKSMITH_OAUTH_SEALING_KEY": sealing_key()},
        label="oau-device",
        upstream=False,
    )
    holder["t"] = t
    for path, body in (
        (f"/admin/operator/models/{NAME}", device_registration(fake)),
        (f"/admin/operator/tools/{LEGACY_NAME}", legacy_registration(fake)),
    ):
        put = admin(t, "PUT", path, body)
        assert put.status == 200, put.text
    yield t, fake
    fake.device_fails, fake.device_approve_after = False, 2
    fake.stop()


def start(t, label, replace=False, token=None):
    return admin(
        t,
        "POST",
        f"/admin/operator/oauth/{NAME}/device-login?label={label}",
        {"replace": replace},
        token=token,
    )


def poll(t, attempt, token=None):
    return admin(
        t, "GET", f"/admin/operator/oauth/{NAME}/device-login/{attempt}", token=token
    )


def status(t, label):
    result = t.cli("oauth", "status", NAME, "--label", label)
    assert result.code == 0, result.err
    return result.json


def revoke(t, label):
    assert t.cli("oauth", "revoke", NAME, "--label", label).code == 0


@case(
    "SMK-OAU-043",
    area="OAU",
    kind="positive",
    covers=[START, POLL, STATUS, CLI],
)
def test_device_login_signs_a_session_in(dl):
    """cli-reference.md `oauth device-login`: prints a URL and one-time code, waits
    while the operator signs in, and the daemon exchanges the code itself; the label
    then reads present and healthy, and no token reaches the CLI output."""
    t, fake = dl
    before = dict(fake.counts)
    result = t.cli("oauth", "device-login", NAME, "--label", "acct1")
    assert result.code == 0, result.err
    assert f"{fake.origin}/codex/device" in result.err
    assert result.json["present"] is True
    assert result.json["reconnect_required"] is False
    assert fake.counts["device-poll"] - before.get("device-poll", 0) >= 2
    assert fake.counts["code-exchange"] - before.get("code-exchange", 0) == 1
    view = status(t, "acct1")
    assert view["present"] is True and view["reconnect_required"] is False


@case(
    "SMK-OAU-044",
    area="OAU",
    kind="refusal",
    covers=[START, CLI],
    codes=["unknown_name", "device_login_unsupported"],
)
def test_device_login_needs_a_known_openai_registration(dl):
    """cli-reference.md: only OpenAI's device dialect is supported; an unknown name is
    404 unknown_name and another OAuth registration is device_login_unsupported, both
    before any provider call."""
    t, fake = dl
    before = dict(fake.counts)
    unknown = t.cli("oauth", "device-login", "no-such-provider")
    assert unknown.code == 4 and unknown.error_code == "unknown_name"
    other = admin(t, "POST", f"/admin/operator/oauth/{LEGACY_NAME}/device-login", {})
    assert other.status == 400 and other.code == "device_login_unsupported"
    assert dict(fake.counts) == before


@case(
    "SMK-OAU-045",
    area="OAU",
    kind="refusal",
    covers=[START],
    codes=["session_exists"],
)
def test_healthy_session_needs_replace(dl):
    """cli-reference.md: a second label warns like bootstrap does; a healthy session
    is replaced only with --replace (409 session_exists otherwise); with replace the
    login starts."""
    t, fake = dl
    second = t.cli("oauth", "device-login", NAME, "--label", "acct2")
    assert second.code == 0, second.err
    assert "warning:" in second.err and "acct1" in second.err, (
        "a second label warns about the single-grant trap"
    )
    before = dict(fake.counts)
    refused = start(t, "acct2")
    assert refused.status == 409 and refused.code == "session_exists"
    assert dict(fake.counts) == before
    replacing = start(t, "acct2", replace=True)
    assert replacing.status == 202, replacing.text
    revoke(t, "acct2")


@case(
    "SMK-OAU-046",
    area="OAU",
    kind="refusal",
    covers=[START, POLL],
    codes=["invalid_credential"],
)
def test_device_login_routes_require_operator(dl):
    """The device-login routes are operator-authenticated: a wrong token is 401
    invalid_credential and no provider call is made."""
    t, fake = dl
    wrong = "qa-wrong.not-a-real-operator-token"
    before = dict(fake.counts)
    for response in (start(t, "intruder", token=wrong), poll(t, "0" * 36, token=wrong)):
        assert response.status == 401 and response.code == "invalid_credential"
    assert dict(fake.counts) == before


@case(
    "SMK-OAU-047",
    area="OAU",
    kind="refusal",
    covers=[POLL, "cli.oauth.revoke"],
    codes=["unknown_attempt"],
)
def test_revoke_ends_a_pending_login(dl):
    """cli-reference.md: revoking the label ends its pending logins; the attempt is
    then unknown and nothing is published."""
    t, fake = dl
    fake.device_approve_after = 99
    try:
        started = start(t, "acct3")
        assert started.status == 202, started.text
        attempt = started.json["attempt"]
        pending = poll(t, attempt)
        assert pending.status == 200 and pending.json["status"] == "pending"
        revoke(t, "acct3")
        gone = poll(t, attempt)
        assert gone.status == 404 and gone.code == "unknown_attempt"
        assert poll(t, "f" * 36).code == "unknown_attempt"
        assert status(t, "acct3")["present"] is False
    finally:
        fake.device_approve_after = 2


@case(
    "SMK-OAU-048",
    area="OAU",
    kind="refusal",
    covers=[POLL],
    codes=["device_login_failed"],
)
def test_provider_refusal_ends_the_login(dl):
    """A provider refusal ends the attempt with 502 device_login_failed carrying the
    status only, and no session is created."""
    t, fake = dl
    started = start(t, "acct4")
    assert started.status == 202, started.text
    fake.device_fails = True
    try:
        failed = poll(t, started.json["attempt"])
    finally:
        fake.device_fails = False
    assert failed.status == 502 and failed.code == "device_login_failed"
    assert "access_denied" not in failed.text
    assert poll(t, started.json["attempt"]).code == "unknown_attempt"
    assert status(t, "acct4")["present"] is False


@case(
    "SMK-OAU-049",
    area="OAU",
    kind="refusal",
    covers=[POLL],
    codes=["authority_changed"],
)
def test_changed_client_never_gets_the_code_exchanged(dl):
    """cli-reference.md: a login whose registration changed client while it waited
    fails with 409 authority_changed before any code is exchanged."""
    t, fake = dl
    started = start(t, "acct5")
    assert started.status == 202, started.text
    attempt = started.json["attempt"]
    assert poll(t, attempt).json["status"] == "pending"
    changed = device_registration(fake)
    changed["auth"]["client_id"] = "qa-other-client"
    put = admin(t, "PUT", f"/admin/operator/models/{NAME}", changed)
    assert put.status == 200, put.text
    before = dict(fake.counts)
    try:
        refused = poll(t, attempt)
        assert refused.status == 409 and refused.code == "authority_changed"
        assert fake.counts["code-exchange"] == before.get("code-exchange", 0)
        assert status(t, "acct5")["present"] is False
    finally:
        restore = admin(
            t, "PUT", f"/admin/operator/models/{NAME}", device_registration(fake)
        )
        assert restore.status == 200, restore.text


@case(
    "SMK-OAU-050",
    area="OAU",
    kind="refusal",
    covers=[START],
    codes=["too_many_device_logins"],
)
def test_pending_logins_are_capped(dl):
    """cli-reference.md: at most 16 logins are pending at once (429
    too_many_device_logins); revoking their labels frees the slots."""
    t, _fake = dl
    labels = [f"cap{i}" for i in range(16)]
    for label in labels:
        assert start(t, label).status == 202
    refused = start(t, "cap-extra")
    assert refused.status == 429 and refused.code == "too_many_device_logins"
    for label in labels:
        revoke(t, label)
    freed = start(t, "cap-extra")
    assert freed.status == 202, freed.text
    revoke(t, "cap-extra")
