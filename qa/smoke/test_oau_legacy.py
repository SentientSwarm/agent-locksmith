"""Legacy OAuth custody: refresh-token handoff, status/list/revoke, refresh on
expiry and the recovery path (docs/user/concepts/oauth-flow.md,
docs/user/operator/oauth-recovery.md), against the local fake provider in
qa/fakes/oau_provider.py registered as an `oauth_pkce` tool through the
operator PUT /admin/operator/tools/{name} interface (oauth-consent.md:58-64).
No real provider is contacted."""

import time

import pytest

from fakes.oau_admin import admin
from fakes.oau_consent import sealing_key
from fakes.oau_provider import LEGACY_NAME as NAME
from fakes.oau_provider import FakeProvider, legacy_registration

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
LIST = "admin.GET./admin/operator/oauth"
STATUS = "admin.GET./admin/operator/oauth/{name}"
REVOKE = "admin.DELETE./admin/operator/oauth/{name}"
BOOT = "admin.POST./admin/operator/oauth/{name}/bootstrap"
TASK = "beh.oauth.refresh-task"


@pytest.fixture(scope="module")
def lg(target_factory):
    holder = {}
    fake = FakeProvider(
        on_secret=lambda v, label: holder["t"].canaries.add(v, label)
    ).start()
    t = target_factory(
        env={"LOCKSMITH_OAUTH_SEALING_KEY": sealing_key()},
        label="oau-legacy",
        upstream=False,
    )
    holder["t"] = t
    put = admin(t, "PUT", f"/admin/operator/tools/{NAME}", legacy_registration(fake))
    assert put.status == 200, put.text
    plain = t.cli(
        "tool",
        "put",
        "plain",
        "--upstream",
        f"{fake.origin}/api",
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
    )
    assert plain.code == 0, plain.err
    yield t, fake
    fake.expires_in, fake.refresh_fails = 3600, False
    fake.stop()


def bootstrap(t, fake, label, expires_in=3600):
    fake.expires_in = expires_in
    try:
        return t.cli(
            "oauth",
            "bootstrap",
            NAME,
            "--label",
            label,
            "--refresh-token-stdin",
            stdin=fake.mint_refresh_token() + "\n",
        )
    finally:
        fake.expires_in = 3600


def bound_agent(t, label):
    reg = t.cli(
        "agent", "register", "--name", f"oau-legacy-{label}", "--allowlist", NAME
    )
    assert reg.code == 0, reg.err
    bind = t.cli(
        "agent", "set-credential", reg.json["public_id"], NAME, "--oauth-session", label
    )
    assert bind.code == 0, bind.err
    return reg.json


def status(t, label):
    result = t.cli("oauth", "status", NAME, "--label", label)
    assert result.code == 0, result.err
    return result.json


@case(
    "SMK-OAU-001",
    area="OAU",
    kind="positive",
    covers=[
        BOOT,
        STATUS,
        LIST,
        API,
        "cli.oauth.bootstrap",
        "cli.oauth.status",
        "cli.oauth.list",
        "cli.agent.set-credential",
    ],
)
def test_bootstrap_status_list_and_selected_call(lg):
    """oauth-flow.md:112-153 (bootstrap exchanges the handed-off refresh token at the
    token endpoint and seals custody; an explicitly selected agent then calls through),
    oauth-flow.md:182-205 (status fields) and oauth-recovery.md:16-23 (list includes
    refresh_pending/reconnect_required)."""
    t, fake = lg
    before = fake.counts["refresh"]
    boot = bootstrap(t, fake, "default")
    assert boot.code == 0, boot.err
    assert fake.counts["refresh"] == before + 1, (
        "bootstrap must exchange the refresh token once"
    )
    view = status(t, "default")
    assert view["present"] is True and view["session_label"] == "default"
    assert view["refresh_pending"] is False and view["reconnect_required"] is False
    assert view["access_token_expires_at"] > time.time()
    assert len(view["audit_session_id"]) == 16
    listed = t.cli("oauth", "list")
    assert listed.code == 0, listed.err
    row = next(
        r for r in listed.json if r["name"] == NAME and r["session_label"] == "default"
    )
    assert row["refresh_pending"] is False and row["reconnect_required"] is False
    agent = bound_agent(t, "default")
    generation = fake.current_generation()
    response = t.http("GET", f"/api/{NAME}/records", token=agent["token"])
    assert response.status == 200, response.text
    assert response.json == {"generation": generation}, (
        "upstream must see the bootstrap access token"
    )


@case("SMK-OAU-002", area="OAU", kind="corner", covers=[BOOT, "cli.oauth.bootstrap"])
def test_second_label_bootstrap_warns_about_single_grant_trap(lg):
    """oauth-flow.md:246-268: bootstrapping a non-default label while other labels exist
    returns an advisory `warnings` field naming the existing labels; bootstrap still succeeds."""
    t, fake = lg
    assert status(t, "default")["present"] is True
    second = bootstrap(t, fake, "second")
    assert second.code == 0, second.err
    assert second.json["session_label"] == "second"
    warnings = second.json.get("warnings")
    assert warnings and "default" in warnings[0] and "second" in warnings[0]


@case(
    "SMK-OAU-003",
    area="OAU",
    kind="positive",
    covers=[REVOKE, API, "cli.oauth.revoke"],
    codes=["oauth_session_missing"],
)
def test_revoke_clears_custody_and_selected_call_refuses(lg):
    """oauth-flow.md:203-205 (revoke clears local state, idempotent per cli help) and
    oauth-flow.md:308 (session missing -> 503 oauth_session_missing) without upstream dispatch."""
    t, fake = lg
    assert bootstrap(t, fake, "revoked").code == 0
    agent = bound_agent(t, "revoked")
    revoke = t.cli("oauth", "revoke", NAME, "--label", "revoked")
    assert revoke.code == 0, revoke.err
    assert revoke.json["revoked"] is True
    assert status(t, "revoked")["present"] is False
    assert t.cli("oauth", "revoke", NAME, "--label", "revoked").code == 0, (
        "revoke is idempotent"
    )
    before = dict(fake.counts)
    response = t.http("GET", f"/api/{NAME}/records", token=agent["token"])
    assert response.status == 503
    assert response.code == "oauth_session_missing"
    assert dict(fake.counts) == before, "a refused call reached the provider"


@case(
    "SMK-OAU-004",
    area="OAU",
    kind="refusal",
    covers=[BOOT, "cli.oauth.bootstrap"],
    codes=["unknown_name"],
)
def test_bootstrap_unknown_registration(lg):
    """cli `oauth bootstrap --help`: the registration must already exist with an OAuth
    AuthSpec; an unknown name is refused before any token exchange."""
    t, fake = lg
    before = dict(fake.counts)
    result = t.cli(
        "oauth",
        "bootstrap",
        "no-such-provider",
        "--refresh-token-stdin",
        stdin=fake.mint_refresh_token() + "\n",
    )
    assert result.code == 4
    assert result.error_code == "unknown_name"
    assert dict(fake.counts) == before


@case(
    "SMK-OAU-005",
    area="OAU",
    kind="refusal",
    covers=[BOOT, "cli.oauth.bootstrap"],
    codes=["not_oauth_registration"],
)
def test_bootstrap_non_oauth_registration(lg):
    """cli `oauth bootstrap --help` (kind=tool/model with an OAuth AuthSpec): a bearer
    registration is refused with not_oauth_registration and no token exchange."""
    t, fake = lg
    before = dict(fake.counts)
    result = t.cli(
        "oauth",
        "bootstrap",
        "plain",
        "--refresh-token-stdin",
        stdin=fake.mint_refresh_token() + "\n",
    )
    assert result.code == 1
    assert result.error_code == "not_oauth_registration"
    assert dict(fake.counts) == before
    assert status(t, "default")["name"] == NAME


@case(
    "SMK-OAU-006",
    area="OAU",
    kind="refusal",
    covers=[LIST, STATUS, REVOKE, BOOT],
    codes=["invalid_credential"],
)
def test_legacy_routes_require_operator(lg):
    """oauth-flow.md:182-205 and src help: the legacy OAuth routes are operator-authenticated;
    a wrong operator token is 401 invalid_credential and changes nothing."""
    t, fake = lg
    wrong = "qa-wrong.not-a-real-operator-token"
    before = dict(fake.counts)
    calls = [
        ("GET", "/admin/operator/oauth", None),
        ("GET", f"/admin/operator/oauth/{NAME}?label=default", None),
        ("DELETE", f"/admin/operator/oauth/{NAME}?label=default", None),
        (
            "POST",
            f"/admin/operator/oauth/{NAME}/bootstrap?label=intruder",
            {"refresh_token": "qa-not-a-token-0"},
        ),
    ]
    for method, path, body in calls:
        response = admin(t, method, path, body, token=wrong)
        assert response.status == 401, f"{method} {path}: {response.status}"
        assert response.code == "invalid_credential"
    assert dict(fake.counts) == before
    assert status(t, "default")["present"] is True
    assert status(t, "intruder")["present"] is False


@case("SMK-OAU-007", area="OAU", kind="positive", covers=[TASK, API])
def test_expired_access_is_refreshed_before_use(lg):
    """oauth-flow.md:304-316 (expired access -> refresh under the per-label lock, the call
    uses the fresh token) and oauth-flow.md:270-276. The fake rejects expired access
    tokens, so a 200 proves locksmith refreshed before dispatch."""
    t, fake = lg
    assert bootstrap(t, fake, "short", expires_in=2).code == 0
    agent = bound_agent(t, "short")
    issued = fake.current_generation()
    refreshes = fake.counts["refresh"]
    time.sleep(2.5)
    response = t.http("GET", f"/api/{NAME}/records", token=agent["token"])
    assert response.status == 200, response.text
    assert response.json["generation"] > issued, "the expired access token was used"
    assert fake.counts["refresh"] == refreshes + 1
    assert fake.counts["expired-access-presented"] == 0
    assert status(t, "short")["access_token_expires_at"] > time.time() + 600


@case("SMK-OAU-008", area="OAU", kind="positive", covers=[TASK, STATUS])
def test_background_task_refreshes_ahead_of_expiry(lg):
    """oauth-flow.md:270-276: the background task wakes every 30 seconds and refreshes
    non-pending sessions whose access expires within 300 seconds, with no agent traffic.
    The label is selected by an agent first: refresh uses consistent selected metadata
    (oauth-flow.md:147-153); an unselected session is not refreshed in the background."""
    t, fake = lg
    assert bootstrap(t, fake, "ahead", expires_in=120).code == 0
    bound_agent(t, "ahead")  # refresh uses the selected metadata (oauth-flow.md:147-153)
    old_expiry = status(t, "ahead")["access_token_expires_at"]
    refreshes, resources = fake.counts["refresh"], fake.counts["resource"]
    deadline = time.monotonic() + 40
    while fake.counts["refresh"] == refreshes and time.monotonic() < deadline:
        time.sleep(0.5)
    assert fake.counts["refresh"] > refreshes, "no background refresh within 40s"
    assert fake.counts["resource"] == resources
    fresh = status(t, "ahead")
    assert fresh["access_token_expires_at"] > old_expiry + 600
    assert fresh["refresh_pending"] is False


@case(
    "SMK-OAU-009",
    area="OAU",
    kind="refusal",
    covers=[TASK, API, STATUS, LIST],
    codes=["oauth_reconnect_required"],
)
def test_failed_refresh_leaves_pending_custody_unavailable(lg):
    """oauth-flow.md:278-291 and oauth-recovery.md:23-36: a rejected refresh leaves
    refresh_pending; status/list show reconnect_required; later calls return 503
    oauth_reconnect_required without another token request or upstream dispatch."""
    t, fake = lg
    assert bootstrap(t, fake, "fragile", expires_in=2).code == 0
    agent = bound_agent(t, "fragile")
    fake.refresh_fails = True
    try:
        time.sleep(2.5)
        first = t.http("GET", f"/api/{NAME}/records", token=agent["token"])
        assert first.status == 503
        assert first.code in ("oauth_refresh_failed", "oauth_reconnect_required")
        view = status(t, "fragile")
        assert view["refresh_pending"] is True and view["reconnect_required"] is True
        listed = t.cli("oauth", "list").json
        assert any(
            r["session_label"] == "fragile" and r["reconnect_required"] for r in listed
        )
        before = dict(fake.counts)
        again = t.http("GET", f"/api/{NAME}/records", token=agent["token"])
        assert again.status == 503
        assert again.code == "oauth_reconnect_required"
        assert dict(fake.counts) == before, "pending custody was retried or dispatched"
    finally:
        fake.refresh_fails = False


@case(
    "SMK-OAU-010",
    area="OAU",
    kind="refusal",
    covers=[BOOT, REVOKE, API, "cli.oauth.bootstrap", "cli.oauth.revoke"],
    codes=["session_exists"],
)
def test_recovery_requires_revoke_then_fresh_bootstrap(lg):
    """oauth-recovery.md:38-58: revoke must precede a fresh bootstrap (bootstrap over the
    uncertain row is refused); revoke + bootstrap with freshly issued credentials restores
    service and preserves the agent's selection."""
    t, fake = lg
    view = status(t, "fragile")
    assert view["refresh_pending"] is True, "depends on SMK-OAU-009"
    refused = bootstrap(t, fake, "fragile")
    assert refused.code == 5
    assert refused.error_code == "session_exists"
    assert t.cli("oauth", "revoke", NAME, "--label", "fragile").code == 0
    fresh = bootstrap(t, fake, "fragile")
    assert fresh.code == 0, fresh.err
    assert fresh.json["refresh_pending"] is False
    agent_list = t.cli("agent", "list").json
    agent = next(a for a in agent_list if a["name"] == "oau-legacy-fragile")
    creds = t.cli("agent", "credentials", "list", agent["public_id"])
    assert creds.code == 0 and "fragile" in creds.out, (
        "selection must survive revoke/rebootstrap"
    )


@case(
    "SMK-OAU-011",
    area="OAU",
    kind="refusal",
    covers=[BOOT, STATUS, "cli.oauth.bootstrap"],
    codes=["oauth_bootstrap_failed"],
)
def test_rejected_bootstrap_retains_uncertain_row(lg):
    """oauth-recovery.md:49-50: a failed bootstrap after the exchange was claimed retains the
    uncertain row; revoke must precede a fresh bootstrap."""
    t, fake = lg
    before = fake.counts["refresh-refused"]
    result = t.cli(
        "oauth",
        "bootstrap",
        NAME,
        "--label",
        "rejected",
        "--refresh-token-stdin",
        stdin="qa-unissued-refresh-token-0\n",
    )
    assert result.code != 0
    assert result.error_code == "oauth_bootstrap_failed"
    assert fake.counts["refresh-refused"] == before + 1
    view = status(t, "rejected")
    assert view["present"] is True
    assert view["refresh_pending"] is True and view["reconnect_required"] is True
