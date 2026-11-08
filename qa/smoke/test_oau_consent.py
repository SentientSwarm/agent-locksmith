"""Owner-bound OAuth consent with a declared custom-oauth-v1 contract against the local
fake IdP (docs/user/operator/custom-oauth.md, custom-oauth-workflow.md, oauth-consent.md,
native-oauth.md). The browser step is a urllib fetch of the authorization URL; the
URL, state and code are canaries and never recorded."""

import json
import secrets
import signal
import tempfile
from pathlib import Path

import pytest

from fakes import oau_consent as oc
from fakes.oau_admin import admin

case = pytest.mark.case
N = oc.NAME
TOOLS = f"/admin/operator/tools/{N}/oauth"
START = "admin.POST./admin/operator/tools/{name}/oauth/attempts"
POLL = "admin.GET./admin/operator/tools/{name}/oauth/attempts/{id}"
CANCEL = "admin.DELETE./admin/operator/tools/{name}/oauth/attempts/{id}"
ACCOUNT = "admin.GET./admin/operator/tools/{name}/oauth/accounts/{label}"
DISCONNECT = "admin.DELETE./admin/operator/tools/{name}/oauth/accounts/{label}"
REFRESH = "admin.POST./admin/operator/tools/{name}/oauth/accounts/{label}/refresh"
CLIENT = "admin.POST./admin/operator/tools/{name}/oauth/client"
CLIENT_GET = (
    "admin.GET./admin/operator/tools/{name}/oauth/clients/{profile}/{generation}"
)
CLIENT_DEL = (
    "admin.DELETE./admin/operator/tools/{name}/oauth/clients/{profile}/{generation}"
)
CALLBACK = "callback.ANY./oauth/callback{,/slack,/custom/{redirect_profile_id}}"
SELECT = "admin.PUT./admin/operator/agents/{agent}/oauth-selection/{name}"
MCP = "agent.ANY./mcp/{name}"
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-11-25",
}


@pytest.fixture(scope="module")
def cs(target_factory):
    """Configured profile, activated definition pin and sealed confidential client
    (custom-oauth-workflow.md:8-38)."""
    holder: dict = {}
    pending: list = []
    consent = oc.Consent(Path(tempfile.mkdtemp(prefix="oau-pki-")))
    consent.start(
        lambda v, label: (
            holder["t"].canaries.add(v, label)
            if "t" in holder
            else pending.append((v, label))
        )
    )
    env = {
        "LOCKSMITH_OAUTH_SEALING_KEY": oc.sealing_key(),
        "LOCKSMITH_CREDENTIAL_SEALING_KEY": oc.sealing_key(),
    }
    t = target_factory(
        config=consent.overlay, env=env, label="oau-consent", upstream=False
    )
    holder["t"] = t
    t.canaries.add(consent.client_secret, "oau-client-secret")
    for value, label in pending:
        t.canaries.add(value, label)
    fake = consent.fake
    assert (
        t.cli(
            "integration",
            "import",
            "--file",
            oc.json_file(t, "oau-definition.json", oc.definition()),
        ).code
        == 0
    )
    made = t.cli(
        "tool",
        "from-definition",
        N,
        "--definition",
        oc.DEFINITION,
        "--revision",
        "1",
        "--auth-profile",
        "controlled",
        "--upstream",
        f"{fake.origin}/mcp",
        "--allow-private-destination",
    )
    assert made.code == 0, made.err
    revision = t.cli("tool", "get", N).json["definition_control"]["revision"]
    active = t.cli(
        "tool",
        "activate-definition",
        N,
        "--if-match",
        revision,
        "--compact",
        "--oauth-profile",
        oc.PROFILE,
        "--contract-policy",
        "finite-v2",
        "--selected-tool",
        "read_record",
        "--selected-tool",
        "inspect_catalog",
    )
    assert active.code == 0, active.err
    assert sum(fake.counts.values()) == 0, "activation must not contact the provider"
    yield t, consent
    fake.refresh_fails = fake.deny_authorize = False
    fake.stop()


def connected(t, c, label):
    """connect -> IdP approval -> callback; returns the attempt id."""
    created = oc.connect(t, label)
    assert created.code == 0, created.err
    location = oc.consent_redirect(c, created.json["authorization_url"])
    assert oc.deliver(c, location)[0] == 200
    return created.json["attempt_id"]


def rpc(t, agent, body, session=None):
    headers = dict(MCP_HEADERS, **({"Mcp-Session-Id": session} if session else {}))
    response = t.http(
        "POST", f"/mcp/{N}", token=agent["token"], body=body, headers=headers
    )
    data = next(
        (line[6:] for line in response.text.splitlines() if line.startswith("data: ")),
        response.text,
    )
    try:
        value = json.loads(data) if data else None
    except ValueError:
        value = None
    session_id = {k.lower(): v for k, v in response.headers.items()}.get(
        "mcp-session-id"
    )
    return response.status, value, session_id


def native_call(t, agent):
    status, _, session = rpc(
        t,
        agent,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "qa-oau", "version": "1"},
            },
        },
    )
    if status != 200:
        return status, None
    rpc(t, agent, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    status, listed, _ = rpc(
        t, agent, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session
    )
    tools = ((listed or {}).get("result") or {}).get("tools") or []
    names = sorted(tool["name"] for tool in tools)
    status, called, _ = rpc(
        t,
        agent,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "read_record", "arguments": {"record": "REC-1"}},
        },
        session,
    )
    return status, {"tools": names, "call": called}


def prepare(t, agent_id):
    """Observe, review and grant both selected tools (native-tool-review.md:75-136)."""
    shown = t.cli("tool", "mcp", "show", N, "--agent", agent_id)
    assert shown.code == 0, shown.err
    generation = (shown.json.get("observation") or {}).get("generation")
    observed = t.cli(
        "tool",
        "mcp",
        "observe",
        N,
        "--agent",
        agent_id,
        "--file",
        "-",
        stdin=json.dumps({"source": shown.json["source"], "generation": generation}),
    )
    assert observed.code == 0, observed.err
    state = observed.json
    granted = []
    for tool in state["observation"]["manifest"]["tools"]:
        review = t.cli(
            "tool",
            "mcp",
            "review",
            N,
            "--agent",
            agent_id,
            "--file",
            "-",
            stdin=json.dumps(
                {
                    "source": state["source"],
                    "generation": state["observation"]["generation"],
                    "name": tool["tool"]["name"],
                    "observed_digest": tool["observed_digest"],
                    "effect": "read",
                    "contract_policy": "finite-v2",
                }
            ),
        )
        assert review.code == 0, review.err
        granted.append(
            {
                "name": tool["tool"]["name"],
                "contract_digest": review.json["contract_digest"],
            }
        )
    grant = t.cli(
        "agent",
        "mcp-grants",
        "replace",
        N,
        "--agent",
        agent_id,
        "--file",
        "-",
        stdin=json.dumps(
            {
                "source": state["source"],
                "generation": state["observation"]["generation"],
                "revision": state["grant_revision"],
                "tools": granted,
            }
        ),
    )
    assert grant.code == 0, grant.err


@case(
    "SMK-OAU-020",
    area="OAU",
    kind="positive",
    covers=[
        START,
        POLL,
        ACCOUNT,
        CLIENT,
        CLIENT_GET,
        CALLBACK,
        "cli.oauth.connect",
        "cli.oauth.attempt-status",
        "cli.oauth.account-status",
        "cli.oauth.client.set",
        "cli.oauth.client.status",
    ],
)
def test_consent_completes_without_a_browser(cs):
    """custom-oauth-workflow.md:33-52 (client set, config_revision, connect, poll) and
    oauth-consent.md:81-130 (201 pending attempt with the URL only once; poll never returns it;
    callback with state+code; account connected_unbound) and custom-oauth.md:39-44, 102-110
    (identity observed before commit; verified_subject; distinct_redirect callback)."""
    t, c = cs
    client = t.cli(
        "oauth",
        "client",
        "set",
        N,
        "--profile",
        oc.PROFILE,
        "--client-generation",
        "1",
        "--secret-stdin",
        stdin=c.client_secret + "\n",
    )
    assert client.code == 0, client.err
    assert c.client_secret not in client.out
    status = t.cli(
        "oauth",
        "client",
        "status",
        N,
        "--profile",
        oc.PROFILE,
        "--client-generation",
        "1",
    )
    assert status.code == 0 and status.json["state"] == "configured"
    absent = oc.account(t, "reader")
    assert absent["state"] == "absent" and absent["account_generation"] is None
    assert isinstance(absent["config_revision"], int)
    created = oc.connect(t, "reader")
    assert created.code == 0, created.err
    assert (
        created.json["state"] == "pending" and created.json["session_label"] == "reader"
    )
    assert created.json["authorization_url"].startswith(f"{c.fake.origin}/authorize?")
    polled = oc.attempt(t, created.json["attempt_id"])
    assert polled["state"] == "pending"
    assert "authorization_url" not in polled and "state=" not in json.dumps(polled)
    location = oc.consent_redirect(c, created.json["authorization_url"])
    assert oc.deliver(c, location) == (
        200,
        "Callback processed. Return to your operator client.",
    )
    done = oc.attempt(t, created.json["attempt_id"])
    assert done["state"] == "connected" and done["account_generation"] == 1
    view = oc.account(t, "reader")
    assert view["state"] == "connected_unbound" and view["kind"] == "custom_oauth_v1"
    assert view["requested_scopes"] == oc.SCOPES and view["granted_scope"] == " ".join(
        oc.SCOPES
    )
    assert view["identity_verified"] is True
    assert view["verified_subject"] == {
        "kind": "user_workspace",
        "workspace_id": "workspace-qa-oau",
        "user_id": "user-qa-oau",
    }
    assert c.fake.counts["code-exchange"] == 1 and c.fake.counts["identity"] == 1
    assert c.fake.counts["code-refused"] == 0, (
        "the S256 verifier or client secret did not match"
    )


@case(
    "SMK-OAU-021",
    area="OAU",
    kind="positive",
    covers=[
        SELECT,
        MCP,
        "cli.agent.select-oauth",
        "cli.tool.mcp.observe",
        "cli.tool.mcp.review",
        "cli.agent.mcp-grants.replace",
    ],
)
def test_selected_account_calls_through_native_mcp(cs):
    """custom-oauth-workflow.md:52-63 and native-oauth.md:26-52: a deliberately selected
    account (connection ACL, select-oauth with the account revision, observe/review/grant)
    lets the agent call the granted tool with the consented access token."""
    t, c = cs
    view = oc.account(t, "reader")
    agent = t.cli("agent", "register", "--name", "oau-reader", "--allowlist", N)
    assert agent.code == 0, agent.err
    selected = t.cli(
        "agent",
        "select-oauth",
        agent.json["public_id"],
        N,
        "--label",
        "reader",
        "--if-match",
        view["revision"],
    )
    assert selected.code == 0, selected.err
    assert (
        selected.json["callable"] is False
        and selected.json["requires_observation"] is True
    )
    assert selected.json["selection"]["session_label"] == "reader"
    prepare(t, agent.json["public_id"])
    calls = c.fake.counts["mcp-tool-call"]
    status, result = native_call(t, agent.json)
    assert status == 200
    assert result["tools"] == ["inspect_catalog", "read_record"]
    text = json.loads(result["call"]["result"]["content"][0]["text"])
    assert text == {"tool": "read_record", "generation": c.fake.current_generation()}
    assert c.fake.counts["mcp-tool-call"] == calls + 1
    cs_agents[0] = agent.json


cs_agents: list = [None]


@case(
    "SMK-OAU-022",
    area="OAU",
    kind="positive",
    covers=[REFRESH, ACCOUNT, "cli.oauth.refresh"],
    codes=["source_conflict"],
)
def test_manual_refresh_with_current_revision(cs):
    """oauth-consent.md:141-157 and 159-176: one explicit renewal with the current revision
    commits a verified pair, advances token_version and keeps the generation; reusing the old
    revision is refused (409) and sends no token request. native-oauth.md:85-89: existing
    sessions no longer authorize calls until reobserve/review/regrant."""
    t, c = cs
    before = oc.account(t, "reader")
    refreshes = c.fake.counts["refresh"]
    renewed = t.cli(
        "oauth", "refresh", N, "--label", "reader", "--if-match", before["revision"]
    )
    assert renewed.code == 0, renewed.err
    assert renewed.json["refresh"]["outcome"] == "committed"
    assert renewed.json["token_version"] > before["token_version"]
    assert renewed.json["account_generation"] == before["account_generation"]
    assert renewed.json["state"] == "connected_unbound"
    assert c.fake.counts["refresh"] == refreshes + 1
    assert c.fake.counts["identity"] >= 2, "refresh must verify identity before commit"
    stale = t.cli(
        "oauth", "refresh", N, "--label", "reader", "--if-match", before["revision"]
    )
    assert stale.code == 5
    assert stale.error_code == "source_conflict"
    assert c.fake.counts["refresh"] == refreshes + 1, (
        "an old revision sent another token request"
    )
    agent = cs_agents[0]
    assert agent is not None, "depends on SMK-OAU-021"
    calls = c.fake.counts["mcp-tool-call"]
    status, result = native_call(t, agent)
    refused = (
        status != 200
        or result["call"] is None
        or "error" in result["call"]
        or result["call"]["result"].get("isError")
    )
    assert refused, "a pre-refresh grant still authorized a call"
    assert c.fake.counts["mcp-tool-call"] == calls
    prepare(t, agent["public_id"])
    status, result = native_call(t, agent)
    assert status == 200
    assert (
        json.loads(result["call"]["result"]["content"][0]["text"])["generation"]
        == c.fake.current_generation()
    )


@case(
    "SMK-OAU-023",
    area="OAU",
    kind="refusal",
    covers=[REFRESH, DISCONNECT],
    codes=["if_match_required"],
)
def test_refresh_and_disconnect_require_if_match(cs):
    """oauth-consent.md:128-129 and 150-152: missing If-Match is 428, a nonempty refresh body is
    400; neither contacts the provider or changes the account."""
    t, c = cs
    before, counts = oc.account(t, "reader"), dict(c.fake.counts)
    for method, path in (
        ("POST", f"{TOOLS}/accounts/reader/refresh"),
        ("DELETE", f"{TOOLS}/accounts/reader"),
    ):
        response = admin(t, method, path)
        assert response.status == 428, f"{method} {path}"
        assert response.code == "if_match_required"
    body = admin(
        t,
        "POST",
        f"{TOOLS}/accounts/reader/refresh",
        b"{}",
        headers={"If-Match": before["revision"], "Content-Type": "application/json"},
    )
    assert body.status == 400
    assert dict(c.fake.counts) == counts
    assert oc.account(t, "reader")["revision"] == before["revision"]


@case(
    "SMK-OAU-024",
    area="OAU",
    kind="refusal",
    covers=[CALLBACK, POLL],
    codes=["callback_refused"],
)
def test_invalid_callbacks_refuse_without_consuming_the_attempt(cs):
    """oauth-consent.md:91-94 and custom-oauth.md:104-110: wrong state, wrong host authority,
    a wrong issuer and duplicate parameters refuse (400 static refusal page; the internal
    callback_refused reason is not exposed) without consuming the attempt or exchanging a
    code; the genuine callback then succeeds once, and a replay refuses (code claimed once)."""
    t, c = cs
    created = oc.connect(t, "callbacks")
    assert created.code == 0, created.err
    location = oc.consent_redirect(c, created.json["authorization_url"])
    refused = (400, "Callback refused. Check the operator client.")
    exchanges = c.fake.counts["code-exchange"]
    other_state = oc.callback_url(
        c, state=secrets.token_urlsafe(32), code="qa-unissued-code-0"
    )
    t.canaries.add(other_state, "oau-forged-callback")
    attempts = {
        "unknown state": oc.deliver(c, other_state),
        "wrong host": oc.deliver(c, location, host=f"localhost:{c.callback_port}"),
        "wrong issuer": oc.deliver(c, location + "&iss=https%3A%2F%2F127.0.0.1%3A1"),
        "duplicate code": oc.deliver(c, location + "&code=qa-second-code"),
    }
    t.bundle.transcript(
        t.current_case,
        "callbacks",
        "\n".join(f"{k}: {v[0]}" for k, v in attempts.items()),
    )
    for name, result in attempts.items():
        assert result == refused, name
    assert oc.attempt(t, created.json["attempt_id"])["state"] == "pending"
    assert c.fake.counts["code-exchange"] == exchanges, (
        "a refused callback exchanged a code"
    )
    assert oc.deliver(c, location)[0] == 200
    assert oc.attempt(t, created.json["attempt_id"])["state"] == "connected"
    assert oc.deliver(c, location) == refused, "a replayed callback was accepted"
    assert c.fake.counts["code-exchange"] == exchanges + 1


@case(
    "SMK-OAU-025",
    area="OAU",
    kind="positive",
    covers=[CANCEL, POLL, "cli.oauth.cancel"],
)
def test_cancel_is_idempotent_and_refuses_later_callback(cs):
    """oauth-consent.md:96-111 and 132: cancel is idempotent for the owning attempt; the attempt
    reads canceled and its callback no longer exchanges a code."""
    t, c = cs
    created = oc.connect(t, "canceled")
    assert created.code == 0, created.err
    location = oc.consent_redirect(c, created.json["authorization_url"])
    for _ in range(2):
        cancel = t.cli("oauth", "cancel", N, created.json["attempt_id"])
        assert cancel.code == 0, cancel.err
    polled = oc.attempt(t, created.json["attempt_id"])
    assert polled["state"] == "canceled"
    exchanges = c.fake.counts["code-exchange"]
    assert oc.deliver(c, location)[0] == 400
    assert c.fake.counts["code-exchange"] == exchanges
    assert oc.account(t, "canceled")["state"] == "absent"


@case(
    "SMK-OAU-026",
    area="OAU",
    kind="corner",
    covers=[POLL, CALLBACK, "cli.oauth.attempt-status"],
)
def test_unfinished_attempts_do_not_survive_a_stop(cs):
    """oauth-consent.md:132-139: graceful shutdown marks unfinished attempts failed
    (daemon_stopped); after an abrupt stop, startup marks them expired (daemon_restarted);
    neither resumes provider work and their callbacks refuse. Committed accounts survive."""
    t, c = cs
    stopped = oc.connect(t, "stopped")
    stopped_location = oc.consent_redirect(c, stopped.json["authorization_url"])
    t.restart()
    after_term = oc.attempt(t, stopped.json["attempt_id"])
    assert (after_term["state"], after_term["safe_reason"]) == (
        "failed",
        "daemon_stopped",
    )
    killed = oc.connect(t, "killed")
    killed_location = oc.consent_redirect(c, killed.json["authorization_url"])
    t.stop(signal.SIGKILL)
    t.start()
    after_kill = oc.attempt(t, killed.json["attempt_id"])
    assert (after_kill["state"], after_kill["safe_reason"]) == (
        "expired",
        "daemon_restarted",
    )
    exchanges = c.fake.counts["code-exchange"]
    assert oc.deliver(c, stopped_location)[0] == 400
    assert oc.deliver(c, killed_location)[0] == 400
    assert c.fake.counts["code-exchange"] == exchanges
    assert oc.account(t, "reader")["state"] == "connected_unbound"


@case(
    "SMK-OAU-027",
    area="OAU",
    kind="refusal",
    covers=[CALLBACK, POLL],
    codes=["authorization_denied"],
)
def test_denied_consent_fails_the_attempt(cs):
    """oauth-consent.md:91-94 and 104-106: a callback carrying `error` instead of `code`
    fails the attempt with a static safe_reason and no token request."""
    t, c = cs
    created = oc.connect(t, "denied")
    tokens = c.fake.counts["token"]
    c.fake.deny_authorize = True
    try:
        location = oc.consent_redirect(c, created.json["authorization_url"])
    finally:
        c.fake.deny_authorize = False
    assert oc.deliver(c, location)[0] == 400
    polled = oc.attempt(t, created.json["attempt_id"])
    assert (polled["state"], polled["safe_reason"]) == (
        "failed",
        "authorization_denied",
    )
    assert c.fake.counts["token"] == tokens
    assert oc.account(t, "denied")["state"] == "absent"


@case(
    "SMK-OAU-028",
    area="OAU",
    kind="refusal",
    covers=[REFRESH, ACCOUNT, DISCONNECT, "cli.oauth.refresh"],
    codes=["reconnect_required"],
)
def test_uncertain_refresh_requires_reconnect(cs):
    """oauth-consent.md:159-169, 185-187 and 203-208: a rejected refresh (400 invalid_grant)
    is reported as refresh_invalid_grant with outcome unknown and leaves pending custody;
    status reads reconnect_required; a further refresh is refused 409 reconnect_required with
    no token request; disconnect then fresh consent restores a connected account."""
    t, c = cs
    connected(t, c, "fragile")
    before = oc.account(t, "fragile")
    c.fake.refresh_fails = True
    try:
        failed = t.cli(
            "oauth",
            "refresh",
            N,
            "--label",
            "fragile",
            "--if-match",
            before["revision"],
        )
    finally:
        c.fake.refresh_fails = False
    assert failed.code != 0
    assert failed.error_code == "refresh_invalid_grant"
    view = oc.account(t, "fragile")
    assert view["state"] == "reconnect_required"
    assert view["refresh_pending"] is True and view["refresh_available"] is False
    assert view["refresh_unavailable_reason"] == "refresh_pending"
    tokens = c.fake.counts["token"]
    again = t.cli(
        "oauth", "refresh", N, "--label", "fragile", "--if-match", view["revision"]
    )
    assert again.code == 5
    assert again.error_code == "reconnect_required"
    assert c.fake.counts["token"] == tokens, "pending custody was retried"
    gone = t.cli(
        "oauth", "disconnect", N, "--label", "fragile", "--if-match", view["revision"]
    )
    assert gone.code == 0, gone.err
    connected(t, c, "fragile")
    assert oc.account(t, "fragile")["state"] == "connected_unbound"


@case(
    "SMK-OAU-029",
    area="OAU",
    kind="positive",
    covers=[DISCONNECT, ACCOUNT, "cli.oauth.disconnect"],
    codes=["source_conflict"],
)
def test_disconnect_with_current_revision(cs):
    """oauth-consent.md:125-130 and native-oauth.md:89: disconnect needs the current revision
    (stale 409), returns disconnected with remote_revocation unsupported, never contacts the
    provider, removes controlled selections, and the label reads absent. The owner's
    selection is visible in the generic listing beforehand (native-oauth.md:41)."""
    t, c = cs
    agent = cs_agents[0]
    assert agent is not None, "depends on SMK-OAU-021"
    listed = t.cli("agent", "credentials", "list", agent["public_id"])
    assert listed.code == 0 and "reader" in listed.out, "the owner's selection is not listed"
    view = oc.account(t, "reader")
    counts = dict(c.fake.counts)
    stale = t.cli(
        "oauth", "disconnect", N, "--label", "reader", "--if-match", "qa-stale-revision"
    )
    assert stale.code == 5 and stale.error_code == "source_conflict"
    gone = t.cli(
        "oauth", "disconnect", N, "--label", "reader", "--if-match", view["revision"]
    )
    assert gone.code == 0, gone.err
    assert (
        gone.json["state"] == "disconnected"
        and gone.json["remote_revocation"] == "unsupported"
    )
    assert gone.json["account_generation"] == view["account_generation"]
    after = {k: v for k, v in c.fake.counts.items() if v != counts.get(k)}
    assert set(after) <= {"mcp-delete"}, f"disconnect contacted the provider: {after}"
    assert oc.account(t, "reader")["state"] == "absent"
    creds = t.cli("agent", "credentials", "list", agent["public_id"])
    assert creds.code == 0 and "reader" not in creds.out, (
        "disconnect left the controlled selection"
    )


@case(
    "SMK-OAU-030",
    area="OAU",
    kind="refusal",
    covers=[START, ACCOUNT, "cli.oauth.connect", "cli.oauth.account-status"],
    codes=["not_found", "account_conflict"],
)
def test_unknown_registration_and_existing_account_refuse(cs):
    """oauth-consent.md:123 (absent account with no registration is 404) and 132-134 (a new
    connect conflicts with an existing account; disconnect first)."""
    t, c = cs
    authorizes = c.fake.counts["authorize"]
    missing = t.cli("oauth", "account-status", "no-such-tool", "--label", "reader")
    assert missing.code == 4 and missing.error_code == "not_found"
    start = admin(
        t,
        "POST",
        "/admin/operator/tools/no-such-tool/oauth/attempts",
        {
            "session_label": "reader",
            "auth_profile_id": oc.PROFILE,
            "client_generation": 1,
            "requested_scopes": oc.SCOPES,
            "redirect_profile_id": oc.REDIRECT,
            "expected_config_revision": oc.account(t, "fragile")["config_revision"],
        },
    )
    assert start.status == 404 and start.code == "not_found"
    conflict = oc.connect(t, "fragile")
    assert conflict.code == 5
    assert conflict.error_code == "account_conflict"
    assert c.fake.counts["authorize"] == authorizes


@case(
    "SMK-OAU-031",
    area="OAU",
    kind="refusal",
    covers=[
        "admin.GET./admin/operator/oauth",
        "admin.GET./admin/operator/oauth/{name}",
        "admin.DELETE./admin/operator/oauth/{name}",
        "admin.POST./admin/operator/oauth/{name}/bootstrap",
    ],
    codes=["oauth_kind_unsupported"],
)
def test_legacy_interfaces_refuse_consent_accounts(cs):
    """oauth-consent.md:237-243: legacy `oauth list` hides owner-bound rows; legacy
    status/revoke/bootstrap refuse them with oauth_kind_unsupported and leave them intact."""
    t, c = cs
    listed = t.cli("oauth", "list")
    assert listed.code == 0 and all(r["name"] != N for r in listed.json)
    tokens = c.fake.counts["token"]
    for args, stdin in (
        (("status",), None),
        (("revoke",), None),
        (("bootstrap", "--refresh-token-stdin"), "qa-not-a-refresh-token-0\n"),
    ):
        result = t.cli("oauth", *args, N, "--label", "fragile", stdin=stdin)
        assert result.code == 5, args
        assert result.error_code == "oauth_kind_unsupported", args
    assert c.fake.counts["token"] == tokens
    assert oc.account(t, "fragile")["state"] == "connected_unbound"


@case(
    "SMK-OAU-032",
    area="OAU",
    kind="refusal",
    covers=[
        START,
        POLL,
        CANCEL,
        ACCOUNT,
        DISCONNECT,
        REFRESH,
        CLIENT,
        CLIENT_GET,
        CLIENT_DEL,
        SELECT,
    ],
    codes=["invalid_credential"],
)
def test_consent_routes_require_operator(cs):
    """oauth-consent.md:76-79: consent routes use the operator token; a wrong token is 401
    invalid_credential and reaches neither custody nor the provider."""
    t, c = cs
    wrong = "qa-wrong.not-a-real-operator-token"
    counts = dict(c.fake.counts)
    fake_id = "A" * 43
    calls = [
        ("POST", f"{TOOLS}/attempts", {"session_label": "intruder"}),
        ("GET", f"{TOOLS}/attempts/{fake_id}", None),
        ("DELETE", f"{TOOLS}/attempts/{fake_id}", None),
        ("GET", f"{TOOLS}/accounts/fragile", None),
        ("DELETE", f"{TOOLS}/accounts/fragile", None),
        ("POST", f"{TOOLS}/accounts/fragile/refresh", None),
        ("POST", f"{TOOLS}/client", {"profile": oc.PROFILE}),
        ("GET", f"{TOOLS}/clients/{oc.PROFILE}/1", None),
        ("DELETE", f"{TOOLS}/clients/{oc.PROFILE}/1", None),
        (
            "PUT",
            f"/admin/operator/agents/{fake_id}/oauth-selection/{N}",
            {"label": "fragile"},
        ),
    ]
    for method, path, body in calls:
        response = admin(t, method, path, body, headers={"If-Match": "x"}, token=wrong)
        assert response.status == 401, f"{method} {path}: {response.status}"
        assert response.code == "invalid_credential", f"{method} {path}"
    assert dict(c.fake.counts) == counts
    assert oc.account(t, "fragile")["state"] == "connected_unbound"


@case(
    "SMK-OAU-034",
    area="OAU",
    kind="refusal",
    covers=[REFRESH, DISCONNECT, SELECT, "cli.oauth.refresh", "cli.oauth.disconnect", "cli.agent.select-oauth"],
    codes=["source_conflict"],
)
def test_stale_account_revision_is_refused(cs):
    """oauth-consent.md:128-130 and 150-157 (stale revision is 409; repeated use of an old
    revision sends no token request) and native-oauth.md:64-65 (a stale selection revision is
    409 source_conflict). The account revision is made stale by one committed renewal."""
    t, c = cs
    old = oc.account(t, "fragile")
    renewed = t.cli("oauth", "refresh", N, "--label", "fragile", "--if-match", old["revision"])
    assert renewed.code == 0, renewed.err
    current = oc.account(t, "fragile")
    assert current["revision"] != old["revision"]
    agent = t.cli("agent", "register", "--name", "oau-stale", "--allowlist", N)
    assert agent.code == 0, agent.err
    counts = dict(c.fake.counts)
    refresh = t.cli("oauth", "refresh", N, "--label", "fragile", "--if-match", old["revision"])
    assert refresh.code == 5 and refresh.error_code == "source_conflict"
    disconnect = t.cli("oauth", "disconnect", N, "--label", "fragile", "--if-match", old["revision"])
    assert disconnect.code == 5 and disconnect.error_code == "source_conflict"
    select = t.cli("agent", "select-oauth", agent.json["public_id"], N, "--label", "fragile",
                   "--if-match", old["revision"])
    assert select.code == 5 and select.error_code == "source_conflict"
    assert dict(c.fake.counts) == counts, "a stale revision reached the provider"
    after = oc.account(t, "fragile")
    assert (after["state"], after["revision"]) == ("connected_unbound", current["revision"])
    creds = t.cli("agent", "credentials", "list", agent.json["public_id"])
    assert creds.code == 0 and "fragile" not in creds.out, "a stale selection was stored"


@case(
    "SMK-OAU-035",
    area="OAU",
    kind="refusal",
    covers=[SELECT],
    codes=["if_match_required"],
)
def test_selection_requires_if_match(cs):
    """native-oauth.md:56-64: the selection API body is only `label` and missing If-Match is 428."""
    t, _ = cs
    agent = t.cli("agent", "register", "--name", "oau-no-if-match", "--allowlist", N)
    assert agent.code == 0, agent.err
    response = admin(t, "PUT", f"/admin/operator/agents/{agent.json['public_id']}/oauth-selection/{N}",
                     {"label": "fragile"})
    assert response.status == 428
    assert response.code == "if_match_required"
    creds = t.cli("agent", "credentials", "list", agent.json["public_id"])
    assert creds.code == 0 and "fragile" not in creds.out


@case(
    "SMK-OAU-036",
    area="OAU",
    kind="refusal",
    covers=[POLL, CANCEL, DISCONNECT, "cli.oauth.attempt-status", "cli.oauth.cancel", "cli.oauth.disconnect"],
    codes=["not_found"],
)
def test_unknown_attempts_and_accounts_are_not_found(cs):
    """oauth-consent.md:110-111 and 126 (attempt-status/cancel take the owner's attempt id;
    another or unknown attempt is 404) and 119-123 (an absent account with no registration
    is 404). Nothing reaches the provider."""
    t, c = cs
    counts = dict(c.fake.counts)
    unknown = "A" * 43
    polled = t.cli("oauth", "attempt-status", N, unknown)
    assert polled.code == 4 and polled.error_code == "not_found"
    canceled = t.cli("oauth", "cancel", N, unknown)
    assert canceled.code == 4 and canceled.error_code == "not_found"
    absent = oc.account(t, "never-connected")
    disconnect = t.cli("oauth", "disconnect", "no-such-tool", "--label", "never-connected",
                       "--if-match", absent["revision"])
    assert disconnect.code == 4 and disconnect.error_code == "not_found"
    assert dict(c.fake.counts) == counts


@case(
    "SMK-OAU-033",
    area="OAU",
    kind="positive",
    covers=[
        CLIENT_DEL,
        CLIENT_GET,
        "cli.oauth.client.retire",
        "cli.oauth.client.status",
    ],
)
def test_retired_client_generation_cannot_start_consent(cs):
    """custom-oauth.md:112-116 and custom-oauth-workflow.md:33-38, 78-82: retiring a
    confidential client generation is local and permanent (replacement needs a new
    generation); a later consent with that generation is refused before any IdP contact."""
    t, c = cs
    counts = dict(c.fake.counts)
    retired = t.cli(
        "oauth",
        "client",
        "retire",
        N,
        "--profile",
        oc.PROFILE,
        "--client-generation",
        "1",
    )
    assert retired.code == 0, retired.err
    assert retired.json["state"] == "retired"
    status = t.cli(
        "oauth",
        "client",
        "status",
        N,
        "--profile",
        oc.PROFILE,
        "--client-generation",
        "1",
    )
    assert status.code == 0 and status.json["state"] == "retired"
    again = t.cli(
        "oauth",
        "client",
        "set",
        N,
        "--profile",
        oc.PROFILE,
        "--client-generation",
        "1",
        "--secret-stdin",
        stdin=c.client_secret + "\n",
    )
    assert again.code != 0, "a retired generation was re-provisioned"
    attempt = oc.connect(t, "after-retire")
    assert attempt.code != 0, "consent started with a retired client generation"
    assert dict(c.fake.counts) == counts
