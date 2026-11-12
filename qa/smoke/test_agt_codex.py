"""Codex wire fixups (CLAUDE.md Phase G2-G5, docs/user/concepts/oauth-flow.md:293-600)
and the OAuth proxy refusals, against a fake upstream whose path contains
/backend-api/codex and a fake token endpoint."""

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from fakes.agt_support import (
    ACCOUNT_ID,
    CRED,
    TokenEndpoint,
    access_jwt,
    audit,
    codex_seed,
    enrol,
    put_tool,
    sealing_key,
    write_seed,
)
from fakes.agt_upstream import Upstream

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
FIX = "beh.codex.fixups"
FLOW = "docs/user/concepts/oauth-flow.md"
DEFAULT_INSTRUCTIONS = "You are a helpful assistant."


@pytest.fixture(scope="module")
def cx(target_factory):
    up = Upstream()
    tokens = TokenEndpoint()
    up.routes["/oauth/token"] = tokens
    seed_dir = Path(tempfile.mkdtemp(prefix="agt-seed-"))
    seed = write_seed(seed_dir, [codex_seed(up)])
    env = {
        "AGT_CRED_TOKEN": CRED,
        "LOCKSMITH_OAUTH_SEALING_KEY": sealing_key(),
        "LOCKSMITH_SEED_PATH": str(seed),
    }
    t = target_factory(label="agt-codex", upstream=False, env=env)
    jwt = access_jwt()
    t.canaries.add(jwt, "agt-codex-access-token")
    tokens.plans["agt-rt-default-0001"] = (jwt, "agt-rt-default-0001", 3600)
    flaky = access_jwt(label="flaky")
    t.canaries.add(flaky, "agt-codex-flaky-access-token")
    # Short-lived first grant; its rotated refresh token is unknown to the
    # fake provider, so every later refresh fails with a provider 500.
    tokens.plans["agt-rt-flaky-0001"] = (flaky, "agt-rt-flaky-0002", 30)
    put_tool(
        t,
        "agt-codexb",
        f"{up.url}/backend-api/codex",
        "bearer=AGT_CRED_TOKEN",
        "--egress",
        "direct",
    )
    # Upstream path does not match the Codex inference rule; the explicit
    # profile alone turns the Codex behaviours on (brokered routes phase 1).
    put_tool(
        t,
        "agt-codexp",
        f"{up.url}/plain",
        "bearer=AGT_CRED_TOKEN",
        "--egress",
        "direct",
        "--profile",
        "openai-codex-responses",
    )
    agent = enrol(
        t,
        "qa-agt-codex",
        ["agt-codexb", "agt-codexp"],
        {
            "agt-codexb": ["--auth", "bearer=AGT_CRED_TOKEN"],
            "agt-codexp": ["--auth", "bearer=AGT_CRED_TOKEN"],
        },
    )
    yield {"t": t, "up": up, "tokens": tokens, "agent": agent, "jwt": jwt}
    up.close()
    shutil.rmtree(seed_dir, ignore_errors=True)


def bootstrap(t, label: str, refresh_token: str):
    return t.cli(
        "oauth",
        "bootstrap",
        "codex",
        "--label",
        label,
        "--refresh-token-stdin",
        stdin=refresh_token + "\n",
    )


@case("SMK-AGT-030", area="AGT", kind="positive", covers=[API, FIX])
def test_codex_responses_body_and_headers_fixed_up(cx):
    """oauth-flow.md:478-499 (G3 store:false, stream:true, default instructions), CLAUDE.md G5
    (max_output_tokens removed), oauth-flow.md:574-590 (G4 OpenAI-Beta forced, originator =
    agent name), oauth-flow.md:521-536 audit details.codex_body_fixup."""
    t, up, agent = cx["t"], cx["up"], cx["agent"]
    body = {
        "model": "qa-model",
        "input": [],
        "store": True,
        "stream": False,
        "max_output_tokens": 9,
    }
    resp = t.http(
        "POST",
        "/api/agt-codexb/responses",
        token=agent["token"],
        body=body,
        headers={"OpenAI-Beta": "agent-chosen-value"},
    )
    assert resp.status == 200
    rec = up.last("/backend-api/codex/responses")
    sent = rec.json()
    assert sent["store"] is False
    assert sent["stream"] is True
    assert sent["instructions"] == DEFAULT_INSTRUCTIONS
    assert "max_output_tokens" not in sent
    assert sent["model"] == "qa-model"
    assert rec.headers.get("openai-beta") == ["responses=experimental"]
    assert rec.header("originator") == agent["name"]
    assert rec.headers.get("authorization") == [f"Bearer {CRED}"]
    fixup = audit(t, "agt-codexb", "proxy_request")[0]["details"]["codex_body_fixup"]
    assert set(fixup["fields_overridden"]) == {"store", "stream"}
    assert "instructions" in fixup["fields_added"]


@case(
    "SMK-AGT-065",
    area="AGT",
    kind="positive",
    covers=[API, FIX, "beh.route.profile"],
)
def test_explicit_codex_profile_applies_fixups_off_codex_path(cx):
    """cli-reference.md "Route profiles": `--profile openai-codex-responses` applies the Codex
    body fixups (G3/G5) and required headers (G4) on an upstream whose path does not contain
    /backend-api/codex, as a broker URL would not."""
    t, up, agent = cx["t"], cx["up"], cx["agent"]
    body = {"model": "qa-model", "input": [], "store": True, "max_output_tokens": 9}
    resp = t.http(
        "POST", "/api/agt-codexp/responses", token=agent["token"], body=body
    )
    assert resp.status == 200
    rec = up.last("/plain/responses")
    sent = rec.json()
    assert sent["store"] is False
    assert sent["stream"] is True
    assert sent["instructions"] == DEFAULT_INSTRUCTIONS
    assert "max_output_tokens" not in sent
    assert rec.headers.get("openai-beta") == ["responses=experimental"]
    assert rec.header("originator") == agent["name"]
    assert rec.headers.get("authorization") == [f"Bearer {CRED}"]


@case("SMK-AGT-031", area="AGT", kind="corner", covers=[API, FIX])
def test_codex_preserves_agent_instructions_and_originator(cx):
    """oauth-flow.md:494-496 instructions preserved if set; :580-584 agent-supplied originator
    preserved; :533-536 codex_body_fixup omitted when the body was already correct."""
    t, up, agent = cx["t"], cx["up"], cx["agent"]
    body = {
        "model": "qa-model",
        "input": [],
        "store": False,
        "stream": True,
        "instructions": "be terse",
    }
    resp = t.http(
        "POST",
        "/api/agt-codexb/responses",
        token=agent["token"],
        body=body,
        headers={"originator": "codex_cli_rs"},
    )
    assert resp.status == 200
    rec = up.last("/backend-api/codex/responses")
    assert rec.json() == body
    assert rec.header("originator") == "codex_cli_rs"
    assert rec.headers.get("openai-beta") == ["responses=experimental"]
    assert (
        "codex_body_fixup" not in audit(t, "agt-codexb", "proxy_request")[0]["details"]
    )


@case("SMK-AGT-032", area="AGT", kind="corner", covers=[API, FIX])
def test_codex_non_responses_path_keeps_body_gets_headers(cx):
    """oauth-flow.md:484-486 other codex endpoints pass through untouched; :570-572 the G4
    headers apply to every /backend-api/codex/* request."""
    t, up, agent = cx["t"], cx["up"], cx["agent"]
    body = {"store": True, "max_output_tokens": 3}
    resp = t.http("POST", "/api/agt-codexb/sessions", token=agent["token"], body=body)
    assert resp.status == 200
    rec = up.last("/backend-api/codex/sessions")
    assert rec.json() == body
    assert rec.headers.get("openai-beta") == ["responses=experimental"]
    assert rec.header("originator") == agent["name"]


@case(
    "SMK-AGT-033",
    area="AGT",
    kind="refusal",
    covers=[API, FIX],
    codes=["codex_body_too_large"],
)
def test_codex_body_over_one_mib_is_413(cx):
    """oauth-flow.md:502-517 — a /responses body over the 1 MiB inspection cap is 413 with
    code codex_body_too_large; nothing is dispatched."""
    t, up, agent = cx["t"], cx["up"], cx["agent"]
    before = up.count("/backend-api")
    big = json.dumps({"model": "qa-model", "input": "x" * (1024 * 1024 + 16)})
    resp = t.http(
        "POST",
        "/api/agt-codexb/responses",
        token=agent["token"],
        body=big,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status == 413
    assert resp.code == "codex_body_too_large"
    assert resp.json["error"]["type"] == "payload_too_large"
    assert up.count("/backend-api") == before, "a refused request reached the upstream"


@case(
    "SMK-AGT-034",
    area="AGT",
    kind="positive",
    covers=[API, FIX, "cli.oauth.bootstrap", "cli.agent.set-credential"],
)
def test_codex_oauth_injects_token_and_account_header(cx):
    """oauth-flow.md:119-150 bootstrap + explicit label selection; :320-326 and :365-377 G2
    `ChatGPT-Account-ID` from the access-token JWT claim; :318-322 agent auth stripped and
    `Authorization: Bearer <access_token>` injected; :415-427 audit fields."""
    t, up, tokens = cx["t"], cx["up"], cx["tokens"]
    boot = bootstrap(t, "default", "agt-rt-default-0001")
    assert boot.code == 0, boot.err
    assert "agt-rt-default-0001" in tokens.calls
    agent = enrol(
        t, "qa-agt-codex-oauth", ["codex"], {"codex": ["--oauth-session", "default"]}
    )
    resp = t.http(
        "POST",
        "/api/codex/responses",
        token=agent["token"],
        body={"model": "qa-model", "input": []},
    )
    assert resp.status == 200
    rec = up.last("/backend-api/codex/responses")
    assert rec.headers.get("authorization") == [f"Bearer {cx['jwt']}"]
    assert rec.header("chatgpt-account-id") == ACCOUNT_ID
    assert rec.headers.get("openai-beta") == ["responses=experimental"]
    assert rec.header("originator") == agent["name"]
    row = audit(t, "codex", "proxy_request")[0]
    assert row["details"]["auth_mode"] == "oauth_device_code"
    assert row["details"]["oauth_session_label"] == "default"
    assert row["details"]["auth_source"] == "agent_override"


@case(
    "SMK-AGT-035",
    area="AGT",
    kind="refusal",
    covers=[API],
    codes=["oauth_session_missing"],
)
def test_selected_oauth_label_without_session_is_503(cx):
    """oauth-flow.md:303-310 + wire-contract.md:231 — the selected label has no bootstrapped
    session: 503 oauth_session_missing, no upstream dispatch, no other label used."""
    t, up = cx["t"], cx["up"]
    agent = enrol(
        t, "qa-agt-codex-ghost", ["codex"], {"codex": ["--oauth-session", "ghost"]}
    )
    before = up.count("/backend-api")
    resp = t.http(
        "POST", "/api/codex/responses", token=agent["token"], body={"input": []}
    )
    assert resp.status == 503
    assert resp.code == "oauth_session_missing"
    assert up.count("/backend-api") == before, "a refused request reached the upstream"


@case(
    "SMK-AGT-036",
    area="AGT",
    kind="refusal",
    covers=[API],
    codes=["oauth_refresh_failed"],
)
def test_failed_refresh_is_503_oauth_refresh_failed(cx):
    """oauth-flow.md:303-315 + wire-contract.md:232 — an expiring access token is refreshed
    inline; when the provider refresh fails the session is degraded and the call is 503
    oauth_refresh_failed with no upstream dispatch."""
    t, up = cx["t"], cx["up"]
    boot = bootstrap(t, "flaky", "agt-rt-flaky-0001")
    assert boot.code == 0, boot.err
    agent = enrol(
        t, "qa-agt-codex-flaky", ["codex"], {"codex": ["--oauth-session", "flaky"]}
    )
    before = up.count("/backend-api")
    resp = t.http(
        "POST", "/api/codex/responses", token=agent["token"], body={"input": []}
    )
    assert resp.status == 503
    assert resp.code == "oauth_refresh_failed"
    assert up.count("/backend-api") == before, "a refused request reached the upstream"
