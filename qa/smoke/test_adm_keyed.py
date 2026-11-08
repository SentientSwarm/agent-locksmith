"""A daemon with a credential-store key and one legacy config tool: stored per-agent
values and the legacy tool listings (per-agent-credentials.md, native-tool-review.md:33-50)."""

import base64
import os

import pytest

from fakes.adm_flows import register
from fakes.adm_uds import uds

case = pytest.mark.case
STORED = (
    "admin.PUT./admin/operator/agents/{public_id}/credentials/{registration}/credential"
)
VALUE_Y = "synthetic-private-account-y"
LEGACY = {
    "name": "adm-legacy",
    "description": "legacy config tool",
    "upstream": "http://127.0.0.1:9",
    "egress": "direct",
}


@pytest.fixture(scope="module")
def keyed(target_factory):
    key = base64.b64encode(os.urandom(32)).decode()
    t = target_factory(
        label="adm-keyed",
        config={"tools": [LEGACY]},
        env={"LOCKSMITH_CREDENTIAL_SEALING_KEY": key},
    )
    put = t.cli(
        "tool",
        "put",
        "accounts",
        "--upstream",
        t.upstream_url,
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
    )
    assert put.code == 0, put.err
    return t


@pytest.fixture(scope="module")
def holder(keyed):
    return register(keyed, "adm-holder", allowlist="accounts")


def selection(t, agent):
    out = t.cli("agent", "credentials", "list", agent["id"])
    assert out.code == 0, out.err
    return [r["auth_spec"] for r in out.json if r["registration"] == "accounts"]


def call_counts(t, agent):
    before = t.upstream_counts()
    response = t.http("GET", "/api/accounts/check", token=agent["token"])
    return response, before, t.upstream_counts()


@case(
    "SMK-ADM-060",
    area="ADM",
    kind="positive",
    covers=[STORED, "cli.agent.set-credential"],
)
def test_stored_bearer_is_sealed_selected_and_used(keyed, holder):
    """`--stored-bearer-stdin` seals the value and returns only an opaque reference;
    the proxy then injects it (native-tool-review.md:33-44, README.md:105-110).
    Reads reveal only the reference (reveal-never: README.md:109)."""
    out = keyed.cli(
        "agent",
        "set-credential",
        holder["id"],
        "accounts",
        "--stored-bearer-stdin",
        stdin=VALUE_Y + "\n",
    )
    assert out.code == 0, out.err
    ref = out.json["secret_ref"]
    assert ref and VALUE_Y not in out.out
    assert selection(keyed, holder) == [{"kind": "stored_bearer", "secret_ref": ref}]
    response, before, after = call_counts(keyed, holder)
    assert (response.status, response.text) == (200, "Y")
    assert after["Y"] == before["Y"] + 1


@case("SMK-ADM-061", area="ADM", kind="positive", covers=[STORED])
def test_stored_value_api_replaces_selection_with_new_reference(keyed, holder):
    """The stored-value API (`{value, bearer: true}`) creates a fresh reference and
    selects it; reads never return the value (native-tool-review.md:39-44,
    sealed-state-recovery.md:138-141)."""
    old = selection(keyed, holder)
    path = f"/admin/operator/agents/{holder['id']}/credentials/accounts/credential"
    r = uds(
        keyed,
        "PUT",
        path,
        token=keyed.op_token,
        body={"value": VALUE_Y, "bearer": True},
    )
    assert r.status == 200, r.text
    assert r.json["secret_ref"] and VALUE_Y not in r.text
    now = selection(keyed, holder)
    assert (
        now == [{"kind": "stored_bearer", "secret_ref": r.json["secret_ref"]}]
        and now != old
    )
    response, _, _ = call_counts(keyed, holder)
    assert (response.status, response.text) == (200, "Y")


@case(
    "SMK-ADM-062",
    area="ADM",
    kind="refusal",
    covers=[STORED],
    codes=["invalid_stored_credential"],
)
def test_malformed_stored_value_is_refused_without_change(keyed, holder):
    """A bearer value must be 1–8192 printable ASCII bytes with no spaces, and bearer
    and header intent are exclusive; a refused write changes nothing
    (native-tool-review.md:39-44)."""
    before = selection(keyed, holder)
    path = f"/admin/operator/agents/{holder['id']}/credentials/accounts/credential"
    for body in (
        {"value": "has space", "bearer": True},
        {"value": "", "bearer": True},
        {"value": "x" * 8193, "bearer": True},
        {"value": "adm-value-z", "bearer": True, "header": "x-api-key"},
    ):
        r = uds(keyed, "PUT", path, token=keyed.op_token, body=body)
        assert (r.status, r.code) == (400, "invalid_stored_credential"), sorted(body)
    assert selection(keyed, holder) == before
    response, before_counts, after = call_counts(keyed, holder)
    assert (response.status, response.text) == (200, "Y")
    assert after["X"] == before_counts["X"]


@case(
    "SMK-ADM-063",
    area="ADM",
    kind="positive",
    covers=["admin.GET./admin/operator/tools-legacy"],
)
def test_operator_legacy_listing_shows_config_tools(keyed):
    """Legacy `config.tools` entries are listed for the operator as configuration-only
    (cli-reference.md:283 "legacy config.tools"; per-agent-credentials.md:83-84)."""
    r = uds(keyed, "GET", "/admin/operator/tools-legacy", token=keyed.op_token)
    assert r.status == 200, r.text
    tools = {t["name"]: t for t in r.json["tools"]}
    assert "adm-legacy" in tools and "accounts" not in tools
    assert tools["adm-legacy"]["activation"] == "configuration_only"


@case(
    "SMK-ADM-064", area="ADM", kind="positive", covers=["admin.GET./admin/agent/tools"]
)
def test_agent_legacy_listing_is_acl_filtered_configuration_only(keyed, holder):
    """`/admin/agent/tools` reports config-only legacy discovery as
    `configuration_only`, never per-agent credential readiness, filtered by the
    agent's ACL (per-agent-credentials.md:83-84, agent-identity-and-acl.md:37-41)."""
    granted = register(keyed, "adm-legacy-user", allowlist="adm-legacy")
    mine = uds(keyed, "GET", "/admin/agent/tools", token=granted["token"])
    assert mine.status == 200, mine.text
    assert [
        (t["name"], t["activation"], t["credential_readiness"])
        for t in mine.json["tools"]
    ] == [("adm-legacy", "configuration_only", "not_checked")]
    other = uds(keyed, "GET", "/admin/agent/tools", token=holder["token"])
    assert other.status == 200 and other.json["tools"] == []


@case(
    "SMK-ADM-065",
    area="ADM",
    kind="refusal",
    covers=[STORED, "cli.agent.set-credential"],
    codes=["agent_not_found"],
)
def test_stored_value_for_unknown_agent_is_404(keyed):
    """An unknown agent is HTTP 404 → exit 4 (cli-reference.md:315); nothing is
    sealed or selected."""
    path = "/admin/operator/agents/adm-no-such-agent/credentials/accounts/credential"
    r = uds(
        keyed,
        "PUT",
        path,
        token=keyed.op_token,
        body={"value": VALUE_Y, "bearer": True},
    )
    assert (r.status, r.code) == (404, "agent_not_found")
    out = keyed.cli(
        "agent",
        "set-credential",
        "adm-no-such-agent",
        "accounts",
        "--stored-bearer-stdin",
        stdin=VALUE_Y + "\n",
    )
    assert out.code == 4, out.err
    assert out.error_code == "agent_not_found", out.err


@case(
    "SMK-ADM-066",
    area="ADM",
    kind="refusal",
    covers=[STORED, "cli.agent.set-credential"],
    codes=["grant_target_invalid"],
)
def test_stored_value_for_unknown_connection_is_refused(keyed, holder):
    """Unknown, disabled and infra names cannot be newly bound
    (per-agent-credentials.md:20-21); the refused write leaves the agent's
    selections unchanged (native-tool-review.md:43-44)."""
    before = keyed.cli("agent", "credentials", "list", holder["id"]).json
    path = f"/admin/operator/agents/{holder['id']}/credentials/adm-not-a-connection/credential"
    r = uds(
        keyed,
        "PUT",
        path,
        token=keyed.op_token,
        body={"value": VALUE_Y, "bearer": True},
    )
    assert (r.status, r.code) == (400, "grant_target_invalid")
    out = keyed.cli(
        "agent",
        "set-credential",
        holder["id"],
        "adm-not-a-connection",
        "--stored-bearer-stdin",
        stdin=VALUE_Y + "\n",
    )
    assert out.code == 1, out.err
    assert out.error_code == "grant_target_invalid", out.err
    assert keyed.cli("agent", "credentials", "list", holder["id"]).json == before
