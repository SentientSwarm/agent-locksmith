"""Operator observe/review/grant and reviewed native dispatch to a TLS upstream.

Docs: docs/user/operator/native-tool-review.md, native-tool-grants.md,
native-oauth.md (select-oauth refusals), and the agent guides
docs/user/agent-integration/native-mcp.md and compact-mcp.md.
"""

import base64
import json
import os
import secrets

import pytest

from fakes import nat_wire as w
from fakes.nat_env import (
    admin_raw,
    native_target,
    observe,
    prepare,
    put_connection,
    register,
    replace_grants,
    review,
    write_json,
)

case = pytest.mark.case
STD = "agent.ANY./mcp/{name}"
CMP = "agent.ANY./mcp/{name}/compact"
OBS_GET = "admin.GET./admin/operator/tools/{name}/mcp/observations/{agent}"
OBS_POST = "admin.POST./admin/operator/tools/{name}/mcp/observations/{agent}"
REVIEW = "admin.PUT./admin/operator/tools/{name}/mcp/reviews/{agent}"
GRANTS_GET = "admin.GET./admin/operator/agents/{agent}/mcp-grants/{name}"
GRANTS_PUT = "admin.PUT./admin/operator/agents/{agent}/mcp-grants/{name}"
OAUTH_SEL = "admin.PUT./admin/operator/agents/{agent}/oauth-selection/{name}"
PREP_CLI = [
    "cli.tool.mcp.show",
    "cli.tool.mcp.observe",
    "cli.tool.mcp.review",
    "cli.agent.mcp-grants.show",
    "cli.agent.mcp-grants.replace",
]
WRONG_OP = "qa-wrong.not-a-real-operator-token"


@pytest.fixture(scope="module")
def env(target_factory):
    key = base64.b64encode(os.urandom(32)).decode()
    target, fake = native_target(
        target_factory, "nat-dispatch", env={"LOCKSMITH_CREDENTIAL_SEALING_KEY": key}
    )
    try:
        for name, compact in (("natdisp", False), ("natcmp", True)):
            put = put_connection(target, fake.url, name, compact=compact)
            assert put.code == 0, put.err
        yield {"t": target, "fake": fake}
    finally:
        fake.close()


def calls(env) -> int:
    return env["fake"].snapshot()["calls"]


@case(
    "SMK-NAT-030",
    area="NAT",
    kind="positive",
    covers=[STD, OBS_GET, OBS_POST, REVIEW, GRANTS_GET, GRANTS_PUT, *PREP_CLI],
)
def test_observe_review_grant_then_call_reaches_upstream(env):
    """The documented operator workflow grants one finite tool; a fresh session lists and calls it.

    docs/user/operator/native-tool-review.md:81-101 (show/observe; initialize and list only,
    never calls tools), :103-125 (review returns contract_digest, prepared_only),
    docs/user/operator/native-tool-grants.md:13-29, :51-57 (show/replace),
    docs/user/agent-integration/native-mcp.md:56-65 (list holds only effective reviewed tools;
    explicit None sends no credential).
    """
    t, fake = env["t"], env["fake"]
    agent = register(t, "nat-disp-agent", "natdisp")
    show = t.cli("tool", "mcp", "show", "natdisp", "--agent", agent["id"])
    assert show.code == 0, show.err
    assert show.json["observation"] is None
    assert set(show.json["source"]) == {
        "instance",
        "revision",
        "account_key",
        "agent_epoch",
    }
    before_observe = fake.snapshot()
    observed = observe(t, "natdisp", agent["id"])
    assert observed.code == 0, observed.err
    names = {
        e["tool"]["name"] for e in observed.json["observation"]["manifest"]["tools"]
    }
    assert names == {"read_record", "delete_record"}
    assert fake.snapshot()["calls"] == before_observe["calls"], (
        "observation called a tool"
    )
    assert fake.snapshot()["counts"].get("tools/list", 0) > before_observe[
        "counts"
    ].get("tools/list", 0)
    reviewed = review(t, "natdisp", agent["id"], observed.json, "read_record")
    assert reviewed.code == 0, reviewed.err
    assert reviewed.json["prepared_only"] is True and reviewed.json["callable"] is False
    assert reviewed.json["contract"]["effect"] == "read"
    digest = reviewed.json["contract_digest"]
    granted = replace_grants(
        t, "natdisp", agent["id"], [{"name": "read_record", "contract_digest": digest}]
    )
    assert granted.code == 0, granted.err
    state = t.cli("agent", "mcp-grants", "show", "natdisp", "--agent", agent["id"])
    assert state.json["tools"] == [{"name": "read_record", "contract_digest": digest}]
    assert state.json["effective_tools"] == ["read_record"]
    assert state.json["callable"] is True
    s = w.Session(t, agent["token"], "/mcp/natdisp").open()
    listed = s.call("tools/list")
    assert [tool["name"] for tool in listed.json["result"]["tools"]] == ["read_record"]
    before = len(fake.calls)
    result = s.call(
        "tools/call", {"name": "read_record", "arguments": {"key": "rec-1"}}
    )
    assert result.json["result"]["isError"] is False
    assert result.json["result"]["content"][0]["text"] == "record rec-1 via read_record"
    assert len(fake.calls) == before + 1
    assert fake.calls[-1]["arguments"] == {"key": "rec-1"}
    assert fake.calls[-1]["authorization"] == "", (
        "explicit None must send no credential"
    )
    ungranted = s.call(
        "tools/call", {"name": "delete_record", "arguments": {"key": "rec-1"}}
    )
    assert ungranted.rpc_code == "tool_not_approved"
    assert len(fake.calls) == before + 1
    s.delete()


@case(
    "SMK-NAT-031", area="NAT", kind="positive", covers=[STD, "cli.agent.set-credential"]
)
def test_sealed_bearer_selection_is_injected_upstream(env):
    """A live sealed-bearer selection is used for observation and reviewed dispatch; agents never hold it.

    docs/user/operator/native-tool-review.md:33-45; docs/user/operator/native-mcp.md:81-83;
    docs/user/agent-integration/native-mcp.md:10-11.
    """
    t, fake = env["t"], env["fake"]
    agent = register(t, "nat-disp-bearer", "natdisp", select=False)
    value = "qa-nat-sealed-" + secrets.token_hex(16)
    t.canaries.add(value, "nat-stored-bearer")
    sel = t.cli(
        "agent",
        "set-credential",
        agent["id"],
        "natdisp",
        "--stored-bearer-stdin",
        stdin=value + "\n",
    )
    assert sel.code == 0, sel.err
    assert value not in sel.out + sel.err
    prepare(t, "natdisp", agent["id"])
    s = w.Session(t, agent["token"], "/mcp/natdisp").open()
    s.call("tools/list")
    result = s.call(
        "tools/call", {"name": "read_record", "arguments": {"key": "rec-2"}}
    )
    s.delete()
    assert result.json["result"]["isError"] is False
    assert fake.calls[-1]["authorization"] == f"Bearer {value}"
    assert value not in result.text


@case(
    "SMK-NAT-032",
    area="NAT",
    kind="refusal",
    covers=[STD, GRANTS_PUT, "cli.agent.mcp-grants.replace"],
    codes=["tool_not_approved"],
)
def test_revocation_refuses_pinned_tool_without_dispatch(env):
    """Existing pins still require current grants on every call; an empty tools array revokes.

    docs/user/agent-integration/native-mcp.md:61-65; docs/user/operator/native-tool-grants.md:57-59.
    """
    t = env["t"]
    agent = register(t, "nat-disp-revoke", "natdisp")
    prepare(t, "natdisp", agent["id"])
    s = w.Session(t, agent["token"], "/mcp/natdisp").open()
    assert [x["name"] for x in s.call("tools/list").json["result"]["tools"]] == [
        "read_record"
    ]
    revoked = replace_grants(t, "natdisp", agent["id"], [])
    assert revoked.code == 0, revoked.err
    before = calls(env)
    denied = s.call(
        "tools/call", {"name": "read_record", "arguments": {"key": "rec-3"}}
    )
    s.delete()
    assert denied.json["error"]["code"] == -32050
    assert denied.rpc_code == "tool_not_approved"
    assert calls(env) == before


@case("SMK-NAT-033", area="NAT", kind="positive", covers=[CMP, "agent.GET./tools"])
def test_compact_search_describe_invoke(env):
    """Compact adds compact_path; search, full describe, then invoke the ordinary checked call.

    docs/user/agent-integration/compact-mcp.md:5-15, :19-41, :43-63, :81-83 (schema_required).
    """
    t, fake = env["t"], env["fake"]
    agent = register(t, "nat-cmp-agent", "natcmp")
    entry = next(
        e
        for e in t.http("GET", "/tools", token=agent["token"]).json["tools"]
        if e["name"] == "natcmp"
    )
    assert entry["path"] == "/mcp/natcmp"
    assert entry["compact_path"] == "/mcp/natcmp/compact"
    prepare(t, "natcmp", agent["id"])
    s = w.Session(t, agent["token"], entry["compact_path"]).open()
    tools = {x["name"] for x in s.call("tools/list").json["result"]["tools"]}
    assert tools == {"search", "describe", "invoke"}
    found = s.call("tools/call", {"name": "search", "arguments": {"query": "record"}})
    matches = json.loads(found.json["result"]["content"][0]["text"])["matches"]
    assert [m["name"] for m in matches] == ["read_record"]
    handle, digest = matches[0]["handle"], matches[0]["contract_digest"]
    before = len(fake.calls)
    invoke = {
        "name": "invoke",
        "arguments": {
            "handle": handle,
            "contract_digest": digest,
            "arguments": {"key": "rec-4"},
        },
    }
    early = s.call("tools/call", invoke)
    assert early.rpc_code == "schema_required"
    assert len(fake.calls) == before
    described = json.loads(
        s.call(
            "tools/call", {"name": "describe", "arguments": {"handle": handle}}
        ).json["result"]["content"][0]["text"]
    )
    assert described["name"] == "read_record" and described["contract_digest"] == digest
    assert described["input_schema"]["required"] == ["key"]
    result = s.call("tools/call", invoke)
    s.delete()
    assert result.json["result"]["content"][0]["text"] == "record rec-4 via read_record"
    assert len(fake.calls) == before + 1


@case(
    "SMK-NAT-034",
    area="NAT",
    kind="refusal",
    covers=[OBS_GET, OBS_POST, REVIEW, GRANTS_GET, GRANTS_PUT, OAUTH_SEL,
            *PREP_CLI, "cli.agent.select-oauth"],
    codes=["invalid_credential"],
)
def test_wrong_operator_token_is_auth_failure(env):
    """The same authenticated operator API serves preparation; a wrong operator token is refused (exit 3).

    docs/user/operator/native-tool-review.md:140-146; docs/user/cli-reference.md:314.
    """
    t = env["t"]
    agent = register(t, "nat-disp-badop", "natdisp")
    source = t.cli("tool", "mcp", "show", "natdisp", "--agent", agent["id"]).json["source"]
    body = write_json(t, "nat-badop.json", {"source": source, "generation": None})
    before = env["fake"].snapshot()
    for args in (
        ("tool", "mcp", "show", "natdisp", "--agent", agent["id"]),
        ("tool", "mcp", "observe", "natdisp", "--agent", agent["id"], "--file", body),
        ("tool", "mcp", "review", "natdisp", "--agent", agent["id"], "--file", body),
        ("agent", "mcp-grants", "show", "natdisp", "--agent", agent["id"]),
        ("agent", "mcp-grants", "replace", "natdisp", "--agent", agent["id"], "--file", body),
        (
            "agent",
            "select-oauth",
            agent["id"],
            "natdisp",
            "--label",
            "acct",
            "--if-match",
            "1",
        ),
    ):
        result = t.cli(*args, op_token=WRONG_OP)
        assert result.code == 3, args
        assert result.error_code == "invalid_credential", args
    assert env["fake"].snapshot() == before, "a refused operator call contacted the upstream"


@case(
    "SMK-NAT-035",
    area="NAT",
    kind="refusal",
    covers=[OBS_POST, REVIEW, "cli.tool.mcp.observe", "cli.tool.mcp.review"],
    codes=["source_conflict", "observation_conflict"],
)
def test_stale_preconditions_refuse_observe_and_review(env):
    """Echo exact returned preconditions; changed source/generation refuses with 409.

    docs/user/operator/native-tool-review.md:85-92, :196-201; docs/user/operator/native-tool-grants.md:70-72;
    docs/user/operator/native-context.md:90.
    """
    t = env["t"]
    agent = register(t, "nat-disp-stale", "natdisp")
    source = t.cli("tool", "mcp", "show", "natdisp", "--agent", agent["id"]).json[
        "source"
    ]
    before = env["fake"].snapshot()
    moved = dict(source, revision=source["revision"] + 1)
    stale_source = t.cli(
        "tool",
        "mcp",
        "observe",
        "natdisp",
        "--agent",
        agent["id"],
        "--file",
        write_json(t, "nat-stale.json", {"source": moved, "generation": None}),
    )
    assert stale_source.code == 5
    assert stale_source.error_code == "source_conflict"
    invented = t.cli(
        "tool",
        "mcp",
        "observe",
        "natdisp",
        "--agent",
        agent["id"],
        "--file",
        write_json(
            t, "nat-stale.json", {"source": source, "generation": "qa-invented"}
        ),
    )
    assert invented.code == 5
    assert invented.error_code == "observation_conflict"
    assert env["fake"].snapshot() == before, (
        "a refused observation contacted the upstream"
    )
    observed = observe(t, "natdisp", agent["id"])
    assert observed.code == 0, observed.err
    stale_review = t.cli(
        "tool",
        "mcp",
        "review",
        "natdisp",
        "--agent",
        agent["id"],
        "--file",
        write_json(
            t,
            "nat-stale.json",
            {
                "source": observed.json["source"],
                "generation": "0" * 32,
                "name": "read_record",
                "observed_digest": "0" * 64,
                "effect": "read",
            },
        ),
    )
    assert stale_review.code == 5
    assert stale_review.error_code == "observation_conflict"


@case(
    "SMK-NAT-036",
    area="NAT",
    kind="refusal",
    covers=[GRANTS_PUT, "cli.agent.mcp-grants.replace"],
    codes=["grant_conflict"],
)
def test_stale_grant_revision_is_409(env):
    """A changed grant revision refuses the write; `revision: null` creates an absent set only.

    docs/user/operator/native-tool-grants.md:42-57, :70-72.
    """
    t = env["t"]
    agent = register(t, "nat-disp-cas", "natdisp")
    prepare(t, "natdisp", agent["id"])
    state = t.cli("agent", "mcp-grants", "show", "natdisp", "--agent", agent["id"]).json
    body = {
        "source": state["source"],
        "generation": state["observation"]["generation"],
        "revision": None,
        "tools": [],
    }
    stale = t.cli(
        "agent",
        "mcp-grants",
        "replace",
        "natdisp",
        "--agent",
        agent["id"],
        "--file",
        write_json(t, "nat-cas.json", body),
    )
    assert stale.code == 5
    assert stale.error_code == "grant_conflict"
    after = t.cli("agent", "mcp-grants", "show", "natdisp", "--agent", agent["id"]).json
    assert after["grant_revision"] == state["grant_revision"]
    assert [x["name"] for x in after["tools"]] == ["read_record"]


@case(
    "SMK-NAT-037",
    area="NAT",
    kind="refusal",
    covers=[GRANTS_PUT, "cli.agent.mcp-grants.replace"],
    codes=["review_required"],
)
def test_unreviewed_digest_cannot_be_granted(env):
    """All entries must match current reviewed contracts. docs/user/operator/native-tool-grants.md:55-57."""
    t = env["t"]
    agent = register(t, "nat-disp-unrev", "natdisp")
    observed = observe(t, "natdisp", agent["id"])
    assert observed.code == 0, observed.err
    result = replace_grants(
        t,
        "natdisp",
        agent["id"],
        [{"name": "read_record", "contract_digest": "1" * 64}],
    )
    assert result.code == 1
    assert result.error_code == "review_required"
    state = t.cli("agent", "mcp-grants", "show", "natdisp", "--agent", agent["id"]).json
    assert state["tools"] == [] and state["grant_revision"] is None


@case("SMK-NAT-041", area="NAT", kind="refusal", covers=[GRANTS_PUT, "cli.agent.mcp-grants.replace"],
      codes=["observation_conflict", "source_conflict"])
def test_stale_source_or_generation_refuses_grant_replace(env):
    """A changed source or generation refuses the grant write (409); echo exact current preconditions.

    docs/user/operator/native-tool-grants.md:31-33, :42-44, :70-72; docs/user/operator/native-tool-review.md:196-201;
    docs/user/operator/native-context.md:90.
    """
    t = env["t"]
    agent = register(t, "nat-disp-grantcas", "natdisp")
    observed = observe(t, "natdisp", agent["id"])
    assert observed.code == 0, observed.err
    reviewed = review(t, "natdisp", agent["id"], observed.json, "read_record")
    assert reviewed.code == 0, reviewed.err
    state = t.cli("agent", "mcp-grants", "show", "natdisp", "--agent", agent["id"]).json
    tools = [{"name": "read_record", "contract_digest": reviewed.json["contract_digest"]}]
    current = {"source": state["source"], "generation": state["observation"]["generation"],
               "revision": state["grant_revision"], "tools": tools}
    before = env["fake"].snapshot()
    for body, code in (
        (dict(current, generation="0" * 32), "observation_conflict"),
        (dict(current, source=dict(state["source"], revision=state["source"]["revision"] + 1)), "source_conflict"),
        (dict(current, source=dict(state["source"], agent_epoch=state["source"]["agent_epoch"] + 1)), "source_conflict"),
    ):
        result = t.cli("agent", "mcp-grants", "replace", "natdisp", "--agent", agent["id"],
                       "--file", write_json(t, "nat-grantcas.json", body))
        assert result.code == 5, code
        assert "409" in result.err, code
        assert result.error_code == code
    after = t.cli("agent", "mcp-grants", "show", "natdisp", "--agent", agent["id"]).json
    assert after["tools"] == [] and after["grant_revision"] is None
    assert env["fake"].snapshot() == before, "a refused grant write contacted the upstream"


@case(
    "SMK-NAT-038",
    area="NAT",
    kind="refusal",
    covers=[OAUTH_SEL, "cli.agent.select-oauth"],
    codes=["if_match_required", "oauth_custody_unavailable"],
)
def test_oauth_selection_refusals(env):
    """Missing If-Match is 428; an unavailable store/key is 503.

    docs/user/operator/native-oauth.md:56-66.
    """
    t = env["t"]
    agent = register(t, "nat-disp-oauth", "natdisp", select=False)
    path = f"/admin/operator/agents/{agent['id']}/oauth-selection/natdisp"
    status, body = admin_raw(t, "PUT", path, {"label": "acct"}, {})
    assert status == 428
    assert body["error"]["code"] == "if_match_required"
    cli = t.cli(
        "agent",
        "select-oauth",
        agent["id"],
        "natdisp",
        "--label",
        "acct",
        "--if-match",
        "1",
    )
    assert cli.code != 0
    assert "503" in cli.err
    assert cli.error_code == "oauth_custody_unavailable"
    creds = t.cli("agent", "credentials", "list", agent["id"])
    assert "natdisp" not in creds.out


@case(
    "SMK-NAT-039",
    area="NAT",
    kind="refusal",
    covers=["cli.tool.put"],
    codes=["invalid_mcp"],
)
def test_native_registration_validation(env):
    """Non-HTTPS endpoints, proxied egress, unsupported versions and private destinations without opt-in reject.

    docs/user/operator/native-mcp.md:87-96.
    """
    t, url = env["t"], env["fake"].url
    cases = [
        ("natbad-http", "http://127.0.0.1:9/mcp", "direct", None),
        ("natbad-proxied", url, "proxied", None),
        (
            "natbad-version",
            url,
            "direct",
            {"protocol_version": "2025-03-26", "allow_private_destination": True},
        ),
        ("natbad-private", url, "direct", {"protocol_version": "2025-11-25"}),
    ]
    for name, upstream, egress, config in cases:
        body = config or {
            "protocol_version": "2025-11-25",
            "allow_private_destination": True,
        }
        path = write_json(t, f"{name}.json", body)
        result = t.cli(
            "tool",
            "put",
            name,
            "--upstream",
            upstream,
            "--auth",
            "none",
            "--egress",
            egress,
            "--protocol",
            "mcp_streamable_http",
            "--mcp-config-file",
            path,
        )
        assert result.code == 1, name
        assert result.error_code == "invalid_mcp", name
        assert t.cli("tool", "get", name).code != 0, f"{name} was persisted"


@case(
    "SMK-NAT-040",
    area="NAT",
    kind="refusal",
    covers=[OBS_POST, "cli.tool.mcp.observe"],
    codes=["http"],
)
def test_untrusted_upstream_certificate_publishes_nothing(target_factory):
    """Upstreams must use verified HTTPS; without the CA in `mcp.upstream_ca_bundle` observation fails.

    docs/user/operator/native-tool-review.md:55-63, :98-101.
    """
    from fakes.nat_mcp import FakeMcp
    from fakes.pki import CA

    t = target_factory(label="nat-untrusted", upstream=False)
    fake = FakeMcp(CA.create("qa-nat-untrusted-ca"), t.work)
    try:
        assert put_connection(t, fake.url, "natuntrusted").code == 0
        agent = register(t, "nat-untrusted-agent", "natuntrusted")
        result = observe(t, "natuntrusted", agent["id"])
        assert result.code != 0
        assert result.error_code == "http"
        assert fake.snapshot()["counts"] == {}
        shown = t.cli("tool", "mcp", "show", "natuntrusted", "--agent", agent["id"]).json
        assert shown["observation"] is None or shown["observation"]["manifest"] is None
        assert shown["effective_tools"] == []
    finally:
        fake.close()
        t.stop()
