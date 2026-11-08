"""Native MCP session lifecycle and admission refusals over raw streamable HTTP.

Docs: docs/user/agent-integration/native-mcp.md (agent wire sequence and errors),
docs/user/operator/native-mcp.md (operator setup and diagnosis).
"""

import pytest

from fakes import nat_wire as w
from fakes.nat_env import native_target, put_connection, register

case = pytest.mark.case
STD = "agent.ANY./mcp/{name}"
CMP = "agent.ANY./mcp/{name}/compact"
PATH = "/mcp/natsess"
PATHS = (PATH, PATH + "/compact")


@pytest.fixture(scope="module")
def env(target_factory):
    target, fake = native_target(target_factory, "nat-session")
    try:
        for name, compact in (("natsess", True), ("natplain", False)):
            put = put_connection(target, fake.url, name, compact=compact)
            assert put.code == 0, put.err
        yield {
            "t": target,
            "fake": fake,
            "agent": register(target, "nat-sess-agent", "natsess"),
        }
    finally:
        fake.close()


def no_arrivals(env, before):
    assert env["fake"].snapshot() == before, "a refused request reached the upstream"



@case(
    "SMK-NAT-001",
    area="NAT",
    kind="positive",
    covers=[STD, "agent.GET./tools", "cli.tool.put"],
)
def test_session_lifecycle_without_grants(env):
    """Discovery shows a native entry; initialize/initialized/ping/list/DELETE follow the documented sequence.

    docs/user/agent-integration/native-mcp.md:7-9 (`/tools` native entry),
    :32-47 (initialize, Mcp-Session-Id, initialized returns 202), :50-58 (unapproved
    call -32050 tool_not_approved, tools_list_required before list, neither sends
    upstream), :77-78 (DELETE returns 202 and retires the session);
    docs/user/operator/native-mcp.md:113-118 (no `/api/` path; empty list, calls refused);
    docs/user/operator/native-mcp.md:61 (compact opt-in adds `compact_path`).
    """
    t, before = env["t"], env["fake"].snapshot()
    tools = t.http("GET", "/tools", token=env["agent"]["token"])
    assert tools.status == 200
    entry = next(e for e in tools.json["tools"] if e["name"] == "natsess")
    assert entry["type"] == "mcp"
    assert entry["path"] == PATH
    assert entry["protocol_version"] == "2025-11-25"
    assert entry["tool_authority"] == "reviewed_per_agent"
    assert entry["compact_path"] == PATH + "/compact"
    s = w.Session(t, env["agent"]["token"], PATH)
    init = s.initialize()
    assert init.status == 200
    assert s.id
    assert init.json["result"]["protocolVersion"] == "2025-11-25"
    assert set(init.json["result"]["capabilities"]) == {"tools"}
    assert not init.json["result"]["capabilities"]["tools"].get("listChanged")
    done = s.notify("notifications/initialized")
    assert done.status == 202 and done.text == ""
    assert s.call("ping").json["result"] == {}
    early = s.call("tools/call", {"name": "read_record", "arguments": {"key": "k"}})
    assert early.json["error"]["code"] == -32050
    assert early.rpc_code == "tools_list_required"
    listed = s.call("tools/list")
    assert listed.json["result"]["tools"] == []
    denied = s.call("tools/call", {"name": "read_record", "arguments": {"key": "k"}})
    assert denied.json["error"]["code"] == -32050
    assert denied.rpc_code == "tool_not_approved"
    closed = s.delete()
    assert closed.status == 202
    after = s.call("ping")
    assert after.status == 404
    assert after.code == "session_unavailable"
    no_arrivals(env, before)




def ping(rid=1):
    return {"jsonrpc": "2.0", "id": rid, "method": "ping"}


@case("SMK-NAT-002", area="NAT", kind="refusal", covers=[STD, CMP], codes=["invalid_credential"])
def test_missing_and_wrong_bearer_are_401(env):
    """401 means no current agent identity; session IDs are not authentication.

    docs/user/agent-integration/native-mcp.md:27-30, :135; docs/user/operator/native-mcp.md:122.
    """
    t, before = env["t"], env["fake"].snapshot()
    for path in PATHS:
        missing = w.send(t, "POST", path, w.POST_HEADERS, w.INIT)
        wrong = w.send(t, "POST", path, [w.auth("qa-wrong.not-a-real-agent-token-000"), *w.POST_HEADERS], w.INIT)
        for reply in (missing, wrong):
            assert reply.status == 401, path
            assert reply.code == "invalid_credential", path
    no_arrivals(env, before)


@case("SMK-NAT-003", area="NAT", kind="refusal", covers=[STD, CMP], codes=["protocol_version"])
def test_unsupported_protocol_version_is_400(env):
    """Protocol 2025-11-25 is explicit; other versions and a missing version header on later requests reject.

    docs/user/agent-integration/native-mcp.md:36-41, :134 (400 malformed protocol/session input).
    """
    t, token, before = env["t"], env["agent"]["token"], env["fake"].snapshot()
    old = dict(w.INIT, params=dict(w.INIT["params"], protocolVersion="2025-03-26"))
    for path in PATHS:
        init = w.send(t, "POST", path, [w.auth(token), *w.POST_HEADERS], old)
        s = w.Session(t, token, path).open()
        unversioned = w.send(t, "POST", path, [w.auth(token), *w.POST_HEADERS, ("Mcp-Session-Id", s.id)], ping(5))
        s.delete()
        for reply in (init, unversioned):
            assert reply.status == 400, path
            assert reply.code == "protocol_version", path
    no_arrivals(env, before)


@case("SMK-NAT-004", area="NAT", kind="refusal", covers=[STD, CMP],
      codes=["session_required", "initialize_has_session"])
def test_session_header_rules(env):
    """Start without a session header; later requests need it.

    docs/user/agent-integration/native-mcp.md:32-41, :134.
    """
    t, token, before = env["t"], env["agent"]["token"], env["fake"].snapshot()
    for path in PATHS:
        missing = w.send(t, "POST", path, [w.auth(token), *w.POST_HEADERS, ("MCP-Protocol-Version", w.PROTOCOL)],
                         ping())
        assert missing.status == 400, path
        assert missing.code == "session_required", path
        extra = w.send(t, "POST", path, [w.auth(token), *w.POST_HEADERS, ("Mcp-Session-Id", "qa-made-up")], w.INIT)
        assert extra.status == 400, path
        assert extra.code == "initialize_has_session", path
    no_arrivals(env, before)


@case("SMK-NAT-005", area="NAT", kind="refusal", covers=[STD, CMP], codes=["initialization_incomplete"])
def test_list_before_initialized_notification_is_refused(env):
    """Send notifications/initialized after consuming InitializeResult, then list.

    docs/user/agent-integration/native-mcp.md:39-51, :134.
    """
    t, before = env["t"], env["fake"].snapshot()
    for path in PATHS:
        s = w.Session(t, env["agent"]["token"], path)
        assert s.initialize().status == 200
        early = s.call("tools/list")
        s.delete()
        assert early.status == 400, path
        assert early.code == "initialization_incomplete", path
    no_arrivals(env, before)


@case("SMK-NAT-006", area="NAT", kind="refusal", covers=[STD, CMP], codes=["session_unavailable"])
def test_unknown_foreign_and_cross_route_sessions_are_404(env):
    """Sessions bind to agent and endpoint; another agent cannot use or close them; never move between paths.

    docs/user/agent-integration/native-mcp.md:27-30, :136 (404 unavailable session);
    docs/user/agent-integration/compact-mcp.md:13-14.
    """
    t, token, before = env["t"], env["agent"]["token"], env["fake"].snapshot()
    other = register(t, "nat-sess-other", "natsess")
    for path, crossed in ((PATHS[0], PATHS[1]), (PATHS[1], PATHS[0])):
        s = w.Session(t, token, path).open()
        hdrs = [("Mcp-Session-Id", s.id), ("MCP-Protocol-Version", w.PROTOCOL)]
        unknown = w.send(t, "POST", path, [w.auth(token), *w.POST_HEADERS, ("Mcp-Session-Id", "qa-unknown-session"),
                                           ("MCP-Protocol-Version", w.PROTOCOL)], ping(77))
        foreign_use = w.send(t, "POST", path, [w.auth(other["token"]), *w.POST_HEADERS, *hdrs], ping(78))
        foreign_close = w.send(t, "DELETE", path, [w.auth(other["token"]), *hdrs])
        other_route = w.send(t, "POST", crossed, [w.auth(token), *w.POST_HEADERS, *hdrs], ping(79))
        still = s.call("ping")
        s.delete()
        for reply in (unknown, foreign_use, foreign_close, other_route):
            assert reply.status == 404, path
            assert reply.code == "session_unavailable", path
        assert still.status == 200 and still.json["result"] == {}, path
    no_arrivals(env, before)


@case("SMK-NAT-007", area="NAT", kind="refusal", covers=[STD, CMP], codes=["request_id_reused"])
def test_reused_request_id_is_409(env):
    """Request IDs share a ledger; reuse is 409.

    docs/user/agent-integration/native-mcp.md:67-70, :137.
    """
    t, before = env["t"], env["fake"].snapshot()
    for path in PATHS:
        s = w.Session(t, env["agent"]["token"], path).open()
        first = s.call("ping", rid="qa-id-1")
        again = s.call("ping", rid="qa-id-1")
        s.delete()
        assert first.status == 200, path
        assert again.status == 409, path
        assert again.code == "request_id_reused", path
    no_arrivals(env, before)


@case("SMK-NAT-008", area="NAT", kind="refusal", covers=[STD, CMP], codes=["unexpected_body", "resume_unsupported"])
def test_get_delete_bodies_and_resume_are_refused(env):
    """Only POST carries JSON; Last-Event-ID / resume are refused.

    docs/user/agent-integration/native-mcp.md:32, :76-81, :134.
    """
    t, token, before = env["t"], env["agent"]["token"], env["fake"].snapshot()
    for path in PATHS:
        s = w.Session(t, token, path).open()
        hdrs = [w.auth(token), ("Mcp-Session-Id", s.id), ("MCP-Protocol-Version", w.PROTOCOL)]
        get_body = w.send(t, "GET", path, [*hdrs, ("Accept", "text/event-stream")], b"x")
        delete_body = w.send(t, "DELETE", path, hdrs, b"x")
        resume = w.send(t, "GET", path, [*hdrs, ("Accept", "text/event-stream"), ("Last-Event-ID", "1")])
        s.delete()
        for reply in (get_body, delete_body):
            assert reply.status == 400, path
            assert reply.code == "unexpected_body", path
        assert resume.status == 400, path
        assert resume.code == "resume_unsupported", path
    no_arrivals(env, before)


@case("SMK-NAT-009", area="NAT", kind="refusal", covers=[STD, CMP],
      codes=["connection_not_allowed", "account_selection_required"])
def test_missing_connection_grant_or_selection_is_403(env):
    """Connection access and explicit account selection permit the lifecycle; 403 when missing.

    docs/user/operator/native-mcp.md:6-7, :122-123; docs/user/agent-integration/native-mcp.md:136;
    docs/user/agent-integration/compact-mcp.md:6-7.
    """
    t, before = env["t"], env["fake"].snapshot()
    not_allowed = register(t, "nat-sess-noacl", "natplain")
    unselected = register(t, "nat-sess-nosel", "natsess", select=False)
    for path in PATHS:
        acl = w.send(t, "POST", path, [w.auth(not_allowed["token"]), *w.POST_HEADERS], w.INIT)
        sel = w.send(t, "POST", path, [w.auth(unselected["token"]), *w.POST_HEADERS], w.INIT)
        assert acl.status == 403, path
        assert acl.code == "connection_not_allowed", path
        assert sel.status == 403, path
        assert sel.code == "account_selection_required", path
    no_arrivals(env, before)


@case("SMK-NAT-010", area="NAT", kind="refusal", covers=[STD, CMP], codes=["connection_unavailable"])
def test_unknown_connection_is_404(env):
    """404 means unavailable connection.

    docs/user/operator/native-mcp.md:122-124; docs/user/agent-integration/native-mcp.md:136.
    """
    t, token, before = env["t"], env["agent"]["token"], env["fake"].snapshot()
    for path in ("/mcp/natsess-nothing", "/mcp/natsess-nothing/compact"):
        unknown = w.send(t, "POST", path, [w.auth(token), *w.POST_HEADERS], w.INIT)
        assert unknown.status == 404, path
        assert unknown.code == "connection_unavailable", path
    no_arrivals(env, before)


@case("SMK-NAT-011", area="NAT", kind="refusal", covers=[CMP], codes=["compact_unavailable"])
def test_compact_route_without_opt_in_is_404(env):
    """Use `compact_path` only when present; it is an operator opt-in.

    docs/user/agent-integration/compact-mcp.md:3-6; docs/user/operator/native-mcp.md:55-61.
    """
    t, before = env["t"], env["fake"].snapshot()
    agent = register(t, "nat-sess-plain", "natplain")
    entry = next(e for e in t.http("GET", "/tools", token=agent["token"]).json["tools"] if e["name"] == "natplain")
    assert "compact_path" not in entry
    reply = w.send(t, "POST", "/mcp/natplain/compact", [w.auth(agent["token"]), *w.POST_HEADERS], w.INIT)
    assert reply.status == 404
    assert reply.code == "compact_unavailable"
    standard = w.Session(t, agent["token"], "/mcp/natplain").open()
    assert standard.delete().status == 202
    no_arrivals(env, before)


@case("SMK-NAT-012", area="NAT", kind="refusal", covers=[STD, CMP, "cli.agent.set-credential"],
      codes=["session_unavailable"])
def test_account_reselection_retires_open_sessions(env):
    """Policy/account changes require a fresh session; the old one is unavailable (404).

    docs/user/agent-integration/native-mcp.md:85-86, :136; docs/user/operator/native-mcp.md:104-106.
    """
    t, before = env["t"], env["fake"].snapshot()
    agent = register(t, "nat-sess-reselect", "natsess")
    sessions = [w.Session(t, agent["token"], path).open() for path in PATHS]
    again = t.cli("agent", "set-credential", agent["id"], "natsess", "--no-auth")
    assert again.code == 0, again.err
    for s in sessions:
        reply = s.call("ping")
        assert reply.status == 404, s.path
        assert reply.code == "session_unavailable", s.path
        fresh = w.Session(t, agent["token"], s.path).open()
        assert fresh.call("ping").status == 200
        fresh.delete()
    no_arrivals(env, before)


@case("SMK-NAT-013", area="NAT", kind="refusal", covers=[STD, CMP], codes=["agent_identity_required"])
def test_identityless_and_shared_gateway_cannot_open_sessions(target_factory):
    """Native access needs an actual registered agent; a shared gateway bearer or identityless setup cannot.

    docs/user/operator/native-mcp.md:19-22; docs/user/agent-integration/wire-contract.md:27-28.
    """
    gateway = target_factory(
        config={"listen": {"admin_socket": None},
                "inbound_auth": {"mode": "bearer", "token": "${QA_NAT_GATEWAY_TOKEN}"}},
        env={"QA_NAT_GATEWAY_TOKEN": "qa-nat-shared-gateway-value"},
        label="nat-gateway", upstream=False,
    )
    bare = target_factory(config={"listen": {"admin_socket": None}}, label="nat-identityless", upstream=False)
    try:
        for path in ("/mcp/sample", "/mcp/sample/compact"):
            shared = w.send(gateway, "POST", path, [w.auth("qa-nat-shared-gateway-value"), *w.POST_HEADERS], w.INIT)
            assert shared.status == 401, path
            assert shared.code == "agent_identity_required", path
            anonymous = w.send(bare, "POST", path, w.POST_HEADERS, w.INIT)
            assert anonymous.status == 401, path
            assert anonymous.code == "agent_identity_required", path
    finally:
        gateway.stop()
        bare.stop()
