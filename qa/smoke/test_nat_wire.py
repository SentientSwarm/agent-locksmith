"""Native MCP HTTP ingress guards under the default `mcp` configuration.

Every guard is checked on the standard path and the opted-in compact path,
which share the same ingress boundary (docs/user/agent-integration/compact-mcp.md:9-15).
Docs: docs/user/agent-integration/native-mcp.md:32-33, :132-147 and
docs/user/operator/native-mcp.md:32-45.
"""

import pytest

from fakes import nat_wire as w
from fakes.nat_env import native_target, put_connection, register

case = pytest.mark.case
STD = "agent.ANY./mcp/{name}"
CMP = "agent.ANY./mcp/{name}/compact"
LIMITS = "beh.native.limits"
PATH = "/mcp/natwire"
PATHS = (PATH, PATH + "/compact")


@pytest.fixture(scope="module")
def env(target_factory):
    target, fake = native_target(target_factory, "nat-wire")
    try:
        put = put_connection(target, fake.url, "natwire", compact=True)
        assert put.code == 0, put.err
        yield {
            "t": target,
            "fake": fake,
            "agent": register(target, "nat-wire-agent", "natwire"),
        }
    finally:
        fake.close()


def post(env, path, extra=None, body=None, host=True):
    headers = [w.auth(env["agent"]["token"]), *w.POST_HEADERS, *(extra or [])]
    return w.send(
        env["t"], "POST", path, headers, w.INIT if body is None else body, host=host
    )


def refused(env, reply, status, code, path):
    assert reply.status == status, path
    assert reply.code == code, path
    assert env["fake"].snapshot()["calls"] == 0


@case("SMK-NAT-020", area="NAT", kind="positive", covers=[STD, CMP, LIMITS])
def test_default_host_allowlist_admits_loopback_listener(env):
    """Defaults are localhost, 127.0.0.1 and [::1] with their listener ports; absent Origin is allowed.

    docs/user/operator/native-mcp.md:40-42; docs/user/agent-integration/native-mcp.md:144;
    docs/user/agent-integration/compact-mcp.md:9-10.
    """
    port = env["t"].port
    for path in PATHS:
        for host in (f"127.0.0.1:{port}", f"localhost:{port}"):
            s = w.Session(env["t"], env["agent"]["token"], path)
            reply = w.send(
                env["t"],
                "POST",
                path,
                [("Host", host), *s.headers()],
                w.INIT,
                host=False,
            )
            assert reply.status == 200, reply.text
            assert reply.json["result"]["protocolVersion"] == "2025-11-25"
            s.id = reply.session
            assert s.notify("notifications/initialized").status == 202
            assert s.call("ping").json["result"] == {}
            assert s.delete().status == 202


@case(
    "SMK-NAT-021",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP],
    codes=["query_unsupported"],
)
def test_query_string_is_400(env):
    """Query strings reject. docs/user/agent-integration/native-mcp.md:145-146."""
    for path in PATHS:
        refused(env, post(env, path + "?cursor=1"), 400, "query_unsupported", path)


@case(
    "SMK-NAT-022",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP, LIMITS],
    codes=["host_required", "host_denied"],
)
def test_missing_or_foreign_host_is_refused(env):
    """Host must match its configured authority.

    docs/user/agent-integration/native-mcp.md:144-145, :134, :136; docs/user/operator/native-mcp.md:40-42.
    """
    for path in PATHS:
        refused(env, post(env, path, host=False), 400, "host_required", path)
        refused(
            env,
            post(env, path, [("Host", "evil.qa.example")], host=False),
            403,
            "host_denied",
            path,
        )


@case(
    "SMK-NAT-023",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP, LIMITS],
    codes=["origin_denied"],
)
def test_any_present_origin_is_denied_by_default(env):
    """An empty `allowed_origins` rejects every present Origin.

    docs/user/operator/native-mcp.md:42-44; docs/user/agent-integration/native-mcp.md:144-145.
    """
    port = env["t"].port
    for path in PATHS:
        for origin in ("https://evil.qa.example", f"http://127.0.0.1:{port}", "null"):
            refused(
                env, post(env, path, [("Origin", origin)]), 403, "origin_denied", path
            )


@case(
    "SMK-NAT-024",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP],
    codes=["duplicate_header"],
)
def test_duplicate_security_headers_are_400(env):
    """Duplicate security headers reject. docs/user/agent-integration/native-mcp.md:145-146."""
    dup = [("MCP-Protocol-Version", w.PROTOCOL), ("MCP-Protocol-Version", w.PROTOCOL)]
    for path in PATHS:
        refused(env, post(env, path, dup), 400, "duplicate_header", path)
        refused(
            env,
            post(env, path, [("Authorization", "Bearer qa-second-value-000")]),
            400,
            "duplicate_header",
            path,
        )


@case(
    "SMK-NAT-025",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP],
    codes=["method_not_allowed"],
)
def test_unsupported_http_method_is_405(env):
    """POST, GET and DELETE are the documented operations. docs/user/agent-integration/native-mcp.md:32, :76-80."""
    for path in PATHS:
        for method in ("PUT", "PATCH"):
            reply = w.send(
                env["t"],
                method,
                path,
                [w.auth(env["agent"]["token"]), *w.POST_HEADERS],
                w.INIT,
            )
            refused(env, reply, 405, "method_not_allowed", path)


@case(
    "SMK-NAT-026",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP],
    codes=["accept", "content_type"],
)
def test_media_negotiation_is_406_or_415(env):
    """POST needs JSON content and both Accept types; GET needs text/event-stream.

    docs/user/agent-integration/native-mcp.md:32-33, :79, :134.
    """
    t, token = env["t"], env["agent"]["token"]
    for path in PATHS:
        json_only = w.send(
            t,
            "POST",
            path,
            [
                w.auth(token),
                ("Content-Type", "application/json"),
                ("Accept", "application/json"),
            ],
            w.INIT,
        )
        refused(env, json_only, 406, "accept", path)
        get = w.send(t, "GET", path, [w.auth(token), ("Accept", "application/json")])
        refused(env, get, 406, "accept", path)
        text = w.send(
            t,
            "POST",
            path,
            [
                w.auth(token),
                ("Content-Type", "text/plain"),
                ("Accept", "application/json, text/event-stream"),
            ],
            w.INIT,
        )
        refused(env, text, 415, "content_type", path)


@case(
    "SMK-NAT-027",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP, LIMITS],
    codes=["request_body_limit"],
)
def test_body_over_default_limit_is_413(env):
    """413 oversized body; default `request_bytes` is 262144.

    docs/user/agent-integration/native-mcp.md:135; docs/development/native-mcp.md:63.
    """
    body = (
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"'
        + b"x" * 262144
        + b'"}}'
    )
    for path in PATHS:
        refused(env, post(env, path, body=body), 413, "request_body_limit", path)


@case(
    "SMK-NAT-028",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP, LIMITS],
    codes=["headers_too_large"],
)
def test_oversized_headers_are_431(env):
    """431 oversized headers; native headers are bounded at 16 KiB / 64 fields.

    docs/user/agent-integration/native-mcp.md:135; docs/development/native-mcp.md:65.
    """
    for path in PATHS:
        refused(
            env,
            post(env, path, [(f"X-Qa-Pad-{i}", "v") for i in range(70)]),
            431,
            "headers_too_large",
            path,
        )
        refused(
            env,
            post(env, path, [("X-Qa-Pad", "v" * 17000)]),
            431,
            "headers_too_large",
            path,
        )


@case("SMK-NAT-029", area="NAT", kind="corner", covers=[STD, CMP])
def test_jsonrpc_envelope_refusals_are_bounded(env):
    """Batches, unknown methods and null/float IDs reject with JSON-RPC errors; invalid IDs become null.

    docs/user/agent-integration/native-mcp.md:55, :139-141, :145-146.
    """
    for path in PATHS:
        s = w.Session(env["t"], env["agent"]["token"], path).open()
        batch = s.post([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])
        unknown = s.call("resources/list")
        float_id = s.post({"jsonrpc": "2.0", "id": 1.5, "method": "ping"})
        null_id = s.post({"jsonrpc": "2.0", "id": None, "method": "ping"})
        s.delete()
        assert batch.json["error"]["code"] == -32600 and batch.json["id"] is None
        assert unknown.json["error"]["code"] == -32601
        for reply in (float_id, null_id):
            assert reply.json["error"]["code"] == -32600 and reply.json["id"] is None
    assert env["fake"].snapshot()["calls"] == 0
