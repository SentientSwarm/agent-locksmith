"""Native MCP finite limits, deadlines and Host/Origin allowlists from the `mcp` block.

Docs: docs/user/operator/native-mcp.md:32-45 (restart-only `mcp` block),
docs/development/native-mcp.md:45-82 (finite policy table, linked from
docs/user/agent-integration/native-mcp.md:147-148 as "finite limits").
"""

import threading
import time

import pytest

from fakes import nat_wire as w
from fakes.nat_env import native_target, put_connection, register

case = pytest.mark.case
STD = "agent.ANY./mcp/{name}"
CMP = "agent.ANY./mcp/{name}/compact"
LIMITS = "beh.native.limits"
PATH = "/mcp/natlim"
PATHS = (PATH, PATH + "/compact")
EXTERNAL = "locksmith.qa.example:9443"
ORIGIN = "https://app.qa.example"
LIMITED = {
    "allowed_hosts": ["127.0.0.1", EXTERNAL],
    "allowed_origins": [ORIGIN],
    "sessions_per_agent": 1,
    "messages": 4,
    "request_ms": 1500,
    "ingress": 2,
    "request_bytes": 4096,
}


@pytest.fixture(scope="module")
def env(target_factory):
    target, fake = native_target(target_factory, "nat-limits", mcp=LIMITED)
    try:
        put = put_connection(target, fake.url, "natlim", compact=True)
        assert put.code == 0, put.err
        yield {"t": target, "fake": fake}
    finally:
        fake.close()


def init(env, agent, extra=None, host=True):
    headers = [w.auth(agent["token"]), *w.POST_HEADERS, *(extra or [])]
    return w.send(env["t"], "POST", PATH, headers, w.INIT, host=host)


def close(env, agent, reply):
    s = w.Session(env["t"], agent["token"], PATH)
    s.id = reply.session
    assert s.delete().status == 202


@case("SMK-NAT-050", area="NAT", kind="positive", covers=[STD, LIMITS])
def test_configured_host_and_origin_are_admitted(env):
    """`allowed_hosts` names the listener authority; a present Origin must exactly match `allowed_origins`.

    docs/user/operator/native-mcp.md:32-44; docs/user/agent-integration/native-mcp.md:144-145.
    """
    agent = register(env["t"], "nat-lim-allowed", "natlim")
    by_host = init(env, agent, [("Host", EXTERNAL)], host=False)
    assert by_host.status == 200, by_host.text
    close(env, agent, by_host)
    by_origin = init(env, agent, [("Origin", ORIGIN)])
    assert by_origin.status == 200, by_origin.text
    close(env, agent, by_origin)


@case(
    "SMK-NAT-051",
    area="NAT",
    kind="refusal",
    covers=[STD, LIMITS],
    codes=["host_denied", "origin_denied"],
)
def test_configured_allowlists_are_exact(env):
    """A specified Host port must match; a configured list replaces the loopback default;
    Origin scheme and port matter, with no wildcards.

    docs/user/operator/native-mcp.md:40-44.
    """
    agent = register(env["t"], "nat-lim-denied", "natlim")
    before = env["fake"].snapshot()
    for host in (
        "locksmith.qa.example:9444",
        f"localhost:{env['t'].port}",
        "other.qa.example",
    ):
        reply = init(env, agent, [("Host", host)], host=False)
        assert reply.status == 403, host
        assert reply.code == "host_denied", host
    for origin in (
        "https://app.qa.example:8443",
        "http://app.qa.example",
        "https://sub.app.qa.example",
    ):
        reply = init(env, agent, [("Origin", origin)])
        assert reply.status == 403, origin
        assert reply.code == "origin_denied", origin
    assert env["fake"].snapshot() == before


@case(
    "SMK-NAT-052",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP, LIMITS],
    codes=["session_limit"],
)
def test_per_agent_session_limit_is_429_with_retry_after(env):
    """429 is finite capacity with `Retry-After: 1`; close your session before requesting another.
    Standard and compact routes share the same agent session limits.

    docs/user/agent-integration/native-mcp.md:137-138; docs/user/operator/native-mcp.md:127;
    docs/user/agent-integration/compact-mcp.md:14-15; docs/development/native-mcp.md:54 (`sessions_per_agent`).
    """
    t = env["t"]
    agent = register(t, "nat-lim-sessions", "natlim")
    before = env["fake"].snapshot()
    for path in PATHS:
        first = w.Session(t, agent["token"], path).open()
        for other in PATHS:
            second = w.send(t, "POST", other, [w.auth(agent["token"]), *w.POST_HEADERS], w.INIT)
            assert second.status == 429, (path, other)
            assert second.headers.get("retry-after") == "1", (path, other)
            assert second.code == "session_limit", (path, other)
        assert first.delete().status == 202
        third = w.Session(t, agent["token"], path).open()
        assert third.delete().status == 202
    assert env["fake"].snapshot() == before


@case(
    "SMK-NAT-053",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP, LIMITS],
    codes=["request_body_limit"],
)
def test_lowered_request_bytes_is_413(env):
    """`request_bytes` may be lowered; an oversized body is 413.

    docs/development/native-mcp.md:47-49, :63; docs/user/agent-integration/native-mcp.md:135.
    """
    agent = register(env["t"], "nat-lim-body", "natlim")
    body = (
        b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"'
        + b"x" * 5000
        + b'"}}'
    )
    for path in PATHS:
        reply = w.send(env["t"], "POST", path, [w.auth(agent["token"]), *w.POST_HEADERS], body)
        assert reply.status == 413, path
        assert reply.code == "request_body_limit", path


@case(
    "SMK-NAT-054",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP, LIMITS],
    codes=["request_deadline"],
)
def test_stalled_body_hits_total_request_deadline(env):
    """One original ingress deadline spans auth/body; 408 is the total request deadline.

    docs/user/agent-integration/native-mcp.md:137, :172-173; docs/development/native-mcp.md:61.
    """
    agent = register(env["t"], "nat-lim-deadline", "natlim")
    for path in PATHS:
        started = time.monotonic()
        sock = w.stalled_post(env["t"], path, agent["token"])
        try:
            reply = w.read_reply(env["t"], sock)
        finally:
            sock.close()
        elapsed = time.monotonic() - started
        assert reply.status == 408, path
        assert reply.code == "request_deadline", path
        assert 1.0 <= elapsed < 5.0, f"{path}: deadline after {elapsed:.2f}s for request_ms 1500"


@case(
    "SMK-NAT-055",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP, LIMITS],
    codes=["ingress_limit"],
)
def test_ingress_capacity_is_429(env):
    """`ingress` bounds concurrent HTTP operations including body waits; 429 with Retry-After: 1.

    docs/development/native-mcp.md:52; docs/user/agent-integration/native-mcp.md:137-138.
    """
    agent = register(env["t"], "nat-lim-ingress", "natlim")
    held = [w.stalled_post(env["t"], path, agent["token"]) for path in PATHS]
    try:
        time.sleep(0.3)
        replies = [w.send(env["t"], "POST", path, [w.auth(agent["token"]), *w.POST_HEADERS], w.INIT)
                   for path in PATHS]
    finally:
        for sock in held:
            sock.close()
    for reply in replies:
        assert reply.status == 429
        assert reply.headers.get("retry-after") == "1"
        assert reply.code == "ingress_limit"


@case("SMK-NAT-056", area="NAT", kind="corner", covers=[STD, LIMITS])
def test_session_message_budget_exhaustion_is_429(env):
    """Request IDs and SDK messages are finite per session; exhaustion is 429 with Retry-After: 1.

    docs/user/agent-integration/native-mcp.md:67-70; docs/development/native-mcp.md:56.
    With `messages: 4`, initialize + initialized + two pings fill the budget.
    """
    agent = register(env["t"], "nat-lim-messages", "natlim")
    s = w.Session(env["t"], agent["token"], PATH).open()
    assert s.call("ping").status == 200
    assert s.call("ping").status == 200
    over = s.call("ping")
    assert over.status == 429
    assert over.headers.get("retry-after") == "1"
    s.delete()


@case(
    "SMK-NAT-057",
    area="NAT",
    kind="refusal",
    covers=[STD, CMP, LIMITS, "beh.shutdown.drain"],
    codes=["shutting_down"],
)
def test_in_flight_request_at_shutdown_is_503(target_factory):
    """503 includes shutdown; shutdown rejects new ingress and cancels native work.

    docs/user/agent-integration/native-mcp.md:138; docs/user/operator/native-mcp.md:123-124;
    docs/development/native-mcp.md:72-74.
    """
    t, fake = native_target(target_factory, "nat-shutdown")
    try:
        assert put_connection(t, fake.url, "natlim", compact=True).code == 0
        agent = register(t, "nat-shutdown-agent", "natlim")
        socks = [w.stalled_post(t, path, agent["token"]) for path in PATHS]
        time.sleep(0.3)
        codes = []
        stopper = threading.Thread(target=lambda: codes.append(t.stop()))
        stopper.start()
        try:
            replies = [w.read_reply(t, sock) for sock in socks]
        finally:
            for sock in socks:
                sock.close()
            stopper.join(timeout=30)
        for reply in replies:
            assert reply.status == 503
            assert reply.code == "shutting_down"
        assert codes == [0]
        assert fake.snapshot()["counts"] == {}
    finally:
        fake.close()


@case("SMK-NAT-058", area="NAT", kind="refusal", covers=[LIMITS])
def test_out_of_range_mcp_config_refuses_startup(target_factory):
    """Defaults are maximums; they may be lowered but never set to zero; lists hold at most 16 entries.

    docs/development/native-mcp.md:47-49, :80; docs/user/operator/native-mcp.md:32.
    """
    t = target_factory(label="nat-badconfig", upstream=False)
    t.stop()
    bad = [
        {"mcp": {"sessions": 0}},
        {"mcp": {"request_ms": 10001}},
        {"mcp": {"allowed_hosts": []}},
        {"mcp": {"allowed_origins": ["https://*.qa.example"]}},
        {"mcp": {"allowed_hosts": [f"h{i}.qa.example" for i in range(17)]}},
    ]
    for overlay in bad:
        t.overlay = overlay
        result = t.run_daemon_once()
        assert result.returncode == 1, overlay
        assert "MCP" in result.stdout + result.stderr, overlay  # refused for the mcp block, not another reason
