"""Broker routes (brokered routes phase 3): a destination that picks the account.

Docs: docs/user/cli-reference.md "Broker routes". Locksmith sends the route's
broker key and the caller's identity, never an agent's own credential; agents
select the route with `--broker`; a broker that fails its health probe answers
503 backend_unavailable without dispatch.
"""

import time

import pytest

from fakes.agt_support import audit, enrol, put_tool, sealing_key
from fakes.agt_upstream import Reply, Upstream
from fakes.cat_uds import uds

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
READY = "agent.GET./readyz"
TOOL_PUT = "admin.PUT./admin/operator/tools/{name}"
TOOL_GET = "admin.GET./admin/operator/tools/{name}"
TOOL_KEY = "admin.PUT./admin/operator/tools/{name}/credential"
MODEL_PUT = "admin.PUT./admin/operator/models/{name}"
MODEL_KEY = "admin.PUT./admin/operator/models/{name}/credential"
BIND = "admin.PUT./admin/operator/agents/{public_id}/credentials/{registration}"
BACKEND_PUT = "admin.PUT./admin/operator/routes/{route}/backends/{backend}"
BACKEND_KEY = "admin.PUT./admin/operator/routes/{route}/backends/{backend}/credential"
SWITCH = "admin.POST./admin/operator/routes/{route}/switch"
# Synthetic, never a real credential; records holding it stay in memory.
KEY = "brk-synthetic-broker-key-0001"
KEY2 = "brk-synthetic-broker-key-0002"


@pytest.fixture(scope="module")
def brk(target_factory):
    up = Upstream()
    t = target_factory(
        label="brk-brokers",
        upstream=False,
        env={"LOCKSMITH_CREDENTIAL_SEALING_KEY": sealing_key()},
    )
    yield {"t": t, "up": up}
    up.close()


def broker_tool(t, name, upstream, *flags):
    put_tool(t, name, upstream, "none", "--egress", "direct", "--broker", *flags)
    key = t.cli("tool", "set-key", name, stdin=KEY)
    assert key.code == 0, key.err
    assert KEY not in key.out


def wait_health(t, name, status, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        got = t.cli("tool", "get", name)
        if (got.json or {}).get("health") and got.json["health"]["status"] == status:
            return got.json["health"]
        time.sleep(0.5)
    raise AssertionError(f"{name} never reported health {status}")


@case(
    "SMK-BRK-001",
    area="BRK",
    kind="positive",
    covers=[
        API,
        TOOL_PUT,
        TOOL_KEY,
        MODEL_PUT,
        MODEL_KEY,
        BIND,
        "beh.broker.key",
        "cli.tool.put",
        "cli.tool.set-key",
        "cli.model.put",
        "cli.model.set-key",
        "cli.agent.set-credential",
    ],
)
def test_broker_key_and_identity_are_injected(brk):
    """The broker receives the route's sealed key as a bearer and the caller's public id
    in X-Locksmith-Agent; audit records auth_mode broker without the key."""
    t, up = brk["t"], brk["up"]
    broker_tool(t, "brk-pool", up.url)
    agent = enrol(t, "qa-brk", ["brk-pool"], {"brk-pool": ["--broker"]})
    brk["agent"] = agent
    assert t.http("GET", "/api/brk-pool/v1/models", token=agent["token"]).status == 200
    sent = up.last("/v1/models")
    assert sent.header("authorization") == f"Bearer {KEY}", "broker key not injected"
    assert sent.header("x-locksmith-agent") == agent["id"]
    row = audit(t, "brk-pool", "proxy_request")[0]
    assert row["details"]["auth_mode"] == "broker"
    assert row["details"]["broker_key_mode"] == "stored_bearer"
    assert KEY not in str(row)
    model = t.cli(
        "model",
        "put",
        "brk-mpool",
        "--upstream",
        up.url,
        "--auth",
        "none",
        "--egress",
        "direct",
        "--broker",
    )
    assert model.code == 0, model.err
    key = t.cli("model", "set-key", "brk-mpool", "--header", "X-Pool-Key", stdin=KEY2)
    assert key.code == 0, key.err
    got = t.cli("model", "get", "brk-mpool").json
    assert (
        got["auth"]["kind"] == "stored_header" and got["auth"]["header"] == "X-Pool-Key"
    )
    assert got["broker"]["identity_header"] == "X-Locksmith-Agent"
    assert KEY2 not in str(got)


@case(
    "SMK-BRK-002",
    area="BRK",
    kind="positive",
    covers=[API, "beh.broker.identity"],
)
def test_agent_identity_header_is_replaced(brk):
    """An agent cannot name another caller: its own X-Locksmith-Agent and Authorization
    are stripped and replaced."""
    t, up, agent = brk["t"], brk["up"], brk["agent"]
    r = t.http(
        "GET",
        "/api/brk-pool/v1/spoof",
        token=agent["token"],
        headers={"X-Locksmith-Agent": "someone-else"},
    )
    assert r.status == 200
    sent = up.last("/v1/spoof")
    assert sent.headers["x-locksmith-agent"] == [agent["id"]]
    assert sent.header("authorization") == f"Bearer {KEY}"


@case(
    "SMK-BRK-003",
    area="BRK",
    kind="refusal",
    covers=[
        BIND,
        API,
        TOOL_PUT,
        TOOL_KEY,
        MODEL_PUT,
        MODEL_KEY,
        BACKEND_PUT,
        BACKEND_KEY,
        "cli.tool.put",
    ],
    codes=[
        "tool_not_allowed",
        "invalid_broker",
        "broker_kind_change",
        "grant_target_invalid",
    ],
)
def test_broker_refusals(brk):
    """An agent granted the route but not bound with --broker is refused before
    dispatch; invalid broker specs and kind changes are refused."""
    t, up = brk["t"], brk["up"]
    other = enrol(t, "qa-brk-unbound", ["brk-pool"], {})
    before = up.count("/v1/unbound")
    r = t.http("GET", "/api/brk-pool/v1/unbound", token=other["token"])
    assert r.status == 403 and r.code == "tool_not_allowed"
    assert up.count("/v1/unbound") == before, "a refused request reached the broker"
    wrong = t.cli("agent", "set-credential", other["id"], "brk-pool", "--no-auth")
    assert wrong.error_code == "grant_target_invalid", wrong.err
    bad = t.cli(
        "tool",
        "put",
        "brk-bad",
        "--upstream",
        up.url,
        "--auth",
        "none",
        "--egress",
        "direct",
        "--broker",
        "--health-path",
        "healthz",
    )
    assert bad.error_code == "invalid_broker", bad.err
    put_tool(t, "brk-plain", up.url, "none", "--egress", "direct")
    flip = t.cli(
        "tool",
        "put",
        "brk-plain",
        "--upstream",
        up.url,
        "--auth",
        "none",
        "--egress",
        "direct",
        "--broker",
    )
    assert flip.error_code == "broker_kind_change", flip.err
    grant = enrol(t, "qa-brk-plain", ["brk-plain"], {})
    wrong = t.cli("agent", "set-credential", grant["id"], "brk-plain", "--broker")
    assert wrong.error_code == "grant_target_invalid", wrong.err
    clash = uds(
        t,
        "PUT",
        "/admin/operator/tools/brk-pool/credential",
        {"value": KEY2, "header": "X-Locksmith-Agent"},
    )
    assert clash.status == 400 and clash.code == "invalid_broker"
    for body, code in (
        (
            {
                "upstream": up.url,
                "auth": {"kind": "none"},
                "egress": "direct",
                "broker": {"identity_header": "Authorization"},
            },
            "invalid_broker",
        ),
        (
            {"upstream": up.url, "auth": {"kind": "none"}, "egress": "direct"},
            "broker_kind_change",
        ),
    ):
        r = uds(t, "PUT", "/admin/operator/models/brk-mpool", body)
        assert r.status in (400, 409) and r.code == code, (code, r.status, r.text)
    r = uds(
        t,
        "PUT",
        "/admin/operator/models/brk-mpool/credential",
        {"value": KEY2, "header": "x-locksmith-agent"},
    )
    assert r.status == 400 and r.code == "invalid_broker"
    r = uds(
        t,
        "PUT",
        "/admin/operator/routes/brk-plain/backends/b",
        {"upstream": up.url, "auth": {"kind": "bearer", "env_var": "K"}, "broker": {}},
    )
    assert r.status == 400 and r.code == "invalid_broker"
    assert (
        uds(
            t,
            "PUT",
            "/admin/operator/routes/brk-plain/backends/b",
            {"upstream": up.url, "auth": {"kind": "none"}, "broker": {}},
        ).status
        == 200
    )
    r = uds(
        t,
        "PUT",
        "/admin/operator/routes/brk-plain/backends/b/credential",
        {"value": KEY2, "header": "x-locksmith-agent"},
    )
    assert r.status == 400 and r.code == "invalid_broker"


@case(
    "SMK-BRK-004",
    area="BRK",
    kind="positive",
    covers=[API, TOOL_PUT, "beh.broker.attribution"],
)
def test_attribution_label_reaches_audit(brk):
    """Editing the broker without --auth keeps its key. A configured response header
    naming the serving account is copied into audit as details.broker_account; it is
    still forwarded to the agent."""
    t, up, agent = brk["t"], brk["up"], brk["agent"]
    up.routes["/v1/attr"] = Reply(headers={"x-account-label": "acct-7"})
    put = t.cli(
        "tool",
        "put",
        "brk-pool",
        "--upstream",
        up.url,
        "--egress",
        "direct",
        "--broker",
        "--attribution-header",
        "x-account-label",
    )
    assert put.code == 0, put.err
    kept = t.cli("tool", "get", "brk-pool").json["auth"]
    assert kept["kind"] == "stored_bearer", (
        "editing a broker without --auth dropped its key"
    )
    r = t.http("GET", "/api/brk-pool/v1/attr", token=agent["token"])
    assert r.status == 200
    assert r.headers.get("x-account-label") == "acct-7"
    row = audit(t, "brk-pool", "proxy_request")[0]
    assert row["details"]["broker_account"] == "acct-7"


@case(
    "SMK-BRK-005",
    area="BRK",
    kind="refusal",
    covers=[API, READY, TOOL_GET, "beh.broker.health"],
    codes=["backend_unavailable"],
)
def test_down_broker_refuses_without_dispatch(brk):
    """A broker whose health probe fails answers 503 backend_unavailable and nothing
    reaches it; /readyz stays 200 and reports counts, never route names."""
    t = brk["t"]
    health = Upstream()
    try:
        health.routes["/healthz"] = Reply(status=200)
        broker_tool(
            t,
            "brk-health",
            health.url,
            "--health-path",
            "/healthz",
            "--health-interval",
            "5",
        )
        agent = enrol(t, "qa-brk-health", ["brk-health"], {"brk-health": ["--broker"]})
        wait_health(t, "brk-health", "up")
        assert health.last("/healthz").header("authorization") == f"Bearer {KEY}"
        assert t.http("GET", "/api/brk-health/v1/x", token=agent["token"]).status == 200
        health.routes["/healthz"] = Reply(status=500)
        got = wait_health(t, "brk-health", "down")
        assert got["http_status"] == 500
        before = health.count("/v1/")
        r = t.http("GET", "/api/brk-health/v1/x", token=agent["token"])
        assert r.status == 503 and r.code == "backend_unavailable"
        assert health.count("/v1/") == before, "a down broker received a request"
        ready = t.http("GET", "/readyz")
        assert ready.status == 200
        assert ready.json["brokers"]["down"] == 1
        assert "brk-health" not in ready.text
    finally:
        health.close()


@case(
    "SMK-BRK-006",
    area="BRK",
    kind="positive",
    covers=[
        API,
        BACKEND_PUT,
        BACKEND_KEY,
        SWITCH,
        "beh.broker.backend",
        "cli.route.backend.put",
        "cli.route.backend.set-credential",
        "cli.route.switch",
    ],
)
def test_switch_to_a_broker_backend_and_back(brk):
    """A route switched onto a broker backend never sends an upstream binding there;
    the agent binds --broker, the broker gets its own key, and switching back
    restores the upstream binding."""
    t = brk["t"]
    a, b = Upstream(), Upstream()
    try:
        put_tool(t, "brk-r", a.url, "none", "--egress", "direct")
        agent = enrol(t, "qa-brk-switch", ["brk-r"], {"brk-r": ["--no-auth"]})
        put = t.cli(
            "route",
            "backend",
            "put",
            "brk-r",
            "pool",
            "--upstream",
            b.url,
            "--auth",
            "none",
            "--egress",
            "direct",
            "--broker",
        )
        assert put.code == 0, put.err
        key = t.cli("route", "backend", "set-credential", "brk-r", "pool", stdin=KEY2)
        assert key.code == 0, key.err
        assert KEY2 not in key.out
        rev = t.cli("route", "backend", "list", "brk-r").json["revision"]
        out = t.cli(
            "route", "switch", "brk-r", "--backend", "pool", "--if-match", str(rev)
        )
        assert out.code == 0, out.err
        r = t.http("GET", "/api/brk-r/v1/m", token=agent["token"])
        assert r.status == 403 and b.count("/v1/") == 0
        bind = t.cli("agent", "set-credential", agent["id"], "brk-r", "--broker")
        assert bind.code == 0, bind.err
        assert t.http("GET", "/api/brk-r/v1/m", token=agent["token"]).status == 200
        sent = b.last("/v1/m")
        assert sent.header("authorization") == f"Bearer {KEY2}"
        assert sent.header("x-locksmith-agent") == agent["id"]
        rev = t.cli("route", "backend", "list", "brk-r").json["revision"]
        back = t.cli(
            "route", "switch", "brk-r", "--backend", "primary", "--if-match", str(rev)
        )
        assert back.code == 0, back.err
        assert t.http("GET", "/api/brk-r/v1/m", token=agent["token"]).status == 200
        assert a.last("/v1/m").header("authorization") is None
        assert a.last("/v1/m").header("x-locksmith-agent") is None
    finally:
        a.close()
        b.close()
