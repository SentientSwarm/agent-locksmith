"""Route backends (brokered routes phase 2): declare backends, switch a route.

Docs: docs/user/cli-reference.md "Route backends". A switch keeps grants,
moves bindings with the backend, and refuses stale revisions, OAuth backends,
native routes and the active backend.
"""

import pytest

from fakes.agt_support import enrol, put_tool
from fakes.agt_upstream import Upstream
from fakes.cat_uds import uds

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
LIST = "admin.GET./admin/operator/routes/{route}/backends"
GET = "admin.GET./admin/operator/routes/{route}/backends/{backend}"
PUT = "admin.PUT./admin/operator/routes/{route}/backends/{backend}"
DELETE = "admin.DELETE./admin/operator/routes/{route}/backends/{backend}"
SWITCH = "admin.POST./admin/operator/routes/{route}/switch"
BEH = "beh.route.backends"
BAD_OP = "lkop_qartebadoperator.not-a-real-operator-secret"
MCP_CONFIG = '{"protocol_version":"2025-11-25"}'


@pytest.fixture(scope="module")
def rte(target_factory):
    a, b = Upstream(), Upstream()
    t = target_factory(label="rte-backends", upstream=False)
    put_tool(t, "rte-r", a.url, "none", "--egress", "direct")
    agent = enrol(t, "qa-rte", ["rte-r"], {"rte-r": ["--no-auth"]})
    yield {"t": t, "a": a, "b": b, "agent": agent}
    a.close()
    b.close()


def revision(t, route="rte-r"):
    listed = t.cli("route", "backend", "list", route)
    assert listed.code == 0, listed.err
    return listed.json["revision"]


def switch(t, backend, route="rte-r"):
    return t.cli(
        "route", "switch", route, "--backend", backend, "--if-match", str(revision(t, route))
    )


@case(
    "SMK-RTE-001",
    area="RTE",
    kind="positive",
    covers=[
        API, BEH, LIST, GET, PUT, DELETE, SWITCH,
        "cli.route.backend.list", "cli.route.backend.get", "cli.route.backend.put",
        "cli.route.backend.delete", "cli.route.switch",
    ],
)
def test_switch_keeps_grant_and_moves_binding(rte):
    """A switch keeps the agent's grant; its binding stays with the old backend, so the
    first call after the switch is refused (403 tool_not_allowed, audit
    account_binding_missing) and nothing reaches the new backend. Binding on the new
    backend serves it; switching back restores the original binding."""
    t, a, b, agent = rte["t"], rte["a"], rte["b"], rte["agent"]
    assert t.http("GET", "/api/rte-r/ping", token=agent["token"]).status == 200
    assert a.count("/ping") == 1
    put = t.cli(
        "route", "backend", "put", "rte-r", "brk", "--upstream", b.url,
        "--auth", "none", "--egress", "direct",
    )
    assert put.code == 0, put.err
    got = t.cli("route", "backend", "get", "rte-r", "brk")
    assert got.code == 0 and got.json["upstream"] == b.url
    out = switch(t, "brk")
    assert out.code == 0, out.err
    assert (out.json["from"], out.json["to"]) == ("primary", "brk")
    assert out.json["bindings_stashed"] == 1
    refused = t.http("GET", "/api/rte-r/ping", token=agent["token"])
    assert refused.status == 403 and refused.code == "tool_not_allowed"
    assert b.count("/ping") == 0, "a refused request reached the new backend"
    bind = t.cli("agent", "set-credential", agent["id"], "rte-r", "--no-auth")
    assert bind.code == 0, bind.err
    assert t.http("GET", "/api/rte-r/ping", token=agent["token"]).status == 200
    assert b.count("/ping") == 1
    back = switch(t, "primary")
    assert back.code == 0, back.err
    assert back.json["bindings_restored"] == 1
    assert t.http("GET", "/api/rte-r/ping", token=agent["token"]).status == 200
    assert a.count("/ping") == 2
    rows = t.cli("audit", "query", "--tool", "rte-r", "--limit", "50").json
    switched = [r for r in rows if r.get("event") == "route_backend_switched"]
    assert len(switched) == 2 and switched[0]["event_class"] == "security"
    assert t.cli("route", "backend", "delete", "rte-r", "brk").code == 0
    assert t.cli("route", "backend", "get", "rte-r", "brk").code == 4


@case(
    "SMK-RTE-002", area="RTE", kind="refusal",
    covers=[LIST, GET, PUT, DELETE, SWITCH], codes=["invalid_credential"],
)
def test_backend_routes_require_an_operator(rte):
    """Every route backend endpoint is operator-authenticated."""
    t = rte["t"]
    for method, path, body in (
        ("GET", "/admin/operator/routes/rte-r/backends", None),
        ("GET", "/admin/operator/routes/rte-r/backends/x", None),
        ("PUT", "/admin/operator/routes/rte-r/backends/x", {"upstream": "https://x.example", "auth": {"kind": "none"}}),
        ("DELETE", "/admin/operator/routes/rte-r/backends/x", None),
        ("POST", "/admin/operator/routes/rte-r/switch", {"backend": "x"}),
    ):
        r = uds(t, method, path, body, token=BAD_OP)
        assert r.status == 401 and r.code == "invalid_credential", (method, path, r.status)


@case(
    "SMK-RTE-003", area="RTE", kind="refusal",
    covers=[LIST, GET, PUT, DELETE, SWITCH, "cli.route.backend.get"],
    codes=["unknown_name"],
)
def test_unknown_route_or_backend_is_404(rte):
    """A missing route or backend is 404 unknown_name (CLI exit 4)."""
    t = rte["t"]
    for method, path, body in (
        ("GET", "/admin/operator/routes/rte-none/backends", None),
        ("GET", "/admin/operator/routes/rte-r/backends/none", None),
        ("PUT", "/admin/operator/routes/rte-none/backends/x", {"upstream": "https://x.example", "auth": {"kind": "none"}}),
        ("DELETE", "/admin/operator/routes/rte-r/backends/none", None),
        ("POST", "/admin/operator/routes/rte-r/switch", {"backend": "none"}),
    ):
        headers = {"If-Match": str(revision(t))} if method == "POST" else None
        r = uds(t, method, path, body, headers=headers)
        assert r.status == 404 and r.code == "unknown_name", (method, path, r.status, r.text)
    assert t.cli("route", "backend", "get", "rte-r", "none").code == 4


@case(
    "SMK-RTE-004", area="RTE", kind="refusal",
    covers=[SWITCH, "cli.route.switch"], codes=["if_match_required", "revision_conflict"],
)
def test_switch_needs_the_current_revision(rte):
    """A switch without If-Match is 428; a stale revision is 409 and changes nothing."""
    t = rte["t"]
    r = uds(t, "POST", "/admin/operator/routes/rte-r/switch", {"backend": "primary"})
    assert r.status == 428 and r.code == "if_match_required"
    stale = t.cli("route", "switch", "rte-r", "--backend", "primary", "--if-match", "999999")
    assert stale.error_code == "revision_conflict", stale.err
    assert t.cli("route", "backend", "list", "rte-r").json["active_backend"] == "primary"


@case(
    "SMK-RTE-005", area="RTE", kind="refusal",
    covers=[PUT, DELETE, SWITCH], codes=["active_backend"],
)
def test_active_backend_cannot_be_replaced_deleted_or_reselected(rte):
    """The active backend is edited only through the route itself."""
    t = rte["t"]
    body = {"upstream": "https://x.example", "auth": {"kind": "none"}}
    r = uds(t, "PUT", "/admin/operator/routes/rte-r/backends/primary", body)
    assert r.status == 409 and r.code == "active_backend"
    r = uds(t, "DELETE", "/admin/operator/routes/rte-r/backends/primary")
    assert r.status == 409 and r.code == "active_backend"
    r = uds(
        t, "POST", "/admin/operator/routes/rte-r/switch", {"backend": "primary"},
        headers={"If-Match": str(revision(t))},
    )
    assert r.status == 409 and r.code == "active_backend"


@case(
    "SMK-RTE-006", area="RTE", kind="refusal",
    covers=[PUT, SWITCH], codes=["backend_auth_unsupported"],
)
def test_oauth_backends_are_refused(rte):
    """Phase 2 switches non-OAuth backends only: OAuth sessions are keyed by route."""
    t = rte["t"]
    oauth = {
        "kind": "oauth_device_code", "client_id": "qa", "scopes": [],
        "device_url": "https://o.example/device", "token_url": "https://o.example/token",
    }
    r = uds(t, "PUT", "/admin/operator/routes/rte-r/backends/o", {"upstream": "https://o.example", "auth": oauth})
    assert r.status == 409 and r.code == "backend_auth_unsupported"
    made = uds(t, "PUT", "/admin/operator/models/rte-oauth", {"upstream": "https://o.example", "auth": oauth, "egress": "direct"})
    assert made.status == 200, made.text
    put = uds(t, "PUT", "/admin/operator/routes/rte-oauth/backends/k", {"upstream": "https://k.example", "auth": {"kind": "none"}})
    assert put.status == 200, put.text
    r = uds(
        t, "POST", "/admin/operator/routes/rte-oauth/switch", {"backend": "k"},
        headers={"If-Match": str(revision(t, "rte-oauth"))},
    )
    assert r.status == 409 and r.code == "backend_auth_unsupported"


@case(
    "SMK-RTE-007", area="RTE", kind="refusal",
    covers=[LIST, GET, PUT, DELETE, SWITCH], codes=["route_not_switchable"],
)
def test_native_routes_are_not_switchable(rte, tmp_path):
    """Only HTTP tool/model routes have backends."""
    t = rte["t"]
    cfg = tmp_path / "mcp.json"
    cfg.write_text(MCP_CONFIG)
    put = t.cli(
        "tool", "put", "rte-native", "--upstream", "https://native.example/mcp", "--auth", "none",
        "--egress", "direct", "--protocol", "mcp_streamable_http", "--mcp-config-file", str(cfg),
    )
    assert put.code == 0, put.err
    for method, path, body in (
        ("GET", "/admin/operator/routes/rte-native/backends", None),
        ("GET", "/admin/operator/routes/rte-native/backends/x", None),
        ("PUT", "/admin/operator/routes/rte-native/backends/x", {"upstream": "https://x.example", "auth": {"kind": "none"}}),
        ("DELETE", "/admin/operator/routes/rte-native/backends/x", None),
        ("POST", "/admin/operator/routes/rte-native/switch", {"backend": "x"}),
    ):
        headers = {"If-Match": "1"} if method == "POST" else None
        r = uds(t, method, path, body, headers=headers)
        assert r.status == 409 and r.code == "route_not_switchable", (method, path, r.status)


@case(
    "SMK-RTE-008", area="RTE", kind="refusal",
    covers=[PUT, "cli.route.backend.put"],
    codes=["invalid_upstream", "invalid_name", "invalid_upstream_ca", "invalid_metadata"],
)
def test_backend_put_validates_like_a_route(rte):
    """A backend's destination and auth pass the same validation as a route PUT."""
    t = rte["t"]
    base = "/admin/operator/routes/rte-r/backends"
    none = {"kind": "none"}
    cases = (
        (f"{base}/x", {"upstream": "ftp://x.example", "auth": none}, "invalid_upstream"),
        (f"{base}/Bad%20Name", {"upstream": "https://x.example", "auth": none}, "invalid_name"),
        (f"{base}/x", {"upstream": "https://x.example", "auth": none, "upstream_ca_pem": "not a pem"}, "invalid_upstream_ca"),
        (f"{base}/x", {"upstream": "https://x.example", "auth": {"kind": "op_bearer", "reference": "not-op"}}, "invalid_metadata"),
    )
    for path, body, code in cases:
        r = uds(t, "PUT", path, body)
        assert r.status == 400 and r.code == code, (code, r.status, r.text)
    bad = t.cli("route", "backend", "put", "rte-r", "x", "--upstream", "ftp://x.example", "--auth", "none")
    assert bad.error_code == "invalid_upstream", bad.err
    assert t.cli("route", "backend", "get", "rte-r", "x").code == 4
