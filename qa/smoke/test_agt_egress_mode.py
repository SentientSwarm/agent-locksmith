"""Egress enforcement mode and the published egress policy (AGENT-259 / 261 / 137).

Docs: docs/concepts/architecture.md step 8, config.example.yaml `egress`,
docs/reference/cli-reference.md "Egress policy". A proxied route with nothing
enforcing egress fails closed; `egress.mode: external` lets it connect
directly; the policy lists the hosts proxied routes reach.
"""

import pytest
import yaml
from fakes.agt_support import audit, enrol, put_tool
from fakes.agt_upstream import EgressProxy, Upstream
from fakes.cat_uds import uds

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
MODE = "beh.egress.enforcement"
POLICY = "admin.GET./admin/operator/egress/policy"
BAD_OP = "lkop_qartebadoperator.not-a-real-operator-secret"


@pytest.fixture(scope="module")
def em(target_factory):
    up, proxy = Upstream(), EgressProxy()
    none = target_factory(label="agt-egress-none", upstream=False)
    external = target_factory(
        label="agt-egress-external",
        upstream=False,
        config={"egress": {"mode": "external"}},
    )
    piped = target_factory(
        label="agt-egress-pipelock", upstream=False, config={"egress_proxy": proxy.url}
    )
    agents = {}
    for name, t in (("none", none), ("external", external), ("piped", piped)):
        put_tool(t, "agt-out", f"{up.url}/out", "none", "--egress", "proxied")
        # The piped target never calls agt-lan; a distinct host shows the
        # policy leaves direct routes out (AGENT-269).
        lan = up.url.replace("127.0.0.1", "localhost") if name == "piped" else up.url
        put_tool(t, "agt-lan", f"{lan}/lan", "none", "--egress", "direct")
        agents[name] = enrol(
            t,
            f"qa-egress-{name}",
            ["agt-out", "agt-lan"],
            {"agt-out": ["--no-auth"], "agt-lan": ["--no-auth"]},
        )
    yield {
        "none": none,
        "external": external,
        "piped": piped,
        "agents": agents,
        "up": up,
        "proxy_url": proxy.url,
    }
    up.close()
    proxy.close()


@case(
    "SMK-AGT-066",
    area="AGT",
    kind="refusal",
    covers=[API, MODE],
    codes=["egress_proxy_unconfigured"],
)
def test_proxied_route_without_proxy_fails_closed(em):
    """architecture.md step 8: with neither egress_proxy nor egress.mode, a proxied route
    answers 503 egress_proxy_unconfigured and never reaches the upstream."""
    t, up = em["none"], em["up"]
    before = up.count("/out")
    resp = t.http("GET", "/api/agt-out/ping", token=em["agents"]["none"]["token"])
    assert resp.status == 503 and resp.code == "egress_proxy_unconfigured"
    assert up.count("/out") == before, "a proxied route went direct"
    assert audit(t, "agt-out", "egress_unenforced"), "the refusal is audited"
    direct = t.http("GET", "/api/agt-lan/ping", token=em["agents"]["none"]["token"])
    assert direct.status == 200, "direct routes are unaffected"


@case("SMK-AGT-067", area="AGT", kind="positive", covers=[API, MODE])
def test_external_mode_connects_directly(em):
    """config.example.yaml `egress.mode: external`: the surrounding infrastructure enforces
    egress, so proxied routes connect directly."""
    t, up = em["external"], em["up"]
    before = up.count("/out")
    resp = t.http("GET", "/api/agt-out/ping", token=em["agents"]["external"]["token"])
    assert resp.status == 200
    assert up.count("/out") == before + 1


@case(
    "SMK-AGT-068",
    area="AGT",
    kind="positive",
    covers=[POLICY, MODE, "cli.egress.policy"],
)
def test_policy_lists_proxied_hosts(em):
    """cli-reference.md "Egress policy": hosts reached by proxied routes, the mode, and a
    Pipelock api_allowlist rendering; the proxy URL itself is not returned."""
    t = em["piped"]
    policy = t.cli("egress", "policy")
    assert policy.code == 0, policy.err
    assert policy.json["mode"] == "pipelock"
    assert policy.json["egress_proxy_set"] is True
    assert "egress_proxy" not in policy.json
    routes = [r for h in policy.json["hosts"] for r in h["routes"]]
    assert "agt-out" in routes and "agt-lan" not in routes
    rendered = t.cli("egress", "policy", "--pipelock", fmt=None)
    assert rendered.code == 0, rendered.err
    assert yaml.safe_load(rendered.out)["api_allowlist"] == ["127.0.0.1"]
    for out in (policy.out, rendered.out):
        assert em["proxy_url"] not in out, "the proxy URL was published"


@case(
    "SMK-AGT-069",
    area="AGT",
    kind="refusal",
    covers=[POLICY],
    codes=["invalid_credential"],
)
def test_policy_requires_an_operator(em):
    """The egress policy is operator-authenticated."""
    r = uds(em["piped"], "GET", "/admin/operator/egress/policy", None, token=BAD_OP)
    assert r.status == 401 and r.code == "invalid_credential"
