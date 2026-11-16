"""Per-agent, per-route rate limits (AGENT-266).

Docs: docs/user/cli-reference.md "Rate limits". A route default applies to
each agent separately; over the limit the proxy answers 429 rate_limited
with Retry-After before anything is sent upstream. Limits change live.
"""

import pytest
from fakes.agt_support import audit, enrol, put_tool
from fakes.agt_upstream import Upstream
from fakes.cat_uds import uds

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
LIMIT = "beh.ratelimit"
LIST = "admin.GET./admin/operator/rate-limits"
PUT = "admin.PUT./admin/operator/rate-limits/{route}"
DELETE = "admin.DELETE./admin/operator/rate-limits/{route}"
BAD_OP = "lkop_qartebadoperator.not-a-real-operator-secret"


@pytest.fixture(scope="module")
def rl(target_factory):
    up = Upstream()
    t = target_factory(label="agt-rate-limit")
    put_tool(t, "agt-limited", f"{up.url}/x", "none")
    a = enrol(t, "qa-limit-a", ["agt-limited"], {"agt-limited": ["--no-auth"]})
    b = enrol(t, "qa-limit-b", ["agt-limited"], {"agt-limited": ["--no-auth"]})
    yield {"t": t, "up": up, "a": a, "b": b}
    up.close()


def call(rl, who):
    return rl["t"].http("GET", "/api/agt-limited/x", token=rl[who]["token"])


@case(
    "SMK-AGT-077",
    area="AGT",
    kind="positive",
    covers=[PUT, LIST, "cli.rate-limit.set", "cli.rate-limit.list", LIMIT],
)
def test_limit_is_set_and_listed(rl):
    """`rate-limit set` stores a route default; `rate-limit list` shows it."""
    t = rl["t"]
    put = t.cli("rate-limit", "set", "agt-limited", "--rpm", "1")
    assert put.code == 0, put.err
    listed = t.cli("rate-limit", "list")
    assert listed.code == 0, listed.err
    rows = listed.json["rate_limits"]
    assert rows == [
        {
            "route": "agt-limited",
            "agent": None,
            "requests_per_minute": 1,
            "max_concurrent": None,
            "updated_at": rows[0]["updated_at"],
        }
    ]


@case(
    "SMK-AGT-078",
    area="AGT",
    kind="refusal",
    covers=[API, LIMIT],
    codes=["rate_limited"],
)
def test_over_the_limit_is_429(rl):
    """Each agent gets its own bucket; over it the proxy answers 429 with
    Retry-After and nothing reaches the upstream."""
    t = rl["t"]
    assert call(rl, "a").status == 200
    sent = len(rl["up"].records)
    refused = call(rl, "a")
    assert refused.status == 429 and refused.code == "rate_limited"
    assert int(refused.header("Retry-After")) >= 1
    assert len(rl["up"].records) == sent
    assert call(rl, "b").status == 200
    assert audit(t, "agt-limited", "rate_limited")


@case("SMK-AGT-079", area="AGT", kind="positive", covers=[DELETE, "cli.rate-limit.unset"])
def test_unset_restores_unlimited(rl):
    """`rate-limit unset` removes the limit at once, without a restart."""
    t = rl["t"]
    unset = t.cli("rate-limit", "unset", "agt-limited")
    assert unset.code == 0, unset.err
    for _ in range(3):
        assert call(rl, "a").status == 200


@case(
    "SMK-AGT-080",
    area="AGT",
    kind="refusal",
    covers=[LIST, PUT, DELETE],
    codes=["invalid_credential"],
)
def test_rate_limits_require_an_operator(rl):
    """The rate-limit API is operator-authenticated."""
    t = rl["t"]
    for method, path, body in [
        ("GET", "/admin/operator/rate-limits", None),
        ("PUT", "/admin/operator/rate-limits/agt-limited", {"requests_per_minute": 1}),
        ("DELETE", "/admin/operator/rate-limits/agt-limited", None),
    ]:
        r = uds(t, method, path, body, token=BAD_OP)
        assert r.status == 401 and r.code == "invalid_credential", (method, r.status)


@case(
    "SMK-AGT-081",
    area="AGT",
    kind="refusal",
    covers=[PUT],
    codes=["invalid_rate_limit", "route_not_found", "agent_not_found"],
)
def test_bad_limits_are_refused(rl):
    """A zero limit, an unknown route or an unknown agent is refused."""
    t = rl["t"]
    zero = uds(t, "PUT", "/admin/operator/rate-limits/agt-limited", {"requests_per_minute": 0})
    assert zero.status == 400 and zero.code == "invalid_rate_limit"
    route = uds(t, "PUT", "/admin/operator/rate-limits/agt-nope", {"requests_per_minute": 1})
    assert route.status == 404 and route.code == "route_not_found"
    agent = uds(
        t,
        "PUT",
        "/admin/operator/rate-limits/agt-limited",
        {"requests_per_minute": 1, "agent": "qa-no-such-agent"},
    )
    assert agent.status == 404 and agent.code == "agent_not_found"
