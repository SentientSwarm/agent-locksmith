"""Proxy hot path: header strip, selected-credential injection, query forwarding and
the /api refusals (docs/user/agent-integration/wire-contract.md, docs/user/architecture.md)."""

import shutil
import tempfile
from pathlib import Path

import pytest

from fakes.agt_support import CRED, HDR_CRED, audit, enrol, put_tool, write_seed
from fakes.agt_upstream import Reply, Upstream
from harness.target import free_port

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
STRIP = "beh.proxy.header-strip"
AGENT_X_API_KEY = "agt-agent-supplied-x-api-key-must-not-forward"


@pytest.fixture(scope="module")
def px(target_factory):
    up = Upstream()
    up.routes["/slow"] = Reply(delay=4.0)
    up.routes["/small/big"] = Reply(size=4096)
    seed_dir = Path(tempfile.mkdtemp(prefix="agt-seed-"))
    seed = write_seed(
        seed_dir,
        [
            {
                "name": "agt-seeded",
                "kind": "tool",
                "description": "qa seeded authless tool",
                "upstream": f"{up.url}/seeded",
                "auth": {"kind": "none"},
                "egress": "direct",
            }
        ],
    )
    env = {
        "AGT_CRED_TOKEN": CRED,
        "AGT_HDR_TOKEN": HDR_CRED,
        "AGT_EMPTY_TOKEN": "",
        "LOCKSMITH_SEED_PATH": str(seed),
    }
    t = target_factory(label="agt-proxy", upstream=False, env=env)
    t.canaries.add(AGENT_X_API_KEY, "agt-agent-x-api-key")
    put_tool(
        t,
        "agt-bearer",
        f"{up.url}/bearer",
        "bearer=AGT_CRED_TOKEN",
        "--egress",
        "direct",
    )
    put_tool(
        t,
        "agt-header",
        f"{up.url}/header",
        "header:X-Api-Key=AGT_HDR_TOKEN",
        "--egress",
        "direct",
    )
    for name, path in (
        ("agt-open", "open"),
        ("agt-unbound", "unbound"),
        ("agt-unset", "unset"),
        ("agt-empty", "empty"),
        ("agt-down", None),
    ):
        upstream = (
            f"http://127.0.0.1:{free_port()}" if path is None else f"{up.url}/{path}"
        )
        put_tool(t, name, upstream, "none", "--egress", "direct")
    put_tool(
        t,
        "agt-small",
        f"{up.url}/small",
        "none",
        "--egress",
        "direct",
        "--body-limit",
        "64",
    )
    put_tool(
        t,
        "agt-slow",
        f"{up.url}/slow",
        "none",
        "--egress",
        "direct",
        "--timeout-request",
        "1",
    )
    names = [
        "agt-bearer",
        "agt-header",
        "agt-open",
        "agt-unbound",
        "agt-unset",
        "agt-empty",
        "agt-down",
        "agt-small",
        "agt-slow",
        "agt-seeded",
    ]
    no_auth = ["--no-auth"]
    agent = enrol(
        t,
        "qa-agt-proxy",
        names,
        {
            "agt-bearer": ["--auth", "bearer=AGT_CRED_TOKEN"],
            "agt-header": ["--auth", "header=X-Api-Key:AGT_HDR_TOKEN"],
            "agt-open": no_auth,
            "agt-down": no_auth,
            "agt-small": no_auth,
            "agt-slow": no_auth,
            "agt-seeded": no_auth,
            "agt-unset": ["--auth", "bearer=AGT_NEVER_SET_TOKEN"],
            "agt-empty": ["--auth", "bearer=AGT_EMPTY_TOKEN"],
        },
    )
    yield t, up, agent
    up.close()
    shutil.rmtree(seed_dir, ignore_errors=True)


def audit_reason(t, tool: str, key: str) -> list:
    return [(r.get("details") or {}).get(key) for r in audit(t, tool)]


@case("SMK-AGT-010", area="AGT", kind="positive", covers=[API, STRIP])
def test_bearer_selected_credential_replaces_agent_auth(px):
    """wire-contract.md:155-180 — method, body, query string and path are forwarded; agent
    Authorization and x-api-key are stripped; only the selected `Authorization: Bearer
    <env value>` is injected; other headers forwarded as-is. README.md:102 query forwarding."""
    t, up, agent = px
    before = up.count("/bearer")
    resp = t.http(
        "POST",
        "/api/agt-bearer/v1/items?a=1&b=two",
        token=agent["token"],
        body={"probe": "agt-010"},
        headers={"X-Api-Key": AGENT_X_API_KEY, "X-QA-Trace": "agt-010"},
    )
    assert resp.status == 200
    assert up.count("/bearer") == before + 1
    rec = up.last("/bearer")
    assert rec.method == "POST"
    assert rec.path == "/bearer/v1/items?a=1&b=two"
    assert rec.json() == {"probe": "agt-010"}
    assert rec.headers.get("authorization") == [f"Bearer {CRED}"]
    assert "x-api-key" not in rec.headers
    assert rec.header("x-qa-trace") == "agt-010"


@case("SMK-AGT-011", area="AGT", kind="positive", covers=[API, STRIP])
def test_header_selected_credential_strips_agent_values(px):
    """wire-contract.md:155-176 — the target's own auth header (x-api-key) and the agent's
    Authorization are stripped; only `X-Api-Key: <selected env value>` reaches upstream."""
    t, up, agent = px
    resp = t.http(
        "GET",
        "/api/agt-header/ping",
        token=agent["token"],
        headers={"X-Api-Key": AGENT_X_API_KEY},
    )
    assert resp.status == 200
    rec = up.last("/header")
    assert rec.headers.get("x-api-key") == [HDR_CRED]
    assert "authorization" not in rec.headers


@case("SMK-AGT-012", area="AGT", kind="positive", covers=[API, STRIP])
def test_explicit_none_forwards_no_credentials(px):
    """wire-contract.md:155-176 — Authorization and x-api-key are stripped even when the
    selection is `none`, and nothing is injected."""
    t, up, agent = px
    resp = t.http(
        "GET",
        "/api/agt-open/ping?x=1",
        token=agent["token"],
        headers={"X-Api-Key": AGENT_X_API_KEY},
    )
    assert resp.status == 200
    rec = up.last("/open")
    assert rec.path == "/open/ping?x=1"
    assert "authorization" not in rec.headers
    assert "x-api-key" not in rec.headers


@case(
    "SMK-AGT-013",
    area="AGT",
    kind="refusal",
    covers=[API],
    codes=["tool_not_allowed", "account_binding_missing"],
)
def test_missing_binding_is_403_audited_account_binding_missing(px):
    """wire-contract.md:149-150,240-243 + error-envelope.md:24,85-90 — an allowed tool with no
    explicit binding denies 403 tool_not_allowed before dispatch; audit reason
    account_binding_missing."""
    t, up, agent = px
    before = up.count("/unbound")
    resp = t.http("GET", "/api/agt-unbound/ping", token=agent["token"])
    assert resp.status == 403
    assert resp.code == "tool_not_allowed"
    assert up.count("/unbound") == before, "a refused request reached the upstream"
    assert "account_binding_missing" in audit_reason(t, "agt-unbound", "reason")


@case(
    "SMK-AGT-014",
    area="AGT",
    kind="refusal",
    covers=[API],
    codes=["credential_unresolved", "selected_credential_unavailable"],
)
def test_selected_env_unset_is_503_without_dispatch(px):
    """wire-contract.md:151-152,229 + error-envelope.md:31 — an unavailable selected source is
    503 credential_unresolved with no alternate/default dispatch (the registration template
    here would resolve)."""
    t, up, agent = px
    before = up.count("/unset")
    resp = t.http("GET", "/api/agt-unset/ping", token=agent["token"])
    assert resp.status == 503
    assert resp.code == "credential_unresolved"
    assert up.count("/unset") == before, "a refused request reached the upstream"
    assert "selected_credential_unavailable" in audit_reason(
        t, "agt-unset", "credential_cause"
    )


@case(
    "SMK-AGT-015",
    area="AGT",
    kind="refusal",
    covers=[API],
    codes=["credential_unresolved", "selected_credential_unavailable"],
)
def test_selected_env_empty_is_503_without_dispatch(px):
    """error-envelope.md:31 — an empty selected environment value is unavailable: 503
    credential_unresolved, no dispatch."""
    t, up, agent = px
    before = up.count("/empty")
    resp = t.http("GET", "/api/agt-empty/ping", token=agent["token"])
    assert resp.status == 503
    assert resp.code == "credential_unresolved"
    assert up.count("/empty") == before, "a refused request reached the upstream"
    assert "selected_credential_unavailable" in audit_reason(
        t, "agt-empty", "credential_cause"
    )


@case(
    "SMK-AGT-016",
    area="AGT",
    kind="refusal",
    covers=[API, "cli.tool.delete"],
    codes=["tool_not_found"],
)
def test_disabled_registration_is_404(px):
    """architecture.md:57-61 — a disabled registration is 404 and never falls through;
    wire-contract.md:225 404 type not_found. cli-reference.md:162 delete disables a seed row."""
    t, up, agent = px
    assert t.http("GET", "/api/agt-seeded/ping", token=agent["token"]).status == 200
    delete = t.cli("tool", "delete", "agt-seeded")
    assert delete.code == 0, delete.err
    before = up.count("/seeded")
    resp = t.http("GET", "/api/agt-seeded/ping", token=agent["token"])
    assert resp.status == 404
    assert resp.json["error"]["type"] == "not_found"
    assert resp.code == "tool_not_found"
    assert up.count("/seeded") == before, "a refused request reached the upstream"


@case("SMK-AGT-017", area="AGT", kind="corner", covers=[API, "cli.tool.enable"])
def test_reenable_preserves_grant_and_selection(px):
    """getting-started.md:271-272 + cli-reference.md:161 — disable/re-enable preserves grants
    and account selections: the same bearer works again with no new grant or binding."""
    t, up, agent = px
    if t.cli("tool", "get", "agt-seeded").json.get("disabled") is not True:
        assert t.cli("tool", "delete", "agt-seeded").code == 0
    enable = t.cli("tool", "enable", "agt-seeded")
    assert enable.code == 0, enable.err
    before = up.count("/seeded")
    resp = t.http("GET", "/api/agt-seeded/again", token=agent["token"])
    assert resp.status == 200
    assert up.count("/seeded") == before + 1


@case("SMK-AGT-018", area="AGT", kind="refusal", covers=[API], codes=["bad_request"])
def test_request_body_over_limit_is_400(px):
    """wire-contract.md:212,226 400 bad_request; m7-response-controls.md:162 request-side
    limit is body_limit_bytes. No dispatch."""
    t, up, agent = px
    before = up.count("/small")
    resp = t.http(
        "POST",
        "/api/agt-small/upload",
        token=agent["token"],
        body=b"x" * 1000,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert resp.status == 400
    assert resp.json["error"]["type"] == "bad_request"
    assert up.count("/small") == before, "a refused request reached the upstream"


@case("SMK-AGT-019", area="AGT", kind="corner", covers=[API, "cli.tool.put"])
def test_body_limit_applies_to_requests_only(px):
    """cli-reference.md (`--body-limit`) and `tool put --help`: the limit is on the agent's
    request body; responses are bounded by response controls, not by `--body-limit`. A
    4096-byte upstream response is delivered whole under a 64-byte limit."""
    t, _, agent = px
    resp = t.http("GET", "/api/agt-small/big", token=agent["token"])
    assert resp.status == 200
    assert len(resp.text) == 4096


@case("SMK-AGT-020", area="AGT", kind="refusal", covers=[API], codes=["upstream_error"])
def test_unreachable_upstream_is_502(px):
    """wire-contract.md:212,227 — upstream unreachable is 502 type upstream_error."""
    t, _, agent = px
    resp = t.http("GET", "/api/agt-down/ping", token=agent["token"])
    assert resp.status == 502
    assert resp.json["error"]["type"] == "upstream_error"


@case(
    "SMK-AGT-021",
    area="AGT",
    kind="refusal",
    covers=[API, "cli.tool.put"],
    codes=["timeout"],
)
def test_slow_upstream_is_504_timeout(px):
    """wire-contract.md:212,228 — upstream slower than the configured timeout is 504 with
    type timeout and code timeout (cli-reference.md:178 `--timeout-request`)."""
    t, up, agent = px
    before = up.count("/slow")
    resp = t.http("GET", "/api/agt-slow/ping", token=agent["token"])
    assert resp.status == 504
    assert up.count("/slow") == before + 1, "the slow upstream never received the call"
    assert resp.json["error"]["type"] == "timeout"
    assert resp.code == "timeout"


@case(
    "SMK-AGT-022",
    area="AGT",
    kind="positive",
    covers=["agent.GET./readyz", "beh.readyz.semantics"],
)
def test_readyz_is_not_a_per_agent_probe(px):
    """wire-contract.md:49-61 + CLAUDE.md /readyz — readiness does not attest per-agent
    bindings: ready while a selected source is unavailable (503 at admission)."""
    t, _, agent = px
    assert t.http("GET", "/api/agt-unset/ping", token=agent["token"]).status == 503
    ready = t.http("GET", "/readyz")
    assert ready.status == 200
    assert ready.json["status"] == "ready"
