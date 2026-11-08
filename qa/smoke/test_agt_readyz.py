"""Readiness semantics and identityless legacy routes (docs/user/agent-integration/
wire-contract.md:49-61, docs/user/operator/account-binding-troubleshooting.md:9,
docs/user/concepts/per-agent-credentials.md:126)."""

import shutil
import tempfile
from pathlib import Path

import pytest

from fakes.agt_support import CRED, codex_seed, enrol, write_seed
from fakes.agt_upstream import Upstream

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
READY = "agent.GET./readyz"
SEM = "beh.readyz.semantics"


@pytest.fixture(scope="module")
def up():
    fake = Upstream()
    yield fake
    fake.close()


@pytest.fixture(scope="module")
def unresolved(target_factory, up):
    """Admin substrate on, one config tool whose credential env var is unset, and a seeded
    OAuth registration while LOCKSMITH_OAUTH_SEALING_KEY is absent."""
    seed_dir = Path(tempfile.mkdtemp(prefix="agt-seed-"))
    seed = write_seed(seed_dir, [codex_seed(up)])
    config = {
        "tools": [
            {
                "name": "agt-cfg-unres",
                "description": "qa unresolved config credential",
                "upstream": f"{up.url}/unres",
                "egress": "direct",
                "auth": {"header": "X-Api-Key", "value": {"from_env": {"var": "AGT_NEVER_SET_TOKEN"}}},
            }
        ]
    }
    t = target_factory(
        label="agt-unresolved",
        upstream=False,
        config=config,
        env={"LOCKSMITH_SEED_PATH": str(seed)},
    )
    yield t
    shutil.rmtree(seed_dir, ignore_errors=True)


@pytest.fixture(scope="module")
def legacy(target_factory, up):
    """No admin substrate: identityless legacy deployment with one credentialed and one
    explicitly authless config tool."""
    config = {
        "listen": {"admin_socket": None},
        "operator_credentials_path": None,
        "database": None,
        "tools": [
            {
                "name": "agt-legacy-cred",
                "description": "qa credentialed",
                "egress": "direct",
                "upstream": f"{up.url}/legacy-cred",
                "auth": {
                    "header": "Authorization",
                    "value": "Bearer ${AGT_CRED_TOKEN}",
                },
            },
            {
                "name": "agt-legacy-open",
                "description": "qa authless",
                "egress": "direct",
                "upstream": f"{up.url}/legacy-open",
            },
        ],
    }
    return target_factory(
        label="agt-legacy", upstream=False, config=config, env={"AGT_CRED_TOKEN": CRED}
    )


@case(
    "SMK-AGT-060", area="AGT", kind="refusal", covers=[READY, SEM], codes=["not_ready"]
)
def test_readyz_unresolved_config_credential(unresolved):
    """wire-contract.md:55-61 — a tool with auth whose credential is unresolved makes /readyz
    503 {status: not_ready, reason: tool_credentials_unresolved, tools: [...]}."""
    resp = unresolved.http("GET", "/readyz")
    assert resp.status == 503
    assert resp.json["status"] == "not_ready"
    assert resp.json["reason"] == "tool_credentials_unresolved"
    assert "agt-cfg-unres" in resp.json["tools"]


@case(
    "SMK-AGT-061",
    area="AGT",
    kind="refusal",
    covers=[API],
    codes=["oauth_sealing_key_unset"],
)
def test_oauth_selection_without_sealing_key_is_503(unresolved, up):
    """wire-contract.md:233 + oauth-flow.md:311 — an OAuth registration on a daemon without
    LOCKSMITH_OAUTH_SEALING_KEY is 503 oauth_sealing_key_unset, no dispatch."""
    agent = enrol(
        unresolved, "qa-agt-nokey", ["codex"], {"codex": ["--oauth-session", "default"]}
    )
    before = up.count("/backend-api")
    resp = unresolved.http(
        "POST", "/api/codex/responses", token=agent["token"], body={"input": []}
    )
    assert resp.status == 503
    assert resp.code == "oauth_sealing_key_unset"
    assert up.count("/backend-api") == before, "a refused request reached the upstream"


@case(
    "SMK-AGT-062", area="AGT", kind="refusal", covers=[READY, SEM], codes=["not_ready"]
)
def test_readyz_refuses_identityless_credentialed_setup(legacy):
    """account-binding-troubleshooting.md:9 + CLAUDE.md /readyz — /readyz diagnoses a
    credentialed identityless configuration (not ready, naming the tool)."""
    resp = legacy.http("GET", "/readyz")
    assert resp.status == 503
    assert resp.json["status"] == "not_ready"
    assert resp.json["reason"] == "agent_identity_required"
    assert resp.json["tools"] == ["agt-legacy-cred"]


@case(
    "SMK-AGT-063",
    area="AGT",
    kind="refusal",
    covers=[API],
    codes=["agent_identity_required"],
)
def test_identityless_call_to_credentialed_tool_is_401(legacy, up):
    """error-envelope.md:34 + wire-contract.md:230 + per-agent-credentials.md:126 — an
    identityless request to a credentialed registration is 401 agent_identity_required
    before dispatch."""
    before = up.count("/legacy-cred")
    resp = legacy.http("GET", "/api/agt-legacy-cred/ping")
    assert resp.status == 401
    assert resp.code == "agent_identity_required"
    assert resp.json["error"]["type"] == "auth_error"
    assert up.count("/legacy-cred") == before, "a refused request reached the upstream"


@case(
    "SMK-AGT-064", area="AGT", kind="positive", covers=[API, "beh.proxy.header-strip"]
)
def test_identityless_call_to_authless_tool_is_forwarded(legacy, up):
    """wire-contract.md:183-185 — only explicitly authless registrations are supported
    identityless; Authorization is stripped even for `auth: none` (wire-contract.md:163)."""
    before = up.count("/legacy-open")
    resp = legacy.http(
        "GET",
        "/api/agt-legacy-open/ping?z=9",
        headers={"Authorization": "Basic cWE6YWd0", "X-Api-Key": "agt-legacy-key"},
    )
    assert resp.status == 200
    assert up.count("/legacy-open") == before + 1
    rec = up.last("/legacy-open")
    assert rec.path == "/legacy-open/ping?z=9"
    assert "authorization" not in rec.headers
    assert "x-api-key" not in rec.headers
