"""Readiness semantics (docs/reference/wire-contract.md#get-livez--liveness). Legacy mode, the
identityless deployment SMK-AGT-062..064 covered, was removed in 3.0.0
(AGENT-297); SMK-DMN-012 covers its refusal to start."""

import shutil
import tempfile
from pathlib import Path

import pytest

from fakes.agt_support import codex_seed, enrol, write_seed
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


@case(
    "SMK-AGT-060", area="AGT", kind="refusal", covers=[READY, SEM], codes=["not_ready"]
)
def test_readyz_unresolved_config_credential(unresolved):
    """docs/reference/wire-contract.md#get-readyz--readiness — a tool with auth whose credential is unresolved makes /readyz
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
    """docs/reference/wire-contract.md#error-envelope + docs/concepts/oauth-flow.md#per-request-hot-path — an OAuth registration on a daemon without
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
