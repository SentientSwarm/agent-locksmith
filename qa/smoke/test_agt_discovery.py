"""Agent discovery surfaces: /skill, /tools, /models
(docs/user/agent-integration/wire-contract.md "Endpoints")."""

import pytest

from fakes.agt_support import enrol, put_tool
from fakes.agt_upstream import Upstream

case = pytest.mark.case
WIRE = "docs/user/agent-integration/wire-contract.md"
BAD_BEARER = "lk_qaAgtNotARealPublicId0.not-a-real-secret-value-for-agt-cases-00"


@pytest.fixture(scope="module")
def disc(target_factory):
    up = Upstream()
    t = target_factory(label="agt-discovery", upstream=False)
    for name in ("agt-d-tool1", "agt-d-tool2"):
        put_tool(t, name, f"{up.url}/{name}")
    for name in ("agt-d-model1", "agt-d-model2"):
        put = t.cli(
            "model",
            "put",
            name,
            "--upstream",
            f"{up.url}/{name}",
            "--auth",
            "none",
            "--metadata",
            "modality=text",
            "--metadata",
            "provider=qa",
        )
        assert put.code == 0, put.err
    agent = enrol(
        t,
        "qa-agt-discovery",
        ["agt-d-tool1", "agt-d-model1"],
        {"agt-d-tool1": ["--no-auth"], "agt-d-model1": ["--no-auth"]},
    )
    yield t, agent
    up.close()


@case("SMK-AGT-001", area="AGT", kind="positive", covers=["agent.GET./skill"])
def test_skill_generic_without_bearer(disc):
    """wire-contract.md:76-90 — no bearer returns the generic form, same for every
    requester, `Cache-Control: public, max-age=86400`, text/markdown."""
    t, _ = disc
    first, second = t.http("GET", "/skill"), t.http("GET", "/skill")
    assert first.status == 200
    assert first.headers.get("cache-control") == "public, max-age=86400"
    assert first.headers.get("content-type", "").startswith("text/markdown")
    assert first.text == second.text
    for name in ("agt-d-tool1", "agt-d-tool2", "agt-d-model1"):
        assert name not in first.text, "generic /skill leaked a catalog entry"


@case("SMK-AGT-002", area="AGT", kind="positive", covers=["agent.GET./skill"])
def test_skill_personalised_with_bearer(disc):
    """wire-contract.md:76-90 — a valid bearer returns the personalised catalog of the
    agent's ACL-eligible tools with `Cache-Control: private, no-cache, no-store`."""
    t, agent = disc
    resp = t.http("GET", "/skill", token=agent["token"])
    assert resp.status == 200
    assert resp.headers.get("cache-control") == "private, no-cache, no-store"
    assert resp.headers.get("content-type", "").startswith("text/markdown")
    assert "agt-d-tool1" in resp.text
    assert "agt-d-tool2" not in resp.text, (
        "personalised /skill lists a tool outside the ACL"
    )


@case(
    "SMK-AGT-003",
    area="AGT",
    kind="refusal",
    covers=["agent.GET./skill"],
    codes=["invalid_credential"],
)
def test_skill_invalid_bearer_is_401(disc):
    """src/app.rs skill route + wire-contract.md:76 + error-envelope.md:22 — a present but
    invalid bearer is 401 invalid_credential, never a silent downgrade to generic."""
    t, _ = disc
    resp = t.http("GET", "/skill", token=BAD_BEARER)
    assert resp.status == 401
    assert resp.code == "invalid_credential"


@case("SMK-AGT-004", area="AGT", kind="positive", covers=["agent.GET./tools"])
def test_tools_is_acl_filtered_tool_kind_only(disc):
    """wire-contract.md:95-117 — /tools returns ONLY kind=tool entries the agent's allowlist
    permits; active DB entries report activation active and credential_readiness not_checked."""
    t, agent = disc
    resp = t.http("GET", "/tools", token=agent["token"])
    assert resp.status == 200
    tools = {e["name"]: e for e in resp.json["tools"]}
    assert set(tools) == {"agt-d-tool1"}
    entry = tools["agt-d-tool1"]
    assert entry["path"] == "/api/agt-d-tool1"
    assert entry["activation"] == "active"
    assert entry["credential_readiness"] == "not_checked"


@case(
    "SMK-AGT-005",
    area="AGT",
    kind="refusal",
    covers=["agent.GET./tools"],
    codes=["invalid_credential"],
)
def test_tools_without_bearer_is_401(disc):
    """wire-contract.md:9-11 — every endpoint except /livez, /readyz, /version, /skill needs a
    bearer; error-envelope.md:22 missing bearer is 401 invalid_credential."""
    t, _ = disc
    resp = t.http("GET", "/tools")
    assert resp.status == 401
    assert resp.code == "invalid_credential"


@case("SMK-AGT-006", area="AGT", kind="positive", covers=["agent.GET./models"])
def test_models_is_acl_filtered_model_kind_only(disc):
    """wire-contract.md:119-134 — same shape as /tools but kind=model only, ACL-filtered."""
    t, agent = disc
    resp = t.http("GET", "/models", token=agent["token"])
    assert resp.status == 200
    assert {e["name"] for e in resp.json["models"]} == {"agt-d-model1"}


@case(
    "SMK-AGT-007",
    area="AGT",
    kind="refusal",
    covers=["agent.GET./models"],
    codes=["invalid_credential"],
)
def test_models_wrong_bearer_is_401(disc):
    """error-envelope.md:22 — any bearer failure is a uniform 401 invalid_credential."""
    t, _ = disc
    resp = t.http("GET", "/models", token=BAD_BEARER)
    assert resp.status == 401
    assert resp.code == "invalid_credential"
