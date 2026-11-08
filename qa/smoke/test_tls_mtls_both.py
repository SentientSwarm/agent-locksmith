"""Agent listener in auth_mode both: mTLS and bearer each authenticate.

Docs: docs/v2/runbooks/m6-mtls-migration.md:26-41 (stage A: "Now both bearer AND
mTLS work; either authenticates an agent"; audit auth_method shows which),
docs/user/architecture.md:195-201.
"""

import pytest

from fakes.pki import CA
from fakes.tls_pki import (
    accounts_tool,
    client_context,
    enrol,
    https,
    now_ms,
    server_files,
    wait_for,
)

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
IDENTITY = "beh.mtls.identity"


@pytest.fixture(scope="module")
def both(target_factory):
    ca = CA.create("qa-tls-both-ca")
    files = {}

    def overlay(work):
        files.update(server_files(work, ca, ca.server(), "both"))
        return {
            "listen": {
                "auth_mode": "both",
                "mtls": {
                    "ca_bundle_path": files["ca"],
                    "server_cert_path": files["cert"],
                    "server_key_path": files["key"],
                },
            }
        }

    target = target_factory(config=overlay, label="tls-both")
    accounts_tool(target)
    agent = enrol(target, "qa-tls-both", "SMOKE_X", "qa-tls-both.agent")
    return {"t": target, "ca": ca, "ca_path": files["ca"], "agent": agent}


def auth_methods(t, agent_id, since):
    rows = t.cli(
        "audit",
        "query",
        "--agent",
        agent_id,
        "--event-class",
        "proxy",
        "--since-ms",
        str(since),
    )
    assert rows.code == 0, rows.err
    return {r.get("auth_method") for r in rows.json or []}


def get(both, ctx, token=None):
    t = both["t"]
    return https(t, "GET", "/api/accounts/check", t.port, ctx, token=token)


@case("SMK-TLS-010", area="TLS", kind="positive", covers=[IDENTITY, API])
def test_bearer_without_cert_authenticates(both):
    """m6-mtls-migration.md:34: in `both`, an agent with no cert still authenticates
    with its bearer; the audit row records auth_method bearer."""
    t = both["t"]
    before, since = t.upstream_counts(), now_ms()
    response, refused = get(
        both, client_context(t, both["ca_path"]), both["agent"]["token"]
    )
    assert refused is None, refused
    assert response.status == 200
    assert response.text == "X"
    assert t.upstream_counts()["X"] == before["X"] + 1
    assert wait_for(lambda: "bearer" in auth_methods(t, both["agent"]["id"], since), 5)


@case("SMK-TLS-011", area="TLS", kind="positive", covers=[IDENTITY, API])
def test_cert_authenticates_in_both_mode(both):
    """m6-mtls-migration.md:34-41: in `both`, a bound cert authenticates the same agent
    and the audit row records auth_method mtls."""
    t = both["t"]
    before, since = t.upstream_counts(), now_ms()
    ctx = client_context(
        t, both["ca_path"], both["ca"].client("qa-tls-both.agent"), "both"
    )
    response, refused = get(both, ctx)
    assert refused is None, refused
    assert response.status == 200
    assert response.text == "X"
    assert t.upstream_counts()["X"] == before["X"] + 1
    assert wait_for(lambda: "mtls" in auth_methods(t, both["agent"]["id"], since), 5)


@case(
    "SMK-TLS-012",
    area="TLS",
    kind="refusal",
    covers=[IDENTITY, API],
    codes=["invalid_credential"],
)
def test_no_cert_wrong_bearer_is_401(both):
    """m6-mtls-migration.md:34 with cli-reference.md exit/HTTP semantics: in `both`
    with no cert the bearer path decides; a wrong bearer is 401 invalid_credential."""
    t = both["t"]
    before = t.upstream_counts()
    response, refused = get(
        both, client_context(t, both["ca_path"]), "qa-wrong.not-a-real-agent-token-000"
    )
    assert refused is None, refused
    assert response.status == 401
    assert response.code == "invalid_credential"
    assert t.upstream_counts() == before
