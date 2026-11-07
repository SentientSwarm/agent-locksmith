"""Agent listener in auth_mode mtls: certificate identity maps to an agent.

Docs: docs/v2/runbooks/m6-mtls-onboarding.md (§2-§6), m6-mtls-migration.md
(stage B and failure modes), docs/user/cli-reference.md:91. Identity is the
CN, else the first SAN DNS, else the first SAN URI (CLAUDE.md agent listener;
`locksmith agent set-cert-identity --help`: "CN, SAN_DNS, or SAN_URI string").
"""

import pytest

from fakes.pki import CA
from fakes.tls_pki import (
    accounts_tool,
    client_context,
    enrol,
    https,
    mtls_failures,
    nameless_client,
    now_ms,
    server_files,
    wait_for,
)

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
IDENTITY = "beh.mtls.identity"
SET_ID = [
    "cli.agent.set-cert-identity",
    "admin.PATCH./admin/operator/agents/{public_id}/cert_identity",
]


@pytest.fixture(scope="module")
def pki():
    ca = CA.create("qa-tls-agents-ca")
    return {"ca": ca, "server": ca.server(), "foreign": CA.create("qa-tls-foreign-ca")}


@pytest.fixture(scope="module")
def mt(target_factory, pki):
    files = {}

    def overlay(work):
        files.update(server_files(work, pki["ca"], pki["server"], "agent"))
        return {
            "listen": {
                "auth_mode": "mtls",
                "mtls": {
                    "ca_bundle_path": files["ca"],
                    "server_cert_path": files["cert"],
                    "server_key_path": files["key"],
                },
            }
        }

    target = target_factory(config=overlay, label="tls-mtls")
    accounts_tool(target)
    ca = pki["ca"]
    return {
        "t": target,
        "ca_path": files["ca"],
        "cn": (
            enrol(target, "qa-tls-cn", "SMOKE_X", "qa-tls-cn.agent"),
            ca.client("qa-tls-cn.agent"),
        ),
        "dns": (
            enrol(target, "qa-tls-dns", "SMOKE_Y", "dns-agent.qa.internal"),
            nameless_client(ca, dns=("dns-agent.qa.internal",)),
        ),
        "uri": (
            enrol(target, "qa-tls-uri", "SMOKE_X", "spiffe://qa.internal/agent-uri"),
            nameless_client(ca, uris=("spiffe://qa.internal/agent-uri",)),
        ),
    }


def call(mt, cert, name, token=None):
    ctx = client_context(mt["t"], mt["ca_path"], cert, name)
    return https(mt["t"], "GET", "/api/accounts/check", mt["t"].port, ctx, token=token)


def mtls_proxy_row(t, agent_id, since):
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
    return [r for r in rows.json or [] if r.get("auth_method") == "mtls"]


def assert_reaches_as(mt, key, account):
    t = mt["t"]
    agent, cert = mt[key]
    before, since = t.upstream_counts(), now_ms()
    response, refused = call(mt, cert, key)
    assert refused is None, refused
    assert response.status == 200, response.text
    assert response.text == account, (
        "the request was served under another agent's account"
    )
    after = t.upstream_counts()
    assert after[account] == before[account] + 1
    assert wait_for(lambda: mtls_proxy_row(t, agent["id"], since), 5), (
        "no auth_method=mtls proxy audit row for the agent"
    )


@case(
    "SMK-TLS-001",
    area="TLS",
    kind="positive",
    covers=[IDENTITY, API, *SET_ID, "cli.agent.get"],
)
def test_cn_identity_maps_to_agent(mt):
    """m6-mtls-onboarding.md:49,76-82,113-123: the CN bound with set-cert-identity
    authenticates the agent; `agent get` carries cert_identity; audit shows mtls."""
    shown = mt["t"].cli("agent", "get", mt["cn"][0]["id"])
    assert shown.code == 0, shown.err
    assert shown.json["cert_identity"] == "qa-tls-cn.agent"
    assert_reaches_as(mt, "cn", "X")


@case("SMK-TLS-002", area="TLS", kind="positive", covers=[IDENTITY, API, *SET_ID])
def test_san_dns_identity_maps_to_agent(mt):
    """m6-mtls-onboarding.md:49 "The CN (or SAN) becomes the cert_identity";
    a cert with no CN maps by its SAN DNS name."""
    assert_reaches_as(mt, "dns", "Y")


@case("SMK-TLS-003", area="TLS", kind="positive", covers=[IDENTITY, API, *SET_ID])
def test_san_uri_identity_maps_to_agent(mt):
    """`agent set-cert-identity --help`: identity may be a SAN_URI string; a cert with
    only a SAN URI maps by it."""
    assert_reaches_as(mt, "uri", "X")


@case("SMK-TLS-004", area="TLS", kind="corner", covers=[IDENTITY, API])
def test_cn_wins_over_san_dns(mt, pki):
    """Identity precedence CN -> SAN DNS -> SAN URI: a cert carrying the CN of one agent
    and the SAN DNS of another authenticates as the CN agent (account X, not Y)."""
    t = mt["t"]
    both = pki["ca"].client("qa-tls-cn.agent", dns=("dns-agent.qa.internal",))
    before = t.upstream_counts()
    response, refused = call(mt, both, "cn-and-dns")
    assert refused is None, refused
    assert response.status == 200
    assert response.text == "X"
    assert t.upstream_counts()["Y"] == before["Y"]


@case(
    "SMK-TLS-005",
    area="TLS",
    kind="refusal",
    covers=[IDENTITY, API],
    codes=["invalid_credential"],
)
def test_unbound_identity_is_401_and_audited(mt, pki):
    """m6-mtls-migration.md:93: a cert whose identity is bound to no agent fails
    authentication; the refusal is a 401 invalid_credential envelope and a security row."""
    t = mt["t"]
    before, since = t.upstream_counts(), now_ms()
    response, refused = call(mt, pki["ca"].client("qa-tls-unbound.agent"), "unbound")
    assert refused is None, refused
    assert response.status == 401
    assert response.code == "invalid_credential"
    assert t.upstream_counts() == before
    rows = wait_for(lambda: mtls_failures(t, since), 5)
    assert any(
        r["event"] == "mtls_unknown_identity" and r.get("decision") == "denied"
        for r in rows
    ), rows


@case(
    "SMK-TLS-006",
    area="TLS",
    kind="refusal",
    covers=[IDENTITY, API],
)
def test_bearer_without_cert_is_refused_at_handshake_in_mtls_mode(mt):
    """m6-mtls-migration.md (auth_mode mtls): the listener requires a client certificate
    during the TLS handshake, so a bearer-only client is refused before any HTTP exchange
    and nothing reaches the upstream."""
    t = mt["t"]
    before = t.upstream_counts()
    ctx = client_context(t, mt["ca_path"])
    response, refused = https(
        t, "GET", "/api/accounts/check", t.port, ctx, token=mt["cn"][0]["token"]
    )
    assert response is None and refused is not None, "a bearer-only client got an HTTP response"
    assert "CERTIFICATE_REQUIRED" in refused.upper()
    assert t.upstream_counts() == before


@case(
    "SMK-TLS-007",
    area="TLS",
    kind="refusal",
    covers=[IDENTITY, API],
)
def test_foreign_ca_cert_is_refused_at_handshake(mt, pki):
    """m6-mtls-migration.md: a cert issued by a CA outside ca_bundle_path is refused during
    the TLS handshake (unknown CA): no HTTP response, no upstream request, and no audit row,
    because no request reached locksmith."""
    t = mt["t"]
    before, since = t.upstream_counts(), now_ms()
    response, refused = call(mt, pki["foreign"].client("qa-tls-cn.agent"), "foreign")
    assert response is None and refused is not None, "a foreign-CA cert got an HTTP response"
    assert "UNKNOWN_CA" in refused.upper()
    assert t.upstream_counts() == before
    assert mtls_failures(t, since) == []


@case(
    "SMK-TLS-008",
    area="TLS",
    kind="refusal",
    covers=[IDENTITY, API, *SET_ID],
    codes=["invalid_credential"],
)
def test_cleared_identity_no_longer_authenticates(mt, pki):
    """m6-mtls-onboarding.md:82-86: `set-cert-identity --clear` removes the binding;
    the agent's cert then no longer authenticates."""
    t = mt["t"]
    agent = enrol(t, "qa-tls-cleared", "SMOKE_X", "qa-tls-cleared.agent")
    cert = pki["ca"].client("qa-tls-cleared.agent")
    first, refused = call(mt, cert, "cleared")
    assert refused is None and first.status == 200, refused or first.text
    clear = t.cli("agent", "set-cert-identity", agent["id"], "--clear")
    assert clear.code == 0, clear.err
    assert t.cli("agent", "get", agent["id"]).json.get("cert_identity") is None
    before = t.upstream_counts()
    response, refused = call(mt, cert, "cleared")
    assert refused is None, refused
    assert response.status == 401
    assert response.code == "invalid_credential"
    assert t.upstream_counts() == before
