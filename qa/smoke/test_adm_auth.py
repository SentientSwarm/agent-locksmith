"""Admin-socket authentication refusals (docs/user/concepts/error-envelope.md,
docs/user/cli-reference.md exit codes)."""

import pytest

from fakes.adm_flows import BAD_AGENT, BAD_OPERATOR, agent_names, register, wrong_secret
from fakes.adm_uds import uds

case = pytest.mark.case
A = "/admin/operator/agents/{public_id}"
CRED = A + "/credentials/{registration}"
OPERATOR_ROUTES = [
    ("GET", "/admin/operator/agents"),
    ("POST", "/admin/operator/agents"),
    ("GET", A),
    ("PATCH", A),
    ("PATCH", A + "/cert_identity"),
    ("POST", A + "/revoke"),
    ("GET", A + "/credentials"),
    ("PUT", CRED),
    ("DELETE", CRED),
    ("PUT", CRED + "/credential"),
    ("GET", "/admin/operator/bootstrap_tokens"),
    ("POST", "/admin/operator/bootstrap_tokens"),
    ("POST", "/admin/operator/bootstrap_tokens/{public_id}/revoke"),
    ("GET", "/admin/operator/tools-legacy"),
    ("GET", "/admin/operator/tools"),
    ("GET", "/admin/operator/audit"),
    ("GET", "/admin/operator/logs"),
]
AGENT_ROUTES = [
    ("GET", "/admin/agent/status"),
    ("POST", "/admin/agent/rotate"),
    ("POST", "/admin/agent/deregister"),
    ("GET", "/admin/agent/tools"),
]
BODIES = {
    "POST /admin/operator/agents": {"name": "adm-sweep-created"},
    "PATCH " + A: {"allowlist": []},
    "PATCH " + A + "/cert_identity": {"cert_identity": "adm-sweep"},
    "PUT " + CRED: {"auth_spec": {"kind": "none"}},
    "PUT " + CRED + "/credential": {"value": "adm-sweep-value", "bearer": True},
    "POST /admin/operator/bootstrap_tokens": {},
    "POST /admin/agent/rotate": {"current_secret": "nope"},
}


def ids(routes):
    return [f"admin.{m}.{p}" for m, p in routes]


@pytest.fixture(scope="module")
def victim(t1):
    return register(t1, "adm-auth-victim")


def concrete(path, victim):
    return path.format(public_id=victim["id"], registration="accounts")


def sweep(t1, routes, tokens, victim):
    """Every (route, token) pair must be 401 invalid_credential."""
    wrong = []
    for method, path in routes:
        body = BODIES.get(f"{method} {path}")
        for token in tokens:
            r = uds(t1, method, concrete(path, victim), token=token, body=body)
            if (r.status, r.code) != (401, "invalid_credential"):
                wrong.append(f"{method} {path} -> {r.status} {r.code}")
    assert not wrong, wrong


@case(
    "SMK-ADM-001",
    area="ADM",
    kind="refusal",
    covers=ids(OPERATOR_ROUTES),
    codes=["invalid_credential"],
)
def test_operator_routes_refuse_missing_and_wrong_credentials(t1, victim):
    """Every operator admin route is operator-authenticated; a missing, malformed,
    wrong-secret or agent-namespace bearer is 401 invalid_credential
    (docs/user/concepts/error-envelope.md:23, cli-reference.md:18), and nothing changes."""
    tokens = [None, BAD_OPERATOR, wrong_secret(t1.op_token), victim["token"]]
    sweep(t1, OPERATOR_ROUTES, tokens, victim)
    assert "adm-sweep-created" not in agent_names(t1, include_revoked=True)
    got = t1.cli("agent", "get", victim["id"])
    assert got.code == 0 and got.json["revoked_at"] is None
    assert got.json["cert_identity"] is None


@case(
    "SMK-ADM-002",
    area="ADM",
    kind="refusal",
    covers=ids(AGENT_ROUTES),
    codes=["invalid_credential"],
)
def test_agent_routes_refuse_missing_wrong_and_operator_credentials(t1, victim):
    """Agent self-service routes take the agent's own bearer
    (cli-reference.md:295-303); missing, wrong, wrong-secret or operator tokens are
    401 invalid_credential (error-envelope.md:23) and the agent stays active."""
    tokens = [None, BAD_AGENT, wrong_secret(victim["token"]), t1.op_token]
    sweep(t1, AGENT_ROUTES, tokens, victim)
    status = uds(t1, "GET", "/admin/agent/status", token=victim["token"])
    assert status.status == 200, status.text


OPERATOR_CLI = [
    ("cli.agent.list", ["agent", "list"]),
    ("cli.agent.get", ["agent", "get", "{id}"]),
    ("cli.agent.modify", ["agent", "modify", "{id}", "--allowlist", "-"]),
    ("cli.agent.revoke", ["agent", "revoke", "{id}"]),
    (
        "cli.agent.set-cert-identity",
        ["agent", "set-cert-identity", "{id}", "adm-sweep"],
    ),
    (
        "cli.agent.set-credential",
        ["agent", "set-credential", "{id}", "accounts", "--no-auth"],
    ),
    ("cli.agent.unset-credential", ["agent", "unset-credential", "{id}", "accounts"]),
    ("cli.agent.credentials.list", ["agent", "credentials", "list", "{id}"]),
    ("cli.bootstrap.mint", ["bootstrap", "mint"]),
    ("cli.bootstrap.list", ["bootstrap", "list"]),
    ("cli.bootstrap.revoke", ["bootstrap", "revoke", "{id}"]),
    ("cli.audit.query", ["audit", "query"]),
    ("cli.export.agents", ["export", "agents"]),
]


@case(
    "SMK-ADM-003",
    area="ADM",
    kind="refusal",
    covers=[c for c, _ in OPERATOR_CLI],
    codes=["invalid_credential"],
)
def test_operator_cli_wrong_or_missing_token_exits_3(t1, victim):
    """A wrong operator token is an HTTP 401 → exit 3 with the daemon's
    invalid_credential code; an unset LOCKSMITH_OP_TOKEN is also exit 3
    (cli-reference.md:18, 305-316)."""
    wrong = []
    for cid, argv in OPERATOR_CLI:
        args = [a.format(id=victim["id"]) for a in argv]
        bad = t1.cli(*args, op_token=BAD_OPERATOR)
        if bad.code != 3 or bad.error_code != "invalid_credential":
            wrong.append(f"{cid} wrong token -> exit {bad.code} {bad.error_code}")
        unset = t1.cli(*args, use_op_token=False)
        if unset.code != 3:
            wrong.append(f"{cid} no token -> exit {unset.code}")
    assert not wrong, wrong
    assert t1.cli("agent", "get", victim["id"]).json["revoked_at"] is None


@case(
    "SMK-ADM-004",
    area="ADM",
    kind="refusal",
    covers=["cli.status", "cli.rotate"],
    codes=["invalid_credential"],
)
def test_self_service_cli_wrong_or_missing_agent_token_exits_3(t1, victim):
    """`status`/`rotate` take LOCKSMITH_AGENT_TOKEN (cli-reference.md:295-303); a wrong
    token is 401 → exit 3, a missing one exit 3 (cli-reference.md:314)."""
    for cmd in ("status", "rotate"):
        bad = t1.cli(cmd, use_op_token=False, agent_token=wrong_secret(victim["token"]))
        assert bad.code == 3, (cmd, bad.err)
        assert bad.error_code == "invalid_credential", (cmd, bad.err)
        assert t1.cli(cmd, use_op_token=False).code == 3
    ok = t1.cli("status", use_op_token=False, agent_token=victim["token"])
    assert ok.code == 0, (
        "the failed attempts must not have rotated or revoked the agent"
    )


@case(
    "SMK-ADM-005",
    area="ADM",
    kind="refusal",
    covers=["admin.GET./admin/operator/audit", "admin.GET./admin/agent/status"],
    codes=["invalid_credential"],
)
def test_admin_401_uses_the_uniform_envelope(t1):
    """Every authentication failure carries the three-field envelope
    {message, type: auth_error, code} (docs/user/concepts/error-envelope.md:3-17, 23)."""
    for path in ("/admin/operator/audit", "/admin/agent/status"):
        r = uds(t1, "GET", path)
        assert r.status == 401
        err = r.json["error"]
        assert err["code"] == "invalid_credential"
        assert err.get("message")
        assert err.get("type") == "auth_error", f"{path}: envelope lacks type: {err}"
