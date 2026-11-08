"""Admin HTTPS listener (listen.admin_https) in bearer, mtls and both modes.

Docs: docs/v2/runbooks/m4-remote-management.md (bearer, CLI over --admin-url /
LOCKSMITH_ADMIN_URL with a CA bundle, bootstrap register without operator auth),
docs/v2/runbooks/m6-mtls-onboarding.md §5 (operator cert_identity in operators.yaml),
docs/user/architecture.md:195-201 (admin HTTPS picks bearer | mtls | both).
"""

import pytest

from fakes.pki import CA
from fakes.tls_pki import client_context, https, server_files
from harness.target import free_port

case = pytest.mark.case
LIST = "admin.GET./admin/operator/agents"
CREATE = "admin.POST./admin/operator/agents"
REGISTER = "admin.ANY./admin/agent/register"
OPERATOR_ID = "qa-operator@example.test"
WRONG_OP = "qa-wrong.not-a-real-operator-token"


def admin_target(target_factory, mode: str, label: str):
    """A daemon whose admin HTTPS listener runs in `mode`; operator `qa` has OPERATOR_ID."""
    ca = CA.create(f"qa-tls-admin-{mode}-ca")
    port = free_port()
    files = {}

    def overlay(work):
        files.update(server_files(work, ca, ca.server(), f"admin-{mode}"))
        block = {
            "enabled": True,
            "host": "127.0.0.1",
            "port": port,
            "auth_mode": mode,
            "cert_path": files["cert"],
            "key_path": files["key"],
        }
        if mode != "bearer":
            # m6-mtls-onboarding.md:99-107: add cert_identity to the operator's entry.
            ops = work / "operators.yaml"
            ops.write_text(
                ops.read_text().rstrip("\n") + f'\n    cert_identity: "{OPERATOR_ID}"\n'
            )
            block["mtls"] = {"ca_bundle_path": files["ca"]}
        return {"listen": {"admin_https": block}}

    target = target_factory(config=overlay, label=label)
    return {
        "t": target,
        "ca": ca,
        "port": port,
        "ca_path": files["ca"],
        "url": f"https://127.0.0.1:{port}",
    }


def remote(adm, *args, op_token=None, ca=True):
    """The CLI over admin HTTPS via LOCKSMITH_ADMIN_URL / LOCKSMITH_CA_BUNDLE (m4 §4)."""
    env = {"LOCKSMITH_ADMIN_URL": adm["url"]}
    if ca:
        env["LOCKSMITH_CA_BUNDLE"] = adm["ca_path"]
    return adm["t"].cli(*args, socket_flag=False, env=env, op_token=op_token)


def operator_ctx(adm, cn=OPERATOR_ID, name="operator"):
    return client_context(adm["t"], adm["ca_path"], adm["ca"].client(cn), name)


@pytest.fixture(scope="module")
def bearer(target_factory):
    return admin_target(target_factory, "bearer", "tls-admin-bearer")


@pytest.fixture(scope="module")
def mtls(target_factory):
    return admin_target(target_factory, "mtls", "tls-admin-mtls")


@pytest.fixture(scope="module")
def both(target_factory):
    return admin_target(target_factory, "both", "tls-admin-both")


@case("SMK-TLS-030", area="TLS", kind="positive", covers=[LIST, "cli.agent.list"])
def test_cli_over_https_env_matches_uds(bearer):
    """m4-remote-management.md:97-105,124,206-217: with LOCKSMITH_ADMIN_URL and
    LOCKSMITH_CA_BUNDLE the CLI runs over HTTPS and its JSON equals the UDS output."""
    t = bearer["t"]
    assert t.cli("agent", "register", "--name", "qa-tls-https-seen").code == 0
    over_https, over_uds = remote(bearer, "agent", "list"), t.cli("agent", "list")
    assert over_https.code == 0, over_https.err
    assert over_https.json == over_uds.json
    assert "qa-tls-https-seen" in over_https.out


@case("SMK-TLS-031", area="TLS", kind="positive", covers=[CREATE, "cli.agent.register"])
def test_cli_admin_url_flag_registers_over_https(bearer):
    """m4-remote-management.md:107-116: the --admin-url/--ca-bundle flag form routes the
    CLI over HTTPS; an agent registered that way exists for the UDS too."""
    t = bearer["t"]
    result = t.cli(
        "--admin-url",
        bearer["url"],
        "--ca-bundle",
        bearer["ca_path"],
        "agent",
        "register",
        "--name",
        "qa-tls-flag-form",
        socket_flag=False,
    )
    assert result.code == 0, result.err
    assert result.json["public_id"]
    assert "qa-tls-flag-form" in t.cli("agent", "list").out


@case(
    "SMK-TLS-032",
    area="TLS",
    kind="refusal",
    covers=[LIST, "cli.agent.list"],
    codes=["invalid_credential"],
)
def test_wrong_operator_token_over_https_is_401(bearer):
    """m4-remote-management.md:229: a wrong LOCKSMITH_OP_TOKEN gets 401 from the HTTPS
    endpoint; the CLI maps it to exit 3 (cli-reference.md exit codes)."""
    ctx = client_context(bearer["t"], bearer["ca_path"])
    response, refused = https(
        bearer["t"],
        "GET",
        "/admin/operator/agents",
        bearer["port"],
        ctx,
        token=WRONG_OP,
    )
    assert refused is None, refused
    assert response.status == 401
    assert response.code == "invalid_credential"
    cli = remote(bearer, "agent", "list", op_token=WRONG_OP)
    assert cli.code == 3
    assert "invalid_credential" in cli.err + cli.out


@case("SMK-TLS-033", area="TLS", kind="corner", covers=[LIST, "cli.agent.list"])
def test_cli_without_ca_bundle_refuses_private_cert(bearer):
    """m4-remote-management.md:118-120,226: without --ca-bundle the CLI uses the system
    roots, so a private-CA admin certificate is not trusted and the command fails."""
    result = remote(bearer, "agent", "list", ca=False)
    assert result.code == 1, result.err
    assert "qa-tls-https-seen" not in result.out


@case(
    "SMK-TLS-034", area="TLS", kind="positive", covers=[REGISTER, "cli.bootstrap.mint"]
)
def test_bootstrap_register_over_https_without_operator(bearer):
    """m4-remote-management.md:128-150: bootstrap-token register works over HTTPS with
    no operator credentials."""
    t = bearer["t"]
    mint = t.cli("bootstrap", "mint")
    assert mint.code == 0, mint.err
    ctx = client_context(t, bearer["ca_path"])
    response, refused = https(
        t,
        "POST",
        "/admin/agent/register",
        bearer["port"],
        ctx,
        body={"bootstrap_token": mint.json["token"], "name": "qa-tls-https-boot"},
    )
    assert refused is None, refused
    assert response.status == 200, response.text
    assert response.json["public_id"] and response.json["token"]


@case("SMK-TLS-035", area="TLS", kind="positive", covers=[LIST])
def test_operator_cert_authenticates_in_mtls_mode(mtls):
    """m6-mtls-onboarding.md:90-109: an operator cert whose identity is the operator's
    cert_identity in operators.yaml authenticates admin HTTPS without a bearer."""
    response, refused = https(
        mtls["t"], "GET", "/admin/operator/agents", mtls["port"], operator_ctx(mtls)
    )
    assert refused is None, refused
    assert response.status == 200, response.text


@case(
    "SMK-TLS-036",
    area="TLS",
    kind="refusal",
    covers=[LIST],
    codes=["invalid_credential"],
)
def test_unmapped_operator_cert_is_401(mtls):
    """m6-mtls-onboarding.md:99-109 (only a declared cert_identity maps to an operator):
    a CA-valid cert naming no operator gets 401 invalid_credential."""
    ctx = operator_ctx(mtls, "qa-not-an-operator@example.test", "not-operator")
    response, refused = https(
        mtls["t"], "GET", "/admin/operator/agents", mtls["port"], ctx
    )
    assert refused is None, refused
    assert response.status == 401
    assert response.code == "invalid_credential"


@case(
    "SMK-TLS-037",
    area="TLS",
    kind="refusal",
    covers=[LIST],
)
def test_missing_operator_cert_in_mtls_mode_is_refused(mtls):
    """architecture.md and m6-mtls-onboarding.md (admin HTTPS `auth_mode: mtls`): a client
    without a certificate is refused during the TLS handshake, even with a valid operator
    bearer, and gets no admin data."""
    t = mtls["t"]
    ctx = client_context(t, mtls["ca_path"])
    response, refused = https(
        t, "GET", "/admin/operator/agents", mtls["port"], ctx, token=t.op_token
    )
    assert response is None and refused is not None, "a client without a cert got an HTTP response"
    assert "CERTIFICATE_REQUIRED" in refused.upper()


@case("SMK-TLS-038", area="TLS", kind="positive", covers=[LIST, "cli.agent.list"])
def test_both_mode_accepts_cert_and_bearer(both):
    """architecture.md:199 (`both`) and m6-mtls-onboarding.md:109 ("operators can use
    either"): an operator cert alone and the CLI with a bearer and no cert both work."""
    response, refused = https(
        both["t"], "GET", "/admin/operator/agents", both["port"], operator_ctx(both)
    )
    assert refused is None, refused
    assert response.status == 200, response.text
    cli = remote(both, "agent", "list")
    assert cli.code == 0, cli.err


@case(
    "SMK-TLS-039",
    area="TLS",
    kind="refusal",
    covers=[LIST, "cli.agent.list"],
    codes=["invalid_credential"],
)
def test_both_mode_no_cert_wrong_bearer_is_401(both):
    """m4-remote-management.md:229 in `both` mode: no cert falls back to bearer and a wrong
    bearer is 401 invalid_credential (CLI exit 3)."""
    ctx = client_context(both["t"], both["ca_path"])
    response, refused = https(
        both["t"], "GET", "/admin/operator/agents", both["port"], ctx, token=WRONG_OP
    )
    assert refused is None, refused
    assert response.status == 401
    assert response.code == "invalid_credential"
    assert remote(both, "agent", "list", op_token=WRONG_OP).code == 3


def https_register(adm, token, name):
    ctx = client_context(adm["t"], adm["ca_path"])
    response, refused = https(
        adm["t"],
        "POST",
        "/admin/agent/register",
        adm["port"],
        ctx,
        body={"bootstrap_token": token, "name": name},
    )
    assert refused is None, refused
    return response


@case(
    "SMK-TLS-050",
    area="TLS",
    kind="refusal",
    covers=[REGISTER],
    codes=["invalid_credential"],
)
def test_https_register_wrong_secret_is_401(bearer):
    """m4-remote-management.md:128-150 with CHANGELOG.md:10-12: over admin HTTPS a token
    with the wrong secret is 401 invalid_credential and creates no agent."""
    t = bearer["t"]
    mint = t.cli("bootstrap", "mint")
    assert mint.code == 0, mint.err
    head, secret = mint.json["token"].split(".", 1)
    wrong = f"{head}.{secret[:-1]}{'A' if secret[-1] != 'A' else 'B'}"
    response = https_register(bearer, wrong, "qa-tls-https-squat")
    assert response.status == 401
    assert response.code == "invalid_credential"
    assert "qa-tls-https-squat" not in t.cli("agent", "list").out


@case(
    "SMK-TLS-051",
    area="TLS",
    kind="refusal",
    covers=[REGISTER],
    codes=["agent_name_conflict"],
)
def test_https_register_name_conflict_is_409(bearer):
    """m4-remote-management.md:128-150 (register works over HTTPS exactly as over UDS):
    a valid token registering a name in use gets 409 agent_name_conflict."""
    t = bearer["t"]
    mint = t.cli("bootstrap", "mint")
    assert mint.code == 0, mint.err
    response = https_register(bearer, mint.json["token"], "qa-tls-https-seen")
    assert response.status == 409
    assert response.code == "agent_name_conflict"
