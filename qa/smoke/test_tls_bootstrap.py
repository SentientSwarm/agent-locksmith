"""Bootstrap-only enrolment listener (listen.bootstrap_only).

Docs: docs/v2/runbooks/m6-mtls-onboarding.md §4 and §7 (lines 61-86, 128-156) and
CHANGELOG.md 3.0.0 lines 5-12 (binds; needs admin_socket; host must be an IP;
port and certificate must be usable; the bootstrap secret is verified before the
agent is created).
"""

import socket
import subprocess

import pytest

from fakes.pki import CA
from fakes.tls_pki import client_context, https, server_files
from harness.target import free_port

case = pytest.mark.case
REGISTER = "bootstrap.POST./admin/agent/register"
LISTENER = "beh.bootstrap-listener"


def bootstrap_block(files, port, host="127.0.0.1"):
    return {
        "enabled": True,
        "host": host,
        "port": port,
        "cert_path": files["cert"],
        "key_path": files["key"],
    }


@pytest.fixture(scope="module")
def boot(target_factory):
    ca = CA.create("qa-tls-boot-ca")
    port = free_port()
    files = {}

    def overlay(work):
        files.update(server_files(work, ca, ca.server(), "boot"))
        return {"listen": {"bootstrap_only": bootstrap_block(files, port)}}

    target = target_factory(config=overlay, label="tls-bootstrap")
    ctx = client_context(target, files["ca"])
    return {"t": target, "port": port, "ctx": ctx}


def register(boot, token, name):
    response, refused = https(
        boot["t"],
        "POST",
        "/admin/agent/register",
        boot["port"],
        boot["ctx"],
        body={"bootstrap_token": token, "name": name},
    )
    assert refused is None, refused
    return response


def mint(t, *flags):
    result = t.cli("bootstrap", "mint", *flags)
    assert result.code == 0, result.err
    return result.json["token"]


def wrong_secret(token: str) -> str:
    head, secret = token.split(".", 1)
    flipped = "A" if secret[-1] != "A" else "B"
    return f"{head}.{secret[:-1]}{flipped}"


def agent_names(t):
    listed = t.cli("agent", "list")
    assert listed.code == 0, listed.err
    return {a["name"] for a in listed.json}


@case(
    "SMK-TLS-040",
    area="TLS",
    kind="positive",
    covers=[REGISTER, LISTENER, "cli.bootstrap.mint"],
)
def test_bootstrap_listener_enrols_with_token(boot):
    """m6-mtls-onboarding.md:142-153 and CHANGELOG.md:5-7: the listener binds at startup,
    and a bootstrap token alone (no operator credential) registers an agent."""
    t = boot["t"]
    assert any(
        "bootstrap-only listener bound" in str(e.get("fields", {}).get("message"))
        for e in t.log_events()
    )
    response = register(boot, mint(t), "qa-tls-boot-a")
    assert response.status == 200, response.text
    assert response.json["public_id"] and response.json["token"]
    assert "qa-tls-boot-a" in agent_names(t)


@case(
    "SMK-TLS-041",
    area="TLS",
    kind="refusal",
    covers=[REGISTER, LISTENER],
    codes=["invalid_credential"],
)
def test_wrong_secret_is_401_and_creates_nothing(boot):
    """CHANGELOG.md:10-12: the bootstrap secret is verified before registration creates
    the agent, so a caller with only the token's public id cannot reserve a name. Wrong
    secret is 401 invalid_credential, no agent appears, and the real token still enrols
    under that name."""
    t = boot["t"]
    token = mint(t)
    response = register(boot, wrong_secret(token), "qa-tls-boot-squat")
    assert response.status == 401
    assert response.code == "invalid_credential"
    assert "qa-tls-boot-squat" not in agent_names(t)
    retry = register(boot, token, "qa-tls-boot-squat")
    assert retry.status == 200, retry.text


@case(
    "SMK-TLS-042",
    area="TLS",
    kind="refusal",
    covers=[REGISTER, LISTENER],
    codes=["agent_name_conflict"],
)
def test_name_conflict_is_409(boot):
    """m6-mtls-onboarding.md:128-153 with cli-reference.md exit code 5 (409 conflict): a
    valid token registering a name already in use gets 409 agent_name_conflict."""
    t = boot["t"]
    assert "qa-tls-boot-a" in agent_names(t)
    response = register(boot, mint(t), "qa-tls-boot-a")
    assert response.status == 409
    assert response.code == "agent_name_conflict"


@case(
    "SMK-TLS-043",
    area="TLS",
    kind="refusal",
    covers=[REGISTER, LISTENER],
    codes=["invalid_credential"],
)
def test_single_use_token_cannot_enrol_twice(boot):
    """m6-mtls-onboarding.md:66-73 and cli-reference.md:134 (mint is single-use unless
    --reusable): a consumed token is refused 401 and creates no second agent."""
    t = boot["t"]
    token = mint(t)
    assert register(boot, token, "qa-tls-boot-once").status == 200
    again = register(boot, token, "qa-tls-boot-twice")
    assert again.status == 401
    assert again.code == "invalid_credential"
    assert "qa-tls-boot-twice" not in agent_names(t)


@case("SMK-TLS-044", area="TLS", kind="corner", covers=[LISTENER])
def test_only_register_is_served(boot):
    """m6-mtls-onboarding.md:130,155: the listener accepts ONLY POST /admin/agent/register;
    every other path returns 404, even with a valid operator bearer."""
    t = boot["t"]
    for method, path in (
        ("GET", "/admin/operator/agents"),
        ("GET", "/livez"),
        ("POST", "/admin/agent/rotate"),
        ("GET", "/api/accounts/check"),
    ):
        response, refused = https(
            t, method, path, boot["port"], boot["ctx"], token=t.op_token
        )
        assert refused is None, refused
        assert response.status == 404, f"{method} {path} -> {response.status}"


@pytest.fixture(scope="module")
def offline(target_factory):
    """A stopped daemon whose config the startup-refusal cases rewrite."""
    ca = CA.create("qa-tls-boot-refusal-ca")
    target = target_factory(label="tls-bootstrap-refusals")
    target.stop()
    pem = server_files(target.work, ca, ca.server(), "refusal")
    return {"t": target, "files": pem}


def refuses_to_start(offline, overlay, expect):
    t = offline["t"]
    t.overlay = overlay
    try:
        proc = t.run_daemon_once(timeout=15)
    except subprocess.TimeoutExpired:
        pytest.fail("locksmithd started and kept running; expected a startup refusal")
    output = proc.stdout + proc.stderr
    assert proc.returncode != 0, output
    assert expect in output, output


@case(
    "SMK-TLS-045",
    area="TLS",
    kind="refusal",
    covers=[LISTENER],
    codes=[],
)
def test_bootstrap_without_admin_socket_refuses_to_start(offline):
    """m6-mtls-onboarding.md:142-145 and CHANGELOG.md:7-9: the listener needs
    listen.admin_socket; startup fails when it is missing."""
    block = bootstrap_block(offline["files"], free_port())
    refuses_to_start(
        offline,
        {"listen": {"admin_socket": None, "bootstrap_only": block}},
        "admin_socket",
    )


@case(
    "SMK-TLS-046",
    area="TLS",
    kind="refusal",
    covers=[LISTENER],
    codes=[],
)
def test_bootstrap_host_must_be_ip(offline):
    """m6-mtls-onboarding.md:143 ("`host` must be an IP address") and CHANGELOG.md:8."""
    block = bootstrap_block(offline["files"], free_port(), host="localhost")
    refuses_to_start(
        offline, {"listen": {"bootstrap_only": block}}, "must be an IP address"
    )


@case(
    "SMK-TLS-047",
    area="TLS",
    kind="refusal",
    covers=[LISTENER],
    codes=[],
)
def test_bootstrap_port_or_cert_unusable_refuses_to_start(offline):
    """m6-mtls-onboarding.md:144-145 and CHANGELOG.md:8-9: the daemon binds the port and
    loads the certificate at startup and refuses to start if either fails."""
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        block = bootstrap_block(offline["files"], taken.getsockname()[1])
        refuses_to_start(
            offline, {"listen": {"bootstrap_only": block}}, "bootstrap-only listener"
        )
    missing = {
        **offline["files"],
        "cert": str(offline["t"].work / "tls" / "absent.crt"),
    }
    block = bootstrap_block(missing, free_port())
    refuses_to_start(
        offline, {"listen": {"bootstrap_only": block}}, "bootstrap-only listener"
    )
