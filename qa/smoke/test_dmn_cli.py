"""Offline `bootstrap-operator` and global CLI behaviour (docs/user/cli-reference.md).

bootstrap-operator output holds a wire token and an argon2 hash, so it runs
through fakes.dmn_support.bootstrap_operator, which registers the token as a
canary and records a hash-free transcript.
"""

import re

import pytest
import yaml

from fakes.dmn_support import bootstrap_operator

case = pytest.mark.case
BOOT = "cli.bootstrap-operator"
LIST = "cli.agent.list"
WIRE = re.compile(r"lkop_([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)")


def operators(stdout: str) -> list:
    return yaml.safe_load(stdout)["operators"]


@case("SMK-DMN-070", area="DMN", kind="positive", covers=[BOOT])
def test_bootstrap_operator_writes_yaml_and_token_once(t1):
    """cli-reference.md:58-74: offline; operators.yaml content (argon2 hash, commented header by
    default) on stdout; the cleartext `lkop_<public_id>.<secret>` token on stderr only."""
    proc = bootstrap_operator(t1, "--name", "dmn-boot")
    assert proc.returncode == 0
    [entry] = operators(proc.stdout)
    assert entry["name"] == "dmn-boot"
    assert entry["token_hash"].startswith("$argon2")
    assert proc.stdout.lstrip().startswith("#"), (
        "default output has no YAML comment header"
    )
    tokens = WIRE.findall(proc.stderr)
    assert tokens and {pid for pid, _ in tokens} == {entry["public_id"]}
    assert all(secret not in proc.stdout for _, secret in tokens), (
        "token secret written to stdout"
    )
    assert not WIRE.search(proc.stdout)


@case("SMK-DMN-071", area="DMN", kind="positive", covers=[BOOT])
def test_bootstrap_operator_header_false(t1):
    """cli-reference.md:72-74: `--header false` omits the comment header for piping."""
    proc = bootstrap_operator(t1, "--name", "dmn-boot-bare", "--header", "false")
    assert proc.returncode == 0
    assert not [
        line for line in proc.stdout.splitlines() if line.lstrip().startswith("#")
    ]
    assert operators(proc.stdout)[0]["name"] == "dmn-boot-bare"


@case("SMK-DMN-072", area="DMN", kind="corner", covers=[BOOT])
def test_bootstrap_operator_header_false_from_help(t1):
    """`locksmith bootstrap-operator --help` (--header): "pass `--header false` for a minimal
    output"; cli-reference.md (`--header true|false`)."""
    help_text = t1.cli("bootstrap-operator", "--help", use_op_token=False, socket_flag=False, fmt=None)
    assert "--header false" in help_text.out, "help does not name the minimal-output form"
    proc = bootstrap_operator(t1, "--header", "false")
    assert proc.returncode == 0, f"--header false refused with exit {proc.returncode}"
    assert not [
        line for line in proc.stdout.splitlines() if line.lstrip().startswith("#")
    ]


@case("SMK-DMN-073", area="DMN", kind="refusal", covers=[BOOT])
def test_bootstrap_operator_bad_header_value_is_usage_error(t1):
    """cli-reference.md:71 (`--header true|false`) and cli-reference.md:314 (exit 2 = usage error)."""
    proc = bootstrap_operator(t1, "--header", "maybe")
    assert proc.returncode == 2
    assert "maybe" in proc.stderr
    assert not WIRE.search(proc.stderr + proc.stdout), (
        "a credential was minted on a usage error"
    )


@case("SMK-DMN-074", area="DMN", kind="refusal", covers=[LIST])
def test_build_info_with_a_command_is_usage_error(t1):
    """build-identity.md:3-9: --build-info prints identity without contacting a daemon;
    cli-reference.md:314: misuse is exit 2."""
    result = t1.cli("--build-info", "agent", "list", fmt=None, socket_flag=False)
    assert result.code == 2
    assert "--build-info" in result.err and "cannot be combined" in result.err


@case("SMK-DMN-075", area="DMN", kind="refusal", covers=["cli.agent.register"])
def test_missing_required_flag_is_usage_error(t1):
    """cli-reference.md:79,314: `agent register --name` is required; a missing flag is exit 2."""
    before = t1.cli("agent", "list")
    result = t1.cli("agent", "register")
    assert result.code == 2
    assert "--name" in result.err
    assert t1.cli("agent", "list").json == before.json


@case("SMK-DMN-076", area="DMN", kind="refusal", covers=[LIST])
def test_bad_format_value_is_usage_error(t1):
    """cli-reference.md:14,314: `--format` is table/json/yaml; bad input is exit 2."""
    result = t1.cli("--format", "xml", "agent", "list", fmt=None)
    assert result.code == 2
    assert "xml" in result.err


@case("SMK-DMN-077", area="DMN", kind="positive", covers=[LIST])
def test_locksmith_socket_env_selects_admin_socket(t1):
    """`locksmith --help` (--socket): falls back to LOCKSMITH_SOCKET, then the system default."""
    result = t1.cli(
        "agent", "list", socket_flag=False, env={"LOCKSMITH_SOCKET": str(t1.socket)}
    )
    assert result.code == 0, result.err
    assert isinstance(result.json, list)


@case("SMK-DMN-078", area="DMN", kind="corner", covers=[LIST])
def test_socket_flag_wins_over_env(t1):
    """`locksmith --help` (--socket): the flag is used first; LOCKSMITH_SOCKET is only a fallback."""
    result = t1.cli(
        "agent", "list", env={"LOCKSMITH_SOCKET": str(t1.work / "absent.sock")}
    )
    assert result.code == 0, result.err


@case("SMK-DMN-079", area="DMN", kind="refusal", covers=[LIST])
def test_missing_operator_token_is_exit_3(t1):
    """cli-reference.md:18,315: operator commands read LOCKSMITH_OP_TOKEN; missing credentials are exit 3."""
    result = t1.cli("agent", "list", use_op_token=False)
    assert result.code == 3
    assert "LOCKSMITH_OP_TOKEN" in result.err


@case("SMK-DMN-080", area="DMN", kind="refusal", covers=[LIST])
def test_daemon_not_running_is_transport_exit_1(t1):
    """cli-reference.md:312: transport errors are exit 1 (admin socket absent: daemon not running)."""
    absent = t1.work / "not-running.sock"
    result = t1.cli(
        "agent", "list", socket_flag=False, env={"LOCKSMITH_SOCKET": str(absent)}
    )
    assert result.code == 1
    assert "transport" in result.err


@case("SMK-DMN-081", area="DMN", kind="refusal", covers=["cli.mtls.revoke"])
def test_mtls_revoke_without_blocklist_path_is_usage_error(t1):
    """`locksmith mtls revoke --help` (--blocklist-path is required) and cli-reference.md:314."""
    result = t1.cli("mtls", "revoke", "0a1b2c", use_op_token=False, fmt=None)
    assert result.code == 2
    assert "--blocklist-path" in result.err


@case("SMK-DMN-082", area="DMN", kind="refusal", covers=["cli.mtls.list-blocklist"])
def test_mtls_list_blocklist_without_path_is_usage_error(t1):
    """`locksmith mtls list-blocklist --help` (--blocklist-path is required) and cli-reference.md:314."""
    result = t1.cli("mtls", "list-blocklist", use_op_token=False, fmt=None)
    assert result.code == 2
    assert "--blocklist-path" in result.err
