"""Operator agent management over the admin socket (docs/user/cli-reference.md)."""

import pytest

from fakes.adm_flows import agent_names, register
from fakes.adm_uds import uds

case = pytest.mark.case
GET = "admin.GET./admin/operator/agents/{public_id}"
PATCH = "admin.PATCH./admin/operator/agents/{public_id}"
CERT = "admin.PATCH./admin/operator/agents/{public_id}/cert_identity"
REVOKE = "admin.POST./admin/operator/agents/{public_id}/revoke"
PRUNE = "admin.POST./admin/operator/revoked-agents/prune"
UNKNOWN = "adm-no-such-agent"


@pytest.fixture(scope="module")
def managed(t1, accounts):
    return register(t1, "adm-managed", allowlist=accounts)


def not_found(result):
    assert result.code == 4, (result.code, result.err)
    assert result.error_code == "agent_not_found", result.err


@case("SMK-ADM-010", area="ADM", kind="positive", covers=["cli.agent.get", GET])
def test_get_by_public_id_and_name_without_secrets(t1, managed):
    """`agent get <public_id>` shows one agent (cli-reference.md:81); the help accepts
    a name too. Reads never return the bearer or its hash
    (agent-identity-and-acl.md:13, cli-reference.md:93)."""
    by_id = t1.cli("agent", "get", managed["id"])
    assert by_id.code == 0, by_id.err
    assert by_id.json["public_id"] == managed["id"]
    assert by_id.json["name"] == "adm-managed"
    assert by_id.json["tool_allowlist"] == ["accounts"]
    assert by_id.json["revoked_at"] is None
    assert "cert_identity" in by_id.json
    assert managed["token"] not in by_id.out
    assert "hash" not in by_id.out
    by_name = t1.cli("agent", "get", "adm-managed")
    assert by_name.code == 0 and by_name.json["public_id"] == managed["id"]


@case(
    "SMK-ADM-011",
    area="ADM",
    kind="refusal",
    covers=["cli.agent.get", GET],
    codes=["agent_not_found"],
)
def test_get_unknown_agent_is_404_exit_4(t1):
    """Unknown agent → HTTP 404 → exit 4 (cli-reference.md:315; SPEC.md:2783 `404`)."""
    not_found(t1.cli("agent", "get", UNKNOWN))
    raw = uds(t1, "GET", f"/admin/operator/agents/{UNKNOWN}", token=t1.op_token)
    assert (raw.status, raw.code) == (404, "agent_not_found")


@case("SMK-ADM-012", area="ADM", kind="positive", covers=["cli.agent.modify", PATCH])
def test_modify_replaces_and_clears_allowlist_keeping_omitted_fields(
    t1, managed, accounts
):
    """`modify --allowlist` replaces the full set, `-` clears it, omitted fields stay
    unchanged (cli-reference.md:95-97)."""
    deny = t1.cli("agent", "modify", managed["id"], "--denylist", "elsewhere")
    assert deny.code == 0, deny.err
    clear = t1.cli("agent", "modify", managed["id"], "--allowlist", "-")
    assert clear.code == 0, clear.err
    got = t1.cli("agent", "get", managed["id"]).json
    assert got["tool_allowlist"] == []
    assert got["tool_denylist"] == ["elsewhere"], "omitted denylist must stay unchanged"
    again = t1.cli("agent", "modify", managed["id"], "--allowlist", accounts)
    assert again.code == 0, again.err
    assert t1.cli("agent", "get", managed["id"]).json["tool_allowlist"] == ["accounts"]


@case(
    "SMK-ADM-013",
    area="ADM",
    kind="refusal",
    covers=["cli.agent.modify", PATCH],
    codes=["agent_not_found"],
)
def test_modify_unknown_agent_is_exit_4(t1, accounts):
    """Unknown agent → HTTP 404 → exit 4 (cli-reference.md:315)."""
    not_found(t1.cli("agent", "modify", UNKNOWN, "--allowlist", accounts))


@case(
    "SMK-ADM-014",
    area="ADM",
    kind="refusal",
    covers=["cli.agent.modify", PATCH],
    codes=["grant_target_invalid"],
)
def test_modify_to_unknown_connection_is_refused_unchanged(t1, managed):
    """Allowlist names must be existing enabled tool/model registrations
    (cli-reference.md:95, per-agent-credentials.md:20-21); the policy is unchanged."""
    bad = t1.cli(
        "agent", "modify", managed["id"], "--allowlist", "accounts,adm-not-a-connection"
    )
    assert bad.code == 1, bad.err
    assert bad.error_code == "grant_target_invalid", bad.err
    assert t1.cli("agent", "get", managed["id"]).json["tool_allowlist"] == ["accounts"]


@case(
    "SMK-ADM-015",
    area="ADM",
    kind="positive",
    covers=["cli.agent.set-cert-identity", CERT],
)
def test_set_and_clear_cert_identity(t1, managed):
    """`set-cert-identity` binds an identity visible via `agent get`; `--clear` removes
    it (cli-reference.md:91, docs/v2/runbooks/m6-mtls-onboarding.md:76-86)."""
    bind = t1.cli("agent", "set-cert-identity", managed["id"], "adm-managed.qa.local")
    assert bind.code == 0, bind.err
    assert (
        t1.cli("agent", "get", managed["id"]).json["cert_identity"]
        == "adm-managed.qa.local"
    )
    clear = t1.cli("agent", "set-cert-identity", managed["id"], "--clear")
    assert clear.code == 0, clear.err
    assert t1.cli("agent", "get", managed["id"]).json["cert_identity"] is None


@case(
    "SMK-ADM-016",
    area="ADM",
    kind="refusal",
    covers=["cli.agent.set-cert-identity", CERT],
    codes=["agent_not_found"],
)
def test_cert_identity_unknown_agent_is_exit_4(t1):
    """Unknown agent → HTTP 404 → exit 4 (cli-reference.md:315)."""
    not_found(t1.cli("agent", "set-cert-identity", UNKNOWN, "adm-x.qa.local"))


@case(
    "SMK-ADM-017",
    area="ADM",
    kind="positive",
    covers=["cli.agent.revoke", REVOKE, "cli.agent.list"],
)
def test_revoke_hides_agent_and_rejects_its_bearer(t1):
    """`revoke` sets the row to revoked and subsequent calls 401
    (cli-reference.md:93-94); `list --include-revoked` still shows it."""
    doomed = register(t1, "adm-doomed")
    assert uds(t1, "GET", "/admin/agent/status", token=doomed["token"]).status == 200
    out = t1.cli("agent", "revoke", doomed["id"], "--reason", "qa")
    assert out.code == 0, out.err
    assert "adm-doomed" not in agent_names(t1)
    revoked = [
        a
        for a in t1.cli("agent", "list", "--include-revoked").json
        if a["name"] == "adm-doomed"
    ]
    assert revoked and revoked[0]["revoked_at"] is not None
    after = uds(t1, "GET", "/admin/agent/status", token=doomed["token"])
    assert (after.status, after.code) == (401, "invalid_credential")


@case(
    "SMK-ADM-018",
    area="ADM",
    kind="refusal",
    covers=["cli.agent.revoke", REVOKE],
    codes=["agent_not_found"],
)
def test_revoke_unknown_agent_is_exit_4(t1):
    """Unknown agent → HTTP 404 → exit 4 (cli-reference.md:315)."""
    not_found(t1.cli("agent", "revoke", UNKNOWN))


@case("SMK-ADM-019", area="ADM", kind="positive", covers=["cli.export.agents"])
def test_export_agents_is_a_secret_free_snapshot(t1, managed):
    """`export agents` emits a JSON snapshot of agent records for backup
    (cli-reference.md:278-286) with no secret material (SPEC.md:2789 "no cleartext")."""
    out = t1.cli("export", "agents")
    assert out.code == 0, out.err
    assert isinstance(out.json, list)
    assert managed["id"] in {a["public_id"] for a in out.json}
    assert managed["token"] not in out.out
    assert "hash" not in out.out and "argon2" not in out.out


@case(
    "SMK-ADM-067",
    area="ADM",
    kind="positive",
    covers=["cli.agent.revoke", REVOKE, "cli.agent.prune-revoked", PRUNE],
)
def test_revoke_removes_bindings_and_prune_finds_nothing(t1, accounts):
    """`revoke` removes the agent's account bindings and grants in the same write and
    audits the counts (#157); `prune-revoked` then finds nothing to remove, with or
    without `--dry-run`."""
    gone = register(t1, "adm-revoke-cascade", allowlist=accounts)
    bind = t1.cli("agent", "set-credential", gone["id"], accounts, "--no-auth")
    assert bind.code == 0, bind.err
    out = t1.cli("agent", "revoke", gone["id"])
    assert out.code == 0, out.err
    rows = t1.cli("audit", "query", "--agent", gone["id"], "--limit", "20").json
    revoked = [r for r in rows if r.get("event") == "agent_revoke"]
    assert revoked and revoked[0]["details"]["removed"]["bindings"] == 1
    assert revoked[0]["details"]["removed"]["grants"] == 1
    for flags in (["--dry-run"], []):
        pruned = t1.cli("agent", "prune-revoked", *flags)
        assert pruned.code == 0, pruned.err
        ids = [a["public_id"] for a in pruned.json["agents"]]
        assert gone["id"] not in ids
