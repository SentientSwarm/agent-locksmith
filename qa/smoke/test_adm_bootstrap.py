"""Bootstrap tokens and agent self-service over the admin socket
(docs/user/cli-reference.md:127-143, 295-303; docs/v2/SPEC.md:2769-2788)."""

import time

import pytest

from fakes.adm_flows import agent_names, mint, register, self_register, wrong_secret
from fakes.adm_uds import uds

case = pytest.mark.case
REGISTER = "admin.ANY./admin/agent/register"
MINT = "admin.POST./admin/operator/bootstrap_tokens"
LIST = "admin.GET./admin/operator/bootstrap_tokens"
REVOKE = "admin.POST./admin/operator/bootstrap_tokens/{public_id}/revoke"
STATUS = "admin.GET./admin/agent/status"
ROTATE = "admin.POST./admin/agent/rotate"


def listed(t1, public_id):
    out = t1.cli("bootstrap", "list")
    assert out.code == 0, out.err
    rows = [r for r in out.json if r["public_id"] == public_id]
    assert len(rows) == 1, f"bootstrap {public_id} not listed once"
    return rows[0]


def refused(result):
    assert (result.status, result.code) == (401, "invalid_credential"), result.text
    assert "token" not in (result.json or {})


@pytest.fixture(scope="module")
def enrolled(t1, accounts):
    bt = mint(t1, "--allowlist", accounts)
    reg = self_register(t1, bt["token"], "adm-self")
    return {"bootstrap": bt, "reg": reg}


@case(
    "SMK-ADM-030",
    area="ADM",
    kind="positive",
    covers=["cli.bootstrap.mint", "cli.bootstrap.list", MINT, LIST],
)
def test_mint_returns_token_once_and_list_omits_it(t1, enrolled):
    """`mint` returns the cleartext once with its scope; `list` shows tokens with no
    cleartext (cli-reference.md:127-143, SPEC.md:2786)."""
    bt = enrolled["bootstrap"]
    assert bt["token"] and bt["public_id"]
    assert bt["scope"]["tool_allowlist"] == ["accounts"]
    assert bt["scope"]["single_use"] is True, (
        "default is single-use (cli-reference.md:142)"
    )
    raw = uds(t1, "GET", "/admin/operator/bootstrap_tokens", token=t1.op_token)
    assert raw.status == 200 and bt["token"] not in raw.text
    row = listed(t1, bt["public_id"])
    assert "token" not in row


@case(
    "SMK-ADM-031", area="ADM", kind="positive", covers=[REGISTER, STATUS, "cli.status"]
)
def test_self_registration_consumes_token_and_constrains_acl(t1, enrolled):
    """A bootstrap token enrols an agent whose ACL is the token's allowlist
    (cli-reference.md:141; SPEC.md:2773); `locksmith status` shows that agent with
    its own bearer (cli-reference.md:298, getting-started.md:170-173)."""
    reg = enrolled["reg"]
    assert reg.status == 200, reg.text
    assert reg.json["allowlist"] == ["accounts"]
    status = t1.cli("status", use_op_token=False, agent_token=reg.json["token"])
    assert status.code == 0, status.err
    assert status.json["public_id"] == reg.json["public_id"]
    assert status.json["name"] == "adm-self"
    assert status.json["allowlist"] == ["accounts"]
    assert reg.json["token"] not in status.out
    assert listed(t1, enrolled["bootstrap"]["public_id"])["used_at"] is not None


@case(
    "SMK-ADM-032",
    area="ADM",
    kind="refusal",
    covers=[REGISTER],
    codes=["invalid_credential"],
)
def test_wrong_bootstrap_secret_is_401_and_does_not_consume(t1):
    """A wrong bootstrap secret is 401 invalid_credential (SPEC.md:2773,
    error-envelope.md:23); the token stays unused and still enrols afterwards."""
    bt = mint(t1)
    refused(self_register(t1, wrong_secret(bt["token"]), "adm-wrong-secret"))
    assert listed(t1, bt["public_id"])["used_at"] is None
    assert self_register(t1, bt["token"], "adm-right-secret").status == 200


@case(
    "SMK-ADM-033",
    area="ADM",
    kind="refusal",
    covers=[REGISTER],
    codes=["invalid_credential"],
)
def test_single_use_token_cannot_be_reused(t1, enrolled):
    """Tokens are single-use by default (cli-reference.md:142); a second consume is 401
    and creates no agent."""
    refused(self_register(t1, enrolled["bootstrap"]["token"], "adm-reuse"))
    assert "adm-reuse" not in agent_names(t1, include_revoked=True)


@case(
    "SMK-ADM-034", area="ADM", kind="positive", covers=["cli.bootstrap.revoke", REVOKE]
)
def test_revoke_marks_token_revoked(t1):
    """`bootstrap revoke <public_id>` revokes an outstanding token
    (cli-reference.md:136; SPEC.md:2787)."""
    bt = mint(t1)
    out = t1.cli("bootstrap", "revoke", bt["public_id"])
    assert out.code == 0, out.err
    assert listed(t1, bt["public_id"])["revoked_at"] is not None
    refused(self_register(t1, bt["token"], "adm-after-revoke"))
    assert "adm-after-revoke" not in agent_names(t1, include_revoked=True)


@case(
    "SMK-ADM-035",
    area="ADM",
    kind="refusal",
    covers=[REGISTER],
    codes=["invalid_credential"],
)
def test_expired_token_cannot_enrol(t1):
    """`--expires-at` sets the token's expiry (cli-reference.md:143); after it, enrolment
    is 401 and creates no agent."""
    bt = mint(t1, "--expires-at", str(int(time.time()) - 60))
    refused(self_register(t1, bt["token"], "adm-expired"))
    assert "adm-expired" not in agent_names(t1, include_revoked=True)


@case(
    "SMK-ADM-036",
    area="ADM",
    kind="refusal",
    covers=[REGISTER],
    codes=["agent_name_conflict"],
)
def test_name_conflict_is_409_and_keeps_token(t1, enrolled):
    """A taken name is 409 agent_name_conflict and the bootstrap token is not consumed
    (SPEC.md:2773, 1459)."""
    bt = mint(t1)
    clash = self_register(t1, bt["token"], "adm-self")
    assert (clash.status, clash.code) == (409, "agent_name_conflict"), clash.text
    assert listed(t1, bt["public_id"])["used_at"] is None
    assert self_register(t1, bt["token"], "adm-self-renamed").status == 200


@case(
    "SMK-ADM-037",
    area="ADM",
    kind="positive",
    covers=["cli.bootstrap.mint", MINT, REGISTER],
)
def test_reusable_token_enrols_more_than_once(t1):
    """`--reusable` allows multiple consumes (cli-reference.md:142)."""
    bt = mint(t1, "--reusable")
    assert bt["scope"]["single_use"] is False
    for name in ("adm-reuse-a", "adm-reuse-b"):
        assert self_register(t1, bt["token"], name).status == 200


@case(
    "SMK-ADM-038",
    area="ADM",
    kind="refusal",
    covers=["cli.bootstrap.revoke", REVOKE],
    codes=["agent_not_found"],
)
def test_revoke_unknown_bootstrap_token_is_exit_4(t1):
    """An unknown bootstrap token is HTTP 404 → exit 4 (cli-reference.md:315). The
    code is undocumented; the product returns `agent_not_found` (surface.yaml)."""
    out = t1.cli("bootstrap", "revoke", "adm-no-such-token")
    assert out.code == 4, out.err
    assert out.error_code == "agent_not_found", out.err
    raw = uds(
        t1,
        "POST",
        "/admin/operator/bootstrap_tokens/adm-no-such-token/revoke",
        token=t1.op_token,
    )
    assert (raw.status, raw.code) == (404, "agent_not_found")


@case("SMK-ADM-039", area="ADM", kind="positive", covers=["cli.rotate", ROTATE])
def test_rotate_replaces_the_bearer(t1):
    """`locksmith rotate` mints a new bearer; the old one is rejected for future
    authentication (cli-reference.md:299, per-agent-credentials.md:76-78)."""
    agent = register(t1, "adm-rotor")
    out = t1.cli("rotate", use_op_token=False, agent_token=agent["token"])
    assert out.code == 0, out.err
    new = out.json["token"]
    assert out.json["public_id"] == agent["id"] and new != agent["token"]
    old = uds(t1, "GET", "/admin/agent/status", token=agent["token"])
    assert (old.status, old.code) == (401, "invalid_credential")
    assert uds(t1, "GET", "/admin/agent/status", token=new).status == 200


@case(
    "SMK-ADM-040",
    area="ADM",
    kind="refusal",
    covers=["cli.rotate", ROTATE],
    codes=["invalid_credential"],
)
def test_rotate_with_wrong_current_secret_keeps_old_bearer(t1):
    """Rotation proves the current secret (cli-reference.md:299 `--current-secret`);
    a wrong one is 401 → exit 3 and the bearer is unchanged."""
    agent = register(t1, "adm-rotor-wrong")
    out = t1.cli(
        "rotate",
        "--current-secret",
        "wrongsecret",
        use_op_token=False,
        agent_token=agent["token"],
    )
    assert out.code == 3, out.err
    assert out.error_code == "invalid_credential", out.err
    assert uds(t1, "GET", "/admin/agent/status", token=agent["token"]).status == 200


@case(
    "SMK-ADM-041",
    area="ADM",
    kind="positive",
    covers=["admin.POST./admin/agent/deregister"],
)
def test_deregister_revokes_own_identity(t1):
    """`POST /admin/agent/deregister` (agent token) returns 204 (SPEC.md:2777); the
    agent is revoked and its bearer 401s (cli-reference.md:93-94)."""
    agent = register(t1, "adm-leaver")
    out = uds(t1, "POST", "/admin/agent/deregister", token=agent["token"])
    assert out.status == 204, out.text
    after = uds(t1, "GET", "/admin/agent/status", token=agent["token"])
    assert (after.status, after.code) == (401, "invalid_credential")
    assert "adm-leaver" not in agent_names(t1)
    assert "adm-leaver" in agent_names(t1, include_revoked=True)


@case(
    "SMK-ADM-042",
    area="ADM",
    kind="refusal",
    covers=["cli.bootstrap.mint", MINT],
    codes=["grant_target_invalid"],
)
def test_mint_with_unknown_connection_is_refused(t1, accounts):
    """Bootstrap allowlists use current finite names (cli-reference.md:129-131);
    unknown names cannot be newly granted (per-agent-credentials.md:20-21). Nothing
    is minted."""
    before = len(t1.cli("bootstrap", "list").json)
    out = t1.cli("bootstrap", "mint", "--allowlist", "accounts,adm-not-a-connection")
    assert out.code == 1, out.err
    assert out.error_code == "grant_target_invalid", out.err
    assert "token" not in (out.json or {})
    assert len(t1.cli("bootstrap", "list").json) == before
