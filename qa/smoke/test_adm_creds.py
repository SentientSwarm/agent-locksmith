"""Per-agent account bindings over the admin socket, without a credential-store key
(docs/user/concepts/per-agent-credentials.md, cli-reference.md:100-125)."""

import pytest

from fakes.adm_flows import register
from fakes.adm_uds import uds

case = pytest.mark.case
BASE = "admin.{}./admin/operator/agents/{{public_id}}/credentials"
LIST = BASE.format("GET")
PUT = BASE.format("PUT") + "/{registration}"
DELETE = BASE.format("DELETE") + "/{registration}"
STORED = BASE.format("PUT") + "/{registration}/credential"
UNKNOWN = "adm-no-such-agent"
OAUTH_SPEC = {
    "kind": "oauth_device_code",
    "client_id": "adm-client",
    "scopes": ["read"],
    "device_url": "https://idp.invalid/device",
    "token_url": "https://idp.invalid/token",
}


@pytest.fixture(scope="module")
def bound(t1, accounts):
    return register(t1, "adm-bound", allowlist=accounts)


def overrides(t1, agent):
    out = t1.cli("agent", "credentials", "list", agent["id"])
    assert out.code == 0, out.err
    return out.json


def put_spec(t1, agent, spec):
    path = f"/admin/operator/agents/{agent['id']}/credentials/accounts"
    return uds(t1, "PUT", path, token=t1.op_token, body={"auth_spec": spec})


@case(
    "SMK-ADM-020",
    area="ADM",
    kind="positive",
    covers=["cli.agent.set-credential", "cli.agent.credentials.list", PUT, LIST],
)
def test_set_and_replace_binding_reads_back_references_only(t1, bound):
    """`set-credential` upserts one binding per agent/registration; `credentials list`
    returns AuthSpec references and timestamps, never values
    (cli-reference.md:112-116, per-agent-credentials.md:92-116)."""
    first = t1.cli(
        "agent", "set-credential", bound["id"], "accounts", "--auth", "bearer=SMOKE_X"
    )
    assert first.code == 0, first.err
    rows = overrides(t1, bound)
    assert [r["auth_spec"] for r in rows] == [{"kind": "bearer", "env_var": "SMOKE_X"}]
    assert rows[0]["created_at"] and rows[0]["updated_at"]
    swap = t1.cli(
        "agent",
        "set-credential",
        bound["id"],
        "accounts",
        "--auth",
        "header=x-api-key:SMOKE_Y",
    )
    assert swap.code == 0, swap.err
    raw = uds(
        t1,
        "GET",
        f"/admin/operator/agents/{bound['id']}/credentials",
        token=t1.op_token,
    )
    assert raw.status == 200
    assert [r["auth_spec"] for r in raw.json["overrides"]] == [
        {"kind": "header", "header": "x-api-key", "env_var": "SMOKE_Y"}
    ]
    assert "synthetic-private-account" not in raw.text + first.out + swap.out


@case(
    "SMK-ADM-021",
    area="ADM",
    kind="positive",
    covers=["cli.agent.unset-credential", DELETE],
)
def test_unset_is_idempotent(t1, bound):
    """`unset-credential` removes the binding and is idempotent — removing an absent
    binding returns success (cli-reference.md:123-125)."""
    assert (
        t1.cli("agent", "set-credential", bound["id"], "accounts", "--no-auth").code
        == 0
    )
    for _ in range(2):
        out = t1.cli("agent", "unset-credential", bound["id"], "accounts")
        assert out.code == 0, out.err
        assert overrides(t1, bound) == []


@case(
    "SMK-ADM-022",
    area="ADM",
    kind="refusal",
    codes=["agent_not_found"],
    covers=[
        "cli.agent.credentials.list",
        "cli.agent.set-credential",
        "cli.agent.unset-credential",
        LIST,
        PUT,
        DELETE,
    ],
)
def test_binding_commands_on_unknown_agent_exit_4(t1, accounts):
    """An unknown agent is HTTP 404 → exit 4 for every binding command
    (cli-reference.md:315)."""
    for args in (
        ["credentials", "list", UNKNOWN],
        ["set-credential", UNKNOWN, "accounts", "--no-auth"],
        ["unset-credential", UNKNOWN, "accounts"],
    ):
        out = t1.cli("agent", *args)
        assert out.code == 4, (args, out.err)
        assert out.error_code == "agent_not_found", (args, out.err)


@case("SMK-ADM-023", area="ADM", kind="refusal", covers=[PUT], codes=["selection_only"])
def test_generic_write_cannot_create_controlled_oauth(t1, bound):
    """`controlled_oauth` is a selection-only stamp; generic credential writes cannot
    create it (docs/user/operator/native-oauth.md:67-68)."""
    spec = {
        "kind": "controlled_oauth",
        "session_label": "x",
        "owner_id": "qa",
        "incarnation": 1,
        "profile_id": "p",
        "profile_digest": "d",
    }
    r = put_spec(t1, bound, spec)
    assert (r.status, r.code) == (400, "selection_only")
    assert overrides(t1, bound) == []


@case(
    "SMK-ADM-024",
    area="ADM",
    kind="refusal",
    covers=[PUT],
    codes=["invalid_op_reference"],
)
def test_op_binding_requires_op_scheme(t1, bound):
    """`op_*` bindings carry an `op://` reference (README.md:110-113); anything else is
    refused before it is stored."""
    for ref in ("https://vault.example/item", "op://"):
        r = put_spec(t1, bound, {"kind": "op_bearer", "reference": ref})
        assert (r.status, r.code) == (400, "invalid_op_reference"), ref
    assert overrides(t1, bound) == []


@case(
    "SMK-ADM-027",
    area="ADM",
    kind="refusal",
    covers=[PUT],
    codes=["oauth_session_label_required"],
)
def test_oauth_binding_requires_a_nonempty_label(t1, bound):
    """Every OAuth account selection must name a nonempty label; missing or empty
    labels reject on operator writes (per-agent-credentials.md:166-168,
    cli-reference.md:118)."""
    for label in (None, "", "  "):
        spec = dict(OAUTH_SPEC)
        if label is not None:
            spec["session_label"] = label
        r = put_spec(t1, bound, spec)
        assert (r.status, r.code) == (400, "oauth_session_label_required"), repr(label)
    assert overrides(t1, bound) == []


@case(
    "SMK-ADM-028",
    area="ADM",
    kind="refusal",
    covers=[PUT],
    codes=["invalid_oauth_selection"],
)
def test_oauth_binding_requires_complete_metadata(t1, bound):
    """An OAuth selection carries the client and token-endpoint metadata its requests
    and refreshes use; placeholder selections with empty metadata are not usable
    (per-agent-credentials.md:170-175, cli-reference.md:118-121)."""
    for broken in (
        {"client_id": ""},
        {"token_url": "not-a-url"},
        {"token_url": "ftp://idp.invalid/t"},
    ):
        spec = {**OAUTH_SPEC, "session_label": "default", **broken}
        r = put_spec(t1, bound, spec)
        assert (r.status, r.code) == (400, "invalid_oauth_selection"), sorted(broken)
    assert overrides(t1, bound) == []


@case(
    "SMK-ADM-025",
    area="ADM",
    kind="refusal",
    covers=[STORED, "cli.agent.set-credential"],
    codes=["credential_store_unconfigured"],
)
def test_stored_value_without_sealing_key_is_refused(t1, bound):
    """Stored values are sealed with LOCKSMITH_CREDENTIAL_SEALING_KEY, which must be
    supplied before startup (getting-started.md:81-82, native-tool-review.md:33-35);
    without it nothing is stored or selected."""
    path = f"/admin/operator/agents/{bound['id']}/credentials/accounts/credential"
    r = uds(
        t1,
        "PUT",
        path,
        token=t1.op_token,
        body={"value": "adm-unsealed-value", "bearer": True},
    )
    assert (r.status, r.code) == (404, "credential_store_unconfigured")
    cli = t1.cli(
        "agent",
        "set-credential",
        bound["id"],
        "accounts",
        "--stored-bearer-stdin",
        stdin="adm-unsealed-value\n",
    )
    assert cli.code == 4, cli.err
    assert cli.error_code == "credential_store_unconfigured", cli.err
    assert overrides(t1, bound) == []


@case(
    "SMK-ADM-026",
    area="ADM",
    kind="refusal",
    covers=[PUT, "cli.agent.set-credential"],
    codes=["grant_target_invalid"],
)
def test_binding_an_unknown_connection_is_refused(t1, bound):
    """Unknown, disabled and infra names cannot be newly granted or bound
    (per-agent-credentials.md:20-21)."""
    out = t1.cli(
        "agent", "set-credential", bound["id"], "adm-not-a-connection", "--no-auth"
    )
    assert out.code == 1, out.err
    assert out.error_code == "grant_target_invalid", out.err
    assert overrides(t1, bound) == []
