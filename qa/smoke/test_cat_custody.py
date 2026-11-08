"""Credential custody: operator stored values, env/stored/op sources and retention.

Docs: README.md:106-112 (custody backends), docs/user/concepts/per-agent-credentials.md,
docs/user/operator/sealed-state-recovery.md, docs/user/operator/native-tool-review.md:32-48
and config.example.yaml:57-63 (credential store).
"""

import time

import pytest

from fakes.cat_support import FakeOp, sealing_key
from fakes.cat_uds import uds
from harness.target import REPO, SMOKE_X, SMOKE_Y

case = pytest.mark.case
OP_Y = "op://qa/acct-y/credential"
OP_MISSING = "op://qa/missing/credential"
CRED_ROUTES = {
    kind: (
        f"admin.PUT./admin/operator/{kind}/{{name}}/credential",
        f"admin.DELETE./admin/operator/{kind}/{{name}}/credential",
    )
    for kind in ("tools", "models", "infra")
}
BAD_OPERATOR = "lkop_qacatbadoperator.not-a-real-operator-secret"


@pytest.fixture(scope="module")
def op_fake(tmp_path_factory):
    return FakeOp(tmp_path_factory.mktemp("cat-op"), {OP_Y: SMOKE_Y})


@pytest.fixture(scope="module")
def cust(target_factory, op_fake):
    """Sealing key set, fake `op` first on PATH, credential-store sweep every second
    with zero-day tombstone retention."""
    t = target_factory(
        label="cat-custody",
        env={
            "LOCKSMITH_CREDENTIAL_SEALING_KEY": sealing_key(),
            "PATH": op_fake.path_env(),
        },
        config={
            "credential_store": {
                "tombstone_retention_days": 0,
                "sweep_interval_seconds": 1,
            }
        },
    )
    for name in ("cat-acc", "cat-rot"):
        put = t.cli(
            "tool",
            "put",
            name,
            "--upstream",
            t.upstream_url,
            "--auth",
            "bearer=SMOKE_X",
            "--egress",
            "direct",
        )
        assert put.code == 0, put.err
    return t


def agent(t, name, registration="cat-acc"):
    reg = t.cli("agent", "register", "--name", name, "--allowlist", registration)
    assert reg.code == 0, reg.err
    return reg.json["public_id"], reg.json["token"]


def call(t, token, registration="cat-acc"):
    before = t.upstream_counts()
    response = t.http("GET", f"/api/{registration}/check", token=token)
    return response, before, t.upstream_counts()


def store(t, kind, name, value):
    t.canaries.add(value, "cat-stored-value")
    return uds(t, "PUT", f"/admin/operator/{kind}/{name}/credential", {"value": value})


@case(
    "SMK-CAT-020",
    area="CAT",
    kind="positive",
    covers=["admin.PUT./admin/operator/tools/{name}/credential", "beh.secret.backends"],
)
def test_operator_stored_value_is_reference_only_and_selectable(cust):
    """per-agent-credentials.md:140-152, README.md:106-110: the operator credential PUT
    seals the value and returns only {secret_ref, set_at}; selecting that reference makes
    requests reach the stored account; reads never reveal the value."""
    response = store(cust, "tools", "cat-acc", SMOKE_Y)
    assert response.status == 200, response.text
    assert set(response.json) == {"secret_ref", "set_at"}
    assert SMOKE_Y not in response.text
    ref = response.json["secret_ref"]
    got = cust.cli("tool", "get", "cat-acc")
    assert got.json["auth"] == {"kind": "stored_bearer", "secret_ref": ref}
    assert SMOKE_Y not in got.out
    public_id, token = agent(cust, "cat-stored")
    select = cust.cli(
        "agent", "set-credential", public_id, "cat-acc", "--stored-bearer-ref", ref
    )
    assert select.code == 0, select.err
    reply, before, after = call(cust, token)
    assert reply.status == 200 and reply.text == "Y"
    assert after["Y"] == before["Y"] + 1
    listing = cust.cli("agent", "credentials", "list", public_id)
    assert ref in listing.out and SMOKE_Y not in listing.out


@case(
    "SMK-CAT-021",
    area="CAT",
    kind="positive",
    covers=["admin.DELETE./admin/operator/tools/{name}/credential"],
)
def test_operator_stored_value_clear_is_idempotent(cust):
    """README.md:106-112: stored custody is set and cleared through the operator API. No user
    doc describes DELETE .../credential; this encodes the route contract (clears back to
    `auth: none`, idempotent; src/registrations/api.rs:752-756) and is reported as a doc gap."""
    assert (
        cust.cli(
            "tool",
            "put",
            "cat-clear",
            "--upstream",
            cust.upstream_url,
            "--auth",
            "none",
            "--egress",
            "direct",
        ).code
        == 0
    )
    assert store(cust, "tools", "cat-clear", SMOKE_X).status == 200
    for _ in range(2):
        cleared = uds(cust, "DELETE", "/admin/operator/tools/cat-clear/credential")
        assert cleared.status == 200 and cleared.json == {"cleared": True}
    assert cust.cli("tool", "get", "cat-clear").json["auth"] == {"kind": "none"}


@case(
    "SMK-CAT-022",
    area="CAT",
    kind="positive",
    covers=[*CRED_ROUTES["models"], *CRED_ROUTES["infra"]],
)
def test_model_and_infra_stored_values(cust):
    """README.md:106-110: a registration (any kind) can hold a stored_* credential set via
    PUT /admin/operator/{kind}/{name}/credential; reads return only the reference."""
    assert (
        cust.cli(
            "model",
            "put",
            "cat-smodel",
            "--upstream",
            cust.upstream_url,
            "--auth",
            "none",
            "--egress",
            "direct",
        ).code
        == 0
    )
    assert (
        cust.cli("infra", "put", "cat-sinfra", "--upstream", cust.upstream_url).code
        == 0
    )
    for kind, cli_kind, name in (
        ("models", "model", "cat-smodel"),
        ("infra", "infra", "cat-sinfra"),
    ):
        response = store(cust, kind, name, SMOKE_X)
        assert response.status == 200 and set(response.json) == {"secret_ref", "set_at"}
        assert cust.cli(cli_kind, "get", name).json["auth"]["kind"] == "stored_bearer"
        cleared = uds(cust, "DELETE", f"/admin/operator/{kind}/{name}/credential")
        assert cleared.status == 200
        assert cust.cli(cli_kind, "get", name).json["auth"] == {"kind": "none"}


@case(
    "SMK-CAT-023",
    area="CAT",
    kind="refusal",
    covers=[route for pair in CRED_ROUTES.values() for route in pair],
    codes=["unknown_name", "wrong_kind"],
)
def test_stored_value_for_absent_or_other_kind(cust):
    """cli-reference.md:313-316 and error-envelope.md:26: an absent registration is 404;
    a name registered under another kind is 409 wrong_kind; nothing is attached."""
    model = cust.cli("model", "put", "cat-wk-model", "--upstream", cust.upstream_url, "--auth", "none",
                     "--egress", "direct")
    assert model.code == 0, model.err
    before = {"tool": cust.cli("tool", "get", "cat-rot").json, "model": model.json}
    for kind in ("tools", "models", "infra"):
        missing = store(cust, kind, "cat-not-here", SMOKE_X)
        assert (missing.status, missing.code) == (404, "unknown_name"), (kind, missing.text)
        gone = uds(cust, "DELETE", f"/admin/operator/{kind}/cat-not-here/credential")
        assert (gone.status, gone.code) == (404, "unknown_name"), (kind, gone.text)
    for kind, name in (("models", "cat-rot"), ("infra", "cat-rot"), ("tools", "cat-wk-model")):
        other = store(cust, kind, name, SMOKE_X)
        assert (other.status, other.code) == (409, "wrong_kind"), (kind, other.text)
        cleared = uds(cust, "DELETE", f"/admin/operator/{kind}/{name}/credential")
        assert (cleared.status, cleared.code) == (409, "wrong_kind"), (kind, cleared.text)
    assert cust.cli("tool", "get", "cat-rot").json == before["tool"]
    assert cust.cli("model", "get", "cat-wk-model").json == before["model"]


@case(
    "SMK-CAT-030",
    area="CAT",
    kind="refusal",
    covers=list(CRED_ROUTES["tools"]),
    codes=["definition_pending"],
)
def test_stored_value_cannot_attach_to_a_pin(cust):
    """integration-definitions.md:155-157,166-167: derived instances cannot be edited by
    credential writers (definition_pending); a refused attachment commits no sealed value."""
    imported = cust.cli("integration", "import", "--file", str(REPO / "definitions" / "customer.example.json"))
    assert imported.code == 0, imported.err
    pin = cust.cli("tool", "from-definition", "cat-pin", "--definition", "local.customer", "--revision", "1",
                   "--auth-profile", "none", "--upstream", "https://example.com/mcp")
    assert pin.code == 0, pin.err
    before = cust.cli("tool", "get", "cat-pin").json
    put = store(cust, "tools", "cat-pin", SMOKE_X)
    assert (put.status, put.code) == (409, "definition_pending"), put.text
    cleared = uds(cust, "DELETE", "/admin/operator/tools/cat-pin/credential")
    assert (cleared.status, cleared.code) == (409, "definition_pending"), cleared.text
    assert cust.cli("tool", "get", "cat-pin").json == before


@case("SMK-CAT-024", area="CAT", kind="positive", covers=["beh.secret.backends"])
def test_env_selection_reaches_account(cust):
    """per-agent-credentials.md:112-115: a bearer=<ENV> selection reads the daemon's env var."""
    public_id, token = agent(cust, "cat-env")
    assert (
        cust.cli(
            "agent", "set-credential", public_id, "cat-acc", "--auth", "bearer=SMOKE_X"
        ).code
        == 0
    )
    reply, before, after = call(cust, token)
    assert reply.status == 200 and reply.text == "X"
    assert after["X"] == before["X"] + 1


@case(
    "SMK-CAT-025",
    area="CAT",
    kind="refusal",
    covers=["beh.secret.backends"],
    codes=["credential_unresolved"],
)
def test_missing_env_value_is_503_without_dispatch(cust):
    """per-agent-credentials.md:112-115, error-envelope.md:32: a missing selected env value
    fails 503 credential_unresolved before any upstream request."""
    public_id, token = agent(cust, "cat-env-missing")
    sel = cust.cli(
        "agent",
        "set-credential",
        public_id,
        "cat-acc",
        "--auth",
        "bearer=QA_CAT_UNSET_ENV",
    )
    assert sel.code == 0, sel.err
    reply, before, after = call(cust, token)
    assert reply.status == 503 and reply.code == "credential_unresolved"
    assert after == before, "a refused request reached the upstream"


@case("SMK-CAT-026", area="CAT", kind="positive", covers=["beh.secret.backends"])
def test_op_reference_resolved_off_the_hot_path(cust, op_fake):
    """README.md:110-112, per-agent-credentials.md:120-122: an op:// reference is resolved
    by the 1Password CLI on change, never per request; the request reads the cache."""
    public_id, token = agent(cust, "cat-op")
    sel = uds(
        cust,
        "PUT",
        f"/admin/operator/agents/{public_id}/credentials/cat-acc",
        {"auth_spec": {"kind": "op_bearer", "reference": OP_Y}},
    )
    assert sel.status == 200, sel.text
    assert OP_Y in op_fake.invocations(), "selecting an op reference did not resolve it"
    calls = len(op_fake.invocations())
    reply, before, after = call(cust, token)
    assert reply.status == 200 and reply.text == "Y"
    assert after["Y"] == before["Y"] + 1
    assert len(op_fake.invocations()) == calls, "the request shelled out to op"


@case(
    "SMK-CAT-027",
    area="CAT",
    kind="refusal",
    covers=["beh.secret.backends"],
    codes=["credential_unresolved"],
)
def test_unresolvable_op_reference_is_503(cust):
    """per-agent-credentials.md:120-123: an unreadable op reference returns 503 before
    dispatch even when another source is healthy."""
    public_id, token = agent(cust, "cat-op-missing")
    sel = uds(
        cust,
        "PUT",
        f"/admin/operator/agents/{public_id}/credentials/cat-acc",
        {"auth_spec": {"kind": "op_bearer", "reference": OP_MISSING}},
    )
    assert sel.status == 200, sel.text
    reply, before, after = call(cust, token)
    assert reply.status == 503 and reply.code == "credential_unresolved"
    assert after == before, "a refused request reached the upstream"


def deleted_by_sweeps(t):
    return sum(
        e.get("fields", {}).get("deleted", 0)
        for e in t.log_events()
        if e.get("fields", {}).get("message")
        == "credential-store sweep deleted tombstoned rows"
    )


@case(
    "SMK-CAT-028",
    area="CAT",
    kind="positive",
    covers=["beh.retention.credential-store"],
)
def test_rotated_value_is_retired_then_swept(cust):
    """config.example.yaml:57-63: the store tombstones values nothing references and the
    sweep hard-deletes tombstoned values past retention; native-tool-review.md:48 a
    selected reference must be live. Sweep evidence is the daemon's log stream."""
    first = store(cust, "tools", "cat-rot", SMOKE_X)
    assert first.status == 200
    swept = deleted_by_sweeps(cust)
    assert store(cust, "tools", "cat-rot", SMOKE_Y).status == 200
    public_id, _ = agent(cust, "cat-rot-agent", "cat-rot")
    stale = cust.cli(
        "agent",
        "set-credential",
        public_id,
        "cat-rot",
        "--stored-bearer-ref",
        first.json["secret_ref"],
    )
    assert stale.code != 0, "a rotated-out reference was selectable"
    assert cust.cli("agent", "credentials", "list", public_id).json == []
    deadline = time.monotonic() + 6
    while deleted_by_sweeps(cust) <= swept and time.monotonic() < deadline:
        time.sleep(0.25)
    assert deleted_by_sweeps(cust) > swept, (
        "the sweep never deleted the tombstoned value"
    )


@case(
    "SMK-CAT-029",
    area="CAT",
    kind="refusal",
    covers=[
        "admin.GET./admin/operator/tools",
        "admin.GET./admin/operator/models",
        "admin.GET./admin/operator/infra",
        *(
            f"admin.{m}./admin/operator/{k}/{{name}}"
            for k in ("tools", "models", "infra")
            for m in ("GET", "PUT", "DELETE")
        ),
        *(
            f"admin.POST./admin/operator/{k}/{{name}}/enable"
            for k in ("tools", "models", "infra")
        ),
        *(route for pair in CRED_ROUTES.values() for route in pair),
        "admin.PUT./admin/operator/integration-definitions/{id}/revisions/{revision}",
        "admin.GET./admin/operator/integration-definitions/{id}/revisions/{revision}",
        "admin.PUT./admin/operator/tools/{name}/definition-activation",
        "admin.POST./admin/operator/tools/{name}/from-definition",
    ],
    codes=["invalid_credential"],
)
def test_wrong_operator_token_is_401_everywhere(cust):
    """error-envelope.md:23 and architecture.md:30-31: every operator catalog route needs a
    valid operator bearer; a wrong one is 401 invalid_credential and changes nothing."""
    before = cust.cli("tool", "get", "cat-acc").json
    put = {"upstream": cust.upstream_url, "auth": {"kind": "none"}, "egress": "direct"}
    requests = [
        ("GET", f"/admin/operator/{k}", None) for k in ("tools", "models", "infra")
    ]
    for k in ("tools", "models", "infra"):
        requests += [
            ("GET", f"/admin/operator/{k}/cat-acc", None),
            ("PUT", f"/admin/operator/{k}/cat-acc", put),
            ("DELETE", f"/admin/operator/{k}/cat-acc", None),
            ("POST", f"/admin/operator/{k}/cat-acc/enable", None),
            (
                "PUT",
                f"/admin/operator/{k}/cat-acc/credential",
                {"value": "qa-not-a-credential"},
            ),
            ("DELETE", f"/admin/operator/{k}/cat-acc/credential", None),
        ]
    requests += [
        (
            "PUT",
            "/admin/operator/integration-definitions/local.qa/revisions/1",
            {"id": "local.qa"},
        ),
        ("GET", "/admin/operator/integration-definitions/local.qa/revisions/1", None),
        (
            "PUT",
            "/admin/operator/tools/cat-acc/definition-activation",
            {"enabled": False},
        ),
        ("POST", "/admin/operator/tools/cat-new/from-definition", {"definition": {}}),
    ]
    for method, path, body in requests:
        response = uds(cust, method, path, body, token=BAD_OPERATOR)
        assert (response.status, response.code) == (401, "invalid_credential"), (
            method,
            path,
            response.text,
        )
    assert cust.cli("tool", "get", "cat-acc").json == before
    assert cust.cli("tool", "get", "cat-new").code == 4
