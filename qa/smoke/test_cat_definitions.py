"""Integration definitions: import, exact reads, disabled pins and deliberate activation.

Docs: docs/user/operator/integration-definitions.md, docs/user/operator/
customer-mcp-journey.md:36-84, docs/user/cli-reference.md:36-55 and
docs/user/changes/integration-definitions.md. Cases run in order on one daemon.
"""

import json

import pytest

from fakes.cat_uds import uds
from harness.target import REPO

case = pytest.mark.case
CUSTOMER = REPO / "definitions" / "customer.example.json"
DEF_PATH = "/admin/operator/integration-definitions/local.customer/revisions/{}"
UPSTREAM = "https://example.com/mcp"
FROM_DEF = (
    "--definition",
    "local.customer",
    "--revision",
    "1",
    "--auth-profile",
    "none",
)


@pytest.fixture(scope="module")
def defs(target_factory):
    return target_factory(label="cat-definitions")


def refused(result, exit_code, code):
    assert result.code == exit_code, (result.code, result.err)
    assert result.error_code == code, result.err


def control(t, name="customer"):
    got = t.cli("tool", "get", name)
    assert got.code == 0, got.err
    return got.json


@case(
    "SMK-CAT-060",
    area="CAT",
    kind="positive",
    covers=[
        "cli.integration.import",
        "cli.integration.get",
        "admin.PUT./admin/operator/integration-definitions/{id}/revisions/{revision}",
        "admin.GET./admin/operator/integration-definitions/{id}/revisions/{revision}",
    ],
)
def test_import_is_idempotent_and_readable(defs):
    """integration-definitions.md:33-44,146-147: import/get return definition, digest,
    authoring_only, verification_source and provider_readiness; identical re-import is a no-op."""
    first = defs.cli("integration", "import", "--file", str(CUSTOMER))
    assert first.code == 0, first.err
    again = defs.cli("integration", "import", "--file", str(CUSTOMER))
    assert again.code == 0, again.err
    got = defs.cli("integration", "get", "local.customer", "--revision", "1")
    assert got.code == 0, got.err
    for doc in (first.json, again.json, got.json):
        assert (
            doc["definition"]["id"] == "local.customer"
            and doc["definition"]["revision"] == 1
        )
        assert doc["authoring_only"] is True
        assert doc["verification_source"] == "operator_declared"
        assert doc["provider_readiness"] == "unverified"
        assert doc["digest"] == first.json["digest"]
    raw = uds(defs, "PUT", DEF_PATH.format(1), CUSTOMER.read_text())
    assert raw.status == 200, raw.text


@case(
    "SMK-CAT-061",
    area="CAT",
    kind="refusal",
    covers=[
        "cli.integration.import",
        "admin.PUT./admin/operator/integration-definitions/{id}/revisions/{revision}",
    ],
    codes=["definition_conflict"],
)
def test_different_content_same_revision_conflicts(defs):
    """integration-definitions.md:148-149: different content at an existing ID/revision is
    HTTP 409 / CLI 5; the saved revision is unchanged."""
    changed = json.loads(CUSTOMER.read_text())
    changed["summary"] = "a different summary"
    path = defs.write_file("cat-changed.json", json.dumps(changed))
    refused(
        defs.cli("integration", "import", "--file", str(path)), 5, "definition_conflict"
    )
    raw = uds(defs, "PUT", DEF_PATH.format(1), changed)
    assert raw.status == 409 and raw.code == "definition_conflict"
    got = defs.cli("integration", "get", "local.customer", "--revision", "1").json
    assert got["definition"]["summary"] == json.loads(CUSTOMER.read_text())["summary"]


@case(
    "SMK-CAT-062",
    area="CAT",
    kind="refusal",
    covers=[
        "cli.integration.import",
        "admin.PUT./admin/operator/integration-definitions/{id}/revisions/{revision}",
    ],
    codes=["definition_invalid"],
)
def test_invalid_input_is_rejected_whole(defs):
    """integration-definitions.md:150-151,170-173: a JSON array is rejected before storage;
    invalid/unsupported input is 400; local CLI decoding exits 2 before sending."""
    doc = json.loads(CUSTOMER.read_text())
    doc["revision"] = 2
    mismatched = uds(defs, "PUT", DEF_PATH.format(3), doc)
    assert mismatched.status == 400 and mismatched.code == "definition_invalid"
    array = uds(defs, "PUT", DEF_PATH.format(2), [doc])
    assert array.status == 400 and array.code == "definition_invalid"
    unknown = dict(doc, surprise=True)
    extra = uds(defs, "PUT", DEF_PATH.format(2), unknown)
    assert extra.status == 400 and extra.code == "definition_invalid"
    local = defs.cli(
        "integration",
        "import",
        "--file",
        str(defs.write_file("cat-array.json", json.dumps([doc]))),
    )
    assert local.code == 2, local.err
    for revision in (2, 3):
        refused(
            defs.cli(
                "integration", "get", "local.customer", "--revision", str(revision)
            ),
            4,
            "definition_not_found",
        )


@case(
    "SMK-CAT-063",
    area="CAT",
    kind="refusal",
    covers=[
        "cli.integration.get",
        "admin.GET./admin/operator/integration-definitions/{id}/revisions/{revision}",
    ],
    codes=["definition_not_found", "definition_invalid"],
)
def test_missing_revision_is_404(defs):
    """integration-definitions.md:150,170-171: no latest alias; a missing exact revision is
    404 / CLI 4; a malformed revision (e.g. `latest`) is invalid input, 400."""
    refused(
        defs.cli("integration", "get", "local.customer", "--revision", "9"),
        4,
        "definition_not_found",
    )
    refused(
        defs.cli("integration", "get", "local.absent", "--revision", "1"),
        4,
        "definition_not_found",
    )
    raw = uds(defs, "GET", DEF_PATH.format(9))
    assert raw.status == 404 and raw.code == "definition_not_found"
    latest = uds(defs, "GET", DEF_PATH.format("latest"))
    assert (latest.status, latest.code) == (400, "definition_invalid"), latest.text


@case(
    "SMK-CAT-064",
    area="CAT",
    kind="positive",
    covers=[
        "cli.tool.from-definition",
        "admin.POST./admin/operator/tools/{name}/from-definition",
    ],
)
def test_from_definition_creates_disabled_pin(defs):
    """integration-definitions.md:41-53: the connection reports configured, disabled,
    activation disabled, credential_readiness not_checked and an mcp.definition pin;
    private destinations need --allow-private-destination."""
    created = defs.cli(
        "tool", "from-definition", "customer", *FROM_DEF, "--upstream", UPSTREAM
    )
    assert created.code == 0, created.err
    got = control(defs)
    assert got["configured"] is True and got["disabled"] is True
    assert (
        got["activation"] == "disabled" and got["credential_readiness"] == "not_checked"
    )
    pin = got["mcp"]["definition"]
    assert (
        pin["id"] == "local.customer"
        and pin["revision"] == 1
        and pin["auth_profile_id"] == "none"
    )
    assert (
        pin["digest"]
        == defs.cli("integration", "get", "local.customer", "--revision", "1").json[
            "digest"
        ]
    )
    assert got["auth"] == {"kind": "none"} and got["upstream"] == UPSTREAM
    private = defs.cli(
        "tool",
        "from-definition",
        "customer-local",
        *FROM_DEF,
        "--upstream",
        "https://127.0.0.1/mcp",
        "--allow-private-destination",
    )
    assert private.code == 0, private.err
    assert control(defs, "customer-local")["disabled"] is True


@case(
    "SMK-CAT-065",
    area="CAT",
    kind="refusal",
    covers=[
        "cli.tool.from-definition",
        "admin.POST./admin/operator/tools/{name}/from-definition",
    ],
    codes=["definition_conflict", "definition_not_found", "definition_invalid"],
)
def test_from_definition_refusals(defs):
    """integration-definitions.md:48-51,153-154,170-172: create-only (existing name 409 even for
    the same input); missing revision 404; a private destination without the flag or an
    unknown auth profile is 400 (CLI 1)."""
    refused(
        defs.cli(
            "tool", "from-definition", "customer", *FROM_DEF, "--upstream", UPSTREAM
        ),
        5,
        "definition_conflict",
    )
    refused(
        defs.cli(
            "tool",
            "from-definition",
            "cat-r9",
            "--definition",
            "local.customer",
            "--revision",
            "9",
            "--auth-profile",
            "none",
            "--upstream",
            UPSTREAM,
        ),
        4,
        "definition_not_found",
    )
    refused(
        defs.cli(
            "tool",
            "from-definition",
            "cat-priv",
            *FROM_DEF,
            "--upstream",
            "https://127.0.0.1/mcp",
        ),
        1,
        "definition_invalid",
    )
    refused(
        defs.cli(
            "tool",
            "from-definition",
            "cat-prof",
            "--definition",
            "local.customer",
            "--revision",
            "1",
            "--auth-profile",
            "nope",
            "--upstream",
            UPSTREAM,
        ),
        1,
        "definition_invalid",
    )
    for name in ("cat-r9", "cat-priv", "cat-prof"):
        assert defs.cli("tool", "get", name).code == 4


@case(
    "SMK-CAT-066",
    area="CAT",
    kind="refusal",
    covers=[
        "cli.tool.put",
        "cli.tool.enable",
        "admin.PUT./admin/operator/tools/{name}",
        "admin.POST./admin/operator/tools/{name}/enable",
    ],
    codes=["definition_pending"],
)
def test_general_writers_cannot_edit_a_pin(defs):
    """integration-definitions.md:155-157: derived instances cannot be enabled or edited by
    general tool PUT or enable; these return definition_pending."""
    before = control(defs)
    refused(
        defs.cli(
            "tool",
            "put",
            "customer",
            "--upstream",
            UPSTREAM,
            "--auth",
            "none",
            "--egress",
            "direct",
        ),
        5,
        "definition_pending",
    )
    refused(defs.cli("tool", "enable", "customer"), 5, "definition_pending")
    assert control(defs) == before


@case(
    "SMK-CAT-067",
    area="CAT",
    kind="positive",
    covers=[
        "cli.tool.activate-definition",
        "admin.PUT./admin/operator/tools/{name}/definition-activation",
    ],
)
def test_activation_promotes_without_authority(defs):
    """integration-definitions.md:79-98: activation with the current revision promotes the
    pin (phase promoted, activation active), preserves pin and destination, and leaves
    credential_readiness not_checked and provider_readiness unverified."""
    before = control(defs)
    active = defs.cli(
        "tool",
        "activate-definition",
        "customer",
        "--if-match",
        before["definition_control"]["revision"],
        "--compact",
    )
    assert active.code == 0, active.err
    got = control(defs)
    assert (
        got["definition_control"]["phase"] == "promoted"
        and got["activation"] == "active"
    )
    assert (
        got["mcp"]["definition"] == before["mcp"]["definition"]
        and got["upstream"] == UPSTREAM
    )
    assert got["mcp"].get("compact") is True
    assert (
        got["credential_readiness"] == "not_checked"
        and got["provider_readiness"] == "unverified"
    )
    assert defs.cli("agent", "list").json in ([], {"agents": []}), (
        "activation created an agent"
    )


@case(
    "SMK-CAT-068",
    area="CAT",
    kind="refusal",
    covers=[
        "cli.tool.activate-definition",
        "admin.PUT./admin/operator/tools/{name}/definition-activation",
    ],
    codes=[
        "definition_conflict",
        "definition_precondition_required",
        "definition_not_found",
        "definition_invalid",
    ],
)
def test_activation_preconditions(defs):
    """integration-definitions.md:135-140: a stale revision always returns 409; a missing
    precondition 428; malformed/unsupported input 400; an absent/unpinned target 404."""
    current = control(defs)["definition_control"]["revision"]
    stale = "0" * len(current)
    refused(
        defs.cli("tool", "activate-definition", "customer", "--if-match", stale),
        5,
        "definition_conflict",
    )
    missing = uds(
        defs,
        "PUT",
        "/admin/operator/tools/customer/definition-activation",
        {"enabled": False},
    )
    assert missing.status == 428 and missing.code == "definition_precondition_required"
    path = "/admin/operator/tools/customer/definition-activation"
    for body in ({"enabled": "yes"}, {"enabled": False, "surprise": True}):
        bad = uds(defs, "PUT", path, body, headers={"If-Match": current})
        assert (bad.status, bad.code) == (400, "definition_invalid"), bad.text
    refused(
        defs.cli("tool", "activate-definition", "cat-nothing", "--if-match", current),
        4,
        "definition_not_found",
    )
    assert control(defs)["definition_control"]["revision"] == current


@case(
    "SMK-CAT-069",
    area="CAT",
    kind="positive",
    covers=["cli.tool.deactivate-definition"],
)
def test_deactivation_retains_the_pin(defs):
    """integration-definitions.md:119-128: disable retains the pin, destination and compact
    setting; the connection is disabled again."""
    before = control(defs)
    off = defs.cli(
        "tool",
        "deactivate-definition",
        "customer",
        "--if-match",
        before["definition_control"]["revision"],
    )
    assert off.code == 0, off.err
    got = control(defs)
    assert got["disabled"] is True and got["activation"] == "disabled"
    assert got["definition_control"]["phase"] == "disabled"
    assert (
        got["mcp"]["definition"] == before["mcp"]["definition"]
        and got["upstream"] == UPSTREAM
    )
    assert got["mcp"].get("compact") is True


@case(
    "SMK-CAT-070",
    area="CAT",
    kind="corner",
    covers=[
        "admin.GET./admin/operator/integration-definitions/{id}/revisions/{revision}",
        "admin.GET./admin/operator/tools",
    ],
    codes=["definition_not_found", "invalid_credential"],
)
def test_error_envelope_has_three_fields(defs):
    """error-envelope.md:5-17: every error response carries message, type and code."""
    responses = [
        uds(defs, "GET", DEF_PATH.format(9)),
        uds(defs, "GET", "/admin/operator/tools", token="lkop_qacatbadoperator.not-a-real-operator-secret"),
    ]
    for response in responses:
        error = response.json["error"]
        assert {"message", "type", "code"} <= set(error), f"{response.status} envelope lacks {error.keys()}"
