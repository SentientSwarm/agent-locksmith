"""Operator catalog management: tool/model/infra registrations and their refusals.

Docs: docs/user/cli-reference.md "tool / model / infra", docs/user/concepts/
error-envelope.md, docs/user/concepts/kind-taxonomy.md, docs/user/operator/
connector-onboarding.md and docs/user/operator/native-mcp.md.
"""

import json

import pytest

from fakes.cat_uds import uds
from harness.target import REPO

case = pytest.mark.case
MCP_CONFIG = '{"protocol_version":"2025-11-25"}'
BAD_SERVICE = {
    "http_service": {"version": 99, "mode": "request_response", "operations": []}
}


@pytest.fixture(scope="module")
def cat(target_factory):
    """A daemon with one routed connection `cat-keep` and an agent selecting X."""
    t = target_factory(label="cat-catalog")
    put = t.cli(
        "tool",
        "put",
        "cat-keep",
        "--upstream",
        t.upstream_url,
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
    )
    assert put.code == 0, put.err
    reg = t.cli("agent", "register", "--name", "cat-keeper", "--allowlist", "cat-keep")
    assert reg.code == 0, reg.err
    bind = t.cli(
        "agent",
        "set-credential",
        reg.json["public_id"],
        "cat-keep",
        "--auth",
        "bearer=SMOKE_X",
    )
    assert bind.code == 0, bind.err
    t.cat_token = reg.json["token"]
    return t


def keep_still_routes_x(t):
    """The existing row, grant and selection are intact: one more X dispatch."""
    before = t.upstream_counts()
    response = t.http("GET", "/api/cat-keep/check", token=t.cat_token)
    assert response.status == 200 and response.text == "X"
    after = t.upstream_counts()
    assert after["X"] == before["X"] + 1


def refused(result, exit_code, code):
    assert result.code == exit_code, (result.code, result.err)
    assert result.error_code == code, result.err


def absent(t, kind, name):
    assert t.cli(kind, "get", name).code in (4, 5), f"{kind} {name} was saved"


@case(
    "SMK-CAT-001",
    area="CAT",
    kind="positive",
    covers=[
        "cli.tool.put",
        "cli.tool.get",
        "cli.tool.list",
        "admin.PUT./admin/operator/tools/{name}",
        "admin.GET./admin/operator/tools/{name}",
        "admin.GET./admin/operator/tools",
    ],
)
def test_tool_put_get_list(cat):
    """cli-reference.md:150-157,171-185: put saves the entry; reads report configured,
    activation and credential_readiness: not_checked."""
    put = cat.cli(
        "tool",
        "put",
        "cat-tool",
        "--upstream",
        cat.upstream_url + "/v2",
        "--auth",
        "none",
        "--egress",
        "direct",
        "--timeout-request",
        "12",
        "--body-limit",
        "4096",
        "--metadata",
        "team=qa",
        "--description",
        "qa tool",
    )
    assert put.code == 0, put.err
    got = cat.cli("tool", "get", "cat-tool").json
    assert got["name"] == "cat-tool" and got["kind"] == "tool"
    assert got["upstream"] == cat.upstream_url + "/v2"
    assert got["auth"] == {"kind": "none"} and got["egress"] == "direct"
    assert got["timeouts"]["request_seconds"] == 12 and got["body_limit_bytes"] == 4096
    assert got["metadata"] == {"team": "qa"} and got["description"] == "qa tool"
    assert got["configured"] is True and got["activation"] == "active"
    assert got["credential_readiness"] == "not_checked"
    assert got["seed"] is False and got["disabled"] is False
    listed = cat.cli("tool", "list")
    assert listed.code == 0, listed.err
    assert "cat-tool" in {row["name"] for row in listed.json}


@case(
    "SMK-CAT-002",
    area="CAT",
    kind="positive",
    covers=["cli.tool.delete", "admin.DELETE./admin/operator/tools/{name}"],
)
def test_operator_tool_delete_is_hard(cat):
    """cli-reference.md:162-163: delete on an operator-created entry hard-deletes it."""
    assert (
        cat.cli(
            "tool", "put", "cat-gone", "--upstream", cat.upstream_url, "--auth", "none"
        ).code
        == 0
    )
    deleted = cat.cli("tool", "delete", "cat-gone")
    assert deleted.code == 0, deleted.err
    refused(cat.cli("tool", "get", "cat-gone"), 4, "unknown_name")
    assert "cat-gone" not in {row["name"] for row in cat.cli("tool", "list").json}


@case(
    "SMK-CAT-003",
    area="CAT",
    kind="positive",
    covers=[
        "cli.model.put",
        "cli.model.get",
        "cli.model.list",
        "cli.model.delete",
        "admin.PUT./admin/operator/models/{name}",
        "admin.GET./admin/operator/models/{name}",
        "admin.GET./admin/operator/models",
        "admin.DELETE./admin/operator/models/{name}",
    ],
)
def test_model_lifecycle_with_explicit_none(cat):
    """kind-taxonomy.md:48 and cli-reference.md:205: kind=model accepts explicit
    `--auth none`; cli-reference.md:162-163 operator rows hard-delete."""
    put = cat.cli(
        "model",
        "put",
        "cat-model",
        "--upstream",
        cat.upstream_url,
        "--auth",
        "none",
        "--egress",
        "direct",
        "--metadata",
        "modality=text",
    )
    assert put.code == 0, put.err
    got = cat.cli("model", "get", "cat-model").json
    assert got["kind"] == "model" and got["auth"] == {"kind": "none"}
    assert got["metadata"] == {"modality": "text"} and got["activation"] == "active"
    assert "cat-model" in {row["name"] for row in cat.cli("model", "list").json}
    assert "cat-model" not in {row["name"] for row in cat.cli("tool", "list").json}
    assert cat.cli("model", "delete", "cat-model").code == 0
    refused(cat.cli("model", "get", "cat-model"), 4, "unknown_name")


@case(
    "SMK-CAT-004",
    area="CAT",
    kind="positive",
    covers=[
        "cli.infra.put",
        "cli.infra.get",
        "cli.infra.list",
        "cli.infra.delete",
        "admin.PUT./admin/operator/infra/{name}",
        "admin.GET./admin/operator/infra/{name}",
        "admin.GET./admin/operator/infra",
        "admin.DELETE./admin/operator/infra/{name}",
    ],
)
def test_infra_lifecycle_defaults_to_no_auth(cat):
    """cli-reference.md:206: kind=infra accepts no --auth flag (defaults to None)."""
    put = cat.cli(
        "infra",
        "put",
        "cat-infra",
        "--upstream",
        cat.upstream_url,
        "--egress",
        "direct",
    )
    assert put.code == 0, put.err
    got = cat.cli("infra", "get", "cat-infra").json
    assert got["kind"] == "infra" and got["auth"] == {"kind": "none"}
    assert "cat-infra" in {row["name"] for row in cat.cli("infra", "list").json}
    assert cat.cli("infra", "delete", "cat-infra").code == 0
    refused(cat.cli("infra", "get", "cat-infra"), 4, "unknown_name")


@case(
    "SMK-CAT-005",
    area="CAT",
    kind="refusal",
    covers=[
        "admin.GET./admin/operator/tools/{name}",
        "admin.GET./admin/operator/models/{name}",
        "admin.GET./admin/operator/infra/{name}",
        "admin.DELETE./admin/operator/tools/{name}",
        "admin.DELETE./admin/operator/models/{name}",
        "admin.DELETE./admin/operator/infra/{name}",
        "admin.POST./admin/operator/tools/{name}/enable",
        "admin.POST./admin/operator/models/{name}/enable",
        "admin.POST./admin/operator/infra/{name}/enable",
        "cli.tool.get",
        "cli.tool.delete",
        "cli.tool.enable",
        "cli.model.get",
        "cli.model.delete",
        "cli.model.enable",
        "cli.infra.get",
        "cli.infra.delete",
        "cli.infra.enable",
    ],
    codes=["unknown_name"],
)
def test_unknown_name_is_404(cat):
    """cli-reference.md:313-315: not found is exit 4 (HTTP 404)."""
    for args in (
        ("tool", "get"),
        ("tool", "delete"),
        ("tool", "enable"),
        ("model", "get"),
        ("model", "delete"),
        ("model", "enable"),
        ("infra", "get"),
        ("infra", "delete"),
        ("infra", "enable"),
    ):
        refused(cat.cli(*args, "cat-nothing"), 4, "unknown_name")
    for kind in ("tools", "models", "infra"):
        response = uds(cat, "GET", f"/admin/operator/{kind}/cat-nothing")
        assert response.status == 404 and response.code == "unknown_name"


@case(
    "SMK-CAT-006",
    area="CAT",
    kind="refusal",
    covers=[
        "cli.tool.put",
        "cli.model.put",
        "admin.PUT./admin/operator/tools/{name}",
        "admin.PUT./admin/operator/models/{name}",
    ],
    codes=["invalid_upstream"],
)
def test_invalid_upstream_changes_nothing(cat):
    """cli-reference.md:166-168, connector-onboarding.md:31-42: a malformed URL, other
    scheme, userinfo, query or fragment is HTTP 400 invalid_upstream / exit 1 before
    saving; the existing row, grant and selection remain unchanged."""
    before = cat.cli("tool", "get", "cat-keep").json
    host = cat.upstream_url.split("://", 1)[1]
    for bad in (
        "ftp://" + host,
        cat.upstream_url + "/?a=1",
        cat.upstream_url + "/#frag",
        "http://user:pw@" + host,
        "not a url",
    ):
        refused(
            cat.cli(
                "tool",
                "put",
                "cat-keep",
                "--upstream",
                bad,
                "--auth",
                "bearer=SMOKE_X",
                "--egress",
                "direct",
            ),
            1,
            "invalid_upstream",
        )
        refused(
            cat.cli(
                "model", "put", "cat-bad-model", "--upstream", bad, "--auth", "none"
            ),
            1,
            "invalid_upstream",
        )
    assert cat.cli("tool", "get", "cat-keep").json == before
    absent(cat, "model", "cat-bad-model")
    keep_still_routes_x(cat)


@case(
    "SMK-CAT-007",
    area="CAT",
    kind="refusal",
    covers=[
        "admin.PUT./admin/operator/tools/{name}",
        "admin.PUT./admin/operator/models/{name}",
        "admin.PUT./admin/operator/infra/{name}",
        "cli.tool.put",
        "cli.model.put",
        "cli.infra.put",
    ],
    codes=["invalid_name"],
)
def test_invalid_name(cat):
    """Registration names are lowercase a-z, 0-9 and dash, 1-64 characters
    (src/registrations/validators.rs:42-64; no user doc states it — reported gap)."""
    for name in ("Cat-Upper", "cat_under", "c" * 65):
        for kind in ("tool", "model", "infra"):
            refused(
                cat.cli(
                    kind, "put", name, "--upstream", cat.upstream_url, "--auth", "none"
                ),
                1,
                "invalid_name",
            )
    assert not any(
        row["name"].lower().startswith("cat-upper")
        for row in cat.cli("tool", "list").json
    )


@case(
    "SMK-CAT-008",
    area="CAT",
    kind="refusal",
    covers=[
        "admin.PUT./admin/operator/tools/{name}",
        "admin.PUT./admin/operator/models/{name}",
        "admin.PUT./admin/operator/infra/{name}",
        "cli.tool.put",
        "cli.model.put",
        "cli.infra.put",
    ],
    codes=["reserved_name"],
)
def test_reserved_name(cat):
    """error-envelope.md:27: names on the reserved list are 400 reserved_name."""
    for name in (
        "livez",
        "readyz",
        "version",
        "health",
        "skill",
        "tools",
        "models",
        "admin",
        "api",
    ):
        for kind in ("tool", "model", "infra"):
            refused(
                cat.cli(
                    kind, "put", name, "--upstream", cat.upstream_url, "--auth", "none"
                ),
                1,
                "reserved_name",
            )


@case(
    "SMK-CAT-009",
    area="CAT",
    kind="refusal",
    covers=[
        "admin.PUT./admin/operator/tools/{name}",
        "admin.PUT./admin/operator/models/{name}",
        "cli.tool.put",
        "cli.model.put",
    ],
    codes=["auth_required"],
)
def test_tool_and_model_require_auth(cat):
    """kind-taxonomy.md:46, error-envelope.md:28, cli-reference.md:204-205: tool and model
    registered without auth are rejected 400 auth_required."""
    for kind in ("tool", "model"):
        refused(
            cat.cli(kind, "put", f"cat-noauth-{kind}", "--upstream", cat.upstream_url),
            1,
            "auth_required",
        )
        absent(cat, kind, f"cat-noauth-{kind}")


@case(
    "SMK-CAT-010",
    area="CAT",
    kind="refusal",
    covers=[
        "admin.PUT./admin/operator/tools/{name}",
        "admin.PUT./admin/operator/models/{name}",
        "admin.PUT./admin/operator/infra/{name}",
        "admin.GET./admin/operator/models/{name}",
        "admin.DELETE./admin/operator/tools/{name}",
        "admin.DELETE./admin/operator/models/{name}",
        "admin.DELETE./admin/operator/infra/{name}",
        "admin.POST./admin/operator/tools/{name}/enable",
        "admin.POST./admin/operator/models/{name}/enable",
        "admin.POST./admin/operator/infra/{name}/enable",
        "cli.tool.put",
        "cli.tool.delete",
        "cli.tool.enable",
        "cli.model.put",
        "cli.model.get",
        "cli.model.delete",
        "cli.model.enable",
        "cli.infra.put",
        "cli.infra.delete",
        "cli.infra.enable",
    ],
    codes=["wrong_kind"],
)
def test_cross_kind_name_is_409(cat):
    """error-envelope.md:26: an operation on a name registered under a different kind
    is 409 wrong_kind (CLI exit 5, cli-reference.md:316); the tool is untouched."""
    before = cat.cli("tool", "get", "cat-keep").json
    refused(
        cat.cli(
            "model", "put", "cat-keep", "--upstream", cat.upstream_url, "--auth", "none"
        ),
        5,
        "wrong_kind",
    )
    refused(
        cat.cli("infra", "put", "cat-keep", "--upstream", cat.upstream_url),
        5,
        "wrong_kind",
    )
    refused(cat.cli("model", "get", "cat-keep"), 5, "wrong_kind")
    for args in (("model", "delete"), ("model", "enable"), ("infra", "delete"), ("infra", "enable")):
        refused(cat.cli(*args, "cat-keep"), 5, "wrong_kind")
    assert cat.cli("tool", "get", "cat-keep").json == before
    model = cat.cli("model", "put", "cat-wk-model", "--upstream", cat.upstream_url, "--auth", "none")
    assert model.code == 0, model.err
    refused(cat.cli("tool", "put", "cat-wk-model", "--upstream", cat.upstream_url, "--auth", "none"), 5, "wrong_kind")
    for args in (("tool", "delete"), ("tool", "enable")):
        refused(cat.cli(*args, "cat-wk-model"), 5, "wrong_kind")
    assert cat.cli("model", "get", "cat-wk-model").json == model.json
    keep_still_routes_x(cat)


@case(
    "SMK-CAT-011",
    area="CAT",
    kind="refusal",
    covers=[
        "admin.PUT./admin/operator/tools/{name}",
        "admin.PUT./admin/operator/models/{name}",
        "admin.PUT./admin/operator/infra/{name}",
    ],
    codes=["invalid_metadata"],
)
def test_malformed_op_reference_is_rejected(cat):
    """README.md:106-112: an op_* source carries an op:// reference; a malformed
    reference is rejected at register time (400 invalid_metadata) and nothing is saved."""
    body = {
        "upstream": cat.upstream_url,
        "egress": "direct",
        "auth": {"kind": "op_bearer", "reference": "vault/item/field"},
    }
    for kind in ("tools", "models", "infra"):
        response = uds(cat, "PUT", f"/admin/operator/{kind}/cat-badop", body)
        assert response.status == 400 and response.code == "invalid_metadata", (
            response.text
        )
    assert uds(cat, "GET", "/admin/operator/tools/cat-badop").status == 404


@case(
    "SMK-CAT-012",
    area="CAT",
    kind="positive",
    covers=["cli.tool.put", "admin.PUT./admin/operator/tools/{name}"],
)
def test_service_description_metadata_keeps_selection(cat):
    """connector-onboarding.md:78-92: --metadata-file publishes the reference description;
    a metadata-only update retains grants and account selections."""
    put = cat.cli(
        "tool",
        "put",
        "cat-keep",
        "--upstream",
        cat.upstream_url,
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
        "--metadata-file",
        str(REPO / "examples" / "http-service-reference.json"),
    )
    assert put.code == 0, put.err
    assert put.json["metadata"]["http_service"]["version"] == 1
    keep_still_routes_x(cat)


@case(
    "SMK-CAT-013",
    area="CAT",
    kind="refusal",
    covers=[
        "cli.tool.put",
        "cli.model.put",
        "admin.PUT./admin/operator/tools/{name}",
        "admin.PUT./admin/operator/models/{name}",
    ],
    codes=["invalid_http_service"],
)
def test_malformed_service_description(cat):
    """cli-reference.md:189-191, connector-onboarding.md:90-91: a malformed http_service is
    HTTP 400 invalid_http_service / exit 1 before writing; file syntax errors are exit 2."""
    before = cat.cli("tool", "get", "cat-keep").json
    bad = cat.write_file("cat-bad-service.json", json.dumps(BAD_SERVICE))
    refused(
        cat.cli(
            "tool",
            "put",
            "cat-keep",
            "--upstream",
            cat.upstream_url,
            "--auth",
            "bearer=SMOKE_X",
            "--egress",
            "direct",
            "--metadata-file",
            str(bad),
        ),
        1,
        "invalid_http_service",
    )
    syntax = cat.write_file("cat-syntax.json", "{not json")
    local = cat.cli(
        "tool",
        "put",
        "cat-keep",
        "--upstream",
        cat.upstream_url,
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
        "--metadata-file",
        str(syntax),
    )
    assert local.code == 2, local.err
    assert cat.cli("tool", "get", "cat-keep").json == before
    refused(
        cat.cli("model", "put", "cat-svc-model", "--upstream", cat.upstream_url, "--auth", "none",
                "--metadata-file", str(bad)),
        1,
        "invalid_http_service",
    )
    absent(cat, "model", "cat-svc-model")
    keep_still_routes_x(cat)


@case(
    "SMK-CAT-014",
    area="CAT",
    kind="positive",
    covers=["cli.tool.put", "admin.PUT./admin/operator/tools/{name}"],
)
def test_native_connection_put(cat):
    """native-mcp.md:66-92 and cli-reference.md:182-183: a native tool needs
    --protocol mcp_streamable_http, a strict config file, HTTPS and direct egress."""
    cfg = cat.write_file("cat-mcp.json", MCP_CONFIG)
    put = cat.cli(
        "tool",
        "put",
        "cat-native",
        "--upstream",
        "https://service.example/mcp",
        "--auth",
        "none",
        "--egress",
        "direct",
        "--protocol",
        "mcp_streamable_http",
        "--mcp-config-file",
        str(cfg),
    )
    assert put.code == 0, put.err
    got = cat.cli("tool", "get", "cat-native").json
    assert got["protocol"] == "mcp_streamable_http"
    assert got["mcp"]["protocol_version"] == "2025-11-25"
    assert got["credential_readiness"] == "not_checked"


@case(
    "SMK-CAT-015",
    area="CAT",
    kind="refusal",
    covers=[
        "cli.tool.put",
        "cli.model.put",
        "cli.infra.put",
        "admin.PUT./admin/operator/tools/{name}",
        "admin.PUT./admin/operator/models/{name}",
        "admin.PUT./admin/operator/infra/{name}",
    ],
    codes=["invalid_mcp"],
)
def test_native_validation_before_persistence(cat):
    """native-mcp.md:87-92: native model/infra, proxied egress, non-HTTPS endpoints and
    private destinations without opt-in are rejected before persistence (400 invalid_mcp)."""
    cfg = str(cat.write_file("cat-mcp.json", MCP_CONFIG))
    native = (
        "--protocol",
        "mcp_streamable_http",
        "--mcp-config-file",
        cfg,
        "--auth",
        "none",
    )
    attempts = [
        ("tool", "cat-nat-http", "http://service.example/mcp", "direct"),
        ("tool", "cat-nat-proxied", "https://service.example/mcp", "proxied"),
        ("tool", "cat-nat-private", "https://127.0.0.1/mcp", "direct"),
        ("model", "cat-nat-model", "https://service.example/mcp", "direct"),
    ]
    for kind, name, upstream, egress in attempts:
        refused(
            cat.cli(
                kind, "put", name, "--upstream", upstream, "--egress", egress, *native
            ),
            1,
            "invalid_mcp",
        )
        absent(cat, kind, name)
    infra = cat.cli("infra", "put", "cat-nat-infra", "--upstream", "https://service.example/mcp",
                    "--egress", "direct", "--protocol", "mcp_streamable_http", "--mcp-config-file", cfg)
    refused(infra, 1, "invalid_mcp")
    absent(cat, "infra", "cat-nat-infra")
