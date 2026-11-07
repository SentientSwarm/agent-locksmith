"""Startup credential resolution for legacy config.tools (env and file-sealed backends).

Docs: docs/user/agent-integration/wire-contract.md:50-66 (/readyz), README.md:200-203,
docs/v2/runbooks/m5-sealed-secrets.md:17-22,213 and docs/user/architecture.md:112-113.
"""

import pytest

case = pytest.mark.case
SEALED = "synthetic-private-account-x\n"


def legacy_tool(name, value):
    return {
        "name": name,
        "description": "legacy",
        "upstream": "http://127.0.0.1:9",
        "egress": "direct",
        "auth": {"header": "Authorization", "value": value},
    }


def sealed_file(work, name, mode):
    path = work / name
    path.write_text(SEALED)
    path.chmod(mode)
    return {"from_file_sealed": {"path": str(path)}}


@case(
    "SMK-CAT-050",
    area="CAT",
    kind="positive",
    covers=["beh.creds.startup-resolution", "beh.secret.backends"],
)
def test_resolved_startup_credentials_are_ready(target_factory):
    """m5-sealed-secrets.md:17,21: a chmod-0600 sealed file and a present env var resolve at
    startup; wire-contract.md:52-56 /readyz is 200 ready."""
    t = target_factory(
        label="cat-ready",
        config=lambda work: {
            "tools": [
                legacy_tool("cat-fs-ok", sealed_file(work, "fs-ok", 0o600)),
                legacy_tool("cat-env-ok", {"from_env": {"var": "SMOKE_X"}}),
            ]
        },
    )
    ready = t.http("GET", "/readyz")
    assert ready.status == 200, ready.text
    assert ready.json["status"] == "ready"


@case(
    "SMK-CAT-051",
    area="CAT",
    kind="refusal",
    covers=["beh.creds.startup-resolution", "beh.secret.backends"],
    codes=["tool_credentials_unresolved"],
)
def test_unresolved_startup_credentials_fail_readiness(target_factory):
    """m5-sealed-secrets.md:18,22,213: a group/world-readable sealed file is rejected and a
    missing env var is unresolved; the tool degrades without taking the daemon down.
    wire-contract.md:58-63: /readyz is 503 tool_credentials_unresolved naming exactly them."""
    t = target_factory(
        label="cat-unready",
        config=lambda work: {
            "tools": [
                legacy_tool("cat-fs-ok", sealed_file(work, "fs-ok", 0o600)),
                legacy_tool("cat-fs-loose", sealed_file(work, "fs-loose", 0o644)),
                legacy_tool(
                    "cat-env-missing", {"from_env": {"var": "QA_CAT_UNSET_ENV"}}
                ),
            ]
        },
    )
    assert t.http("GET", "/livez").status == 200
    ready = t.http("GET", "/readyz")
    assert ready.status == 503
    assert ready.json["status"] == "not_ready"
    assert ready.json["reason"] == "tool_credentials_unresolved"
    assert sorted(ready.json["tools"]) == ["cat-env-missing", "cat-fs-loose"]
    assert "group or world read" in t.log_text()
