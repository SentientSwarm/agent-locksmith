"""Seed catalog and legacy config.tools bootstrap into registrations.

Docs: seed/catalog.yaml header (shipped catalog contract), docs/user/concepts/
kind-taxonomy.md:50-60, docs/user/cli-reference.md:157-169,187,
docs/user/operator/connector-onboarding.md:41-45 and docs/user/architecture.md:118-121,
166-189. Cases in this module run in order against one daemon.
"""

import pytest

from fakes.cat_support import seed_entries, write_seed
from fakes.cat_uds import uds

case = pytest.mark.case
LEGACY_UP = "http://127.0.0.1:9"


def legacy(var, upstream):
    return {
        "tools": [
            {
                "name": "cat-legacy",
                "description": "legacy",
                "upstream": upstream,
                "egress": "direct",
                "auth": {"header": "x-legacy-key", "value": {"from_env": {"var": var}}},
            }
        ]
    }


@pytest.fixture(scope="module")
def seeded(target_factory, tmp_path_factory):
    seed = tmp_path_factory.mktemp("cat-seed") / "catalog.yaml"
    write_seed(seed, "1.0.0", seed_entries("http://127.0.0.1:1"))
    t = target_factory(
        label="cat-seed",
        env={"LOCKSMITH_SEED_PATH": str(seed)},
        config=legacy("SMOKE_X", LEGACY_UP),
    )
    t.seed_file = seed
    return t


def rows(t, kind):
    result = t.cli(kind, "list")
    assert result.code == 0, result.err
    return {row["name"]: row for row in result.json}


def restart_with(t, overlay=None):
    t.restart(config=overlay)


@case(
    "SMK-CAT-040",
    area="CAT",
    kind="positive",
    covers=[
        "beh.seed.catalog",
        "cli.tool.list",
        "cli.model.list",
        "cli.infra.list",
        "admin.GET./admin/operator/models",
        "admin.GET./admin/operator/infra",
    ],
)
def test_seed_and_legacy_entries_load(seeded):
    """kind-taxonomy.md:52 and seed/catalog.yaml:4: first boot loads the catalog with seed=1;
    architecture.md:120-121 legacy config.tools entries migrate with seed=false."""
    tools = rows(seeded, "tool")
    assert {"seed-acc", "seed-off", "seed-own"} <= set(tools)
    assert all(tools[n]["seed"] is True for n in ("seed-acc", "seed-off", "seed-own"))
    assert tools["seed-acc"]["auth"] == {"kind": "bearer", "env_var": "SMOKE_X"}
    assert rows(seeded, "model")["seed-model"]["seed"] is True
    assert rows(seeded, "infra")["seed-infra"]["auth"] == {"kind": "none"}
    legacy_row = tools["cat-legacy"]
    assert legacy_row["seed"] is False and legacy_row["upstream"] == LEGACY_UP
    assert legacy_row["auth"] == {
        "kind": "header",
        "header": "x-legacy-key",
        "env_var": "SMOKE_X",
    }


@case(
    "SMK-CAT-041",
    area="CAT",
    kind="positive",
    covers=[
        "cli.tool.delete",
        "cli.tool.enable",
        "cli.model.delete",
        "cli.model.enable",
        "cli.infra.delete",
        "cli.infra.enable",
        "admin.DELETE./admin/operator/tools/{name}",
        "admin.POST./admin/operator/tools/{name}/enable",
        "admin.DELETE./admin/operator/models/{name}",
        "admin.POST./admin/operator/models/{name}/enable",
        "admin.DELETE./admin/operator/infra/{name}",
        "admin.POST./admin/operator/infra/{name}/enable",
    ],
)
def test_seed_delete_disables_and_enable_restores(seeded):
    """cli-reference.md:161-163,187: delete on a seeded entry disables it (activation
    disabled); enable un-disables it."""
    for kind, name in (
        ("tool", "seed-acc"),
        ("model", "seed-model"),
        ("infra", "seed-infra"),
    ):
        assert seeded.cli(kind, "delete", name).code == 0
        got = seeded.cli(kind, "get", name)
        assert got.code == 0, got.err
        assert got.json["disabled"] is True and got.json["activation"] == "disabled"
        assert seeded.cli(kind, "enable", name).code == 0
        again = seeded.cli(kind, "get", name).json
        assert again["disabled"] is False and again["activation"] == "active"


@case("SMK-CAT-042", area="CAT", kind="positive", covers=["beh.seed.catalog"])
def test_newer_catalog_preserves_overrides_and_disables(seeded):
    """seed/catalog.yaml:5-17 and kind-taxonomy.md:60: a newer catalog updates seed rows,
    keeps operator overrides (seed=0) and sticky disables; architecture.md:187-189 an
    edit to config.tools does not change an existing registration."""
    override = seeded.cli(
        "tool",
        "put",
        "seed-own",
        "--upstream",
        "http://127.0.0.1:3",
        "--auth",
        "none",
        "--egress",
        "direct",
    )
    assert override.code == 0 and override.json["seed"] is False
    assert seeded.cli("tool", "delete", "seed-off").code == 0
    write_seed(seeded.seed_file, "1.1.0", seed_entries("http://127.0.0.1:4"))
    restart_with(seeded, legacy("SMOKE_Y", "http://127.0.0.1:5"))
    tools = rows(seeded, "tool")
    assert (
        tools["seed-acc"]["upstream"] == "http://127.0.0.1:4"
        and tools["seed-acc"]["seed"] is True
    )
    assert (
        tools["seed-own"]["upstream"] == "http://127.0.0.1:3"
        and tools["seed-own"]["seed"] is False
    )
    assert tools["seed-off"]["disabled"] is True
    assert tools["cat-legacy"]["upstream"] == LEGACY_UP
    assert tools["cat-legacy"]["auth"]["env_var"] == "SMOKE_X"


@case("SMK-CAT-043", area="CAT", kind="refusal", covers=["beh.seed.catalog"], codes=[])
def test_malformed_catalog_changes_nothing(seeded):
    """connector-onboarding.md:41-44: a malformed destination anywhere in an applied seed
    catalog rejects that catalog before any entry or seed version changes; equal versions
    skip. Proven by restarting on 1.1.0 (unchanged rows) and then applying a valid 1.2.0."""
    bad = seed_entries("http://127.0.0.1:6") + [
        {
            "name": "seed-bad",
            "kind": "tool",
            "upstream": "ftp://127.0.0.1/x",
            "auth": {"kind": "none"},
        }
    ]
    write_seed(seeded.seed_file, "1.2.0", bad)
    seeded.stop()
    once = seeded.run_daemon_once()
    assert once.returncode != 0, "a malformed catalog was accepted"
    assert "invalid upstream" in once.stdout + once.stderr
    write_seed(seeded.seed_file, "1.1.0", seed_entries("http://127.0.0.1:4"))
    seeded.start_daemon()
    tools = rows(seeded, "tool")
    assert (
        tools["seed-acc"]["upstream"] == "http://127.0.0.1:4"
        and "seed-bad" not in tools
    )
    write_seed(seeded.seed_file, "1.2.0", seed_entries("http://127.0.0.1:6"))
    restart_with(seeded)
    assert rows(seeded, "tool")["seed-acc"]["upstream"] == "http://127.0.0.1:6", (
        "seed version advanced on failure"
    )


@case(
    "SMK-CAT-044",
    area="CAT",
    kind="refusal",
    covers=[
        "admin.PUT./admin/operator/tools/{name}/credential",
        "admin.DELETE./admin/operator/tools/{name}/credential",
    ],
    codes=["unknown_name"],
)
def test_custody_routes_disabled_without_sealing_key(seeded):
    """sealed-state-recovery.md:20: a missing key permits startup but disables that
    domain's custody routes; the registration is untouched."""
    before = seeded.cli("tool", "get", "seed-own").json
    put = uds(
        seeded,
        "PUT",
        "/admin/operator/tools/seed-own/credential",
        {"value": "qa-not-a-credential"},
    )
    assert put.status == 404 and put.code == "unknown_name"
    cleared = uds(seeded, "DELETE", "/admin/operator/tools/seed-own/credential")
    assert cleared.status == 404 and cleared.code == "unknown_name"
    assert seeded.cli("tool", "get", "seed-own").json == before
