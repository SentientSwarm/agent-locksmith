"""Offline account-binding migration (`locksmith migrate-bindings`).

Docs: docs/user/concepts/migrating-account-bindings.md and docs/user/cli-reference.md:374-388.
Runs the documented preview/apply commands with no operator token against a stopped
daemon's database. Cases run in order on one target.
"""

import json

import pytest

case = pytest.mark.case


@pytest.fixture(scope="module")
def mig(target_factory):
    """`cat-acc` routed to X; `cat-mapped` and `cat-unmapped` granted it without selections."""
    t = target_factory(label="cat-migrate")
    put = t.cli(
        "tool",
        "put",
        "cat-acc",
        "--upstream",
        t.upstream_url,
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
    )
    assert put.code == 0, put.err
    t.agents = {}
    for name in ("cat-mapped", "cat-unmapped"):
        reg = t.cli("agent", "register", "--name", name, "--allowlist", "cat-acc")
        assert reg.code == 0, reg.err
        t.agents[name] = reg.json
    t.stop()
    t.db = str(t.work / "locksmith.db")
    t.cfg = str(t.work / "config.yaml")
    return t


def offline(t, *args):
    """The documented command line: no socket, no operator token."""
    return t.cli(
        "migrate-bindings", *args, use_op_token=False, socket_flag=False, fmt=None
    )


def preview(t):
    result = offline(
        t, "preview", "--grants", "--database", t.db, "--legacy-config", t.cfg
    )
    assert result.code == 0, result.err
    assert isinstance(result.json, dict), "preview did not print a JSON plan"
    return result.json


def agent_row(plan, name):
    return next(a for a in plan["agents"] if a["name"] == name)


def review(t, plan, name, filename):
    """Change only selected flags, for one agent's proposal and grant (lines 90-94)."""
    agent_id = agent_row(plan, name)["id"]
    for entry in plan["entries"]:
        if entry["agent_id"] == agent_id and entry["action"] == "propose":
            entry["selected"] = True
    for grant in plan["grants"]:
        if grant["agent_id"] == agent_id:
            grant["selected"] = True
    return str(t.write_file(filename, json.dumps(plan)))


def apply(t, plan_path):
    return offline(
        t, "apply", "--database", t.db, "--legacy-config", t.cfg, "--plan", plan_path
    )


def bindings(t, name):
    result = t.cli("agent", "credentials", "list", t.agents[name]["public_id"])
    assert result.code == 0, result.err
    return result.json


@case(
    "SMK-CAT-080",
    area="CAT",
    kind="refusal",
    covers=["cli.migrate-bindings.apply"],
    codes=["migration_invalid"],
)
def test_invalid_plan_exits_2(mig):
    """migrating-account-bindings.md:147-150: invalid inputs exit 2 (migration_invalid),
    with no writes: a fresh preview reports the same snapshot."""
    before = preview(mig)["snapshot"]
    garbage = str(mig.write_file("cat-garbage.json", "{not a plan"))
    result = apply(mig, garbage)
    assert result.code == 2 and "migration_invalid" in result.err, (
        result.code,
        result.err,
    )
    plan = preview(mig)
    plan["entries"][0]["selected"] = "yes"
    typed = str(mig.write_file("cat-typed.json", json.dumps(plan)))
    result = apply(mig, typed)
    assert result.code == 2 and "migration_invalid" in result.err, (
        result.code,
        result.err,
    )
    assert preview(mig)["snapshot"] == before


@case(
    "SMK-CAT-081",
    area="CAT",
    kind="refusal",
    covers=["cli.migrate-bindings.preview", "cli.migrate-bindings.apply"],
    codes=["migration_database"],
)
def test_missing_database_exits_1_without_creating_it(mig):
    """migrating-account-bindings.md:37,47-48,147-148: preview does not create databases;
    database failures exit 1 (migration_database)."""
    missing = mig.work / "cat-absent.db"
    result = offline(mig, "preview", "--grants", "--database", str(missing))
    assert result.code == 1 and "migration_database" in result.err, (
        result.code,
        result.err,
    )
    plan = review(mig, preview(mig), "cat-mapped", "cat-for-missing.json")
    result = offline(mig, "apply", "--database", str(missing), "--plan", plan)
    assert result.code == 1 and "migration_database" in result.err, (
        result.code,
        result.err,
    )
    assert not missing.exists()


@case(
    "SMK-CAT-082",
    area="CAT",
    kind="refusal",
    covers=["cli.migrate-bindings.apply"],
    codes=["migration_conflict"],
)
def test_drift_after_review_exits_5_without_writes(mig):
    """migrating-account-bindings.md:133-139: relevant inventory changes after preview
    (here the registration's auth) produce exit 5 migration_conflict with no partial writes."""
    plan = review(mig, preview(mig), "cat-mapped", "cat-drifted.json")
    reauth(mig, "SMOKE_Y")
    result = apply(mig, plan)
    assert result.code == 5 and "migration_conflict" in result.err, (result.code, result.err)
    mig.start_daemon()
    try:
        assert bindings(mig, "cat-mapped") == []
    finally:
        mig.stop()
        reauth(mig, "SMOKE_X")


def reauth(t, env):
    """Change only the template auth reference (same destination keeps grants)."""
    t.start_daemon()
    try:
        put = t.cli("tool", "put", "cat-acc", "--upstream", t.upstream_url, "--auth", f"bearer={env}",
                    "--egress", "direct")
        assert put.code == 0, put.err
    finally:
        t.stop()


@case(
    "SMK-CAT-083",
    area="CAT",
    kind="positive",
    covers=["cli.migrate-bindings.preview", "cli.migrate-bindings.apply"],
)
def test_reviewed_plan_applies_once_and_routes(mig):
    """migrating-account-bindings.md:65-72,90-94,119-131,152-156: preview prints a plan;
    apply of selected proposals prints {"inserted":N}, an unchanged repeat {"inserted":0};
    after restart the mapped caller reaches X and the unmapped caller is 403 with zero
    upstream requests."""
    plan = preview(mig)
    assert {"snapshot", "agents", "entries", "grants"} <= set(plan)
    mapped_id = agent_row(plan, "cat-mapped")["id"]
    proposal = next(e for e in plan["entries"] if e["agent_id"] == mapped_id)
    assert proposal["action"] == "propose" and proposal["selected"] is False
    reviewed = review(mig, plan, "cat-mapped", "cat-reviewed.json")
    first = apply(mig, reviewed)
    assert first.code == 0, first.err
    assert first.json == {"inserted": 1}
    repeat = apply(mig, reviewed)
    assert repeat.code == 0, repeat.err
    assert repeat.json == {"inserted": 0}
    mig.start_daemon()
    assert bindings(mig, "cat-mapped")[0]["auth_spec"] == {
        "kind": "bearer",
        "env_var": "SMOKE_X",
    }
    before = mig.upstream_counts()
    mapped = mig.http(
        "GET", "/api/cat-acc/check", token=mig.agents["cat-mapped"]["token"]
    )
    assert mapped.status == 200 and mapped.text == "X"
    after = mig.upstream_counts()
    assert after["X"] == before["X"] + 1
    unmapped = mig.http(
        "GET", "/api/cat-acc/check", token=mig.agents["cat-unmapped"]["token"]
    )
    assert unmapped.status == 403
    assert mig.upstream_counts() == after, "an unmapped caller reached the upstream"
