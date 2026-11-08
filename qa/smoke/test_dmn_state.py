"""Daemon state lifecycle: migrations, single instance, restart-only configuration.

Cases share one dedicated daemon and run in file order; each leaves it live.
"""

import pytest
import yaml

from fakes.dmn_support import (
    mint_operator,
    mirror_files,
    mirror_lines,
    run_once,
    wait_for,
)
from harness.target import free_port, merge

case = pytest.mark.case
RESTART_ONLY = "beh.config.restart-only"
SINGLE = "beh.daemon.single-instance"


@pytest.fixture(scope="module")
def st(target_factory):
    return target_factory(label="dmn-state", upstream=False)


def agent_names(t) -> list[str]:
    listed = t.cli("agent", "list")
    assert listed.code == 0, listed.err
    return [a["name"] for a in listed.json]


@case(
    "SMK-DMN-020", area="DMN", kind="positive", covers=["beh.migrations.forward-only"]
)
def test_fresh_database_migrates_and_survives_restart(st):
    """architecture.md:114-115 (open SQLite, run migrations at startup) and architecture.md:136-138
    (state that must outlive locksmithd lives in the DB): a fresh database is usable at once and a
    restart re-opens the migrated database with its rows intact."""
    assert agent_names(st) == []
    reg = st.cli("agent", "register", "--name", "dmn-persist")
    assert reg.code == 0, reg.err
    st.restart()
    assert "dmn-persist" in agent_names(st)


def second_daemon_config(st, **db) -> dict:
    return merge(
        st.config,
        {
            "listen": {
                "port": free_port(),
                "admin_socket": {"path": str(st.work / "second.sock")},
            },
            **({"database": db} if db else {}),
        },
    )


@case("SMK-DMN-021", area="DMN", kind="refusal", covers=[SINGLE])
def test_second_daemon_on_same_database_refused(st):
    """changes/native-mcp.md:57-62: a process-lifetime `<database>.daemon.lock` is held; a second
    daemon using that state refuses before listeners. Run one daemon per database."""
    once = run_once(st, "dmn-second", second_daemon_config(st))
    assert once.code == 1, f"expected exit 1, got {once.code}"
    assert "database already owned by another daemon" in once.output
    assert not (st.work / "second.sock").exists(), (
        "second daemon bound its admin socket"
    )
    assert st.http("GET", "/livez").status == 200


@case("SMK-DMN-022", area="DMN", kind="corner", covers=[SINGLE])
def test_relative_path_alias_is_the_same_lock(st):
    """changes/native-mcp.md:58: equivalent ordinary relative/absolute paths resolve to the same lock."""
    cfg = second_daemon_config(st, path="./locksmith.db")
    once = run_once(st, "dmn-second-relative", cfg, cwd=st.work)
    assert once.code == 1, f"expected exit 1, got {once.code}"
    assert "database already owned by another daemon" in once.output


@case("SMK-DMN-023", area="DMN", kind="positive", covers=[SINGLE])
def test_owner_keeps_serving_and_lock_releases_on_stop(st):
    """changes/native-mcp.md:57-62: the refusal leaves the owning daemon serving; the lock is
    process-lifetime, so once the owner stops a new daemon on the same database starts."""
    assert run_once(st, "dmn-second-again", second_daemon_config(st)).code == 1
    assert st.cli("agent", "list").code == 0
    assert st.stop() == 0
    st.start()
    assert "dmn-persist" in agent_names(st)


@case("SMK-DMN-024", area="DMN", kind="positive", covers=[RESTART_ONLY])
def test_config_edit_applies_only_after_restart(st):
    """architecture.md:166-172: the YAML is read once at startup; no reload; restart to apply an edit.

    The edit adds an audit JSONL mirror: an audited write before the restart must not create it,
    one after the restart must land in it.
    """
    mirror = st.work / "restart-mirror"
    edited = merge(
        yaml.safe_load((st.work / "config.yaml").read_text()),
        {"audit": {"jsonl_path": str(mirror / "audit.jsonl")}},
    )
    st.write_file("config.yaml", yaml.safe_dump(edited, sort_keys=False))
    before = st.cli("agent", "register", "--name", "dmn-before-restart")
    assert before.code == 0, before.err
    assert st.http("GET", "/livez").status == 200, "daemon did not survive the file edit"
    assert mirror_files(mirror) == [], "edit applied without a restart"
    st.restart()
    after = st.cli("agent", "register", "--name", "dmn-after-restart")
    assert after.code == 0, after.err
    lines = wait_for(lambda: [ln for ln in mirror_lines(mirror) if after.json["public_id"] in ln], timeout=5)
    assert lines, "edit not applied after restart"
    assert not any(before.json["public_id"] in ln for ln in mirror_lines(mirror))


@case("SMK-DMN-025", area="DMN", kind="positive", covers=[RESTART_ONLY])
def test_operator_file_replacement_applies_only_after_restart(st):
    """architecture.md:168-170: operator_credentials_path is read once at startup; restart to apply."""
    old = st.op_token
    text, new = mint_operator(st, "dmn-rotated")
    st.write_file("operators.yaml", text)
    assert st.cli("agent", "list", op_token=old).code == 0, (
        "old operator lost before restart"
    )
    before = st.cli("agent", "list", op_token=new)
    assert before.code == 3, (
        f"new operator accepted before restart (exit {before.code})"
    )
    st.restart()
    st.op_token = new
    assert st.cli("agent", "list", op_token=new).code == 0
    after = st.cli("agent", "list", op_token=old)
    assert after.code == 3, (
        f"replaced operator still accepted after restart (exit {after.code})"
    )
