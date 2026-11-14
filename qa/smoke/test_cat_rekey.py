"""Offline stored-credential re-key (`locksmith rekey-credentials`).

Docs: docs/user/operator/sealed-state-recovery.md (rotate the stored sealing key) and
docs/user/cli-reference.md. Runs the documented command with no operator token against a
stopped daemon's database, then restarts the daemon under the new key. Cases run in order
on one target.
"""

import pytest

from fakes.cat_support import sealing_key
from fakes.cat_uds import uds
from harness.target import SMOKE_Y

case = pytest.mark.case
REKEY = "cli.rekey-credentials"
KEY_ENV = "LOCKSMITH_CREDENTIAL_SEALING_KEY"


@pytest.fixture(scope="module")
def rk(target_factory):
    """`cat-rk` selects an operator-stored value for agent `cat-rk-agent`; daemon stopped."""
    t = target_factory(label="cat-rekey", env={KEY_ENV: sealing_key()})
    put = t.cli(
        "tool", "put", "cat-rk", "--upstream", t.upstream_url,
        "--auth", "bearer=SMOKE_X", "--egress", "direct",
    )  # fmt: skip
    assert put.code == 0, put.err
    t.canaries.add(SMOKE_Y, "cat-stored-value")
    stored = uds(
        t, "PUT", "/admin/operator/tools/cat-rk/credential", {"value": SMOKE_Y}
    )
    assert stored.status == 200, stored.text
    reg = t.cli("agent", "register", "--name", "cat-rk-agent", "--allowlist", "cat-rk")
    assert reg.code == 0, reg.err
    t.agent_token = reg.json["token"]
    ref = stored.json["secret_ref"]
    select = t.cli(
        "agent",
        "set-credential",
        reg.json["public_id"],
        "cat-rk",
        "--stored-bearer-ref",
        ref,
    )
    assert select.code == 0, select.err
    t.stop()
    t.db = str(t.work / "locksmith.db")
    return t


def key_file(t, name, key, mode=0o600):
    t.canaries.add(key, f"cat-rekey-{name}")
    return str(t.write_file(name, key + "\n", mode))


def rekey(t, old, new):
    return t.cli(
        "rekey-credentials", "--database", t.db, "--old-key-file", old,
        "--new-key-file", new, use_op_token=False, socket_flag=False, fmt=None,
    )  # fmt: skip


def reaches_y(t):
    t.start_daemon()
    try:
        reply = t.http("GET", "/api/cat-rk/check", token=t.agent_token)
        return reply.status == 200 and reply.text == "Y"
    finally:
        t.stop()


@case("SMK-CAT-090", area="CAT", kind="refusal", covers=[REKEY])
def test_rekey_refuses_a_key_file_others_can_read(rk):
    """sealed-state-recovery.md: a key file group or others can read is refused (exit 2)."""
    old = key_file(rk, "old-open.key", rk.extra_env[KEY_ENV], mode=0o644)
    new = key_file(rk, "new-a.key", sealing_key())
    result = rekey(rk, old, new)
    assert result.code == 2
    assert "old-open.key" in result.err


@case("SMK-CAT-091", area="CAT", kind="refusal", covers=[REKEY])
def test_rekey_with_a_wrong_old_key_changes_nothing(rk):
    """sealed-state-recovery.md: if the old key cannot open a row, exit 1, nothing changed;
    the daemon still serves the stored value under its current key."""
    result = rekey(
        rk,
        key_file(rk, "wrong.key", sealing_key()),
        key_file(rk, "new-b.key", sealing_key()),
    )
    assert result.code == 1
    assert "nothing was changed" in result.err
    assert reaches_y(rk)


@case("SMK-CAT-092", area="CAT", kind="positive", covers=[REKEY])
def test_rekey_moves_stored_values_to_the_new_key(rk):
    """sealed-state-recovery.md: re-key offline, prints {"rekeyed":N}, then start the daemon
    with the new key: the selected stored value still reaches the upstream."""
    new_key = sealing_key()
    old = key_file(rk, "old.key", rk.extra_env[KEY_ENV])
    result = rekey(rk, old, key_file(rk, "new.key", new_key))
    assert result.code == 0, result.err
    assert result.json == {"rekeyed": 1}
    rk.extra_env[KEY_ENV] = new_key
    assert reaches_y(rk)
