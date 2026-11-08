"""Journey 3: keep credentials in Locksmith (operator). Guide: docs/guide/03-credential-custody.md."""

import json
import signal
import urllib.request
from pathlib import Path

import pytest

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"
PAGE = "03-credential-custody.md"
PORTS = ("LOCKSMITH_PORT", "REFERENCE_PORT")
OP_VALUES = {"op://Agents/accounts-y/credential": "synthetic-private-account-y"}


def case(n, kind="positive", covers=()):
    return pytest.mark.case(
        f"UAT-OPR-CUSTODY-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:03-credential-custody#{c}" for c in covers],
    )


def up(url):
    with urllib.request.urlopen(url, timeout=2) as r:
        return r.status == 200


def live(j):
    return up(f"http://127.0.0.1:{j.var('LOCKSMITH_PORT')}/livez")


def counts(j):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{j.var('REFERENCE_PORT')}/counts", timeout=5
    ) as r:
        return json.loads(r.read())


def stub_op(j):
    """A stand-in `op` that answers `op read <ref>` from a fixed synthetic table."""
    bin_dir = j.work / "op-stub"
    bin_dir.mkdir()
    table = bin_dir / "values.json"
    table.write_text(json.dumps(OP_VALUES))
    script = bin_dir / "op"
    script.write_text(
        "#!/usr/bin/env python3\nimport json, sys\n"
        f"v = json.load(open({str(table)!r})).get(sys.argv[2] if len(sys.argv) == 3 and sys.argv[1] == 'read' else '')\n"
        "sys.exit(1) if v is None else print(v)\n"
    )
    script.chmod(0o700)
    j.env["PATH"] = f"{bin_dir}:{j.env['PATH']}"
    j.substitute(
        "1Password CLI replaced by a stub `op read` returning synthetic values"
    )


@case(1, covers=["sealing-key", "service", "start"])
def test_daemon_mounts_the_sealed_store(journey):
    journey.prereq(GUIDE / "01-install.md", "home", "operator", "config")
    journey.run("sealing-key")
    journey.secret_file("credential-sealing.key", "credential-sealing-key")
    stub_op(journey)
    journey.start(
        "service",
        ready=lambda: up(f"http://127.0.0.1:{journey.var('REFERENCE_PORT')}/counts"),
    )
    journey.start("start", ready=lambda: live(journey))
    assert "stored-credential routes not mounted" not in journey.log("start")


@case(2, covers=["register", "seal", "call"])
def test_sealed_value_selects_the_account(journey):
    journey.run("register")
    out = journey.run("seal").out
    assert "stored_bearer" in out
    assert "synthetic-private-account-x" not in out
    before = counts(journey)
    assert journey.run("call").out.strip() == "X"
    assert counts(journey)["X"] == before["X"] + 1


@case(3, covers=["call-after-restart"])
def test_sealed_value_survives_restart(journey):
    assert journey.stop("start", signal.SIGTERM) == 0
    journey.start("start", ready=lambda: live(journey), shot=False)
    assert journey.run("call-after-restart").out.strip() == "X"


@case(4, covers=["op-select", "op-call"])
def test_op_reference_selects_the_account(journey):
    out = journey.run("op-select").out
    assert "op://Agents/accounts-y/credential" in out
    assert "synthetic-private-account-y" not in out
    assert journey.run("op-call").out.strip() == "Y"


@case(5, kind="refusal", covers=["start-without-key", "no-key-call"])
def test_missing_sealing_key_fails_closed(journey):
    assert journey.stop("start", signal.SIGTERM) == 0
    journey.start("start-without-key", ready=lambda: live(journey))
    before = counts(journey)
    out = journey.run("no-key-call").out
    assert "HTTP 503" in out and "credential_unresolved" in out
    assert counts(journey)["received"] == before["received"]
