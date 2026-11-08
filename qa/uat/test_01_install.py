"""Journey 1: install and first run (operator). Guide: docs/guide/01-install.md."""

import json
import signal
import stat
import urllib.request
from pathlib import Path

import pytest

PAGE = "01-install.md"
PORTS = ("LOCKSMITH_PORT",)


def case(n, kind="positive", covers=()):
    return pytest.mark.case(
        f"UAT-OPR-INSTALL-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:01-install#{c}" for c in covers],
    )


def live(j):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{j.var('LOCKSMITH_PORT')}/livez", timeout=2
    ) as r:
        return r.status == 200


@case(1, covers=["versions"])
def test_both_programs_report_the_build_version(journey):
    out = journey.run("versions").out
    info = json.loads(journey.sh("locksmithd --build-info").out)
    assert f"locksmith {info['version']}" in out
    assert f"locksmithd {info['version']}" in out


@case(2, covers=["home", "operator"])
def test_operator_file_holds_only_a_hash(journey):
    journey.run("home")
    out = journey.run("operator").out
    assert "operator token loaded" in out
    home = Path(journey.var("LOCKSMITH_HOME"))
    assert stat.S_IMODE(home.stat().st_mode) == 0o700
    ops = home / "operators.yaml"
    assert stat.S_IMODE(ops.stat().st_mode) == 0o600
    token = journey.var("LOCKSMITH_OP_TOKEN")
    assert token and token not in ops.read_text()
    assert "$argon2" in ops.read_text()


@case(3, covers=["config", "start", "health"])
def test_daemon_starts_and_answers(journey):
    journey.run("config")
    journey.start("start", ready=lambda: live(journey))
    out = journey.run("health").out
    assert '"version":"' in out.replace(" ", "")
    info = json.loads(journey.sh("locksmithd --build-info").out)
    assert info["version"] in out


@case(4, covers=["first-command"])
def test_operator_reaches_the_admin_socket(journey):
    journey.run("first-command")
    socket = Path(journey.var("LOCKSMITH_SOCKET"))
    assert socket.is_socket()


@case(5, kind="refusal", covers=["no-token"])
def test_cli_without_operator_token_exits_3(journey):
    out = journey.run("no-token").out
    assert "LOCKSMITH_OP_TOKEN env var not set" in out
    assert "exit status 3" in out


@case(6, covers=["stop"])
def test_sigterm_shuts_down_cleanly(journey):
    assert journey.stop("start", signal.SIGTERM) == 0
    assert "clean shutdown complete" in journey.log("start")
