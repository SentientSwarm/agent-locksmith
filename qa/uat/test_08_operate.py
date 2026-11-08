"""Journey 8: day-two operations (operator, agent). Guide: docs/guide/08-operate.md."""

import json
import signal
import socket
from pathlib import Path

import pytest

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"
PAGE = "08-operate.md"
PORTS = ("LOCKSMITH_PORT", "REFERENCE_PORT")
HTTP = GUIDE / "02-http-service.md"


def case(n, kind="positive", covers=(), persona="OPR"):
    return pytest.mark.case(
        f"UAT-{persona}-OPERATE-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:08-operate#{c}" for c in covers],
    )


def port_open(port):
    with socket.create_connection(("127.0.0.1", int(port)), timeout=1):
        return True


def restart(j):
    """The reader's Control-C and rerun of journey 2's start command."""
    assert j.stop("daemon", signal.SIGTERM) == 0
    start_daemon(j)


def start_daemon(j):
    j.start_from(
        HTTP, "start", "daemon", ready=lambda: port_open(j.var("LOCKSMITH_PORT"))
    )


@case(1, covers=["agent-rotate"], persona="AGT")
def test_agent_rotates_its_own_token(journey):
    journey.prereq(GUIDE / "01-install.md", "home", "operator", "config")
    journey.start_from(
        HTTP,
        "service",
        "service",
        ready=lambda: port_open(journey.var("REFERENCE_PORT")),
    )
    journey.prereq(HTTP, "credentials")
    start_daemon(journey)
    journey.prereq(HTTP, "register-service", "register-agent", "select-account")
    old = journey.var("BILLING_BOT_TOKEN")
    out = journey.run("agent-rotate").out
    lines = out.strip().splitlines()
    assert json.loads(lines[0]) == {"name": "billing-bot", "allowlist": ["accounts"]}
    assert lines[-2:] == ["401", "200"]
    assert journey.var("BILLING_BOT_TOKEN") != old


@case(2, covers=["rotate-operator", "operator-check"])
def test_operator_token_rotates_on_restart(journey):
    journey.run("rotate-operator")
    restart(journey)
    out = journey.run("operator-check").out
    assert "old operator token refused" in out
    assert out.strip().splitlines()[-1] == "1"


@case(3, covers=["backup", "restore", "after-restore"])
def test_backup_restores_agents_and_history(journey):
    out = journey.run("backup").out
    assert "locksmith.db" in out
    assert journey.stop("daemon", signal.SIGTERM) == 0
    journey.run("restore")
    start_daemon(journey)
    lines = journey.run("after-restore").out.strip().splitlines()
    assert lines[0] == "X"
    assert int(lines[-1]) >= 2


@case(4, kind="refusal", covers=["revoke"])
def test_revoked_agent_is_refused(journey):
    out = journey.run("revoke").out
    assert "HTTP 401" in out
    assert json.loads(out.strip().splitlines()[-1]) == {
        "name": "billing-bot",
        "revoked": True,
    }
