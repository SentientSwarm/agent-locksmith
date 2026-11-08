"""Journey 4: enrol agents with bootstrap tokens and certificates. Guide: docs/guide/04-enrol-agents.md."""

import json
import urllib.request
from pathlib import Path

import pytest

from harness.uat import daemon_ready, port_open

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"
PAGE = "04-enrol-agents.md"
PORTS = ("LOCKSMITH_PORT", "REFERENCE_PORT", "BOOTSTRAP_PORT")


def case(n, kind="positive", covers=(), persona="OPR"):
    return pytest.mark.case(
        f"UAT-{persona}-ENROL-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:04-enrol-agents#{c}" for c in covers],
    )


def counts(j):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{j.var('REFERENCE_PORT')}/counts", timeout=5
    ) as r:
        return json.loads(r.read())


@case(1, covers=["pki", "config", "service", "start", "register-service"])
def test_tls_listeners_start(journey):
    journey.prereq(GUIDE / "01-install.md", "home", "operator")
    out = journey.run("pki").out
    assert "edge-bot.pem" in out and "server.pem" in out
    journey.run("config")
    journey.start("service", ready=lambda: port_open(journey.var("REFERENCE_PORT")))
    journey.start(
        "start",
        ready=lambda: daemon_ready(journey, "LOCKSMITH_PORT", "BOOTSTRAP_PORT"),
    )
    log = journey.log("start")
    assert "bootstrap-only listener bound" in log
    assert "registered" in journey.run("register-service").out


@case(2, covers=["mint", "enrol"], persona="AGT")
def test_agent_enrols_with_a_bootstrap_token(journey):
    journey.run("mint")
    out = journey.run("enrol").out
    assert f"enrolled as {journey.var('EDGE_BOT_ID')}" in out
    listed = journey.sh("locksmith --format json agent list").json
    edge = next(a for a in listed if a["name"] == "edge-bot")
    assert edge["tool_allowlist"] == ["accounts"]


@case(3, kind="refusal", covers=["enrol-again"], persona="AGT")
def test_spent_bootstrap_token_is_refused(journey):
    out = journey.run("enrol-again").out
    assert "HTTP 401" in out
    names = {a["name"] for a in journey.sh("locksmith --format json agent list").json}
    assert "edge-bot-2" not in names


@case(4, covers=["select"], persona="AGT")
def test_enrolled_agent_calls_over_tls(journey):
    assert journey.run("select").out.strip() == "X"


@case(5, covers=["bind-cert", "mtls-call"], persona="AGT")
def test_certificate_alone_identifies_the_agent(journey):
    journey.run("bind-cert")
    before = counts(journey)
    assert journey.run("mtls-call").out.strip() == "X"
    assert counts(journey)["X"] == before["X"] + 1


@case(6, kind="refusal", covers=["revoke"])
def test_revoked_certificate_is_refused_without_dispatch(journey):
    before = counts(journey)
    out = journey.run("revoke").out
    assert "HTTP 401" in out
    assert counts(journey)["received"] == before["received"]
