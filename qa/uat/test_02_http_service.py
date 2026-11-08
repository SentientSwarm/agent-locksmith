"""Journey 2: connect an HTTP service (operator, agent). Guide: docs/guide/02-http-service.md."""

import json
import urllib.request

from pathlib import Path

import pytest

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"

PAGE = "02-http-service.md"
PORTS = ("LOCKSMITH_PORT", "REFERENCE_PORT")


def case(n, kind="positive", covers=(), persona="OPR"):
    return pytest.mark.case(
        f"UAT-{persona}-HTTP-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:02-http-service#{c}" for c in covers],
    )


def up(url):
    with urllib.request.urlopen(url, timeout=2) as r:
        return r.status == 200


def counts(j):
    with urllib.request.urlopen(
        f"http://127.0.0.1:{j.var('REFERENCE_PORT')}/counts", timeout=5
    ) as r:
        return json.loads(r.read())


@case(1, covers=["service", "credentials", "start", "register-service"])
def test_service_registers_active(journey):
    journey.prereq(GUIDE / "01-install.md", "home", "operator", "config")
    journey.start(
        "service",
        ready=lambda: up(f"http://127.0.0.1:{journey.var('REFERENCE_PORT')}/counts"),
    )
    journey.run("credentials")
    journey.start(
        "start",
        ready=lambda: up(f"http://127.0.0.1:{journey.var('LOCKSMITH_PORT')}/livez"),
    )
    out = journey.run("register-service").out
    assert "active" in out
    assert "synthetic-private-account" not in out


@case(2, covers=["register-agent"])
def test_agent_registered_with_allowlist(journey):
    out = journey.run("register-agent").out
    agent_id = journey.var("BILLING_BOT_ID")
    assert agent_id and f"public_id: {agent_id}" in out
    assert journey.var("BILLING_BOT_TOKEN").startswith("lk_")
    assert "accounts" in out


@case(3, covers=["select-account", "call", "discover"], persona="AGT")
def test_agent_calls_as_selected_account(journey):
    before = counts(journey)
    listed = journey.run("select-account").out
    assert "ACCOUNTS_X_TOKEN" in listed
    out = journey.run("call").out
    assert out.splitlines()[0] == "X"
    assert counts(journey)["X"] == before["X"] + 1
    tools = journey.run("discover").out
    assert '"accounts"' in tools


@case(4, covers=["second-agent"], persona="AGT")
def test_second_agent_gets_its_own_account(journey):
    before = counts(journey)
    out = journey.run("second-agent").out
    assert out.strip().splitlines()[-1] == "Y"
    after = counts(journey)
    assert (after["Y"], after["X"]) == (before["Y"] + 1, before["X"])


@case(5, kind="refusal", covers=["deny"])
def test_unselected_account_is_refused_with_zero_dispatch(journey):
    before = counts(journey)
    out = journey.run("deny").out
    assert "HTTP 403" in out
    assert '"code":"tool_not_allowed"' in out.replace(" ", "")
    assert counts(journey)["received"] == before["received"] + 0


@case(6, covers=["repair"])
def test_reselection_restores_access_without_restart(journey):
    out = journey.run("repair").out
    assert out.strip().splitlines()[-1] == "X"


@case(7, covers=["audit"], persona="AUD")
def test_audit_shows_allowed_and_denied_calls(journey):
    out = journey.run("audit").out
    assert "allowed" in out
    assert "denied" in out
