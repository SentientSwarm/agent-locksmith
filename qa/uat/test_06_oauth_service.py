"""Journey 6: connect an OAuth service (owner, operator, agent). Guide: docs/guide/06-oauth-service.md."""

import json
import socket
import ssl
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"
PAGE = "06-oauth-service.md"
PORTS = ("LOCKSMITH_PORT", "MCP_PORT", "CALLBACK_PORT")


def case(n, kind="positive", covers=(), persona="OPR"):
    return pytest.mark.case(
        f"UAT-{persona}-OAUTH-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:06-oauth-service#{c}" for c in covers],
    )


def port_open(port):
    with socket.create_connection(("127.0.0.1", int(port)), timeout=1):
        return True


def counts(j):
    ctx = ssl.create_default_context(
        cafile=str(Path(j.var("LOCKSMITH_HOME")) / "pki" / "ca.pem")
    )
    with urllib.request.urlopen(
        f"https://127.0.0.1:{j.var('MCP_PORT')}/counts", timeout=5, context=ctx
    ) as r:
        return json.loads(r.read())


@case(
    1,
    covers=[
        "client-secret",
        "service",
        "keys",
        "config",
        "start",
        "definition",
        "client",
    ],
)
def test_profile_connection_and_client_are_configured(journey):
    journey.prereq(GUIDE / "01-install.md", "home", "operator")
    journey.prereq(GUIDE / "04-enrol-agents.md", "pki")
    journey.prereq(GUIDE / "05-mcp-service.md", "helper")
    journey.run("client-secret")
    secret = (
        (Path(journey.var("LOCKSMITH_HOME")) / "records-client-secret.txt")
        .read_text()
        .strip()
    )
    journey.canaries.add(secret, "oauth-client-secret")
    journey.start("service", ready=lambda: port_open(journey.var("MCP_PORT")))
    journey.run("keys")
    journey.run("config")
    journey.start(
        "start",
        ready=lambda: (
            port_open(journey.var("LOCKSMITH_PORT"))
            and port_open(journey.var("CALLBACK_PORT"))
        ),
    )
    out = journey.run("definition").out
    assert '"activation": "active"' in out
    assert json.loads(journey.run("client").out) == {"state": "configured"}
    assert counts(journey)["received"] == 0, "setup must not contact the provider"


@case(2, covers=["connect", "consent", "callback", "status"], persona="OWN")
def test_owner_approves_in_the_browser(journey):
    out = journey.run("connect").out
    assert '"state": "pending"' in out
    url = json.loads(
        (Path(journey.var("LOCKSMITH_HOME")) / "attempt.json").read_text()
    )["authorization_url"]
    journey.canaries.add(url, "authorization-url")
    journey.canaries.add(parse_qs(urlsplit(url).query)["state"][0], "oauth-state")
    page = journey.browser(trust_dev_ca=True).page
    page.goto(url)
    page.get_by_text("is asking to").wait_for()
    journey.browser_shot("consent")
    page.get_by_role("button", name="Approve").click()
    page.get_by_text("Callback processed").wait_for()
    page.set_viewport_size({"width": 900, "height": 120})
    journey.browser_shot("callback")
    status = journey.run("status").out
    assert '"state": "connected"' in status and '"state": "connected_unbound"' in status
    assert '"identity_verified": true' in status
    assert '"user_id": "ada"' in status


@case(3, covers=["select", "grant", "call"], persona="AGT")
def test_agent_calls_with_the_consented_account(journey):
    selected = journey.run("select").out
    assert '"session_label": "reader"' in selected and '"callable": false' in selected
    assert json.loads(journey.run("grant").out) == {"tools": ["read_record"]}
    before = counts(journey)
    out = journey.run("call").out
    assert '"customer": "Contoso"' in out
    after = counts(journey)
    assert after["tools/call"] == before["tools/call"] + 1
    assert after["unauthorized"] == before["unauthorized"]


@case(4, covers=["refresh"])
def test_deliberate_refresh_keeps_a_verified_account(journey):
    out = journey.run("refresh").out
    assert json.loads(out) == {"state": "connected_unbound", "identity_verified": True}
