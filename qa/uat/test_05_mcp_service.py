"""Journey 5: connect an MCP service (operator, agent). Guide: docs/guide/05-mcp-service.md."""

import json
import socket
import ssl
import urllib.request
from pathlib import Path

import pytest

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"
PAGE = "05-mcp-service.md"
PORTS = ("LOCKSMITH_PORT", "MCP_PORT")


def case(n, kind="positive", covers=(), persona="OPR"):
    return pytest.mark.case(
        f"UAT-{persona}-MCP-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:05-mcp-service#{c}" for c in covers],
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


@case(1, covers=["service", "config", "start", "register"])
def test_mcp_connection_registers_active(journey):
    journey.prereq(GUIDE / "01-install.md", "home", "operator")
    journey.prereq(GUIDE / "04-enrol-agents.md", "pki")
    journey.start("service", ready=lambda: port_open(journey.var("MCP_PORT")))
    journey.run("config")
    journey.start("start", ready=lambda: port_open(journey.var("LOCKSMITH_PORT")))
    out = journey.run("register").out
    assert "protocol: mcp_streamable_http" in out and "activation: active" in out


@case(2, covers=["observe"])
def test_observation_lists_both_tools(journey):
    out = journey.run("observe").out
    assert "read_record" in out and "delete_record" in out


@case(3, covers=["review", "grant"])
def test_review_and_grant_one_tool(journey):
    journey.run("review")
    out = journey.run("grant").out
    assert json.loads(out) == {"tools": ["read_record"]}


@case(4, covers=["helper", "session", "call"], persona="AGT")
def test_agent_sees_and_calls_only_the_granted_tool(journey):
    journey.run("helper")
    assert json.loads(journey.run("session").out) == ["read_record"]
    before = counts(journey)
    out = journey.run("call").out
    assert '"total": "1250.00"' in out
    assert counts(journey)["tools/call"] == before["tools/call"] + 1


@case(5, kind="refusal", covers=["refuse"], persona="AGT")
def test_ungranted_tool_is_refused_before_the_server(journey):
    before = counts(journey)
    out = journey.run("refuse").out
    assert "tool_not_approved" in out
    assert counts(journey)["tools/call"] == before["tools/call"]
