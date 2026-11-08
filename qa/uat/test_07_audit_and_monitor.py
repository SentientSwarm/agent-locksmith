"""Journey 7: audit and monitor (auditor, operator). Guide: docs/guide/07-audit-and-monitor.md."""

import json
from pathlib import Path

import pytest

from harness.uat import daemon_ready, port_open

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "guide"
PAGE = "07-audit-and-monitor.md"
PORTS = ("LOCKSMITH_PORT", "REFERENCE_PORT")


def case(n, kind="positive", covers=(), persona="AUD"):
    return pytest.mark.case(
        f"UAT-{persona}-AUDIT-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:07-audit-and-monitor#{c}" for c in covers],
    )


@case(1, covers=["config", "service", "start", "traffic"], persona="OPR")
def test_records_configured_and_traffic_made(journey):
    journey.prereq(GUIDE / "01-install.md", "home", "operator")
    journey.run("config")
    journey.start("service", ready=lambda: port_open(journey.var("REFERENCE_PORT")))
    journey.start("start", ready=lambda: daemon_ready(journey, "LOCKSMITH_PORT"))
    journey.prereq(
        GUIDE / "02-http-service.md",
        "register-service",
        "register-agent",
        "select-account",
    )
    out = journey.run("traffic").out
    assert "200 allowed" in out and "401 bad token" in out and "403 not allowed" in out
    assert journey.log("start").strip() == "", (
        "with logging.file set, stdout stays empty"
    )


@case(2, covers=["health"], persona="OPR")
def test_health_endpoints_answer(journey):
    out = journey.run("health").out
    assert out.count("(HTTP 200)") == 3


@case(3, covers=["audit-denied", "audit-operator", "jsonl"])
def test_audit_records_refusals_and_admin_changes(journey):
    denied = journey.run("audit-denied").out
    assert "authz_denied\tbilling-bot\tpayroll\t403\tnot_in_allowlist" in denied
    assert "auth_failure" in denied
    operator = journey.run("audit-operator").out
    assert "admin" in operator
    lines = journey.run("jsonl").out.splitlines()
    assert lines[0].startswith("audit.jsonl.")
    rows = [json.loads(line) for line in lines[1:]]
    assert rows and all(set(r) == {"event", "decision", "tool", "status"} for r in rows)


@case(4, covers=["oplog", "process-log"], persona="OPR")
def test_operational_and_process_logs_are_readable(journey):
    oplog = journey.run("oplog").out
    # Operator-path agent registration writes no `agent` event yet (AGENT-221).
    assert (
        "registry\tregistration_created" in oplog and "config\tconfig_loaded" in oplog
    )
    process = [json.loads(line) for line in journey.run("process-log").out.splitlines()]
    assert process and all("level" in p for p in process)


@case(5, covers=["export"])
def test_export_lists_agents(journey):
    out = journey.run("export").out
    assert out.startswith("billing-bot\taccounts\t")
