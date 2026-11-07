"""Audit queries and the operational-log stream (cli-reference.md:258-276,
error-envelope.md:95-114, README.md:113-117, 243)."""

import time

import pytest

from fakes.adm_flows import register, wrong_secret
from fakes.adm_uds import uds

case = pytest.mark.case
AUDIT = "admin.GET./admin/operator/audit"
LOGS = "admin.GET./admin/operator/logs"
DOC_CLASSES = ("proxy", "operator", "security")


@pytest.fixture(scope="module")
def audited(t1, accounts):
    agent = register(t1, "adm-audited", allowlist=accounts)
    bad = t1.http("GET", "/api/accounts/check", token=wrong_secret(agent["token"]))
    assert bad.status == 401
    return agent


def query(t1, *flags):
    out = t1.cli("audit", "query", *flags)
    assert out.code == 0, out.err
    return out.json


@case("SMK-ADM-050", area="ADM", kind="positive", covers=["cli.audit.query", AUDIT])
def test_audit_filters_narrow_results(t1, audited):
    """`audit query` filters by agent, event class, decision, time and page size
    (cli-reference.md:265-276)."""
    rows = query(t1, "--agent", audited["id"])
    assert rows and all(r["agent_public_id"] == audited["id"] for r in rows)
    assert "agent_create" in {r["event"] for r in rows}
    ops = query(
        t1,
        "--agent",
        audited["id"],
        "--event-class",
        "operator",
        "--decision",
        "allowed",
    )
    assert ops and all(
        r["event_class"] == "operator" and r["decision"] == "allowed" for r in ops
    )
    assert len(query(t1, "--limit", "1")) == 1
    future = str(int(time.time() * 1000) + 3_600_000)
    assert query(t1, "--since-ms", future) == []
    assert audited["token"] not in t1.cli("audit", "query").out


@case("SMK-ADM-051", area="ADM", kind="positive", covers=["cli.audit.query", AUDIT])
def test_security_query_discriminates_bearer_failure(t1, audited):
    """The wire says only invalid_credential; `audit query --event-class security
    --agent <pid>` carries details.reason `secret_mismatch` (error-envelope.md:95-114)."""
    rows = query(
        t1,
        "--event-class",
        "security",
        "--agent",
        audited["id"],
        "--decision",
        "denied",
    )
    reasons = {(r.get("details") or {}).get("reason") for r in rows}
    assert "secret_mismatch" in reasons, reasons


@case("SMK-ADM-052", area="ADM", kind="refusal", covers=["cli.audit.query", AUDIT],
      codes=["invalid_event_class"])
def test_every_documented_event_class_is_accepted(t1, audited):
    """`--event-class` accepts `proxy|operator|security` (cli-reference.md, audit query);
    any other class is refused with 400 `invalid_event_class`."""
    refused = {}
    for cls in DOC_CLASSES:
        out = t1.cli("audit", "query", "--event-class", cls, "--limit", "1")
        if out.code != 0:
            refused[cls] = (out.code, out.error_code)
    assert not refused, f"documented event classes refused: {refused}"
    other = t1.cli("audit", "query", "--event-class", "admin", "--limit", "1")
    assert other.code == 1 and other.error_code == "invalid_event_class", other.err


@case("SMK-ADM-053", area="ADM", kind="corner", covers=["cli.audit.query", AUDIT])
def test_until_ms_is_exclusive(t1, audited):
    """`--since-ms` is inclusive and `--until-ms` exclusive (cli-reference.md, audit
    query; `audit query --help`)."""
    newest = query(t1, "--agent", audited["id"], "--limit", "1")[0]
    ts = newest["ts_ms"]
    at = query(t1, "--agent", audited["id"], "--since-ms", str(ts), "--until-ms", str(ts + 1))
    assert newest["event"] in {r["event"] for r in at}, "event at since_ms was excluded"
    before = query(t1, "--agent", audited["id"], "--since-ms", str(ts), "--until-ms", str(ts))
    assert before == [], "event at until_ms was included"


@case("SMK-ADM-054", area="ADM", kind="positive", covers=[LOGS, "beh.oplog.store"])
def test_operational_log_records_config_and_registry_events(t1, accounts, audited):
    """Secret-free operational events (config, registry, OAuth, proxy, credential
    resolution) are stored in their own table and queried via
    `GET /admin/operator/logs?level=&component=` (README.md:113-117, 243)."""

    def logs(query):
        r = uds(t1, "GET", f"/admin/operator/logs?{query}", token=t1.op_token)
        assert r.status == 200, r.text
        return r.json["logs"]

    deadline = time.monotonic() + 5
    registry = []
    while not registry and time.monotonic() < deadline:
        registry = logs("component=registry")
        time.sleep(0.2)
    assert registry, (
        "the `tool put accounts` catalog write is not in the operational log"
    )
    assert all(r["component"] == "registry" for r in registry)
    assert any(r["event"] == "config_loaded" for r in logs("component=config"))
    info = logs("level=info&limit=2")
    assert 0 < len(info) <= 2 and all(r["level"] == "info" for r in info)
    everything = str(logs("limit=1000"))
    assert "synthetic-private-account" not in everything
    assert audited["token"] not in everything


@case(
    "SMK-ADM-055",
    area="ADM",
    kind="refusal",
    covers=[LOGS],
    codes=["invalid_level", "invalid_component"],
)
def test_logs_reject_unknown_level_and_component(t1):
    """`/logs` filters by `level` and `component` (README.md:113-117, 243). The value
    sets are undocumented; an unknown value is a 400 with a stable code rather than
    a silently empty or unfiltered result."""
    for query, code in (
        ("level=debug", "invalid_level"),
        ("component=adm-bogus", "invalid_component"),
    ):
        r = uds(t1, "GET", f"/admin/operator/logs?{query}", token=t1.op_token)
        assert (r.status, r.code) == (400, code), query
        assert "logs" not in (r.json or {})
