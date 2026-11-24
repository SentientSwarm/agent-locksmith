"""An unwritable database (AGENT-251; docs/concepts/architecture.md#when-the-database-stops-taking-writes).

The daemon's database lives on a FUSE directory whose writes can be made to fail
with EIO, as on the 2026-11-14 XFS shutdown. While writes fail /readyz is not
ready and a proxied request is refused before it reaches the upstream, so no
request goes unaudited; when writes succeed again both recover by themselves.
The cases run in order on one daemon.
"""

import json
import time

import pytest

from fakes import dmn_faultfs
from fakes.agt_support import audit, enrol, put_tool
from fakes.agt_upstream import Upstream

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
READY = "agent.GET./readyz"
LIVE = "agent.GET./livez"
SEM = "beh.audit.write-health"
TOOL = "dmn-wh"
# The daemon probes every 2 s (repo::write_health::PROBE_INTERVAL); allow
# a few intervals for a loaded host.
SETTLE = 15.0

pytestmark = pytest.mark.skipif(
    dmn_faultfs.available() is not None, reason=str(dmn_faultfs.available())
)


def _ready(t) -> tuple[int, dict]:
    resp = t.http("GET", "/readyz")
    return resp.status, resp.json if isinstance(resp.json, dict) else {}


def _wait_ready_status(t, status: int) -> dict:
    deadline = time.monotonic() + SETTLE
    while True:
        code, body = _ready(t)
        if code == status:
            return body
        if time.monotonic() > deadline:
            raise AssertionError(f"/readyz stayed {code} {body}, wanted {status}")
        time.sleep(0.2)


def _error_lines(t) -> list[dict]:
    return [e for e in t.log_events() if e.get("level") == "ERROR"]


@pytest.fixture(scope="module")
def wh(target_factory):
    fs = dmn_faultfs.FaultFs()
    up = Upstream()
    t = target_factory(
        label="dmn-unwritable",
        config={"database": {"path": str(fs.mount / "locksmith.db")}},
    )
    put_tool(t, TOOL, up.url, "none", "--egress", "direct")
    agent = enrol(t, "qa-dmn-unwritable", [TOOL], {TOOL: ["--no-auth"]})
    ok = t.http("GET", f"/api/{TOOL}/before", token=agent["token"])
    assert ok.status == 200, ok.text
    yield t, fs, up, agent
    # Stop the daemon before the filesystem goes away under it.
    if "locksmithd" in t.procs:
        t.stop()
    fs.close()
    up.close()


@case("SMK-DMN-083", area="DMN", kind="refusal", covers=[READY, LIVE, SEM], codes=["not_ready"])
def test_unwritable_database_is_not_ready(wh):
    """docs/reference/wire-contract.md#get-readyz--readiness — once the database stops
    taking writes /readyz is 503 {status: not_ready, reason: database_unwritable} within
    the probe interval; /livez stays 200."""
    t, fs, _up, _agent = wh
    assert _ready(t)[0] == 200
    fs.fail_writes()
    body = _wait_ready_status(t, 503)
    assert body == {"status": "not_ready", "reason": "database_unwritable"}, body
    assert t.http("GET", "/livez").status == 200


@case("SMK-DMN-084", area="DMN", kind="refusal", covers=[API, SEM], codes=["audit_unavailable"])
def test_proxied_request_fails_closed(wh):
    """docs/reference/wire-contract.md#error-envelope — while the audit row can't be
    written a proxied request is 503 audit_unavailable and the upstream sees nothing;
    one error line names the failure, without the agent's credential."""
    t, _fs, up, agent = wh
    before = up.count()
    for _ in range(3):
        resp = t.http("POST", f"/api/{TOOL}/during", token=agent["token"], body={"n": 1})
        assert resp.status == 503, resp.text
        assert resp.code == "audit_unavailable", resp.text
        assert resp.json["error"]["type"] == "availability_error"
    assert up.count() == before, "a refused request reached the upstream"
    errors = [e for e in _error_lines(t) if "database write failed" in json.dumps(e)]
    assert len(errors) == 1, f"want one transition error line, got {len(errors)}"
    assert agent["token"] not in t.log_text()


@case("SMK-DMN-085", area="DMN", kind="positive", covers=[READY, API, SEM])
def test_recovers_when_writes_succeed(wh):
    """docs/concepts/architecture.md#when-the-database-stops-taking-writes — when writes
    succeed again /readyz returns 200 within the probe interval, and the next proxied
    request reaches the upstream with exactly one audit row."""
    t, fs, up, agent = wh
    fs.restore()
    _wait_ready_status(t, 200)
    rows_before = len(audit(t, TOOL))
    before = up.count()
    resp = t.http("GET", f"/api/{TOOL}/after", token=agent["token"])
    assert resp.status == 200, resp.text
    assert up.count() == before + 1
    rows = audit(t, TOOL)
    assert len(rows) == rows_before + 1, "want exactly one new audit row"
    assert rows[0]["path"].endswith("/after") and rows[0]["status"] == 200, rows[0]
    assert not any((r.get("path") or "").endswith("/during") for r in rows), (
        "a refused request was audited"
    )


@case("SMK-DMN-086", area="DMN", kind="refusal", covers=[SEM], codes=["database_unwritable"])
def test_restart_while_unwritable_refuses_to_start(wh):
    """docs/concepts/architecture.md#when-the-database-stops-taking-writes — a daemon
    started while its database takes no writes exits non-zero with an error naming the
    database, instead of serving or hanging; it starts and is ready once writes succeed."""
    t, fs, _up, _agent = wh
    t.stop()
    fs.fail_writes()
    once = t.run_daemon_once(timeout=30)
    assert once.returncode != 0, "daemon started on an unwritable database"
    output = once.stdout + once.stderr
    assert "database" in output and "disk I/O error" in output, t.canaries.redact(output[-600:])
    fs.restore()
    t.start_daemon()
    _wait_ready_status(t, 200)
