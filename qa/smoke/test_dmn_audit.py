"""Audit JSONL mirror, retention sweepers and the operational-log store.

The mirror files and operational logs are product output read from the work
directory or the admin socket; transcripts record counts, never their rows.
"""

import json
import time

import pytest

from fakes.dmn_support import mirror_files, mirror_lines, uds_get, wait_for
from harness.target import SMOKE_X

case = pytest.mark.case
MIRROR = "beh.audit.jsonl-mirror"
RETENTION = "beh.retention.audit-and-logs"
MAX_BYTES = 4096
KEEP = 3


def _mirror_overlay(work):
    return {
        "audit": {
            "jsonl_path": str(work / "mirror" / "audit.jsonl"),
            "jsonl_max_bytes": MAX_BYTES,
            "jsonl_keep_files": KEEP,
        }
    }


@pytest.fixture(scope="module")
def mt(target_factory):
    t = target_factory(label="dmn-jsonl", config=_mirror_overlay)
    put = t.cli(
        "tool",
        "put",
        "accounts",
        "--upstream",
        t.upstream_url,
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
    )
    assert put.code == 0, put.err
    reg = t.cli("agent", "register", "--name", "dmn-mirror", "--allowlist", "accounts")
    assert reg.code == 0, reg.err
    bind = t.cli(
        "agent",
        "set-credential",
        reg.json["public_id"],
        "accounts",
        "--auth",
        "bearer=SMOKE_X",
    )
    assert bind.code == 0, bind.err
    t.dmn_agent = reg.json
    return t


def mirror_dir(t):
    return t.work / "mirror"


def audit_rows(t, *args: str) -> list:
    rows = t.cli("audit", "query", "--limit", "1000", *args)
    assert rows.code == 0, rows.err
    return rows.json


def call(t, path: str = "/api/accounts/check"):
    response = t.http("GET", path, token=t.dmn_agent["token"])
    assert response.status == 200
    return response


@case("SMK-DMN-040", area="DMN", kind="positive", covers=[MIRROR])
def test_mirror_has_one_line_per_audit_row(mt):
    """architecture.md:89,151-152 and README.md:296-300: every audit row is also appended to the
    optional JSONL mirror at audit.jsonl_path; one proxied request adds exactly one line."""
    before = len(mirror_lines(mirror_dir(mt)))
    call(mt)
    lines = wait_for(
        lambda: (ls := mirror_lines(mirror_dir(mt))) and len(ls) > before and ls,
        timeout=5,
    )
    assert len(lines) == before + 1, f"{len(lines) - before} lines for one request"
    rows = audit_rows(mt)
    parsed = [json.loads(line) for line in lines]
    assert sorted((r["ts_ms"], r["event"]) for r in parsed) == sorted(
        (r["ts_ms"], r["event"]) for r in rows
    )
    newest = max(parsed, key=lambda r: r["ts_ms"])
    assert newest["tool"] == "accounts"
    assert newest["agent_public_id"] == mt.dmn_agent["public_id"]
    mt.bundle.transcript(
        mt.current_case, "mirror", f"lines={len(lines)} audit_rows={len(rows)}"
    )


@case("SMK-DMN-041", area="DMN", kind="corner", covers=[MIRROR])
def test_mirror_lines_hold_no_secrets(mt):
    """README.md:96-97: credentials are never logged; architecture.md:89,151: the mirror carries
    the audit rows. Neither the injected value nor agent/operator tokens may appear in it."""
    call(mt)
    text = "\n".join(mirror_lines(mirror_dir(mt)))
    assert text, "mirror is empty"
    for label, value in (
        ("injected", SMOKE_X),
        ("agent token", mt.dmn_agent["token"]),
        ("operator token", mt.op_token),
        ("bearer header", "Bearer "),
    ):
        assert value not in text, f"{label} found in the JSONL mirror"


@case("SMK-DMN-042", area="DMN", kind="positive", covers=[MIRROR])
def test_mirror_rotates_at_max_bytes_keeping_keep_files(mt):
    """README.md:298-300 and architecture.md:151-152: the mirror rotates when a file reaches
    jsonl_max_bytes and keeps at most jsonl_keep_files files."""
    for _ in range(30):
        call(mt)
    time.sleep(0.5)
    files = mirror_files(mirror_dir(mt))
    sizes = {f.name.replace(str(mt.work), ""): f.stat().st_size for f in files}
    mt.bundle.transcript(mt.current_case, "mirror-files", json.dumps(sizes, indent=1))
    assert 2 <= len(files) <= KEEP, f"{len(files)} mirror files with keep_files={KEEP}"
    assert all(size <= MAX_BYTES for size in sizes.values()), (
        f"a file exceeds {MAX_BYTES} bytes"
    )
    for line in mirror_lines(mirror_dir(mt)):
        assert isinstance(json.loads(line), dict)


@case("SMK-DMN-043", area="DMN", kind="positive", covers=["beh.oplog.store"])
def test_operational_log_store_is_queryable_and_secret_free(mt):
    """README.md:113-116: secret-free operational events (config, registry, ...) in their own
    table, queried via GET /admin/operator/logs?level=&component=."""
    status, body = uds_get(mt, "/admin/operator/logs?component=registry&limit=100")
    assert status == 200
    registry = body["logs"]
    assert registry and all(e["component"] == "registry" for e in registry)
    assert any("accounts" in json.dumps(e) for e in registry), (
        "tool put left no registry event"
    )
    status, body = uds_get(mt, "/admin/operator/logs?component=config&limit=100")
    assert status == 200 and body["logs"], "no config event after startup"
    status, body = uds_get(mt, "/admin/operator/logs?limit=1000")
    text = json.dumps(body)
    assert (
        SMOKE_X not in text
        and mt.op_token not in text
        and mt.dmn_agent["token"] not in text
    )


SWEEP = {"retention_days": 0, "sweep_interval_seconds": 1}


@pytest.fixture(scope="module")
def rt(target_factory):
    return target_factory(
        label="dmn-retention",
        upstream=False,
        config={"audit": SWEEP, "operational_log": SWEEP},
    )


def register(t, name: str) -> str:
    reg = t.cli("agent", "register", "--name", name)
    assert reg.code == 0, reg.err
    return reg.json["public_id"]


def revoked(t, name: str) -> str:
    """Register then revoke an agent; revocation emits an `agent` operational event."""
    public_id = register(t, name)
    revoke = t.cli("agent", "revoke", public_id, "--reason", "dmn")
    assert revoke.code == 0, revoke.err
    return public_id


def agent_oplogs(t, public_id: str) -> list:
    status, body = uds_get(t, "/admin/operator/logs?component=agent&limit=1000")
    assert status == 200
    return [e for e in body["logs"] if public_id in json.dumps(e)]


@case("SMK-DMN-030", area="DMN", kind="positive", covers=[RETENTION])
def test_audit_retention_sweeps_expired_rows(rt, t1):
    """README.md:295-297: audit.retention_days with sweep_interval_seconds bounds audit history.

    retention_days 0 is the smallest window the schema accepts; with a 1 s sweep every row is
    expired within seconds. t1 (default 90 days) is the control for the same write.
    """
    swept, kept = register(rt, "dmn-retention"), register(t1, "dmn-retention-control")
    gone = wait_for(lambda: audit_rows(rt, "--agent", swept) == [], timeout=8, step=0.5)
    assert gone, "audit rows outlived retention_days=0"
    assert audit_rows(t1, "--agent", kept), (
        "control audit row vanished under default retention"
    )


@case("SMK-DMN-031", area="DMN", kind="positive", covers=[RETENTION, "beh.oplog.store"])
def test_operational_log_retention_sweeps_expired_rows(rt, t1):
    """README.md:113-116,302-304 and config.example.yaml:47-55: the operational-log stream has its
    own retention (operational_log.retention_days / sweep_interval_seconds)."""
    swept, kept = revoked(rt, "dmn-oplog-retention"), revoked(t1, "dmn-oplog-control")
    assert wait_for(lambda: agent_oplogs(t1, kept), timeout=5), (
        "control agent event never stored"
    )
    gone = wait_for(lambda: agent_oplogs(rt, swept) == [], timeout=8, step=0.5)
    assert gone, "operational-log rows outlived retention_days=0"
