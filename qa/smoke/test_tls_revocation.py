"""mTLS revocation on the agent listener: CRL and the local emergency blocklist.

Docs: docs/v2/runbooks/m6-mtls-revocation.md and CHANGELOG.md 3.0.0 ("Enforce mTLS
revocation on the agent listener", lines 29-53). The cases run in order against
one daemon: no CRL ever in force, an untrusted CRL, a trusted CRL, a CRL
revocation, then the blocklist. The CRL is served by fakes.tls_crl on 127.0.0.1.
"""

import pytest

from fakes.pki import CA
from fakes.tls_crl import CrlServer
from fakes.tls_pki import (
    accounts_tool,
    client_context,
    enrol,
    https,
    mtls_failures,
    now_ms,
    serial_hex,
    server_files,
    wait_for,
)

case = pytest.mark.case
API = "agent.ANY./api/{tool_name}/{*path}"
REVOCATION = "beh.mtls.revocation"
RELOAD_S = 1


@pytest.fixture(scope="module")
def crl():
    server = CrlServer()
    yield server
    server.close()


@pytest.fixture(scope="module")
def rv(target_factory, crl):
    ca = CA.create("qa-tls-rev-ca")
    files = {}

    def overlay(work):
        files.update(server_files(work, ca, ca.server(), "rev"))
        files["blocklist"] = str(work / "tls" / "blocklist")
        (work / "tls" / "blocklist").write_text("# qa emergency blocklist\n")
        return {
            "listen": {
                "auth_mode": "mtls",
                "mtls": {
                    "ca_bundle_path": files["ca"],
                    "server_cert_path": files["cert"],
                    "server_key_path": files["key"],
                    "crl_url": crl.url,
                    "crl_refresh_interval_seconds": RELOAD_S,
                    "blocklist_path": files["blocklist"],
                    "blocklist_reload_interval_seconds": RELOAD_S,
                },
            }
        }

    target = target_factory(config=overlay, label="tls-revocation")
    accounts_tool(target)
    state = {"t": target, "ca": ca, "files": files, "rows": {}}
    for key in ("a", "b", "c"):
        name = f"qa-rev-{key}"
        state[key] = {
            "agent": enrol(target, name, "SMOKE_X", f"{name}.agent"),
            "cert": ca.client(f"{name}.agent"),
        }
    return state


def call(rv, key):
    t = rv["t"]
    ctx = client_context(t, rv["files"]["ca"], rv[key]["cert"], f"rev-{key}")
    response, refused = https(t, "GET", "/api/accounts/check", t.port, ctx)
    assert refused is None, refused
    return response


def ok(rv, key):
    return call(rv, key).status == 200


def reason_rows(rv, since, reason):
    return [
        r
        for r in mtls_failures(rv["t"], since)
        if r["event"] == "mtls_auth_failure"
        and (r.get("details") or {}).get("reason") == reason
    ]


def assert_refused(rv, key, reason, since):
    """One refused request with zero dispatch and its audit row (runbook §3 shape)."""
    t = rv["t"]
    before = t.upstream_counts()
    response = call(rv, key)
    assert response.status == 401
    assert response.code == "invalid_credential"
    assert t.upstream_counts() == before, (
        "a revoked cert's request reached the upstream"
    )
    rows = wait_for(lambda: reason_rows(rv, since, reason), 5)
    assert rows, f"no mtls_auth_failure reason={reason} audit row"
    row = rows[-1]
    assert row.get("decision") == "denied"
    assert row.get("auth_method") == "mtls"
    return row


@case(
    "SMK-TLS-020",
    area="TLS",
    kind="refusal",
    covers=[REVOCATION, API],
    codes=["crl_unavailable"],
)
def test_no_crl_in_force_refuses_mtls(rv, crl):
    """m6-mtls-revocation.md:66: with neither a fetched nor a cached CRL the daemon logs
    `no CRL in force` at error level and refuses every mTLS client, audited as
    `mtls_auth_failure reason=crl_unavailable`."""
    since = now_ms()
    assert crl.fetches >= 1, "the daemon never fetched crl_url before serving"
    assert any(
        e.get("level") == "ERROR"
        and "no CRL in force" in str(e.get("fields", {}).get("message"))
        for e in rv["t"].log_events()
    )
    assert_refused(rv, "a", "crl_unavailable", since)


@case(
    "SMK-TLS-021",
    area="TLS",
    kind="refusal",
    covers=[REVOCATION, API],
    codes=["crl_unavailable"],
)
def test_crl_from_untrusted_signer_is_not_applied(rv, crl):
    """CHANGELOG.md:35-37: a CRL is applied only when a CA certificate in the agent CA
    bundle that matches its issuer signed it. An impostor CA with the same name is
    fetched but not applied, so mTLS stays refused as crl_unavailable."""
    impostor = CA.create("qa-tls-rev-ca")
    crl.serve(impostor.crl())
    seen = crl.fetches
    assert wait_for(lambda: crl.fetches >= seen + 2, 10), (
        "the daemon stopped polling crl_url"
    )
    since = now_ms()
    assert_refused(rv, "a", "crl_unavailable", since)


@case("SMK-TLS-022", area="TLS", kind="positive", covers=[REVOCATION, API])
def test_trusted_crl_restores_mtls(rv, crl):
    """m6-mtls-revocation.md:66 ("until a CRL is applied") and CHANGELOG.md:32-46: a CRL
    signed by the bundle CA is applied on the next refresh, mTLS clients are served, and
    the last good CRL is kept in mtls-crl-cache.pem beside the database."""
    crl.serve(rv["ca"].crl())
    assert wait_for(lambda: ok(rv, "a"), 10), (
        "mTLS still refused after a valid CRL was served"
    )
    assert (rv["t"].work / "mtls-crl-cache.pem").exists()


@case(
    "SMK-TLS-023",
    area="TLS",
    kind="refusal",
    covers=[REVOCATION, API],
    codes=["revoked_by_crl"],
)
def test_crl_revoked_serial_is_refused(rv, crl):
    """m6-mtls-revocation.md:53-64,74-88: a serial on the CA's CRL is refused after the
    next refresh, audited `mtls_auth_failure` reason revoked_by_crl;
    other certs of the same CA keep working."""
    since = now_ms()
    crl.serve(rv["ca"].crl(revoked=(rv["b"]["cert"].serial,)))
    assert wait_for(lambda: not ok(rv, "b"), 10), "CRL-revoked cert still authenticates"
    rv["rows"]["b"] = assert_refused(rv, "b", "revoked_by_crl", since)
    assert ok(rv, "a"), "an unrevoked cert was refused"


@case(
    "SMK-TLS-024",
    area="TLS",
    kind="refusal",
    covers=[REVOCATION, API, "cli.mtls.revoke", "cli.mtls.list-blocklist"],
    codes=["revoked_by_blocklist"],
)
def test_blocklist_revoke_refuses_within_reload_interval(rv):
    """m6-mtls-revocation.md:35-49: `locksmith mtls revoke` adds the serial; the daemon
    picks it up within blocklist_reload_interval_seconds and the next request is refused
    `mtls_auth_failure reason=revoked_by_blocklist`; `list-blocklist` shows it."""
    t, serial = rv["t"], serial_hex(rv["c"]["cert"])
    assert ok(rv, "c")
    since = now_ms()
    revoke = t.cli(
        "mtls",
        "revoke",
        serial.upper(),
        "--blocklist-path",
        rv["files"]["blocklist"],
        "--reason",
        "qa drill: suspected key exfiltration",
        socket_flag=False,
    )
    assert revoke.code == 0, revoke.err
    listed = t.cli(
        "mtls",
        "list-blocklist",
        "--blocklist-path",
        rv["files"]["blocklist"],
        socket_flag=False,
    )
    assert listed.code == 0, listed.err
    assert serial in listed.json
    assert wait_for(lambda: not ok(rv, "c"), RELOAD_S + 5), (
        "blocklisted cert still authenticates"
    )
    rv["rows"]["c"] = assert_refused(rv, "c", "revoked_by_blocklist", since)


@case("SMK-TLS-025", area="TLS", kind="positive", covers=[REVOCATION, API])
def test_blocklist_removal_restores_access(rv):
    """m6-mtls-revocation.md:140-147 (tabletop drill step 4): removing the serial from
    the blocklist restores access within the reload interval."""
    t = rv["t"]
    t.write_file("tls/blocklist", "# qa drill complete\n")
    assert wait_for(lambda: ok(rv, "c"), RELOAD_S + 5), (
        "access not restored after blocklist removal"
    )


@case(
    "SMK-TLS-026",
    area="TLS",
    kind="refusal",
    covers=["cli.mtls.revoke"],
    codes=[],
)
def test_revoke_rejects_non_hex_serial(rv):
    """CHANGELOG.md:52-53: `locksmith mtls revoke` rejects a non-hex serial (usage error,
    exit 2 per cli-reference.md exit codes) and leaves the file unchanged."""
    path = rv["t"].work / "tls" / "blocklist"
    before = path.read_text()
    result = rv["t"].cli(
        "mtls",
        "revoke",
        "not-a-serial",
        "--blocklist-path",
        str(path),
        socket_flag=False,
    )
    assert result.code == 2
    assert "not a hex serial" in result.err
    assert path.read_text() == before


@case("SMK-TLS-027", area="TLS", kind="positive", covers=["cli.mtls.crl-status"])
def test_crl_status_points_to_the_daemon_log(rv, crl):
    """cli-reference.md (`mtls crl-status`) and `locksmith mtls crl-status --help`: the
    command does not contact the daemon; CRL state is read from the daemon log (`CRL
    applied`) and from `mtls-crl-cache.pem` beside the database. Following that procedure
    on a daemon with a CRL in force finds both."""
    t = rv["t"]
    result = t.cli("mtls", "crl-status")
    assert result.code == 0, result.err
    assert "log" in (result.out + result.err).lower()
    assert any("CRL applied" in str(e.get("fields", {}).get("message", "")) for e in t.log_events())
    assert (t.work / "mtls-crl-cache.pem").exists()


@case("SMK-TLS-028", area="TLS", kind="corner", covers=[REVOCATION])
def test_revocation_audit_rows_carry_serial(rv):
    """m6-mtls-revocation.md:28-30 (find the serial via `.details.serial_hex` in audit)
    and :76-88 (rejected-request row shape with "serial_hex"): the revoked_by_crl and
    revoked_by_blocklist rows written by SMK-TLS-023/024 name the refused cert's serial."""
    assert set(rv["rows"]) == {"b", "c"}, (
        "SMK-TLS-023/024 did not record their refusal rows"
    )
    for key, row in rv["rows"].items():
        assert row["details"].get("serial_hex") == serial_hex(rv[key]["cert"]), row[
            "details"
        ]


@case(
    "SMK-TLS-029",
    area="TLS",
    kind="positive",
    covers=["cli.mtls.revoke", "cli.mtls.list-blocklist"],
)
def test_revoke_canonicalises_serials_and_keeps_reason(rv):
    """CHANGELOG.md:50-53 (`7A:11`, `0x7a11` and `007a11` match `7a11`; revoke replaces
    the file atomically) and m6-mtls-revocation.md:35-46,135 (`--reason` is kept as a
    comment for the next operator; list-blocklist prints the serials)."""
    t = rv["t"]
    path = str(t.work / "tls" / "drill-blocklist")
    for form in ("7A:11", "0x7a11", "007a11"):
        result = t.cli(
            "mtls",
            "revoke",
            form,
            "--blocklist-path",
            path,
            "--reason",
            f"qa drill {form}",
            socket_flag=False,
        )
        assert result.code == 0, result.err
    listed = t.cli(
        "mtls", "list-blocklist", "--blocklist-path", path, socket_flag=False
    )
    assert listed.code == 0, listed.err
    assert listed.json == ["7a11", "7a11", "7a11"]
    assert "# qa drill 7A:11" in (t.work / "tls" / "drill-blocklist").read_text()
