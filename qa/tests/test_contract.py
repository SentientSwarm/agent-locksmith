import datetime as dt
import shutil
from pathlib import Path

import pytest
import yaml

from harness.contract import ContractError, check_source, coverage, load, source_routes
from harness.status import CaseRecord, Status

FIXTURE = Path(__file__).parent / "fixtures" / "repo"


def route(rid, method, route_literal, refusals=()):
    return {"id": rid, "listener": "admin", "method": method, "path": route_literal,
            "source": {"file": "src/admin/uds.rs", "route": route_literal}, "refusals": list(refusals)}


ROUTES = [
    route("r.list", "GET", "/tools"),
    route("r.show", "GET", "/tools/{name}", ["unknown_name"]),
    route("r.save", "PUT", "/tools/{name}"),
    {"id": "r.cb", "listener": "callback", "method": "ANY", "path": "/oauth/callback",
     "source": {"file": "src/admin/uds.rs", "route": "*fallback*"}},
]


def write(tmp_path, routes=ROUTES, gaps=(), today=None):
    path = tmp_path / "surface.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "routes": routes, "known_gaps": list(gaps)}))
    return load(path, today)


def test_source_routes_parses_multiline_and_fallback():
    found = source_routes(FIXTURE)
    assert found == {
        ("src/admin/uds.rs", "/tools", "GET"): 1,
        ("src/admin/uds.rs", "/tools/{name}", "GET"): 1,
        ("src/admin/uds.rs", "/tools/{name}", "PUT"): 1,
        ("src/admin/uds.rs", "*fallback*", "ANY"): 1,
    }


def test_matching_contract_is_clean(tmp_path):
    assert check_source(write(tmp_path), FIXTURE, None) == []


def test_extra_source_route_is_named(tmp_path):
    contract = write(tmp_path, ROUTES[1:])
    errors = check_source(contract, FIXTURE, None)
    assert errors == ["route GET /tools in src/admin/uds.rs: source has 1, contract has 0"]


def test_unparseable_route_fails_closed(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    (repo / "src" / "admin" / "uds.rs").write_text('Router::new().route(PATH, get(x))\n')
    with pytest.raises(ContractError, match="cannot parse"):
        source_routes(repo)


APPROVED = "the owner, 2026-11-24"


def rec(covers, kind, status=Status.PASS, codes=()):
    return CaseRecord("C", "A", kind, covers, status, codes=list(codes))


def test_route_with_refusals_needs_refusal_case(tmp_path):
    contract = write(tmp_path)
    cov = coverage(contract, [rec(["r.show"], "positive")])
    assert cov["r.show"] == "NOT_EXERCISED"
    cov = coverage(contract, [rec(["r.show"], "positive"), rec(["r.show"], "refusal")])
    assert cov["r.show"] == "NOT_EXERCISED"
    cov = coverage(contract, [rec(["r.show"], "positive"), rec(["r.show"], "refusal", codes=["unknown_name"])])
    assert cov["r.show"] == "PASS"


def test_failed_covering_case_marks_fail(tmp_path):
    cov = coverage(write(tmp_path), [rec(["r.list"], "positive"), rec(["r.list"], "corner", Status.FAIL)])
    assert cov["r.list"] == "FAIL"


def test_known_gap_expiry(tmp_path):
    gap = {"id": "r.save", "reason": "later", "ticket": "AGENT-1", "expires": "2026-12-01", "approved": APPROVED}
    contract = write(tmp_path, gaps=[gap])
    assert coverage(contract, [], dt.date(2026, 11, 30))["r.save"] == "NOT_APPLICABLE"
    assert coverage(contract, [], dt.date(2026, 12, 2))["r.save"] == "NOT_EXERCISED"


def test_known_gap_requires_ticket(tmp_path):
    with pytest.raises(ContractError, match="lacks"):
        write(tmp_path, gaps=[{"id": "r.save", "reason": "x", "expires": "2026-12-01", "approved": APPROVED}])


def test_known_gap_requires_owner_approval(tmp_path):
    # No PRs on this repo's fast-forward lane: the approval is recorded on the gap.
    with pytest.raises(ContractError, match="lacks"):
        write(tmp_path, gaps=[{"id": "r.save", "reason": "x", "ticket": "AGENT-1", "expires": "2026-12-01"}])


@pytest.mark.parametrize("value", ["  ", None, 0])
@pytest.mark.parametrize("field", ["reason", "ticket", "approved"])
def test_known_gap_fields_must_be_nonempty_text(tmp_path, field, value):
    # `approved:` with no value loads as None; it must not count as an approval.
    gap = {"id": "r.save", "reason": "x", "ticket": "AGENT-1", "expires": "2026-12-01", "approved": APPROVED}
    with pytest.raises(ContractError, match="empty"):
        write(tmp_path, gaps=[dict(gap, **{field: value})])


def test_duplicate_ids_rejected(tmp_path):
    with pytest.raises(ContractError, match="duplicate"):
        write(tmp_path, ROUTES + [ROUTES[0]])


def test_fault_refusals_do_not_block_coverage_but_are_listed(tmp_path):
    from harness.contract import fault_gaps

    routes = [dict(ROUTES[0], fault_refusals=["backend_error"])] + ROUTES[1:]
    contract = write(tmp_path, routes)
    records = [rec(["r.list"], "positive")]
    assert coverage(contract, records)["r.list"] == "PASS"
    assert fault_gaps(contract, records) == ["r.list: backend_error (fault-only)"]
    assert fault_gaps(contract, records + [rec(["r.list"], "refusal", codes=["backend_error"])]) == []


FAULT_ROUTES = [dict(ROUTES[1], fault_refusals=["store_down", "race_lost"])] + [ROUTES[0]] + ROUTES[2:]
TODAY = dt.date(2026, 11, 24)


def fault_gap(code, expires="2026-12-24", **extra):
    return {"id": "r.show", "code": code, "reason": "needs a fault build", "ticket": "AGENT-227",
            "expires": expires, "approved": APPROVED, **extra}


def test_code_gap_waives_only_that_fault_code(tmp_path):
    from harness.contract import fault_gaps, fault_waivers

    contract = write(tmp_path, FAULT_ROUTES, [fault_gap("store_down")], TODAY)
    records = [rec(["r.show"], "positive"), rec(["r.show"], "refusal", codes=["unknown_name"])]
    assert fault_gaps(contract, records, TODAY) == ["r.show: race_lost (fault-only)"]
    assert fault_waivers(contract, records, TODAY) == [
        "r.show: store_down NOT_APPLICABLE (known gap AGENT-227, expires 2026-12-24: needs a fault build)"
    ]
    assert fault_gaps(contract, records, dt.date(2026, 12, 25)) == [
        "r.show: store_down (fault-only)", "r.show: race_lost (fault-only)"]


def test_code_gap_does_not_mask_entry_coverage(tmp_path):
    contract = write(tmp_path, FAULT_ROUTES, [fault_gap("store_down"), fault_gap("race_lost")], TODAY)
    assert coverage(contract, [rec(["r.show"], "positive")], TODAY)["r.show"] == "NOT_EXERCISED"


def test_produced_fault_code_needs_no_waiver(tmp_path):
    from harness.contract import fault_waivers

    contract = write(tmp_path, FAULT_ROUTES, [fault_gap("store_down")], TODAY)
    records = [rec(["r.show"], "refusal", codes=["store_down"])]
    assert fault_waivers(contract, records, TODAY) == []


def test_code_gap_must_name_a_fault_only_code(tmp_path):
    with pytest.raises(ContractError, match="not one of the entry's fault_refusals"):
        write(tmp_path, FAULT_ROUTES, [fault_gap("unknown_name")], TODAY)


def test_duplicate_code_gap_rejected(tmp_path):
    with pytest.raises(ContractError, match="duplicate known gap r.show: store_down"):
        write(tmp_path, FAULT_ROUTES, [fault_gap("store_down"), fault_gap("store_down")], TODAY)


def test_gap_expiry_at_most_30_days_out(tmp_path):
    write(tmp_path, FAULT_ROUTES, [fault_gap("store_down", "2026-12-24")], TODAY)
    with pytest.raises(ContractError, match="more than 30 days out"):
        write(tmp_path, FAULT_ROUTES, [fault_gap("store_down", "2026-12-25")], TODAY)
