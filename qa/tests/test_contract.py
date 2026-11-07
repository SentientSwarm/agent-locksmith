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


def write(tmp_path, routes=ROUTES, gaps=()):
    path = tmp_path / "surface.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "routes": routes, "known_gaps": list(gaps)}))
    return load(path)


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
    gap = {"id": "r.save", "reason": "later", "ticket": "AGENT-1", "expires": "2026-12-01"}
    contract = write(tmp_path, gaps=[gap])
    assert coverage(contract, [], dt.date(2026, 11, 30))["r.save"] == "NOT_APPLICABLE"
    assert coverage(contract, [], dt.date(2026, 12, 2))["r.save"] == "NOT_EXERCISED"


def test_known_gap_requires_ticket(tmp_path):
    with pytest.raises(ContractError, match="lacks"):
        write(tmp_path, gaps=[{"id": "r.save", "reason": "x", "expires": "2026-12-01"}])


def test_duplicate_ids_rejected(tmp_path):
    with pytest.raises(ContractError, match="duplicate"):
        write(tmp_path, ROUTES + [ROUTES[0]])
