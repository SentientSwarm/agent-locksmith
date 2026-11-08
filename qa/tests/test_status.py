from harness.status import CaseRecord, Status, gate


def rec(cid, status, area="HEALTH"):
    return CaseRecord(id=cid, area=area, kind="positive", covers=[], status=status)


def test_fail_fails_both_modes():
    records = [rec("A", Status.PASS), rec("B", Status.FAIL)]
    for mode in ("pr", "release"):
        passed, reasons = gate(records, {}, mode)
        assert not passed
        assert any("B" in r for r in reasons)


def test_not_exercised_fails_release_only():
    records = [rec("A", Status.PASS), rec("B", Status.NOT_EXERCISED)]
    assert gate(records, {}, "pr")[0]
    passed, reasons = gate(records, {}, "release")
    assert not passed
    assert any("NOT_EXERCISED" in r for r in reasons)


def test_below_floor_fails_release():
    records = [rec("A", Status.PASS), rec("B", Status.PASS)]
    passed, reasons = gate(records, {"HEALTH": 3}, "release")
    assert not passed
    assert any("below floor" in r for r in reasons)


def test_below_floor_fails_pr_too():
    assert not gate([rec("A", Status.PASS)], {"HEALTH": 3}, "pr")[0]


def test_zero_records_fails():
    for mode in ("pr", "release"):
        passed, reasons = gate([], {}, mode)
        assert not passed
        assert "no cases" in reasons[0]


def test_not_applicable_never_counts_toward_floor():
    records = [rec("A", Status.PASS), rec("B", Status.NOT_APPLICABLE)]
    assert not gate(records, {"HEALTH": 2}, "release")[0]


def test_unknown_mode_rejected():
    import pytest

    with pytest.raises(ValueError):
        gate([rec("A", Status.PASS)], {}, "yolo")
