import json
from pathlib import Path

from harness.evidence import Bundle
from harness.redact import Canaries
from harness.status import CaseRecord, Status

CANARY = "canary-value-0123456789abcdef"


def records():
    return [
        CaseRecord("SMK-HEALTH-001", "HEALTH", "positive", ["agent.GET./livez"], Status.PASS),
        CaseRecord("SMK-PROXY-002", "PROXY", "refusal", ["agent.ANY./api/{tool_name}/{*path}"], Status.FAIL, "got 200"),
    ]


def test_results_round_trip(tmp_path: Path):
    bundle = Bundle(tmp_path, Canaries())
    bundle.write_results(records(), (False, ["SMK-PROXY-002 FAIL"]), {"agent.GET./livez": "PASS"})
    data = json.loads((tmp_path / "results.json").read_text())
    assert [c["status"] for c in data["cases"]] == ["PASS", "FAIL"]
    assert data["gate"] == {"passed": False, "reasons": ["SMK-PROXY-002 FAIL"]}
    assert data["coverage"] == {"agent.GET./livez": "PASS"}


def test_report_lists_every_case(tmp_path: Path):
    bundle = Bundle(tmp_path, Canaries())
    bundle.write_manifest({"commit": "abc", "mode": "pr"})
    bundle.write_results(records(), (False, ["x"]), {})
    report = (tmp_path / "report.md").read_text()
    assert "SMK-HEALTH-001" in report and "SMK-PROXY-002" in report
    assert "got 200" in report


def test_transcript_redacts_canary(tmp_path: Path):
    canaries = Canaries()
    canaries.add(CANARY, "op-token")
    bundle = Bundle(tmp_path, canaries)
    rel = bundle.transcript("SMK-ENROL-001", "register", f"token={CANARY}")
    text = (tmp_path / rel).read_text()
    assert CANARY not in text and "<redacted:op-token>" in text
    assert rel.startswith("cases/SMK-ENROL-001/")


def test_transcript_names_are_unique(tmp_path: Path):
    bundle = Bundle(tmp_path, Canaries())
    a = bundle.transcript("C", "cli", "1")
    b = bundle.transcript("C", "cli", "2")
    assert a != b
