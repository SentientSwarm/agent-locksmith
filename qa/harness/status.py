"""Case statuses and the release gate.

Absent, skipped or zero-collected cases never read as PASS.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum

MODES = ("pr", "release")


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_EXERCISED = "NOT_EXERCISED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class CaseRecord:
    id: str
    area: str
    kind: str
    covers: list[str]
    status: Status
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    codes: list[str] = field(default_factory=list)  # refusal codes this case produced


def gate(records: list[CaseRecord], floors: dict[str, int], mode: str) -> tuple[bool, list[str]]:
    """Return (passed, reasons). Floors apply in both modes; NOT_EXERCISED blocks release."""
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}")
    if not records:
        return False, ["no cases recorded"]
    reasons = [f"{r.id} FAIL: {r.detail}".rstrip(": ") for r in records if r.status is Status.FAIL]
    if mode == "release":
        reasons += [f"{r.id} NOT_EXERCISED" for r in records if r.status is Status.NOT_EXERCISED]
    passed = Counter(r.area for r in records if r.status is Status.PASS)
    for area, floor in sorted(floors.items()):
        if passed[area] < floor:
            reasons.append(f"{area}: {passed[area]} passed, below floor {floor}")
    return not reasons, reasons
