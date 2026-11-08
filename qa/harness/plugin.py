"""pytest plugin: binds tests to case IDs and records one CaseRecord each.

Every collected test under smoke/ or uat/ must carry `@pytest.mark.case`.
A case that is selected but never runs stays NOT_EXERCISED; a skip is
NOT_EXERCISED; an error in setup, call or teardown is FAIL.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from .evidence import Bundle
from .guide import load as load_page
from .journey import Journey
from .redact import Canaries
from .status import CaseRecord, Status
from .target import LocalTarget, free_port

KINDS = {"positive", "refusal", "corner"}


class QaPlugin:
    def __init__(self, bins: Path, bundle: Bundle, canaries: Canaries) -> None:
        self.bins = bins
        self.bundle = bundle
        self.canaries = canaries
        self.records: dict[str, CaseRecord] = {}
        self.by_node: dict[str, str] = {}
        self.target: LocalTarget | None = None
        self.errors: list[str] = []
        self.current = "setup"
        self.targets: list = []  # LocalTarget or Journey; both carry current_case
        self.journeys: list[Journey] = []

    def pytest_configure(self, config) -> None:
        config.qa_plugin = self

    def make_target(self, **kwargs) -> LocalTarget:
        target = LocalTarget(self.bins, self.canaries, self.bundle, **kwargs)
        target.current_case = self.current
        self.targets.append(target)
        if self.target is None:
            self.target = target
        return target

    def make_journey(self, page: Path, ports: tuple[str, ...]) -> Journey:
        """A journey over one guide page, with each named port pinned free."""
        journey = Journey(load_page(page), self.bins, self.bundle, self.canaries, {p: str(free_port()) for p in ports})
        journey.current_case = self.current
        self.targets.append(journey)
        self.journeys.append(journey)
        return journey

    def pytest_collection_modifyitems(self, items) -> None:
        for item in items:
            marker = item.get_closest_marker("case")
            if marker is None:
                self.errors.append(f"{item.nodeid}: no @pytest.mark.case")
                continue
            cid = marker.args[0]
            kw = marker.kwargs
            if cid in self.records:
                self.errors.append(f"{item.nodeid}: duplicate case id {cid}")
                continue
            if kw.get("kind") not in KINDS or not kw.get("area") or not kw.get("covers"):
                self.errors.append(f"{item.nodeid}: case {cid} needs area, kind in {sorted(KINDS)} and covers")
                continue
            self.records[cid] = CaseRecord(
                id=cid, area=kw["area"], kind=kw["kind"], covers=list(kw["covers"]),
                status=Status.NOT_EXERCISED, codes=list(kw.get("codes", [])),
            )
            self.by_node[item.nodeid] = cid

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_setup(self, item) -> None:
        self.current = self.by_node.get(item.nodeid, "unbound")
        for target in self.targets:
            target.current_case = self.current

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_call(self, item):
        for target in self.targets:
            target.current_case = self.by_node.get(item.nodeid, "unbound")
        yield

    def pytest_runtest_logreport(self, report) -> None:
        cid = self.by_node.get(report.nodeid)
        if cid is None:
            return
        record = self.records[cid]
        if report.failed:
            record.status = Status.FAIL
            record.detail = self.canaries.redact(_short(report))
        elif report.skipped and record.status is not Status.FAIL:
            record.status = Status.NOT_EXERCISED
            record.detail = "skipped"
        elif report.when == "call" and report.passed and record.status is Status.NOT_EXERCISED:
            record.status = Status.PASS
        prefix = f"cases/{cid}/"
        record.evidence = sorted(
            p.relative_to(self.bundle.root).as_posix()
            for p in (self.bundle.root / prefix).glob("*") if p.is_file()
        )


def _short(report) -> str:
    crash = getattr(report.longrepr, "reprcrash", None)
    text = crash.message if crash is not None else str(report.longrepr)
    return f"{report.when}: {text.splitlines()[0] if text else 'failed'}"[:300]
