#!/usr/bin/env python3
"""Run Locksmith smoke against built binaries and write an evidence bundle.

Exit 0 only when the gate passes: contract matches the source, no case FAILs,
floors are met, the redaction scan is clean, and (release mode) nothing is
NOT_EXERCISED. See qa/README.md.
"""

from __future__ import annotations

import argparse
import datetime as dt
import subprocess
import sys
from pathlib import Path

QA = Path(__file__).resolve().parent
sys.path.insert(0, str(QA))

import pytest

from harness.contract import check_source, coverage, load
from harness.evidence import Bundle
from harness.plugin import QaPlugin
from harness.redact import Canaries, scan_bundle
from harness.status import Status, gate

REPO = QA.parent


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(REPO), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bins",
        type=Path,
        required=True,
        help="directory holding locksmith and locksmithd",
    )
    parser.add_argument("--mode", choices=("pr", "release"), default="pr")
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="evidence bundle directory (must not exist)",
    )
    parser.add_argument(
        "-k", dest="keyword", help="pytest -k filter; marks the run not release-ready"
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.out.exists():
        print(
            f"refusing to reuse existing evidence directory {args.out}", file=sys.stderr
        )
        return 2
    canaries = Canaries()
    bundle = Bundle(args.out, canaries)
    bundle.write_manifest(
        {
            "commit": git("rev-parse", "HEAD"),
            "tree_dirty": bool(git("status", "--porcelain")),
            "target": "t1-local-binary",
            "mode": args.mode,
            "release_ready": args.mode == "release" and not args.keyword,
            "started": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        }
    )
    contract = load(QA / "surface.yaml")
    errors = check_source(contract, REPO, args.bins / "locksmith")

    plugin = QaPlugin(args.bins, bundle, canaries)
    pytest_args = [
        "-c",
        str(QA / "pytest.ini"),
        "--rootdir",
        str(QA),
        "-p",
        "no:cacheprovider",
        "-q",
        str(QA / "smoke"),
    ]
    if args.keyword:
        pytest_args += ["-k", args.keyword]
    code = pytest.main(pytest_args, plugins=[plugin])
    errors += plugin.errors
    if code not in (pytest.ExitCode.OK, pytest.ExitCode.TESTS_FAILED):
        errors.append(f"pytest exited {int(code)} ({code.name})")

    records = sorted(plugin.records.values(), key=lambda r: r.id)
    if plugin.target is not None:
        try:
            bundle.write_manifest({"binaries": plugin.target.build_info()})
        except (OSError, subprocess.CalledProcessError, ValueError) as err:
            errors.append(f"cannot read build identity: {err}")
    cov = coverage(contract, records)
    passed, reasons = gate(records, contract.floors, args.mode)
    reasons = errors + reasons
    if args.mode == "release":
        reasons += [
            f"surface {eid} {status}"
            for eid, status in sorted(cov.items())
            if status in (Status.FAIL.value, Status.NOT_EXERCISED.value)
        ]
    counts = {s.value: sum(r.status is s for r in records) for s in Status}
    bundle.write_manifest(
        {
            "finished": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "counts": counts,
        }
    )
    bundle.write_results(records, (passed and not reasons, reasons), cov)
    leaks = scan_bundle(args.out, canaries)
    if leaks:
        reasons = reasons + [f"redaction: {leak}" for leak in leaks]
        bundle.write_results(records, (False, reasons), cov)
    ok = passed and not reasons
    print(f"\nQA {args.mode} gate: {'PASS' if ok else 'FAIL'}  {counts}")
    for reason in reasons:
        print(f"  - {reason}")
    print(f"evidence: {args.out}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
