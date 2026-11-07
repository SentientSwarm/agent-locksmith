"""run.py end to end against a daemon that cannot start (needs QA_BINS)."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

QA = Path(__file__).resolve().parents[1]
BINS = os.environ.get("QA_BINS")
pytestmark = pytest.mark.skipif(not BINS, reason="set QA_BINS to the built binaries directory")


def test_daemon_that_cannot_start_fails_fast_and_names_the_cause(tmp_path):
    bins = tmp_path / "bins"
    bins.mkdir()
    (bins / "locksmith").symlink_to(Path(BINS).resolve() / "locksmith")
    fake = bins / "locksmithd"
    fake.write_text('#!/bin/sh\n[ "$1" = --build-info ] && exec "$(dirname "$0")/locksmith" --build-info\n'
                    'echo \'{"level":"ERROR","fields":{"message":"daemon exited with error","error":"qa-forced"}}\'\nexit 1\n')
    fake.chmod(0o755)
    out = tmp_path / "evidence"
    started = time.monotonic()
    proc = subprocess.run([sys.executable, str(QA / "run.py"), "--bins", str(bins), "--out", str(out)],
                          capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 1
    assert time.monotonic() - started < 60
    results = json.loads((out / "results.json").read_text())
    assert results["gate"]["passed"] is False
    assert all(c["status"] == "FAIL" for c in results["cases"])
    assert any("qa-forced" in c["detail"] for c in results["cases"])
    assert not list(Path("/tmp").glob("lsqa-*")), "work directory left behind"


def test_existing_evidence_directory_is_refused(tmp_path):
    proc = subprocess.run([sys.executable, str(QA / "run.py"), "--bins", BINS, "--out", str(tmp_path)],
                          capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 2
    assert "refusing to reuse" in proc.stderr
