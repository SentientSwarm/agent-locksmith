#!/usr/bin/env python3
"""Run the release-mode QA gate on built binaries and check what it proved.

  scripts/release-gate.py --bins DIR --out DIR [--expected-revision SHA]

Runs `qa/run.py --mode release` against the binaries in --bins, then checks the
bundle's manifest: the gate is release-ready, it ran on a clean tree at the
expected revision, and both binaries report that revision, a clean source state
and the Cargo.toml version. Prints a JSON summary (with the run time) and exits 0
only when all of that holds. No local CI job runs release mode; run this before
cutting a release (see qa/README.md).
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QA_TIMEOUT = 3600
INFO_TIMEOUT = 10
BINARIES = ("locksmith", "locksmithd")


def cargo_version(root=ROOT):
    with (root / "Cargo.toml").open("rb") as source:
        return tomllib.load(source)["package"]["version"]


def head_revision(root=ROOT):
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=INFO_TIMEOUT,
    ).stdout.strip()


def build_info(path):
    out = subprocess.run(
        [str(path), "--build-info"],
        check=True, capture_output=True, text=True, timeout=INFO_TIMEOUT,
    ).stdout
    return json.loads(out)


def check_identity(name, info, version, revision):
    problems = []
    build = info.get("build") or {}
    if info.get("version") != version:
        problems.append(f"{name}: version {info.get('version')!r}, expected {version!r}")
    if build.get("revision") != revision:
        problems.append(f"{name}: revision {build.get('revision')!r}, expected {revision!r}")
    if build.get("source_state") != "clean":
        problems.append(f"{name}: source_state {build.get('source_state')!r}, expected 'clean'")
    return problems


def check_manifest(manifest, version, revision):
    """Problems with a QA bundle manifest for a release at version/revision."""
    problems = []
    if manifest.get("mode") != "release":
        problems.append(f"manifest: mode {manifest.get('mode')!r}, expected 'release'")
    if manifest.get("release_ready") is not True:
        problems.append("manifest: release_ready is not true")
    if manifest.get("commit") != revision:
        problems.append(f"manifest: commit {manifest.get('commit')!r}, expected {revision!r}")
    if manifest.get("tree_dirty") is not False:
        problems.append("manifest: tree_dirty is not false")
    binaries = manifest.get("binaries") or {}
    for name in BINARIES:
        if name not in binaries:
            problems.append(f"manifest: no build info for {name}")
        else:
            problems += check_identity(f"manifest {name}", binaries[name], version, revision)
    return problems


def run_qa(bins, out):
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "qa/run.py"), "--bins", str(bins),
         "--mode", "release", "--out", str(out)],
        cwd=ROOT, start_new_session=True,
    )
    try:
        return process.wait(timeout=QA_TIMEOUT)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        return None
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bins", required=True, type=Path,
                        help="directory holding locksmith and locksmithd")
    parser.add_argument("--out", required=True, type=Path,
                        help="QA evidence bundle directory (must not exist)")
    parser.add_argument("--expected-revision",
                        help="full commit the binaries must report (default: HEAD)")
    args = parser.parse_args(argv)

    version = cargo_version()
    revision = args.expected_revision or head_revision()
    problems = []
    for name in BINARIES:
        try:
            problems += check_identity(name, build_info(args.bins / name), version, revision)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            problems.append(f"{name}: --build-info failed: {error}")
    if problems:
        print(json.dumps({"ok": False, "problems": problems}, indent=2))
        return 1

    started = time.monotonic()
    rc = run_qa(args.bins, args.out)
    seconds = round(time.monotonic() - started)
    if rc != 0:
        problems.append("qa/run.py timed out" if rc is None else f"qa/run.py exited {rc}")
    try:
        manifest = json.loads((args.out / "manifest.json").read_text())
        problems += check_manifest(manifest, version, revision)
    except (OSError, ValueError) as error:
        manifest = {}
        problems.append(f"manifest: {error}")
    print(json.dumps({
        "ok": not problems,
        "version": version,
        "revision": revision,
        "seconds": seconds,
        "counts": manifest.get("counts"),
        "fault_only_known_gaps": len(manifest.get("fault_only_known_gaps") or []),
        "bundle": str(args.out),
        "problems": problems,
    }, indent=2))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
