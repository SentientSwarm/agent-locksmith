#!/usr/bin/python3
"""Fail closed before starting a service on the migrated custody volume.

Contains no credential handling. Receipts attest the operator's completed
stop/move ceremony; they cannot discover a remote refresher by themselves.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

TRUSTED_UID = 0
COMPONENTS = {
    "edge-locksmith": {"locksmith-prod", "locksmith-staging"},
    "edge-pipelock": {"pipelock"},
    "edge-brokers": {"codex", "teamclaude", "token-monitor", "lf-scan"},
}


class Refusal(Exception):
    pass


def mount_type(root):
    result = subprocess.run(
        ["findmnt", "--json", "--mountpoint", str(root), "--output", "FSTYPE"],
        capture_output=True, text=True, timeout=5, check=False,
    )
    if result.returncode:
        return None
    filesystems = json.loads(result.stdout).get("filesystems", [])
    return filesystems[0].get("fstype") if len(filesystems) == 1 else None


def protected(path, *, directory=False):
    try:
        info = path.lstat()
    except OSError as error:
        raise Refusal("storage marker or its directory is unavailable") from error
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
        raise Refusal("storage marker or its directory has unsafe ownership/type/mode")


def read_receipt(path):
    protected(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        return stream.read(128).strip()


def check(root, instance, component):
    if os.getuid() != 0:
        raise Refusal("storage preflight must run as root")
    if component not in COMPONENTS.get(instance, set()):
        raise Refusal("unknown instance/component")
    if mount_type(root) != "zfs":
        raise Refusal("custody root must be a separate mounted ZFS filesystem")
    protected(root, directory=True)
    if read_receipt(root / ".edge-state-id") != instance:
        raise Refusal("wrong custody volume identity")
    protected(root / "custody", directory=True)
    if read_receipt(root / "custody" / f"{component}.ready") != f"{instance}:{component}":
        raise Refusal("custody ceremony has not been acknowledged for this service")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance", choices=COMPONENTS)
    parser.add_argument("component")
    parser.add_argument("--root", type=Path, default=Path("/srv/edge-state"))
    args = parser.parse_args()
    try:
        check(args.root, args.instance, args.component)
    except (Refusal, OSError, ValueError, subprocess.SubprocessError) as error:
        # Never print file contents, subprocess stdout/stderr, or environment.
        print(f"edge startup refused: {type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
