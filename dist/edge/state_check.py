#!/usr/bin/python3 -I
"""Fail closed before a Locksmith edge service starts on its custody volume.

Runs as an isolated root ExecStartPre (python3 -I ignores PYTHON* variables
and user site-packages). The allowed components and the state root come
from a root-owned components.json written by render.py, never from argv.
It handles no credentials. Receipts attest the operator's completed custody
ceremony; they cannot discover a remote copy by themselves.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

TRUSTED_UID = 0
DEFAULT_CONFIG = Path("/etc/locksmith-edge/components.json")
MAX_CONFIG_BYTES = 65536


class Refusal(Exception):
    pass


def mount_type(root: Path) -> str | None:
    """The filesystem type when root is itself a mount point, else None."""
    result = subprocess.run(
        ["findmnt", "--json", "--mountpoint", str(root), "--output", "FSTYPE"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode:
        return None
    filesystems = json.loads(result.stdout).get("filesystems", [])
    return filesystems[0].get("fstype") if len(filesystems) == 1 else None


def protected(path: Path, *, directory: bool = False) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise Refusal(f"{path.name or path} is unavailable") from error
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
        raise Refusal(f"{path.name or path} has unsafe ownership, type or mode")


def read_protected(path: Path, limit: int) -> str:
    protected(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8") as stream:
        return stream.read(limit)


def load_components(config: Path) -> dict:
    try:
        protected(config.parent, directory=True)
        data = json.loads(read_protected(config, MAX_CONFIG_BYTES))
        root = data["state_root"]
        if not isinstance(root, str) or not PurePosixPath(root).is_absolute():
            raise ValueError("state_root")
        if not isinstance(data["components"], dict) or not isinstance(
            data["instance"], str
        ):
            raise TypeError("shape")
        if not isinstance(data.get("require_zfs", True), bool):
            raise TypeError("require_zfs")
    except (Refusal, OSError, ValueError, KeyError, TypeError) as error:
        raise Refusal("components file is missing, unsafe or malformed") from error
    return data


def check(config: Path, instance: str, component: str) -> None:
    if os.getuid() != 0:
        raise Refusal("storage preflight must run as root")
    data = load_components(config)
    if data["instance"] != instance:
        raise Refusal("instance does not match the components file")
    if component not in data["components"]:
        raise Refusal("component is not listed for this instance")
    root = Path(data["state_root"])
    fstype = mount_type(root)
    if fstype is None:
        raise Refusal("state root must be a separately mounted filesystem")
    if data.get("require_zfs", True) and fstype != "zfs":
        raise Refusal("state root must be a ZFS filesystem")
    protected(root, directory=True)
    if read_protected(root / ".locksmith-edge-id", 128).strip() != instance:
        raise Refusal("wrong state volume identity")
    protected(root / "custody", directory=True)
    receipt = read_protected(root / "custody" / f"{component}.ready", 128).strip()
    if receipt != f"{instance}:{component}":
        raise Refusal("custody ceremony has not been acknowledged for this component")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("instance")
    parser.add_argument("component")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    try:
        check(args.config, args.instance, args.component)
    except Refusal as error:
        # Messages are fixed text plus file names; never file contents.
        print(f"locksmith-edge startup refused: {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(
            f"locksmith-edge startup refused: {type(error).__name__}", file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
