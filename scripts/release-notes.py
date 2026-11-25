#!/usr/bin/env python3
"""Check a validated release asset set and write its notes from CHANGELOG.md.

The assets are the CLI and daemon for each shipped platform (Linux amd64 and
arm64, macOS arm64), SHA256SUMS and validation.json. A tag must name the Cargo
version, and every checksum must match. Exit 1 refuses with a reason.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
# darwin-amd64 is not shipped from 3.0.0: Intel Macs build from source.
SUFFIXES = ["linux-amd64", "linux-arm64", "darwin-arm64"]
BINARIES = sorted(
    f"{role}-{s}" for role in ("locksmith", "locksmithd") for s in SUFFIXES
)
EXPECTED = set(BINARIES) | {"SHA256SUMS", "validation.json"}


def version(root: Path) -> str:
    return tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]


def check_ref(ref: str, cargo_version: str) -> None:
    if ref.startswith("refs/tags/") and ref != f"refs/tags/v{cargo_version}":
        raise ValueError(
            f"tag {ref.removeprefix('refs/tags/')} does not name Cargo version {cargo_version}"
        )


def check_assets(assets: Path, cargo_version: str, revision: str) -> None:
    present = {p.name for p in assets.iterdir()}
    if present != EXPECTED:
        raise ValueError(
            f"asset set differs: missing {sorted(EXPECTED - present)}, extra {sorted(present - EXPECTED)}"
        )
    sums = {}
    for line in (assets / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        sums[name] = digest
    if set(sums) != set(BINARIES):
        raise ValueError("SHA256SUMS does not list exactly the six binaries")
    for name, digest in sums.items():
        if hashlib.sha256((assets / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"{name} does not match SHA256SUMS")
    source = json.loads((assets / "validation.json").read_text())["source"]
    if source["version"] != cargo_version:
        raise ValueError(
            f"validated version {source['version']} is not Cargo version {cargo_version}"
        )
    if source["revision"] != revision:
        raise ValueError(f"validated revision {source['revision']} is not this run's {revision}")


def changelog_section(text: str, cargo_version: str) -> str:
    match = re.search(
        rf"^## {re.escape(cargo_version)}\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL
    )
    body = match.group(1).strip() if match else ""
    if not body:
        raise ValueError(f"CHANGELOG.md has no section for {cargo_version}")
    return body


def notes(body: str) -> str:
    return (
        f"{body}\n\n## Assets\n\n"
        "There are programs for Linux amd64 (`linux-amd64`), Linux arm64 "
        "(`linux-arm64`) and macOS on Apple silicon (`darwin-arm64`). Each platform "
        "has two: `locksmithd` (the daemon) and `locksmith` (the CLI). On an Intel "
        "Mac, build from source with `cargo +1.94.0 build --locked --release --bins`. "
        "All six were built with Rust 1.94.0 and `--locked` and smoke-tested before "
        "upload, linux-arm64 under qemu-user and the others natively. Check a download with "
        "`shasum -a 256 -c SHA256SUMS --ignore-missing`; `validation.json` records "
        "the source revision and how each binary was built and tested.\n"
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--ref", required=True, help="GITHUB_REF of the run")
    parser.add_argument("--revision", required=True, help="GITHUB_SHA of the run")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        cargo_version = version(ROOT)
        check_ref(args.ref, cargo_version)
        check_assets(args.assets, cargo_version, args.revision)
        args.out.write_text(
            notes(changelog_section((ROOT / "CHANGELOG.md").read_text(), cargo_version))
        )
    except (ValueError, OSError, KeyError) as error:
        print(f"release refused: {error}", file=sys.stderr)
        return 1
    print(
        f"release {cargo_version}: {len(BINARIES)} binaries checked, notes in {args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
