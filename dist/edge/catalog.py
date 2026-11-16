"""Inspector model catalog: pinned revisions and per-file digests.

Loaded by install_model.py. A file is checked by SHA-256 (LFS files) or by
its git blob SHA-1 (small files), exactly one of the two.
"""

from __future__ import annotations

import json
import re
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
REV_RE = re.compile(r"^[0-9a-f]{40}$")
PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
HEX = {"sha256": 64, "git_sha1": 40}


class InstallError(Exception):
    pass


@dataclass(frozen=True)
class ModelFile:
    path: str
    size: int
    sha256: str | None
    git_sha1: str | None


@dataclass(frozen=True)
class Model:
    id: str
    repo: str
    revision: str
    license: str
    gated: bool
    files: list[ModelFile]


def load_catalog(path: Path) -> dict[str, Model]:
    return parse_catalog(Path(path).read_text(encoding="utf-8"))


def parse_catalog(text: str) -> dict[str, Model]:
    try:
        entries = tomllib.loads(text).get("model", [])
        models = [_model(e) for e in entries]
    except (tomllib.TOMLDecodeError, TypeError, KeyError, AttributeError) as err:
        raise InstallError(f"invalid catalog: {err}") from None
    return {m.id: m for m in models}


def _model(entry: dict) -> Model:
    extra = set(entry) - {"id", "repo", "revision", "license", "gated", "files"}
    if extra:
        raise InstallError(f"catalog: unknown key {min(extra)!r}")
    if not REPO_RE.match(entry["repo"]) or not REV_RE.match(entry["revision"]):
        raise InstallError(f"catalog {entry['id']}: repo or revision is not pinned")
    if not isinstance(entry["gated"], bool):
        raise InstallError(f"catalog {entry['id']}: gated must be true or false")
    files = [_file(f, entry["id"]) for f in entry["files"]]
    return Model(
        entry["id"],
        entry["repo"],
        entry["revision"],
        entry["license"],
        entry["gated"],
        files,
    )


def _file(entry: dict, model_id: str) -> ModelFile:
    extra = set(entry) - {"path", "size", *HEX}
    digests = [k for k in HEX if k in entry]
    path, size = entry["path"], entry["size"]
    bad_path = not PATH_RE.match(path) or ".." in PurePosixPath(path).parts
    if extra or bad_path or type(size) is not int or size < 1 or len(digests) != 1:
        raise InstallError(f"catalog {model_id}: invalid file entry {path!r}")
    digest = entry[digests[0]]
    if not re.fullmatch(f"[0-9a-f]{{{HEX[digests[0]]}}}", digest):
        raise InstallError(f"catalog {model_id}: invalid digest for {path!r}")
    return ModelFile(path, size, entry.get("sha256"), entry.get("git_sha1"))


def manifest(model: Model, accepted_by: str) -> str:
    files = [
        {
            "path": f.path,
            "size": f.size,
            **({"sha256": f.sha256} if f.sha256 else {"git_sha1": f.git_sha1}),
        }
        for f in model.files
    ]
    data = {
        "repo": model.repo,
        "revision": model.revision,
        "license": model.license,
        "gated": model.gated,
        "accepted_by": accepted_by,
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": files,
    }
    return json.dumps(data, indent=2) + "\n"
