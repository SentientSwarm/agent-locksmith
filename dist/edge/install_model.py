#!/usr/bin/python3 -I
"""Install a pinned inspector model into an offline Hugging Face cache.

Weights are never shipped with Locksmith. A gated model downloads under the
operator's own HF token, read from a 0600 file or a hidden prompt, never
argv. The token is sent only to the HF origin (urllib does not forward an
unredirected header to the CDN it redirects to) and is never written to
disk. Every file is pinned by revision and checked by SHA-256 or git blob
SHA-1 before the install is renamed into place. Run the inspector with
HF_HUB_OFFLINE=1 and HF_HOME pointing at the same directory.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import re
import shutil
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ENDPOINT = "https://huggingface.co"
REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
REV_RE = re.compile(r"^[0-9a-f]{40}$")
PATH_RE = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
HEX = {"sha256": 64, "git_sha1": 40}
CHUNK = 1 << 20


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


def read_token_file(path: Path) -> str:
    info = path.stat()
    if info.st_mode & 0o077:
        raise InstallError(
            f"{path} must not be readable by group or others (chmod 600)"
        )
    token = path.read_text(encoding="utf-8").strip()
    if not token or any(c.isspace() for c in token):
        raise InstallError(f"{path} must contain one token")
    return token


def redirect_allowed(old: str, new: str) -> bool:
    old_scheme, new_scheme = (
        urllib.parse.urlsplit(old).scheme,
        urllib.parse.urlsplit(new).scheme,
    )
    return new_scheme == "https" or (old_scheme == new_scheme == "http")


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not redirect_allowed(req.full_url, newurl):
            raise InstallError("refusing a redirect that downgrades from https")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(
    opener, url: str, token: str | None, dest: Path, spec: ModelFile, gated: bool
) -> None:
    request = urllib.request.Request(url)
    if token is not None:
        # Unredirected: urllib never copies this header onto a redirect.
        request.add_unredirected_header("Authorization", f"Bearer {token}")
    sha256, sha1 = hashlib.sha256(), hashlib.sha1(b"blob %d\0" % spec.size)
    count = 0
    try:
        with opener.open(request, timeout=60) as resp, dest.open("wb") as out:
            while chunk := resp.read(CHUNK):
                count += len(chunk)
                if count > spec.size:
                    raise InstallError(f"{spec.path}: larger than the catalog size")
                sha256.update(chunk)
                sha1.update(chunk)
                out.write(chunk)
    except urllib.error.HTTPError as err:
        if gated and err.code in (401, 403):
            raise InstallError(
                "access refused: accept the licence for this model on Hugging Face with the "
                "account that owns the token, then retry"
            ) from None
        raise InstallError(f"{spec.path}: HTTP {err.code}") from None
    except urllib.error.URLError as err:
        raise InstallError(f"{spec.path}: cannot download ({err.reason})") from None
    if count != spec.size:
        raise InstallError(f"{spec.path}: size {count} does not match the catalog")
    ok = (
        sha256.hexdigest() == spec.sha256
        if spec.sha256
        else sha1.hexdigest() == spec.git_sha1
    )
    if not ok:
        raise InstallError(f"{spec.path}: checksum does not match the catalog")


def install(
    model: Model,
    hf_home: Path,
    *,
    token: str | None,
    endpoint: str = ENDPOINT,
    accepted_by: str = "unrecorded",
) -> Path:
    if model.gated and not token:
        raise InstallError(
            f"{model.repo} is gated: supply your own token with --token-file or --token-prompt"
        )
    hub = hf_home / "hub"
    target = hub / ("models--" + model.repo.replace("/", "--"))
    if target.exists():
        raise InstallError(f"{target} exists; refusing to overwrite an installed model")
    hub.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".locksmith-install-", dir=hub))
    try:
        repo = staging / target.name
        snap = repo / "snapshots" / model.revision
        opener = urllib.request.build_opener(_Redirects)
        for spec in model.files:
            dest = snap / spec.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            partial = dest.with_name(dest.name + ".partial")
            url = f"{endpoint}/{model.repo}/resolve/{model.revision}/{urllib.parse.quote(spec.path)}"
            _fetch(
                opener, url, token if model.gated else None, partial, spec, model.gated
            )
            partial.rename(dest)
        (repo / "refs").mkdir()
        (repo / "refs" / "main").write_text(model.revision)
        (repo / "locksmith-manifest.json").write_text(_manifest(model, accepted_by))
        if target.exists():
            raise InstallError(
                f"{target} appeared during the install; leaving it alone"
            )
        repo.rename(target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return target


def _manifest(model: Model, accepted_by: str) -> str:
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("model", help="model id from the catalog")
    parser.add_argument(
        "--hf-home", type=Path, required=True, help="HF_HOME the inspector will use"
    )
    parser.add_argument(
        "--catalog", type=Path, default=Path(__file__).with_name("models.toml")
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--token-file", type=Path, help="a 0600 file holding your HF token"
    )
    source.add_argument(
        "--token-prompt", action="store_true", help="ask for the token without echo"
    )
    parser.add_argument(
        "--accepted-by",
        default="unrecorded",
        help="who accepted the licence (recorded)",
    )
    args = parser.parse_args()
    try:
        model = load_catalog(args.catalog).get(args.model)
        if model is None:
            parser.error(f"no model {args.model!r} in {args.catalog}")
        token = None
        if args.token_file:
            token = read_token_file(args.token_file)
        elif args.token_prompt:
            token = getpass.getpass("Hugging Face token: ").strip() or None
        target = install(model, args.hf_home, token=token, accepted_by=args.accepted_by)
    except (InstallError, OSError) as err:
        print(f"install_model: {err}", file=sys.stderr)
        return 2
    print(f"installed {model.repo}@{model.revision[:12]} into {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
