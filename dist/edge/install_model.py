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
import http.client
import os
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# -I drops the script directory from sys.path; add back only that directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalog import (
    InstallError,
    Model,
    ModelFile,
    load_catalog,
    manifest,
    parse_catalog,
)
from hfhttp import _origin, _Redirects, check_token, read_token_file, redirect_allowed  # noqa: F401

# Re-exported so callers and tests need only this module.
__all__ = [
    "InstallError",
    "Model",
    "check_token",
    "install",
    "load_catalog",
    "parse_catalog",
    "read_token_file",
    "redirect_allowed",
]

ENDPOINT = "https://huggingface.co"
CHUNK = 1 << 20


def _check_parents(path: Path, owners: frozenset[int]) -> None:
    """Refuse a cache that anyone but root (or the installer) could replace.

    Renaming a directory needs write access only on its parent, so a
    service-owned or shared-writable ancestor would let the inspector swap
    the weights for its own. Sticky directories such as /tmp are allowed.
    """
    for parent in [path, *path.parents]:
        try:
            info = parent.stat()
        except FileNotFoundError:
            continue
        if info.st_uid not in owners:
            raise InstallError(
                f"{parent} is owned by uid {info.st_uid}; install the model cache under "
                "directories only root can change, outside any service's state directory"
            )
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise InstallError(
                f"{parent} is group- or world-writable; install the model cache under "
                "directories only root can change"
            )


def _publishable(repo: Path) -> None:
    """Make the install readable by the service whatever the installer's umask."""
    for path in [repo, *repo.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)


def _mkdir_readable(path: Path) -> None:
    missing = [p for p in [path, *path.parents] if not p.exists()]
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)  # never briefly writable by others
        directory.chmod(0o755)


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
    except (http.client.HTTPException, ValueError) as err:
        # A dropped connection or a malformed redirect; name the type only.
        raise InstallError(f"{spec.path}: download failed ({type(err).__name__})") from None
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
    trusted_owners: frozenset[int] | None = None,
) -> Path:
    if model.gated and not token:
        raise InstallError(
            f"{model.repo} is gated: supply your own token with --token-file or --token-prompt"
        )
    owners = trusted_owners if trusted_owners is not None else frozenset({0, os.geteuid()})
    # Lexical and resolved: a symlinked ancestor must not hide a writable
    # parent. Checking hub covers an existing hub and everything above it.
    hub_path = hf_home.absolute() / "hub"
    for path in (hub_path, hub_path.resolve()):
        _check_parents(path, owners)
    hub = hf_home / "hub"
    if hf_home.is_symlink() or hub.is_symlink():
        raise InstallError(f"{hub} or its parent is a symlink; refusing to follow it")
    target = hub / ("models--" + model.repo.replace("/", "--"))
    if target.exists():
        raise InstallError(f"{target} exists; refusing to overwrite an installed model")
    _mkdir_readable(hf_home)
    _mkdir_readable(hub)
    staging = Path(tempfile.mkdtemp(prefix=".locksmith-install-", dir=hub))
    try:
        repo = staging / target.name
        snap = repo / "snapshots" / model.revision
        sent = token if model.gated else None
        opener = urllib.request.build_opener(_Redirects(endpoint, sent))
        for spec in model.files:
            dest = snap / spec.path
            dest.parent.mkdir(parents=True, exist_ok=True)
            partial = dest.with_name(dest.name + ".partial")
            url = f"{endpoint}/{model.repo}/resolve/{model.revision}/{urllib.parse.quote(spec.path)}"
            _fetch(opener, url, sent, partial, spec, model.gated)
            partial.rename(dest)
        (repo / "refs").mkdir()
        (repo / "refs" / "main").write_text(model.revision)
        (repo / "locksmith-manifest.json").write_text(manifest(model, accepted_by))
        _publishable(repo)
        if target.exists():
            raise InstallError(
                f"{target} appeared during the install; leaving it alone"
            )
        repo.rename(target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return target


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
    if os.geteuid() != 0:
        # As non-root, this user's own directories would count as trusted
        # cache parents, so a cache it can rewrite would pass (AGENT-288).
        print("install_model: run as root (sudo)", file=sys.stderr)
        return 2
    try:
        model = load_catalog(args.catalog).get(args.model)
        if model is None:
            parser.error(f"no model {args.model!r} in {args.catalog}")
        token = None
        if args.token_file:
            token = read_token_file(args.token_file)
        elif args.token_prompt:
            token = check_token(getpass.getpass("Hugging Face token: "), "the prompt")
        target = install(model, args.hf_home, token=token, accepted_by=args.accepted_by)
    except (InstallError, OSError) as err:
        print(f"install_model: {err}", file=sys.stderr)
        return 2
    print(f"installed {model.repo}@{model.revision[:12]} into {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
