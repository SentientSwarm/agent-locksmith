"""Verify the vendored SDK and its complete reversible authored delta."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import tempfile


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify() -> None:
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "upstream.json").read_text())
    source = root / "rmcp"
    actual = {str(p.relative_to(source)) for p in source.rglob("*") if p.is_file()}
    assert actual == set(manifest["files"]), "unexpected or missing vendor files"
    changed = {name for name, sha in manifest["files"].items() if digest(source / name) != sha}
    assert changed == {
        "src/service.rs", "src/transport/worker.rs",
        "src/transport/streamable_http_server/session.rs",
        "src/transport/streamable_http_server/tower.rs",
    }, changed
    with tempfile.TemporaryDirectory(prefix="locksmith-sdk-provenance-") as directory:
        restored = Path(directory) / "rmcp"
        shutil.copytree(source, restored)
        subprocess.run(["patch", "--batch", "--reverse", "-p1", "-d", str(restored)],
                       input=(root / "ownership.patch").read_bytes(), check=True)
        for name, sha in manifest["files"].items():
            assert digest(restored / name) == sha, name
    print(f"rmcp3.7.0: {len(actual)} upstream files, four authored files, reversible patch verified")


if __name__ == "__main__":
    verify()
