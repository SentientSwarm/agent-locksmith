"""CAT helpers: per-run sealing keys, a fake 1Password `op` CLI and seed files.

Nothing here is evidence. The fake `op` answers only `op read <ref>` for the
references it was given and logs each invocation so a case can prove the
proxy hot path never shells out.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import yaml


def sealing_key() -> str:
    """A fresh base64 encoding of 32 random bytes (sealed-state-recovery.md:11)."""
    return base64.b64encode(os.urandom(32)).decode()


class FakeOp:
    """An executable `op` placed first on the daemon's PATH."""

    def __init__(self, directory: Path, values: dict[str, str]) -> None:
        self.dir = directory
        self.calls = directory / "calls.log"
        table = directory / "values.json"
        table.write_text(json.dumps(values))
        table.chmod(0o600)
        script = directory / "op"
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            f"CALLS = {str(self.calls)!r}\n"
            f"TABLE = {str(table)!r}\n"
            "if len(sys.argv) != 3 or sys.argv[1] != 'read':\n"
            "    sys.exit(64)\n"
            "with open(CALLS, 'a') as f:\n"
            "    f.write(sys.argv[2] + '\\n')\n"
            "value = json.load(open(TABLE)).get(sys.argv[2])\n"
            "if value is None:\n"
            "    sys.stderr.write('[ERROR] item not found\\n')\n"
            "    sys.exit(1)\n"
            "print(value)\n"
        )
        script.chmod(0o700)

    def path_env(self) -> str:
        return f"{self.dir}:{os.environ.get('PATH', '/usr/bin:/bin')}"

    def invocations(self) -> list[str]:
        return self.calls.read_text().splitlines() if self.calls.exists() else []


def write_seed(path: Path, version: str, entries: list[dict]) -> None:
    path.write_text(
        yaml.safe_dump({"version": version, "entries": entries}, sort_keys=False)
    )
    path.chmod(0o600)


def seed_entries(upstream: str) -> list[dict]:
    """Small catalog covering all three kinds (seed/catalog.yaml header)."""
    return [
        {
            "name": "seed-acc",
            "kind": "tool",
            "upstream": upstream,
            "auth": {"kind": "bearer", "env_var": "SMOKE_X"},
            "egress": "direct",
        },
        {
            "name": "seed-off",
            "kind": "tool",
            "upstream": upstream,
            "auth": {"kind": "none"},
            "egress": "direct",
        },
        {
            "name": "seed-own",
            "kind": "tool",
            "upstream": upstream,
            "auth": {"kind": "none"},
            "egress": "direct",
        },
        {
            "name": "seed-model",
            "kind": "model",
            "upstream": upstream,
            "auth": {"kind": "none"},
            "egress": "direct",
            "metadata": {"modality": "text"},
        },
        {
            "name": "seed-infra",
            "kind": "infra",
            "upstream": upstream,
            "egress": "direct",
        },
    ]
