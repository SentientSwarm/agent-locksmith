"""DMN helpers: one-shot daemon runs, offline operator minting, UDS reads.

Everything drives the shipped binaries or the admin socket as an operator
would; nothing writes Locksmith state. Transcripts go through the bundle's
canary redaction, and minted operator tokens are registered as canaries
before anything is recorded.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

TOKEN_RE = re.compile(r"export LOCKSMITH_OP_TOKEN='([^']+)'")
HASH_RE = re.compile(r"\$argon2[a-z]*\$[^\"'\s]+")


@dataclass
class Once:
    code: int | None  # None: the daemon accepted the config and kept running
    output: str


def run_once(
    target,
    name: str,
    config: dict | str,
    *,
    env: dict | None = None,
    cwd: Path | None = None,
    timeout: float = 15.0,
) -> Once:
    """Run locksmithd in the foreground on a config written into the work dir."""
    text = (
        config if isinstance(config, str) else yaml.safe_dump(config, sort_keys=False)
    )
    path = target.write_file(f"{name}.yaml", text)
    try:
        proc = subprocess.run(
            [str(target.bins / "locksmithd"), "--config", str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env={**target.daemon_env(), **(env or {})},
            cwd=cwd,
        )
        once = Once(proc.returncode, proc.stdout + proc.stderr)
    except subprocess.TimeoutExpired as err:
        out = (err.stdout or b"") + (err.stderr or b"")
        once = Once(
            None, out.decode(errors="replace") if isinstance(out, bytes) else out
        )
    target.bundle.transcript(
        target.current_case,
        f"locksmithd-{name}",
        f"exit {once.code}\n--- config\n{text}\n--- output\n{once.output}",
    )
    return once


def bootstrap_operator(target, *args: str) -> subprocess.CompletedProcess:
    """Run the offline `locksmith bootstrap-operator`; record a redacted transcript."""
    proc = subprocess.run(
        [str(target.bins / "locksmith"), "bootstrap-operator", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    match = TOKEN_RE.search(proc.stderr)
    if match:
        target.canaries.add(match.group(1), "dmn-operator-token")
    shown = HASH_RE.sub("<argon2-hash>", proc.stdout)
    target.bundle.transcript(
        target.current_case,
        "bootstrap-operator",
        f"$ locksmith bootstrap-operator {' '.join(args)}\nexit {proc.returncode}\n"
        f"--- stdout\n{shown}\n--- stderr\n{HASH_RE.sub('<argon2-hash>', proc.stderr)}",
    )
    return proc


def mint_operator(target, name: str) -> tuple[str, str]:
    """Return (operators.yaml text, wire token) for a fresh operator."""
    proc = bootstrap_operator(target, "--name", name)
    match = TOKEN_RE.search(proc.stderr)
    assert proc.returncode == 0 and match, f"bootstrap-operator exit {proc.returncode}"
    return proc.stdout, match.group(1)


class _Unix(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def uds_get(target, path: str, token: str | None = None) -> tuple[int, Any]:
    """GET an admin route over the daemon's admin socket as the operator."""
    conn = _Unix(str(target.socket), timeout=30)
    headers = {"Authorization": f"Bearer {token or target.op_token}"}
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        status, raw = resp.status, resp.read().decode(errors="replace")
    finally:
        conn.close()
    target.bundle.transcript(
        target.current_case, "uds", f"GET {path} (operator)\n--- {status}\n{raw[:4000]}"
    )
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, None


def mirror_files(directory: Path, stem: str = "audit.jsonl") -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(
        p for p in directory.iterdir() if p.name.startswith(stem) and p.is_file()
    )


def mirror_lines(directory: Path, stem: str = "audit.jsonl") -> list[str]:
    return [
        line
        for f in mirror_files(directory, stem)
        for line in f.read_text().splitlines()
        if line
    ]


def wait_for(predicate, timeout: float = 10.0, step: float = 0.2):
    """Poll predicate() until truthy; return its last value."""
    deadline = time.monotonic() + timeout
    value = predicate()
    while not value and time.monotonic() < deadline:
        time.sleep(step)
        value = predicate()
    return value
