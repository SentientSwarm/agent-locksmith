"""T1 local-binary target: release binaries, disposable directory, local fakes.

Cases reach the product only through `cli()` and `http()`; every exchange is
written to the evidence bundle after canary redaction.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evidence import Bundle
from .redact import Canaries

REPO = Path(__file__).resolve().parents[2]
REFERENCE_API = REPO / "examples" / "http-account-service.py"
SMOKE_X = "synthetic-private-account-x"
SMOKE_Y = "synthetic-private-account-y"
STARTUP_TIMEOUT = 20.0
SECRET_KEYS = {"token", "secret", "wire_token", "access_token", "refresh_token"}


class TargetError(Exception):
    pass


@dataclass
class CliResult:
    code: int
    out: str
    err: str
    json: Any


@dataclass
class HttpResult:
    status: int
    headers: dict
    text: str
    json: Any

    @property
    def code(self) -> str | None:
        """The error envelope's code, if any."""
        if isinstance(self.json, dict) and isinstance(self.json.get("error"), dict):
            return self.json["error"].get("code")
        return None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


class LocalTarget:
    name = "t1-local-binary"

    def __init__(self, bins: Path, canaries: Canaries, bundle: Bundle) -> None:
        self.bins = bins.resolve()
        # Short path outside the bundle: the admin socket path must fit SUN_LEN,
        # and the work directory (operators file, database) is never evidence.
        base = "/tmp" if Path("/tmp").is_dir() else None
        self.work = Path(tempfile.mkdtemp(prefix="lsqa-", dir=base)).resolve()
        canaries.add(str(self.work), "workdir")
        self.canaries = canaries
        self.bundle = bundle
        self.current_case = "setup"
        self.op_token: str | None = None
        self.procs: dict[str, subprocess.Popen] = {}
        self.port = 0
        self.upstream_url = ""
        self.socket = self.work / "admin.sock"
        canaries.add(SMOKE_X, "smoke-x-credential")
        canaries.add(SMOKE_Y, "smoke-y-credential")

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        os.umask(0o077)
        self._start_upstream()
        self._mint_operator()
        self._write_config()
        self._start_daemon()

    def close(self) -> None:
        for name, proc in list(self.procs.items()):
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        log = self.work / "locksmithd.log"
        if log.exists():
            self.bundle.transcript(
                "run", "locksmithd-log", log.read_text(errors="replace")
            )
        self.procs.clear()
        shutil.rmtree(self.work, ignore_errors=True)

    def _start_upstream(self) -> None:
        proc = subprocess.Popen(
            [sys.executable, str(REFERENCE_API), "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self.procs["upstream"] = proc
        assert proc.stdout is not None
        line = proc.stdout.readline().strip()
        if not line.startswith("http://127.0.0.1:"):
            raise TargetError(f"reference API did not start (got {line!r})")
        self.upstream_url = line

    def _mint_operator(self) -> None:
        result = subprocess.run(
            [str(self.bins / "locksmith"), "bootstrap-operator", "--name", "qa"],
            capture_output=True,
            text=True,
            check=False,
        )
        match = re.search(r"export LOCKSMITH_OP_TOKEN='([^']+)'", result.stderr)
        if result.returncode != 0 or not match:
            raise TargetError(f"bootstrap-operator failed (exit {result.returncode})")
        self.op_token = match.group(1)
        self.canaries.add(self.op_token, "operator-token")
        (self.work / "operators.yaml").write_text(result.stdout)

    def _write_config(self) -> None:
        self.port = free_port()
        config = f"""listen:
  host: "127.0.0.1"
  port: {self.port}
  auth_mode: bearer
  admin_socket:
    path: "{self.socket}"
operator_credentials_path: "{self.work / "operators.yaml"}"
database:
  path: "{self.work / "locksmith.db"}"
shutdown:
  drain_window_seconds: 1
tools: []
"""
        (self.work / "config.yaml").write_text(config)

    def _start_daemon(self) -> None:
        env = {
            **os.environ,
            "LOCKSMITH_SEED_PATH": "",
            "SMOKE_X": SMOKE_X,
            "SMOKE_Y": SMOKE_Y,
        }
        with open(self.work / "locksmithd.log", "w") as log:
            self.procs["locksmithd"] = subprocess.Popen(
                [
                    str(self.bins / "locksmithd"),
                    "--config",
                    str(self.work / "config.yaml"),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                env=env,
            )
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while time.monotonic() < deadline:
            if self.procs["locksmithd"].poll() is not None:
                raise TargetError(
                    f"locksmithd exited {self.procs['locksmithd'].returncode}: {self._log_error()}"
                )
            try:
                if (
                    self.http("GET", "/livez", record=False).status == 200
                    and self.socket.exists()
                ):
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise TargetError(
            f"locksmithd not live after {STARTUP_TIMEOUT:.0f}s: {self._log_error()}"
        )

    def _log_error(self) -> str:
        """The daemon's last error-level message (full log goes to cases/run/)."""
        log = self.work / "locksmithd.log"
        lines = log.read_text(errors="replace").splitlines() if log.exists() else []
        for line in reversed(lines):
            entry = _parse_json(line)
            if isinstance(entry, dict) and entry.get("level") == "ERROR":
                fields = entry.get("fields", {})
                return self.canaries.redact(
                    f"{fields.get('message', '')}: {fields.get('error', '')}"
                )
        return "no error-level log line; see cases/run/ locksmithd log"

    # -- product interfaces ----------------------------------------------
    def cli(
        self,
        *args: str,
        op_token: str | None = None,
        agent_token: str | None = None,
        use_op_token: bool = True,
    ) -> CliResult:
        env = {k: v for k, v in os.environ.items() if not k.startswith("LOCKSMITH_")}
        if use_op_token:
            token = op_token if op_token is not None else self.op_token
            if token is None:
                raise TargetError("operator token not minted; call start() first")
            env["LOCKSMITH_OP_TOKEN"] = token
        if agent_token is not None:
            env["LOCKSMITH_AGENT_TOKEN"] = agent_token
        argv = [
            str(self.bins / "locksmith"),
            "--socket",
            str(self.socket),
            "--format",
            "json",
            *args,
        ]
        proc = subprocess.run(
            argv, check=False, capture_output=True, text=True, env=env, timeout=60
        )
        parsed = _parse_json(proc.stdout)
        self._harvest(parsed)
        shown = " ".join(["locksmith", *args])
        self.bundle.transcript(
            self.current_case,
            "cli",
            f"$ {shown}\nexit {proc.returncode}\n--- stdout\n{proc.stdout}\n--- stderr\n{proc.stderr}",
        )
        return CliResult(proc.returncode, proc.stdout, proc.stderr, parsed)

    def http(
        self,
        method: str,
        path: str,
        token: str | None = None,
        body: bytes | None = None,
        headers: dict | None = None,
        record: bool = True,
    ) -> HttpResult:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=body, method=method
        )
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status, hdrs, raw = resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            status, hdrs, raw = err.code, dict(err.headers), err.read()
        text = raw.decode(errors="replace")
        result = HttpResult(status, hdrs, text, _parse_json(text))
        if record:
            auth = " (bearer)" if token is not None else ""
            self.bundle.transcript(
                self.current_case,
                "http",
                f"{method} {path}{auth}\n--- {status}\n{text[:4000]}",
            )
        return result

    def upstream_counts(self) -> dict:
        with urllib.request.urlopen(f"{self.upstream_url}/counts", timeout=10) as resp:
            return json.loads(resp.read())

    def build_info(self) -> dict:
        info = {}
        for name in ("locksmith", "locksmithd"):
            out = subprocess.run(
                [str(self.bins / name), "--build-info"],
                capture_output=True,
                text=True,
                check=True,
            )
            info[name] = json.loads(out.stdout)
        return info

    def _harvest(self, value: Any) -> None:
        """Register any secret-named field in CLI output as a canary before it is recorded."""
        if isinstance(value, dict):
            for key, item in value.items():
                if key in SECRET_KEYS and isinstance(item, str):
                    self.canaries.add(item, f"cli-{key}")
                else:
                    self._harvest(item)
        elif isinstance(value, list):
            for item in value:
                self._harvest(item)
