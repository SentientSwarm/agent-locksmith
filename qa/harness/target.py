"""T1 local-binary target: release binaries, disposable directory, local fakes.

Cases reach the product only through `cli()` and `http()`; every exchange is
written to the evidence bundle after canary redaction. A target can take a
config overlay and extra daemon environment, so one session can run several
differently configured daemons.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .evidence import Bundle
from .redact import Canaries

REPO = Path(__file__).resolve().parents[2]
REFERENCE_API = REPO / "examples" / "http-account-service.py"
SMOKE_X = "synthetic-private-account-x"
SMOKE_Y = "synthetic-private-account-y"
STARTUP_TIMEOUT = 20.0
SECRET_KEYS = {
    "token",
    "secret",
    "wire_token",
    "access_token",
    "refresh_token",
    "client_secret",
}

Overlay = dict | Callable[[Path], dict] | None


class TargetError(Exception):
    pass


@dataclass
class CliResult:
    code: int
    out: str
    err: str
    json: Any

    @property
    def error_code(self) -> str | None:
        """The daemon error code the CLI printed, if any."""
        match = re.search(r'"code":"([a-z_]+)"', self.err + self.out)
        return match.group(1) if match else None


@dataclass
class HttpResult:
    status: int
    headers: dict
    text: str
    json: Any

    def header(self, name: str) -> str | None:
        """Case-insensitive response header lookup."""
        wanted = name.lower()
        return next((v for k, v in self.headers.items() if k.lower() == wanted), None)

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


def merge(base: dict, overlay: dict) -> dict:
    """Deep-merge overlay into a copy of base; a None value deletes the key."""
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        if value is None:
            out.pop(key, None)
        elif isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class LocalTarget:
    name = "t1-local-binary"

    def __init__(
        self,
        bins: Path,
        canaries: Canaries,
        bundle: Bundle,
        *,
        config: Overlay = None,
        env: dict | None = None,
        label: str = "main",
        upstream: bool = True,
    ) -> None:
        self.bins = bins.resolve()
        # Short path outside the bundle: the admin socket path must fit SUN_LEN,
        # and the work directory (operators file, database) is never evidence.
        base = "/tmp" if Path("/tmp").is_dir() else None
        self.work = Path(tempfile.mkdtemp(prefix="lsqa-", dir=base)).resolve()
        canaries.add(str(self.work), "workdir")
        self.canaries = canaries
        self.bundle = bundle
        self.label = label
        self.overlay = config
        self.extra_env = dict(env or {})
        self.want_upstream = upstream
        self.current_case = "setup"
        self.op_token: str | None = None
        self.procs: dict[str, subprocess.Popen] = {}
        self.port = 0
        self.upstream_url = ""
        self.socket = self.work / "admin.sock"
        self.config: dict = {}
        canaries.add(SMOKE_X, "smoke-x-credential")
        canaries.add(SMOKE_Y, "smoke-y-credential")
        for key, value in self.extra_env.items():
            if "KEY" in key or "SECRET" in key or "TOKEN" in key:
                canaries.add(value, f"env-{key.lower()}")

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        os.umask(0o077)
        if self.want_upstream and "upstream" not in self.procs:
            self._start_upstream()
        if self.op_token is None:
            self._mint_operator()
        self._write_config()
        self._start_daemon()

    def stop(self, sig: int = signal.SIGTERM, timeout: float = 15.0) -> int:
        """Stop the daemon only; returns its exit code."""
        proc = self.procs.pop("locksmithd", None)
        if proc is None:
            raise TargetError("locksmithd is not running")
        if proc.poll() is None:
            proc.send_signal(sig)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise TargetError(
                    f"locksmithd ignored signal {sig} for {timeout:.0f}s"
                ) from None
        return proc.returncode

    def restart(self, config: Overlay = None) -> None:
        """Stop and start the daemon; a new overlay (if given) is written first."""
        self.stop()
        if config is not None:
            self.overlay = config
            self._write_config()
        self._start_daemon()

    def reconfigure(self, config: Overlay) -> None:
        """Replace the overlay and rewrite config.yaml without starting (daemon must be stopped)."""
        if "locksmithd" in self.procs:
            raise TargetError("stop the daemon before reconfigure()")
        self.overlay = config
        self._write_config()

    def start_daemon(self) -> None:
        """Start the daemon against the current config.yaml (after stop() or reconfigure())."""
        self._start_daemon()

    def close(self) -> None:
        for proc in list(self.procs.values()):
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
                "run", f"locksmithd-{self.label}-log", log.read_text(errors="replace")
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

    def base_config(self) -> dict:
        return {
            "listen": {
                "host": "127.0.0.1",
                "port": self.port,
                "auth_mode": "bearer",
                "admin_socket": {"path": str(self.socket)},
            },
            "operator_credentials_path": str(self.work / "operators.yaml"),
            "database": {"path": str(self.work / "locksmith.db")},
            "shutdown": {"drain_window_seconds": 1},
            "tools": [],
        }

    def _write_config(self) -> None:
        if not self.port:
            self.port = free_port()
        overlay = (
            self.overlay(self.work) if callable(self.overlay) else (self.overlay or {})
        )
        self.config = merge(self.base_config(), overlay)
        self.port = self.config["listen"]["port"]
        self.write_file("config.yaml", yaml.safe_dump(self.config, sort_keys=False))

    def daemon_env(self) -> dict:
        """Daemon environment; RUST_LOG is dropped so `logging.level` decides."""
        inherited = {k: v for k, v in os.environ.items() if k != "RUST_LOG"}
        return {**inherited, "LOCKSMITH_SEED_PATH": "", "SMOKE_X": SMOKE_X, "SMOKE_Y": SMOKE_Y,
                **self.extra_env}

    def _start_daemon(self) -> None:
        with open(self.work / "locksmithd.log", "a") as log:
            self.procs["locksmithd"] = subprocess.Popen(
                [
                    str(self.bins / "locksmithd"),
                    "--config",
                    str(self.work / "config.yaml"),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                env=self.daemon_env(),
            )
        self.wait_live()

    def wait_live(self, timeout: float = STARTUP_TIMEOUT) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            proc = self.procs.get("locksmithd")
            if proc is None or proc.poll() is not None:
                code = proc.returncode if proc else "?"
                raise TargetError(f"locksmithd exited {code}: {self.log_error()}")
            if self._live():
                return
            time.sleep(0.1)
        raise TargetError(
            f"locksmithd not live after {timeout:.0f}s: {self.log_error()}"
        )

    def _live(self) -> bool:
        if "admin_socket" in self.config.get("listen", {}) and not self.socket.exists():
            return False
        if self.config["listen"].get("auth_mode", "bearer") != "bearer":
            return self._port_open(self.port)
        try:
            return self.http("GET", "/livez", record=False).status == 200
        except OSError:
            return False

    @staticmethod
    def _port_open(port: int) -> bool:
        with socket.socket() as s:
            s.settimeout(0.5)
            return s.connect_ex(("127.0.0.1", port)) == 0

    def run_daemon_once(self, timeout: float = 20.0) -> subprocess.CompletedProcess:
        """Run locksmithd in the foreground against the current config (for refusals to start)."""
        os.umask(0o077)
        if self.op_token is None:
            self._mint_operator()
        self._write_config()
        proc = subprocess.run(
            [str(self.bins / "locksmithd"), "--config", str(self.work / "config.yaml")],
            capture_output=True,
            text=True,
            env=self.daemon_env(),
            timeout=timeout,
            check=False,
        )
        self.bundle.transcript(
            self.current_case,
            "locksmithd-once",
            f"exit {proc.returncode}\n--- output\n{proc.stdout}{proc.stderr}",
        )
        return proc

    def log_text(self) -> str:
        log = self.work / "locksmithd.log"
        return log.read_text(errors="replace") if log.exists() else ""

    def log_events(self) -> list[dict]:
        return [
            e
            for e in (_parse_json(line) for line in self.log_text().splitlines())
            if isinstance(e, dict)
        ]

    def log_error(self) -> str:
        """The daemon's last error-level message (full log goes to cases/run/)."""
        for entry in reversed(self.log_events()):
            if entry.get("level") == "ERROR":
                fields = entry.get("fields", {})
                return self.canaries.redact(
                    f"{fields.get('message', '')}: {fields.get('error', '')}"
                )
        return "no error-level log line; see the locksmithd log under cases/run/"

    def write_file(self, name: str, text: str | bytes, mode: int = 0o600) -> Path:
        path = self.work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            path.write_bytes(text)
        else:
            path.write_text(text)
        path.chmod(mode)
        return path

    # -- product interfaces ----------------------------------------------
    def cli(
        self,
        *args: str,
        op_token: str | None = None,
        agent_token: str | None = None,
        use_op_token: bool = True,
        socket_flag: bool = True,
        stdin: str | None = None,
        env: dict | None = None,
        fmt: str | None = "json",
    ) -> CliResult:
        run_env = {
            k: v for k, v in os.environ.items() if not k.startswith("LOCKSMITH_")
        }
        if use_op_token:
            token = op_token if op_token is not None else self.op_token
            if token is None:
                raise TargetError("operator token not minted; call start() first")
            run_env["LOCKSMITH_OP_TOKEN"] = token
        if agent_token is not None:
            run_env["LOCKSMITH_AGENT_TOKEN"] = agent_token
        run_env.update(env or {})
        argv = [str(self.bins / "locksmith")]
        if socket_flag:
            argv += ["--socket", str(self.socket)]
        if fmt:
            argv += ["--format", fmt]
        argv += list(args)
        proc = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            env=run_env,
            timeout=60,
            input=stdin,
        )
        parsed = _parse_json(proc.stdout)
        self._harvest(parsed)
        shown = " ".join(["locksmith", *args]) + (
            " <stdin>" if stdin is not None else ""
        )
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
        body: bytes | str | dict | None = None,
        headers: dict | None = None,
        record: bool = True,
        base: str | None = None,
        context: ssl.SSLContext | None = None,
        timeout: float = 30,
    ) -> HttpResult:
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers = {"Content-Type": "application/json", **(headers or {})}
        elif isinstance(body, str):
            body = body.encode()
        url = f"{base or f'http://127.0.0.1:{self.port}'}{path}"
        req = urllib.request.Request(url, data=body, method=method)
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                status, hdrs, raw = resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            status, hdrs, raw = err.code, dict(err.headers), err.read()
        text = raw.decode(errors="replace")
        result = HttpResult(status, hdrs, text, _parse_json(text))
        self._harvest(result.json)
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
