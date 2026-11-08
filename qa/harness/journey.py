"""Run a guide page's steps as a reader would, and record what happened.

Each journey gets a fresh HOME under /tmp, the binaries under test first on
PATH and pinned ports. Steps run verbatim in Bash; exported variables and the
working directory carry from one step to the next. Pinned variables override
whatever a step exports, so a page can say `${LOCKSMITH_PORT:-9200}` and still
run on a free port here.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import figure
from .evidence import Bundle
from .guide import Page
from .redact import Canaries

REPO = Path(__file__).resolve().parents[2]
SECRET_ENV = re.compile(r"TOKEN|SECRET|PASSWORD|SEALING_KEY|_KEY$")
SECRET_FIELD = re.compile(
    r'"(token|secret|wire_token|access_token|refresh_token|client_secret)"\s*:\s*"([^"]+)"'
)
INTERNAL = {"PWD", "OLDPWD", "SHLVL", "_"}


class StepFailed(AssertionError):
    pass


@dataclass
class Result:
    code: int
    out: str

    @property
    def json(self) -> Any:
        try:
            return json.loads(self.out)
        except ValueError:
            return None


class Journey:
    def __init__(
        self,
        page: Page,
        bins: Path,
        bundle: Bundle,
        canaries: Canaries,
        pins: dict[str, str],
    ) -> None:
        self.page, self.bundle, self.canaries = page, bundle, canaries
        self.current_case = "setup"
        self.work = Path(tempfile.mkdtemp(prefix="lsuat-", dir="/tmp"))
        self.home = self.work / "home"
        self.home.mkdir()
        (self.work / "tmp").mkdir()
        self.pins = {"LOCKSMITH_SRC": str(REPO), **pins}
        self.env = {
            "HOME": str(self.home),
            "PATH": f"{bins.resolve()}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "TMPDIR": str(self.work / "tmp"),
            "LANG": "C.UTF-8",
            "TERM": "dumb",
            **self.pins,
        }
        self.cwd = self.home
        self.ran: list[str] = []
        self.procs: dict[str, tuple[subprocess.Popen, Path]] = {}
        self.failed = False
        self.substitutions: list[str] = []
        self._browser: figure.Browser | None = None
        canaries.add(str(self.work), "workdir")
        # Values printed in the published guide (synthetic demo accounts) are not secrets.
        self.public = "\n".join(p.read_text() for p in page.path.parent.glob("*.md"))

    # -- steps ---------------------------------------------------------
    def run(
        self,
        name: str,
        *,
        expect: int | None = 0,
        timeout: float = 120,
        shot: bool = True,
    ) -> Result:
        step = self.page.step(name)
        if step.background:
            raise StepFailed(f"{name} is a background step; use start()")
        result = self._bash(step.code, timeout, carry=True)
        self.ran.append(name)
        self._record(f"step-{name}", step.code, result)
        if shot:
            self._terminal(name, step.code, result.out)
        if expect is not None and result.code != expect:
            raise StepFailed(
                f"step {name} exited {result.code}, expected {expect}: {self._tail(result.out)}"
            )
        return result

    def prereq(self, page: Path, *names: str) -> None:
        """Run steps from an earlier page, as the reader did before this one."""
        from .guide import load

        other = load(page)
        for name in names:
            step = other.step(name)
            result = self._bash(step.code, 120, carry=True)
            self._record(f"prereq-{other.stem}-{name}", step.code, result)
            if result.code != 0:
                raise StepFailed(
                    f"prerequisite {other.stem}#{name} exited {result.code}: {self._tail(result.out)}"
                )

    def start(
        self,
        name: str,
        ready: Callable[[], bool],
        *,
        timeout: float = 30,
        shot: bool = True,
    ) -> None:
        step = self.page.step(name)
        log = self.work / f"{name}.log"
        handle = log.open("w")
        proc = subprocess.Popen(
            ["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", step.code],
            cwd=self.cwd,
            env=self.env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        handle.close()
        self.procs[name] = (proc, log)
        self.ran.append(name)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            if _quiet(ready):
                text = log.read_text(errors="replace")
                self._record(f"step-{name}", step.code, Result(0, text))
                if shot:
                    self._terminal(name, step.code, text)
                return
            time.sleep(0.2)
        text = log.read_text(errors="replace")
        self._record(f"step-{name}", step.code, Result(proc.returncode or -1, text))
        raise StepFailed(
            f"step {name} not ready (exit {proc.returncode}): {self._tail(text)}"
        )

    def substitute(self, note: str) -> None:
        """Record something this run stands in for, such as a stub CLI; the report lists it."""
        self.substitutions.append(note)

    def stop(self, name: str, sig: int = signal.SIGTERM, timeout: float = 15) -> int:
        proc, _ = self.procs.pop(name)
        if proc.poll() is None:
            os.killpg(proc.pid, sig)
            try:
                proc.wait(timeout)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        return proc.returncode

    def log(self, name: str) -> str:
        return (self.work / f"{name}.log").read_text(errors="replace")

    # -- checkpoints ----------------------------------------------------
    def sh(self, script: str, *, timeout: float = 60) -> Result:
        """Run a checkpoint command with the journey's environment; no figure."""
        result = self._bash(script, timeout, carry=False)
        self._record("check", script, result)
        return result

    def var(self, name: str) -> str:
        return self.env.get(name, "")

    def browser(self, trust_dev_ca: bool = False) -> figure.Browser:
        if self._browser is None:
            self._browser = figure.Browser(trust_dev_ca)
            note = "browser steps driven by headless Chrome (Playwright)"
            self.substitute(note + (", accepting the development CA" if trust_dev_ca else ""))
        return self._browser

    def browser_shot(self, name: str) -> None:
        self.browser().shot(self.bundle.root / "shots" / self.page.stem / f"{name}.png")

    def close(self) -> None:
        for name in list(self.procs):
            self.stop(name)
        if self._browser is not None:
            self._browser.close()
        shutil.rmtree(self.work, ignore_errors=True)

    # -- internals ------------------------------------------------------
    def _bash(self, code: str, timeout: float, carry: bool) -> Result:
        dump = self.work / "env.dump"
        cwd_file = self.work / "cwd.dump"
        trap = f"trap 'env -0 > {dump}; pwd > {cwd_file}' EXIT\n" if carry else ""
        try:
            proc = subprocess.run(
                [
                    "bash",
                    "--noprofile",
                    "--norc",
                    "-euo",
                    "pipefail",
                    "-c",
                    trap + code,
                ],
                check=False,
                cwd=self.cwd,
                env=self.env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # interleaved, as a terminal shows them
                text=True,
                timeout=timeout,
            )
            result = Result(proc.returncode, proc.stdout)
        except subprocess.TimeoutExpired as err:
            out = (
                (err.stdout or b"").decode(errors="replace")
                if isinstance(err.stdout, bytes)
                else (err.stdout or "")
            )
            result = Result(124, out + f"\n[timed out after {timeout}s]")
        if carry and dump.exists():
            env = dict(
                item.split("=", 1)
                for item in dump.read_text().split("\0")
                if "=" in item
            )
            self.env = {k: v for k, v in env.items() if k not in INTERNAL} | self.pins
            self.cwd = Path(cwd_file.read_text().strip())
            dump.unlink()
        self._harvest(result.out)
        return result

    def _harvest(self, out: str) -> None:
        for key, value in self.env.items():
            if SECRET_ENV.search(key) and value not in self.public:
                self.canaries.add(value, f"env-{key.lower()}")
        for key, value in SECRET_FIELD.findall(out):
            self.canaries.add(value, f"field-{key}")

    def _display(self, text: str) -> str:
        text = text.replace(str(self.home), "~").replace(str(self.work), "/tmp/uat")
        return self.canaries.redact(text)

    def _record(self, label: str, code: str, result: Result) -> None:
        self.bundle.transcript(
            self.current_case,
            label,
            f"$ {code}\n--- exit {result.code}\n{self._display(result.out)}",
        )

    def _terminal(self, name: str, code: str, out: str) -> None:
        path = self.bundle.root / "shots" / self.page.stem / f"{name}.svg"
        figure.terminal(
            path, f"{self.page.stem}: {name}", self._display(code), self._display(out)
        )

    def _tail(self, text: str) -> str:
        return self._display(text).strip()[-400:]


def _quiet(check: Callable[[], bool]) -> bool:
    try:
        return bool(check())
    except (OSError, ValueError, KeyError):  # probes fail until the service is up
        return False
