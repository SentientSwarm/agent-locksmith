"""Daemon logging (config.example.yaml:34-36, README.md:313-314).

The harness passes its own environment to the daemon; RUST_LOG, when set,
overrides logging.level, so these cases expect RUST_LOG to be unset.
"""

import json
import os

import pytest

from fakes.dmn_support import wait_for

case = pytest.mark.case
LOGGING = "beh.telemetry.logging"


def levels(t) -> set[str]:
    return {e.get("level") for e in t.log_events()}


def assert_json_lines(text: str) -> None:
    lines = [line for line in text.splitlines() if line.strip()]
    assert lines, "no log output"
    for line in lines:
        entry = json.loads(line)
        assert (
            isinstance(entry, dict) and {"timestamp", "level", "fields"} <= entry.keys()
        )


@case("SMK-DMN-060", area="DMN", kind="positive", covers=[LOGGING])
def test_warn_level_suppresses_info(target_factory, t1):
    """config.example.yaml:34-35: logging.level selects the minimum level; t1 (info) is the control."""
    assert "RUST_LOG" not in os.environ, (
        "RUST_LOG overrides logging.level; unset it for this run"
    )
    t = target_factory(
        label="dmn-log-warn", upstream=False, config={"logging": {"level": "warn"}}
    )
    assert t.cli("agent", "register", "--name", "dmn-log-warn").code == 0
    assert "INFO" in levels(t1), "control daemon at info logged no INFO line"
    assert not levels(t) & {"INFO", "DEBUG", "TRACE"}, (
        f"warn-level daemon logged {levels(t)}"
    )


@case("SMK-DMN-061", area="DMN", kind="positive", covers=[LOGGING])
def test_debug_level_emits_debug_json_lines(target_factory):
    """config.example.yaml:34-35 and docs/v2/SPEC.md:252: logging.level debug adds
    DEBUG entries; every line is a JSON object."""
    t = target_factory(
        label="dmn-log-debug", upstream=False, config={"logging": {"level": "debug"}}
    )
    assert t.cli("agent", "list").code == 0
    assert "DEBUG" in levels(t), "debug level produced no DEBUG line"
    assert_json_lines(t.log_text())


@case("SMK-DMN-062", area="DMN", kind="positive", covers=[LOGGING])
def test_logging_file_receives_json_lines(target_factory):
    """config.example.yaml:34-36: `logging.file` names the daemon's log file
    (`# file: "/var/log/locksmith/proxy.log"`); the daemon writes its JSON log lines there."""
    t = target_factory(
        label="dmn-log-file",
        upstream=False,
        config=lambda work: (work / "logs").mkdir(exist_ok=True)
        or {"logging": {"level": "info", "file": str(work / "logs" / "locksmithd.log")}},
    )
    assert t.cli("agent", "register", "--name", "dmn-log-file").code == 0
    path = t.work / "logs" / "locksmithd.log"
    assert wait_for(lambda: path.exists() and path.stat().st_size > 0, timeout=5), (
        "logging.file was not written"
    )
    assert_json_lines(path.read_text())


@case("SMK-DMN-063", area="DMN", kind="refusal", covers=[LOGGING, "beh.config.validation"])
def test_unopenable_logging_file_refuses_to_start(target_factory):
    """config.example.yaml (`logging.file`) with docs/user/architecture.md (startup validates
    the config and refuses to start on any error): a log file that cannot be opened stops
    startup with exit 1 and a message naming `logging.file`, rather than logging nowhere."""
    t = target_factory(
        start=False,
        label="dmn-log-file-bad",
        upstream=False,
        config=lambda work: {"logging": {"file": str(work / "missing-dir" / "l.log")}},
    )
    proc = t.run_daemon_once()
    assert proc.returncode == 1
    assert "logging.file" in proc.stdout + proc.stderr
