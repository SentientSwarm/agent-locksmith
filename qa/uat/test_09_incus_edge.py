"""Journey 9: deploy to an Incus edge (operator). Guide: docs/guide/09-incus-edge.md.

The UAT has no Incus host. It runs what the page does on the operator's own
machine (the site file, the refusals, the preparation script and the render)
and checks the rendered units. The Incus, systemd and in-container blocks are
unmarked, so the bundle lists them in NOT-EXECUTED.md. The edge configuration
is loaded by this build's daemon on the UAT host with its paths moved under a
temporary directory, which the run records as a substitution.
"""

import json
import os
import signal
import stat
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

PAGE = "09-incus-edge.md"
PORTS = ("LOCKSMITH_PORT",)
UNITS = "usr/local/lib/systemd/system"
RENDERED = sorted(
    [
        "etc/locksmith-edge/components.json",
        "etc/locksmith-edge/input.nft",
        "etc/locksmith-edge/instance",
        "etc/sysusers.d/locksmith-edge.conf",
        f"{UNITS}/locksmith-edge-input.service",
        f"{UNITS}/locksmith-edge-locksmith-guard.service",
        f"{UNITS}/locksmith-edge-locksmith.service",
        "usr/local/sbin/locksmith-edge-state-check",
    ]
)


def case(n, kind="positive", covers=()):
    return pytest.mark.case(
        f"UAT-OPR-EDGE-CP{n}",
        area="UAT",
        kind=kind,
        covers=[f"guide:09-incus-edge#{c}" for c in covers],
    )


def render_dir(j):
    return Path(j.var("SITE"), "render", "edge-locksmith-1")


@case(1, covers=["site-dir", "site"])
def test_site_file_is_written_privately(journey):
    journey.run("site-dir", shot=False)
    journey.run("site", shot=False)
    site = Path(journey.var("SITE"))
    assert stat.S_IMODE(site.stat().st_mode) == 0o700
    assert 'name = "edge-locksmith"' in (site / "site.toml").read_text()


@case(2, kind="refusal", covers=["site-refused"])
def test_a_service_running_as_root_is_refused(journey):
    out = journey.run("site-refused").out
    assert "user must be a non-root system user name" in out
    assert "exit status 2" in out
    assert not Path(journey.var("SITE"), "render", "as-root").exists()


@case(3, covers=["prepare"])
def test_preparation_script_creates_a_stopped_unprivileged_container(journey):
    out = journey.run("prepare").out
    init = next(line for line in out.splitlines() if " init " in line)
    assert "edge-locksmith" in init
    for setting in (
        "boot.autostart=false",
        "security.nesting=false",
        "security.privileged=false",
        "limits.cpu=2",
        "limits.memory=2GiB",
    ):
        assert setting in init, setting
    assert "ipv4.address=10.0.0.10" in out
    assert "source=edge-locksmith-state path=/srv/locksmith-edge" in out
    script = Path(journey.var("SITE"), "prepare.sh").read_text()
    assert " start " not in script and " exec " not in script


@case(4, covers=["render", "review"])
def test_render_is_inactive_and_custody_gated(journey):
    out = journey.run("render").out
    assert "no state, receipts or activation" in out
    root = render_dir(journey)
    files = sorted(
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
    )
    assert files == RENDERED
    assert not any(p.name.endswith(".wants") for p in root.rglob("*"))
    assert (
        stat.S_IMODE((root / "etc/locksmith-edge/components.json").stat().st_mode)
        == 0o644
    )
    assert (
        stat.S_IMODE(
            (root / "usr/local/sbin/locksmith-edge-state-check").stat().st_mode
        )
        == 0o755
    )
    components = json.loads((root / "etc/locksmith-edge/components.json").read_text())
    assert components["instance"] == "edge-locksmith"
    assert components["components"]["locksmith"]["environment_file"] is True

    review = journey.run("review").out
    for line in (
        "ConditionPathExists=/srv/locksmith-edge/custody/locksmith.ready",
        "User=locksmith",
        "EnvironmentFile=/srv/locksmith-edge/environment/locksmith.env",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "MemoryDenyWriteExecute=yes",
        "ReadWritePaths=/srv/locksmith-edge/locksmith /run/locksmith-edge/locksmith",
    ):
        assert line in review, line
    assert "locksmith-edge-locksmith-guard.service" in review
    assert "ip saddr { 203.0.113.0/24 } tcp dport 9200 accept;" in review
    assert "tcp dport { 9200, 9201 } reject;" in review
    guard = (root / UNITS / "locksmith-edge-locksmith-guard.service").read_text()
    assert "EnvironmentFile" not in guard and "PrivateNetwork=yes" in guard


@case(5, kind="refusal", covers=["render-refused"])
def test_a_render_never_overwrites_an_earlier_one(journey):
    before = sorted(p.as_posix() for p in render_dir(journey).rglob("*"))
    out = journey.run("render-refused").out
    assert "exists; render into a new directory" in out
    assert "exit status 2" in out
    assert sorted(p.as_posix() for p in render_dir(journey).rglob("*")) == before


def _get(port, probe):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/{probe}", timeout=2) as r:
        return r.status, r.read().decode()


def _serve_moved_config(j, config: Path):
    """Start locksmithd on `config`; return (readyz, version) and stop it."""
    env = {
        **j.env,
        "LOCKSMITH_SEED_PATH": str(Path(j.var("LOCKSMITH_SRC"), "seed/catalog.yaml")),
    }
    log = (j.work / "edge-daemon.log").open("w")
    proc = subprocess.Popen(
        ["locksmithd", "--config", str(config)],
        env=env,
        cwd=j.work,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    log.close()
    port = j.var("LOCKSMITH_PORT")
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                return _get(port, "readyz"), _get(port, "version")
            except OSError:
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


@case(6, covers=["config"])
def test_edge_configuration_loads_in_this_build(journey):
    journey.run("config", shot=False)
    text = Path(journey.var("SITE"), "config.yaml").read_text()
    assert "mode: external" in text
    moved = journey.work / "edge-root"
    (moved / "srv/locksmith").mkdir(parents=True, mode=0o700)
    (moved / "run/locksmith").mkdir(parents=True, mode=0o700)
    port = journey.var("LOCKSMITH_PORT")
    config = journey.work / "edge-config.yaml"
    config.write_text(
        text.replace("/srv/locksmith-edge", str(moved / "srv"))
        .replace("/run/locksmith-edge", str(moved / "run"))
        .replace("9200", port)
    )
    journey.substitute(
        "edge config.yaml loaded by this build's locksmithd on the UAT host, with "
        "/srv/locksmith-edge and /run/locksmith-edge moved under a temp dir and "
        "port 9200 replaced by a free port; Incus, systemd and the root guard were not run"
    )
    ops = moved / "srv/locksmith/operators.yaml"
    minted = journey.sh(
        f"umask 077; locksmith bootstrap-operator --name edge-admin > '{ops}' 2> /dev/null"
    )
    assert minted.code == 0 and "$argon2" in ops.read_text()
    (status, ready), (_, version) = _serve_moved_config(journey, config)
    assert status == 200 and '"ready"' in ready.replace(" ", "")
    info = json.loads(journey.sh("locksmithd --build-info").out)
    assert info["version"] in version
