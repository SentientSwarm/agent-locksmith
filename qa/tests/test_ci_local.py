"""Tests for scripts/ci-local.py, the local CI runner."""

import importlib.util
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ci-local.py"
spec = importlib.util.spec_from_file_location("ci_local", SCRIPT)
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


def git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def make_repo(path):
    path.mkdir()
    git(path, "init", "-q")
    git(
        path,
        *("-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"),
        *("commit", "-q", "--allow-empty", "-m", "x"),
    )
    return path


def run(steps, tmp_path, job_extra=None):
    job = {"runs-on": "x", "steps": steps, **(job_extra or {})}
    env = {"PATH": "/usr/bin:/bin", "GITHUB_ENV": str(tmp_path / "github-env")}
    with open(tmp_path / "log", "w") as log:
        return ci.run_job("t", job, {}, env, tmp_path, tmp_path, tmp_path, log)


def test_a_failure_step_runs_after_a_failed_step(tmp_path):
    ok, steps = run(
        [
            {"name": "breaks", "run": "false"},
            {"name": "skipped", "run": "true"},
            {"name": "on failure", "if": "failure()", "run": "touch marker"},
            {"name": "always", "if": "always()", "run": "true"},
        ],
        tmp_path,
    )
    assert not ok
    assert steps == [
        ("breaks", "FAIL"),
        ("skipped", "skipped"),
        ("on failure", "pass"),
        ("always", "pass"),
    ]
    assert (tmp_path / "marker").exists()


def test_a_failure_step_is_skipped_on_success(tmp_path):
    ok, steps = run([{"name": "f", "if": "failure()", "run": "false"}], tmp_path)
    assert ok and steps == [("f", "skipped")]


@pytest.mark.parametrize(
    "step",
    [
        {"name": "x", "run": "true", "working-directory": "crates/x"},
        {"name": "x", "run": "true", "shell": "sh"},
        {"name": "x", "run": "true", "continue-on-error": True},
        {"name": "x", "run": "true", "if": "github.event_name == 'push'"},
    ],
)
def test_unsupported_step_settings_fail_closed(tmp_path, step):
    with pytest.raises(SystemExit):
        run([step], tmp_path)


@pytest.mark.parametrize(
    "extra", [{"env": {"RUSTFLAGS": "-D warnings"}}, {"if": "false"}, {"defaults": {}}]
)
def test_unsupported_job_settings_fail_closed(tmp_path, extra):
    with pytest.raises(SystemExit):
        run([{"name": "x", "run": "true"}], tmp_path, extra)


def test_unsupported_workflow_settings_fail_closed():
    ci.check_workflow({"name": "CI", True: {}, "env": {}, "jobs": {}})
    with pytest.raises(SystemExit):
        ci.check_workflow({"jobs": {}, "defaults": {"run": {"shell": "sh"}}})


def test_the_base_environment_is_an_allowlist():
    env = ci.base_env(
        {
            "PATH": "/bin",
            "HOME": "/h",
            "ANTHROPIC_API_KEY": "k",
            "OPENAI_API_KEY": "k",
            "CARGO_TARGET_DIR": "/elsewhere",
            "RUSTFLAGS": "-C x",
            "BASH_ENV": "/evil",
        }
    )
    assert env == {"PATH": "/bin", "HOME": "/h"}


def test_each_repository_gets_its_own_cache(tmp_path):
    first = make_repo(tmp_path / "a")
    clone = tmp_path / "b"
    git(tmp_path, "clone", "-q", str(first), str(clone))
    base = tmp_path / "cache"
    assert ci.cache_dir(base, first) != ci.cache_dir(base, clone)
    assert ci.cache_dir(base, first) == ci.cache_dir(base, first)
    assert ci.cache_dir(base, first).parent.parent == base


def test_a_cached_prior_build_is_used_only_for_its_pinned_commit(tmp_path, monkeypatch):
    pin = make_repo(tmp_path / "pin")
    head = git(pin, "rev-parse", "HEAD")
    monkeypatch.setattr(ci, "CACHE", tmp_path / "cache")
    cached = tmp_path / "cache" / "prior-bins" / "out"
    cached.mkdir(parents=True)
    (cached / "PROVENANCE.txt").write_text(f"source_commit={'0' * 40}\n")
    calls = []

    def fake_run(env):
        calls.append(env)
        return False

    temp = tmp_path / "temp"
    temp.mkdir()
    with open(tmp_path / "log", "w") as log:
        ok = ci.run_prior_build(
            ("p", "out", "0" * 40), {"p": pin}, {}, fake_run, temp, log, "k"
        )
    assert not ok and len(calls) == 1, "a pin at another commit must not use the cache"
    assert head != "0" * 40


def prior_cache(tmp_path, monkeypatch, key):
    pin = make_repo(tmp_path / "pin")
    head = git(pin, "rev-parse", "HEAD")
    monkeypatch.setattr(ci, "CACHE", tmp_path / "cache")
    cached = tmp_path / "cache" / "prior-bins" / "out"
    cached.mkdir(parents=True)
    (cached / "PROVENANCE.txt").write_text(f"source_commit={head}\n")
    (cached / "BUILD-KEY").write_text(key)
    temp = tmp_path / "temp"
    temp.mkdir()
    return pin, head, temp


@pytest.mark.parametrize(
    "stored, wanted, hit", [("k", "k", True), ("k", "other", False)]
)
def test_a_cached_prior_build_needs_the_same_build_and_compiler(
    tmp_path, monkeypatch, stored, wanted, hit
):
    pin, head, temp = prior_cache(tmp_path, monkeypatch, stored)
    calls = []
    with open(tmp_path / "log", "w") as log:
        ci.run_prior_build(
            ("p", "out", head), {"p": pin}, {}, calls.append, temp, log, wanted
        )
    assert (not calls) == hit
    assert (temp / "out" / "PROVENANCE.txt").exists() == hit


def test_a_bad_toolchain_stops_the_run_and_leaves_the_env_alone(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}
    with pytest.raises(SystemExit):
        ci.toolchain_env(env, "0.0.1", tmp_path)
    assert "RUSTUP_TOOLCHAIN" not in env


def test_retention_keeps_the_newest_runs_whatever_their_commit(tmp_path):
    runs = tmp_path / "runs"
    names = [f"{c * 12}-2026111{d}T000000Z" for c, d in zip("fedcba", "012345")]
    for name in names:
        (runs / name).mkdir(parents=True)
    ci.prune_runs(runs, keep=2)
    assert sorted(p.name for p in runs.iterdir()) == sorted(names[-2:])


RUSTUP = Path.home() / ".rustup"


@pytest.mark.skipif(
    not any(RUSTUP.glob("toolchains/1.94.0-*")), reason="needs rustup 1.94.0"
)
def test_the_toolchain_is_selected_for_every_later_step(tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
    ci.toolchain_env(env, "1.94.0", tmp_path)
    assert env["RUSTUP_TOOLCHAIN"] == "1.94.0"
    assert "1.94.0" in env["PATH"].split(":")[0]
