#!/usr/bin/env python3
"""Run the repository's CI workflow locally against one commit.

GitHub Actions is off for this repository, so this is the CI gate. The
workflow files at the tested commit stay the single specification: each
`run:` step executes as written, and each `uses:` step gets its local
equivalent (a worktree for a pinned checkout, a toolchain check, a copy of
uploaded artifacts into the evidence directory). See docs/development/local-ci.md.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

CACHE_BASE = Path(
    os.environ.get("LOCKSMITH_CI_CACHE", Path.home() / ".cache/locksmith-ci")
)
CACHE = CACHE_BASE  # set per repository in main()
# native-validation.yml is release provenance: it records the GitHub runner
# image and needs all four native runners, so it is not run locally.
JOBS = {"test": "ci.yml", "qa-smoke": "ci.yml"}
KEEP_RUNS = 20
# Only what the workflows rely on. Anything else, such as provider API keys
# (which switch on paid live tests), CARGO_* or BASH_ENV, would make the
# result depend on the developer's shell.
ENV_ALLOWLIST = {
    "HOME", "USER", "LOGNAME", "PATH", "SHELL", "TMPDIR", "LANG", "LC_ALL",
    "TERM", "CARGO_HOME", "RUSTUP_HOME",
}  # fmt: skip
WORKFLOW_KEYS = {"name", True, "on", "env", "jobs", "permissions", "concurrency"}
JOB_KEYS = {"name", "runs-on", "steps"}
STEP_KEYS = {"name", "uses", "with", "run", "env", "if"}
CONDITIONS = {"", "always()", "failure()", "success()"}


def git(*args, cwd=None, check=True):
    out = subprocess.run(
        ["git", *args], cwd=cwd, check=check, capture_output=True, text=True
    )
    return out.stdout.strip()


def base_env(environ):
    return {k: v for k, v in environ.items() if k in ENV_ALLOWLIST}


def cache_dir(base, repo):
    """Per-repository cache: worktrees only resolve their own repository's commits."""
    common = Path(git("rev-parse", "--git-common-dir", cwd=repo))
    common = (Path(repo) / common).resolve()
    return Path(base) / "repos" / hashlib.sha256(str(common).encode()).hexdigest()[:16]


def unsupported(what, keys, allowed):
    extra = sorted(str(k) for k in set(keys) - allowed)
    if extra:
        raise SystemExit(f"{what} uses settings this runner does not support: {extra}")


def check_workflow(wf):
    unsupported("workflow", wf, WORKFLOW_KEYS)


def expand(text, ctx):
    """Substitute the `${{ ... }}` expressions these workflows use."""

    def one(match):
        key = match.group(1).strip()
        if key not in ctx:
            raise SystemExit(f"unsupported workflow expression: ${{{{ {key} }}}}")
        return str(ctx[key])

    return re.sub(r"\$\{\{(.*?)\}\}", one, str(text))


def prepare_workspace(repo, sha):
    """A persistent detached worktree at `sha`; target/ survives between runs."""
    ws = CACHE / "ws"
    if not (ws / ".git").exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        git("worktree", "add", "--detach", str(ws), sha, cwd=repo)
    git("checkout", "-q", "--detach", "--force", sha, cwd=ws)
    git("clean", "-qfdx", "-e", "/target", cwd=ws)
    return ws


def pinned_checkout(repo, ws, ref, path):
    """`actions/checkout` with `ref` + `path`: a cached worktree, linked in."""
    src = CACHE / "pinned" / ref
    if not (src / ".git").exists():
        git("fetch", "-q", "origin", ref, cwd=repo, check=False)
        git("worktree", "add", "--detach", str(src), ref, cwd=repo)
    link(ws / path, src)
    return src


def link(at, to):
    if at.is_symlink() or at.exists():
        at.unlink()
    at.symlink_to(to)


def prior_build(text, pins):
    """A step that builds a pinned checkout into `$RUNNER_TEMP/<dir>`.

    Returns (path, dir, commit) or None. Such outputs depend only on the
    pinned commit, so they are cached by it, and a miss builds in its own
    target directory: one shared target lets cargo's mtime freshness hand
    one revision's binary to another.
    """
    out = re.search(r'mkdir -p "\$RUNNER_TEMP/([^"]+)"', text)
    commit = re.search(r"source_commit=([0-9a-f]{40})", text)
    path = next((p for p in pins if f"$GITHUB_WORKSPACE/{p}/" in text), None)
    return (path, out.group(1), commit.group(1)) if out and commit and path else None


def output(cmd, env, cwd):
    """A command's stdout, or "" when it is missing or fails."""
    try:
        done = subprocess.run(
            cmd, check=False, cwd=cwd, env=env, capture_output=True, text=True
        )
    except FileNotFoundError:
        return ""
    return done.stdout if done.returncode == 0 else ""


def build_key(text, env, ws):
    """The build step and the compiler: a change to either invalidates the cache."""
    rustc = output(["rustc", "--version", "--verbose"], env, ws)
    return hashlib.sha256(f"{text}\0{rustc}".encode()).hexdigest()


def cache_hit(cached, pin, commit, key):
    provenance, stored = cached / "PROVENANCE.txt", cached / "BUILD-KEY"
    return (
        git("rev-parse", "HEAD", cwd=pin, check=False) == commit
        and provenance.exists()
        and f"source_commit={commit}" in provenance.read_text()
        and stored.exists()
        and stored.read_text() == key
    )


def run_prior_build(build, pins, step_env, run, temp, log, key):
    path, out, commit = build
    cached = CACHE / "prior-bins" / out
    if cache_hit(cached, pins[path], commit, key):
        shutil.copytree(cached, temp / out, dirs_exist_ok=True)
        log.write(f"cached prior build {out} at {commit}\n")
        return True
    pin_ws = CACHE / "pin-ws" / path
    pin_ws.mkdir(parents=True, exist_ok=True)
    link(pin_ws / path, pins[path])
    ok = run({**step_env, "GITHUB_WORKSPACE": str(pin_ws)})
    if ok:  # stage, then swap in, so an interrupted copy is never a hit
        staged = cached.with_name(out + ".new")
        shutil.rmtree(staged, ignore_errors=True)
        shutil.copytree(temp / out, staged)
        (staged / "BUILD-KEY").write_text(key)
        shutil.rmtree(cached, ignore_errors=True)
        staged.rename(cached)
    shutil.rmtree(pin_ws / "target", ignore_errors=True)
    return ok


def toolchain_env(env, version, ws):
    """`dtolnay/rust-toolchain@V`: select V for every later step, then check it."""
    home = Path(env.get("RUSTUP_HOME") or Path(env["HOME"]) / ".rustup")
    path = env["PATH"]
    for tc in sorted(home.glob(f"toolchains/{version}-*")):
        path = f"{tc}/bin:{path}"
    pinned = {**env, "PATH": path, "RUSTUP_TOOLCHAIN": version}
    found = output(["rustc", "--version"], pinned, ws)
    if not found.startswith(f"rustc {version} "):
        raise SystemExit(f"rust {version} required, found: {found.strip() or 'none'}")
    env.update(pinned)


def prune_runs(runs, keep):
    """Keep the newest `keep` runs; directories are `<sha>-<UTC stamp>`."""
    by_age = sorted(runs.iterdir(), key=lambda p: p.name.split("-", 1)[-1])
    for old in by_age[:-keep]:
        shutil.rmtree(old, ignore_errors=True)


def keep_artifact(with_, evidence):
    """`actions/upload-artifact`: copy the paths into the evidence directory."""
    dest = evidence / with_["name"]
    found = False
    for pattern in with_["path"].split():
        for hit in Path("/").glob(pattern.lstrip("/")):
            found = True
            if hit.is_dir():
                shutil.copytree(hit, dest / hit.name, dirs_exist_ok=True)
            else:
                dest.mkdir(parents=True, exist_ok=True)
                shutil.copy2(hit, dest)
    return found or with_.get("if-no-files-found", "warn") != "error"


def should_run(cond, failed):
    if cond not in CONDITIONS:
        raise SystemExit(f"unsupported step condition: if: {cond}")
    return cond == "always()" or (cond == "failure()") == failed


def run_job(name, job, ctx, env, ws, repo, evidence, log):
    unsupported(f"job {name}", job, JOB_KEYS)
    for step in job["steps"]:
        unsupported(f"a step of job {name}", step, STEP_KEYS)
        should_run(str(step.get("if", "")).strip(), False)
    results, failed, pins = [], False, {}
    for i, step in enumerate(job["steps"], 1):
        label = step.get("name") or step.get("uses") or step["run"].splitlines()[0]
        if not should_run(str(step.get("if", "")).strip(), failed):
            results.append((label, "skipped"))
            continue
        log.write(f"\n===== [{name} {i}] {label}\n")
        log.flush()
        uses = step.get("uses", "")
        with_ = {k: expand(v, ctx) for k, v in (step.get("with") or {}).items()}
        ok = True
        if uses.startswith("actions/checkout"):
            if "ref" in with_:
                pins[with_["path"]] = pinned_checkout(
                    repo, ws, with_["ref"], with_["path"]
                )
        elif uses.startswith("dtolnay/rust-toolchain"):
            toolchain_env(env, uses.split("@")[1], ws)
        elif uses.startswith("astral-sh/setup-uv"):
            ok = shutil.which("uv") is not None
        elif uses.startswith("Swatinem/rust-cache"):
            pass  # the target directory persists between runs
        elif uses.startswith("actions/upload-artifact"):
            ok = keep_artifact(with_, evidence)
        elif "run" in step:
            step_env = {
                **env,
                **{k: expand(v, ctx) for k, v in (step.get("env") or {}).items()},
            }
            open(env["GITHUB_ENV"], "w").close()
            text = expand(step["run"], ctx)

            def run(run_env, text=text):
                bash = ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", text]
                proc = subprocess.run(
                    bash,
                    check=False,
                    cwd=ws,
                    env=run_env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                return proc.returncode == 0

            build = prior_build(text, pins)
            if build:
                ok = run_prior_build(
                    build,
                    pins,
                    step_env,
                    run,
                    Path(env["RUNNER_TEMP"]),
                    log,
                    build_key(text, step_env, ws),
                )
            else:
                ok = run(step_env)
            for line in Path(env["GITHUB_ENV"]).read_text().splitlines():
                if "=" in line:
                    key, value = line.split("=", 1)
                    env[key] = value
        else:
            raise SystemExit(f"no local equivalent for step: {uses}")
        results.append((label, "pass" if ok else "FAIL"))
        failed = failed or not ok
    return not failed, results


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--rev", default="HEAD", help="commit to test (default HEAD; must be committed)"
    )
    ap.add_argument(
        "--jobs", default=",".join(JOBS), help=f"comma list of {', '.join(JOBS)}"
    )
    ap.add_argument(
        "--post-status",
        action="store_true",
        help="post local-ci/<job> commit statuses to GitHub",
    )
    args = ap.parse_args()

    unknown = set(args.jobs.split(",")) - set(JOBS)
    if unknown:
        raise SystemExit(f"unknown jobs: {sorted(unknown)}; choose from {list(JOBS)}")
    repo = Path(git("rev-parse", "--show-toplevel"))
    sha = git("rev-parse", "--verify", f"{args.rev}^{{commit}}", cwd=repo)
    global CACHE
    CACHE = cache_dir(CACHE_BASE, repo)
    CACHE.mkdir(parents=True, exist_ok=True)
    # Held for the whole run, released when the process exits.
    lock = open(CACHE / "lock", "w")  # noqa: SIM115
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit(f"another local CI run holds {CACHE}/lock")

    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    evidence = CACHE / "runs" / f"{sha[:12]}-{stamp}"
    temp = evidence / "runner-temp"
    temp.mkdir(parents=True)
    ws = prepare_workspace(repo, sha)
    host = f"{platform.system()}-{platform.machine()}"
    ctx = {
        "github.workspace": ws,
        "runner.temp": temp,
        "github.run_attempt": 1,
        "github.sha": sha,
    }
    env = {
        **base_env(os.environ),
        "GITHUB_WORKSPACE": str(ws),
        "RUNNER_TEMP": str(temp),
        "GITHUB_SHA": sha,
        "GITHUB_ENV": str(temp / "github-env"),
        "CI": "true",
    }
    summary = {"sha": sha, "started": stamp, "host_target": host, "jobs": {}}
    with open(evidence / "ci.log", "w") as log:
        for name in args.jobs.split(","):
            # Each GitHub job starts on a fresh runner: clean tree, base env.
            prepare_workspace(repo, sha)
            wf = yaml.safe_load((ws / ".github/workflows" / JOBS[name]).read_text())
            check_workflow(wf)
            job = wf["jobs"][name]
            job_env = {
                **env,
                **{k: expand(v, ctx) for k, v in (wf.get("env") or {}).items()},
            }
            ok, steps = run_job(name, job, ctx, job_env, ws, repo, evidence, log)
            summary["jobs"][name] = {"result": "pass" if ok else "fail", "steps": steps}
            print(f"{name}: {'PASS' if ok else 'FAIL'}", flush=True)
            for label, state in steps:
                if state != "pass":
                    print(f"  {state}: {label}")
    (evidence / "summary.json").write_text(json.dumps(summary, indent=1, default=str))
    # Uploaded artifacts were copied out; the scratch tree holds gigabytes of
    # prior binaries and venvs.
    shutil.rmtree(temp, ignore_errors=True)
    prune_runs(CACHE / "runs", KEEP_RUNS)
    green = all(j["result"] == "pass" for j in summary["jobs"].values())
    print(f"local CI {'PASS' if green else 'FAIL'} at {sha[:12]}; evidence: {evidence}")
    if args.post_status:
        slug = (
            git("remote", "get-url", "origin", cwd=repo)
            .split("github.com")[-1]
            .strip(":/")
            .removesuffix(".git")
        )
        for name, job in summary["jobs"].items():
            posted = subprocess.run(
                [
                    "gh",
                    "api",
                    "-X",
                    "POST",
                    f"repos/{slug}/statuses/{sha}",
                    "-f",
                    f"state={'success' if job['result'] == 'pass' else 'failure'}",
                    "-f",
                    f"context=local-ci/{name}",
                    "-f",
                    f"description=scripts/ci-local.py on {host}",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if posted.returncode != 0:
                raise SystemExit(
                    f"posting local-ci/{name} failed: {posted.stderr.strip()}"
                )
    sys.exit(0 if green else 1)


if __name__ == "__main__":
    main()
