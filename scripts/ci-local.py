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
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

CACHE = Path(os.environ.get("LOCKSMITH_CI_CACHE", Path.home() / ".cache/locksmith-ci"))
# native-validation.yml is release provenance: it records the GitHub runner
# image and needs all four native runners, so it is not run locally.
JOBS = {"test": "ci.yml", "qa-smoke": "ci.yml"}


def git(*args, cwd=None, check=True):
    out = subprocess.run(
        ["git", *args], cwd=cwd, check=check, capture_output=True, text=True
    )
    return out.stdout.strip()


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
    link = ws / path
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(src)


def toolchain_env(version):
    tc = (
        Path.home()
        / f".rustup/toolchains/{version}-{platform.machine().replace('arm64', 'aarch64')}-apple-darwin"
    )
    path = os.environ["PATH"]
    if tc.exists():
        path = f"{tc}/bin:{path}"
    found = subprocess.run(
        ["rustc", "--version"],
        check=False,
        env={**os.environ, "PATH": path},
        capture_output=True,
        text=True,
    ).stdout
    if version not in found:
        raise SystemExit(f"rust {version} required, found: {found.strip() or 'none'}")
    return path


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


def run_job(name, job, ctx, env, ws, repo, evidence, log):
    results, failed = [], False
    for i, step in enumerate(job["steps"], 1):
        label = step.get("name") or step.get("uses") or step["run"].splitlines()[0]
        cond = str(step.get("if", ""))
        if failed and "always()" not in cond:
            results.append((label, "skipped"))
            continue
        if "failure()" in cond and not failed:
            results.append((label, "skipped"))
            continue
        log.write(f"\n===== [{name} {i}] {label}\n")
        log.flush()
        uses = step.get("uses", "")
        with_ = {k: expand(v, ctx) for k, v in (step.get("with") or {}).items()}
        ok = True
        if uses.startswith("actions/checkout"):
            if "ref" in with_:
                pinned_checkout(repo, ws, with_["ref"], with_["path"])
        elif uses.startswith("dtolnay/rust-toolchain"):
            env["PATH"] = toolchain_env(uses.split("@")[1])
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
            proc = subprocess.run(
                [
                    "bash",
                    "--noprofile",
                    "--norc",
                    "-eo",
                    "pipefail",
                    "-c",
                    expand(step["run"], ctx),
                ],
                check=False,
                cwd=ws,
                env=step_env,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            ok = proc.returncode == 0
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

    repo = Path(git("rev-parse", "--show-toplevel"))
    sha = git("rev-parse", "--verify", f"{args.rev}^{{commit}}", cwd=repo)
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
        **os.environ,
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
            subprocess.run(
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
                check=True,
                capture_output=True,
            )
    sys.exit(0 if green else 1)


if __name__ == "__main__":
    main()
