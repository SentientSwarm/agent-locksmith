#!/usr/bin/env python3
"""Read-only, secret-free process/file/listener gate on studio-1 before custody moves."""
import argparse
from pathlib import Path
import os
import re
import shlex
import socket
import subprocess
import sys

JOBS = {
    "codex": "com.jxstanford.agent-pools.codex",
    "teamclaude": "com.karpeleslab.teamclaude",
}
PORTS = {"codex": 43210, "teamclaude": 3456}


class GateError(Exception):
    """Visibility was incomplete; never report a passed drain."""


def classify(command, component):
    # Unique refresher families anywhere, including extensionless shims,
    # relative paths and Node --import=. Intentionally conservative.
    if component == "codex" and re.search(r"codex-multi-auth|runtime-rotation", command, re.I):
        return "pool-capable-helper"
    try:
        args = shlex.split(command)
    except ValueError:
        return "unparseable-process"
    if not args:
        return None
    executable = Path(args[0]).name
    if component == "teamclaude" and executable in {"teamclaude", "teamrouter"}:
        return "pool-capable-helper"
    names = {"codex", "omp", "opencode"} if component == "codex" else {"claude"}
    if executable in names:
        return "pool-capable-agent" if component == "codex" else "claude-client"
    # Bounded package/path names: component/compiler must not match omp.
    if executable in {"node", "nodejs", "bun", "npx"}:
        scripts = " ".join(args[1:])
        boundary = r"(?:^|[/=@\s]){}(?:[/.\s]|$)"
        if component == "teamclaude" and re.search(boundary.format(r"(?:teamclaude|teamrouter)"), scripts, re.I):
            return "pool-capable-helper"
        names_pattern = r"(?:codex|omp|opencode)" if component == "codex" else r"(?:claude|claude-code)"
        if re.search(boundary.format(names_pattern), scripts, re.I):
            return "pool-capable-helper" if component == "codex" else "claude-client"
    return None


def run_visible(argv, timeout=10):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as from_error:
        raise GateError("inspection command unavailable or timed out") from from_error


def lsof_pids(options):
    # Root visibility is mandatory. Never emit lsof's filenames/errors/argv.
    result = run_visible(["sudo", "-n", "/usr/sbin/lsof", "-nP", "-t", *options], timeout=60)
    lines = result.stdout.splitlines()
    if result.stderr.strip() or result.returncode not in {0, 1}:
        raise GateError("privileged open-file/listener visibility unavailable")
    if result.returncode == 1 and lines:
        raise GateError("incomplete open-file/listener result")
    if any(not line.isdecimal() for line in lines):
        raise GateError("unrecognized open-file/listener result")
    return {int(line) for line in lines}


def resource_holders(component, home, custody_paths=()):
    # Component-specific: the teamclaude control plane may stay live during
    # Codex drain. A compatibility relay must be unloaded to free this port.
    holders = {"listener": lsof_pids(["-a", f"-iTCP:{PORTS[component]}", "-sTCP:LISTEN"])}
    if component == "codex":
        paths = [home / ".codex-terminal-pool", home / ".config/agent-pools", *custody_paths]
    else:
        if not custody_paths:
            raise GateError("teamclaude requires an explicit complete --custody-path inventory")
        paths = list(custody_paths)
    holders["custody-open"] = set()
    for path in paths:
        path = Path(path)
        if not path.is_absolute() or path.is_symlink():
            raise GateError("custody path must be absolute and not a symlink")
        if path.exists():
            options = ["+D", str(path)] if path.is_dir() else ["--", str(path)]
            holders["custody-open"].update(lsof_pids(options))
    return holders


def check_source(component, home, custody_paths=()):
    label = f"gui/{os.getuid()}/{JOBS[component]}"
    job = run_visible(["launchctl", "print", label])
    blocked = job.returncode == 0
    if blocked:
        print("REFUSE: source launchd job is still loaded")
    elif "Could not find service" not in job.stdout + job.stderr:
        raise GateError("source launchd visibility unavailable")
    disabled = run_visible(["launchctl", "print-disabled", f"gui/{os.getuid()}"])
    if disabled.returncode or not re.search(r'"' + re.escape(JOBS[component]) + r'"\s*=>\s*true', disabled.stdout):
        print("REFUSE: source launchd job is not confirmed disabled")
        blocked = True
    processes = run_visible(["ps", "-axo", "uid=,pid=,command="])
    if processes.returncode or processes.stderr.strip() or not processes.stdout.strip():
        raise GateError("process visibility unavailable")
    for line in processes.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
            raise GateError("unrecognized process result")
        _, pid, command = fields
        if int(pid) == os.getpid():
            continue
        reason = classify(command, component)
        if reason:
            if reason == "claude-client":
                # A client is not a refresher. The operator still hands control
                # to independent edge Codex and drains Claude requests first.
                print(f"INFO: pid={int(pid)} kind={reason}")
            else:
                print(f"REFUSE: pid={int(pid)} kind={reason}")
                blocked = True
    for reason, pids in resource_holders(component, home, custody_paths).items():
        for pid in sorted(pids):
            print(f"REFUSE: pid={pid} kind={reason}")
            blocked = True
    return blocked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=JOBS)
    parser.add_argument("--custody-path", action="append", type=Path, default=[],
                        help="absolute inventoried custody file/tree; repeat for teamclaude config/state/keys/backups")
    args = parser.parse_args()
    if sys.platform != "darwin" or socket.gethostname().split(".")[0] != "studio-1" or os.getuid() == 0:
        parser.error("run as the source login user on studio-1 macOS; lsof uses sudo -n separately")
    try:
        blocked = check_source(args.component, Path.home(), args.custody_path)
    except GateError as error:
        print(f"REFUSE: {error}")
        blocked = True
    print("source process/file/listener gate: " + ("REFUSED" if blocked else "PASS"))
    return int(blocked)


if __name__ == "__main__":
    sys.exit(main())
