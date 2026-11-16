#!/usr/bin/env python3
"""Read-only, secret-free process gate on studio-1, before moving custody."""
import argparse
from pathlib import Path
import os
import re
import shlex
import subprocess
import sys

JOBS = {
    "codex": "com.jxstanford.agent-pools.codex",
    "teamclaude": "com.karpeleslab.teamclaude",
}


def classify(command, component):
    try:
        args = shlex.split(command)
    except ValueError:
        return "unparseable-process"
    if not args:
        return None
    executable = Path(args[0]).name
    # Check executable/script names, never arbitrary argument values or env.
    scripts = [a for a in args[1:] if a.startswith("/") and
               (a.endswith((".js", ".mjs")) or Path(a).name in
                {"teamclaude", "teamrouter", "codex", "omp", "opencode"})]
    if component == "codex":
        if executable in {"codex", "omp", "opencode", "codex-multi-auth", "codex-multi-auth-codex"}:
            return "pool-capable-agent"
        if any(re.search(r"codex|runtime-rotation|opencode|omp", script, re.I) for script in scripts):
            return "pool-capable-helper"
    if component == "teamclaude":
        if executable in {"teamclaude", "teamrouter", "claude"}:
            return "claude-or-broker"
        if any(re.search(r"teamclaude|teamrouter|claude", script, re.I) for script in scripts):
            return "claude-or-broker"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=JOBS)
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("run this source-side gate on studio-1 macOS")
    label = f"gui/{os.getuid()}/{JOBS[args.component]}"
    job = subprocess.run(["launchctl", "print", label], capture_output=True, timeout=10)
    blocked = job.returncode == 0
    if blocked:
        print("REFUSE: source launchd job is still loaded")
    processes = subprocess.run(
        ["ps", "-axo", "uid=,pid=,command="], capture_output=True,
        text=True, timeout=10, check=True,
    )
    for line in processes.stdout.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        uid, pid, command = fields
        if int(pid) == os.getpid():
            continue
        reason = classify(command, args.component)
        if reason:
            print(f"REFUSE: pid={int(pid)} kind={reason}")
            blocked = True
    print("source process gate: " + ("REFUSED" if blocked else "PASS"))
    return int(blocked)


if __name__ == "__main__":
    sys.exit(main())
