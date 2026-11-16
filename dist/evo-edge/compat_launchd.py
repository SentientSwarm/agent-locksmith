#!/usr/bin/env python3
"""Render an inactive, transport-only studio loopback relay for phase 5a.

Never loads launchd jobs or reads credentials. Install only after that source
broker is stopped and its edge replacement is validated. Remove in phase 5b.
"""
import argparse
from pathlib import Path
import plistlib

PORTS = {"codex": 43210, "teamclaude": 3456}


def definition(component):
    port = PORTS[component]
    return {
        "Label": f"com.sentientswarm.edge-compat.{component}",
        "ProgramArguments": [
            "/usr/bin/ssh", "-N", "-T", "-o", "BatchMode=yes",
            "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3", "-o", "ControlMaster=no",
            "-o", "ControlPath=none", "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no", "-o", "GatewayPorts=no",
            "-o", "PermitLocalCommand=no", "-L",
            f"127.0.0.1:{port}:10.250.4.12:{port}", "evo-x2-1",
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 30,
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=PORTS)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    with args.output.open("xb") as stream:
        plistlib.dump(definition(args.component), stream)
    print("inactive compatibility plist rendered; no job loaded")


if __name__ == "__main__":
    main()
