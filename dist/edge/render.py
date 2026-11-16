#!/usr/bin/python3 -I
"""Render one instance's inactive edge definitions from a site file.

Writes units, sysusers, the ingress nft table, components.json and the
root guard into a NEW directory. It never runs systemctl or incus, never
writes into an existing directory, and never creates receipts,
credentials or enabled-unit links: installing and activating the tree is
a separate, reviewed step.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import sys
from pathlib import Path

# -I drops the script directory from sys.path; add back only that directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import sitefile

UNITS = "usr/local/lib/systemd/system"
GUARD = "/usr/local/sbin/locksmith-edge-state-check"
NFT = "/etc/locksmith-edge/input.nft"
TABLE = "locksmith_edge_input"

SANDBOX = """NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native"""

INPUT_SERVICE = f"""[Unit]
Description=Locksmith edge ingress restrictions
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f {NFT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""


def unit_literal(text: str) -> str:
    """Escape systemd specifiers (%) and variable expansion ($)."""
    return text.replace("%", "%%").replace("$", "$$")


def quoted(text: str) -> str:
    """One double-quoted ExecStart word with systemd's C-style escapes."""
    inner = unit_literal(text).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{inner}"'


def service(site: sitefile.Site, instance: str, comp: sitefile.Component) -> str:
    root = site.state_root
    env = {"HOME": f"{root}/{comp.name}/home", **comp.env}
    words = " ".join(quoted(f"{k}={v}") for k, v in env.items())
    env_file = (
        f"EnvironmentFile={root}/environment/{comp.name}.env\n"
        if comp.environment_file
        else ""
    )
    return f"""[Unit]
Description=Locksmith edge {comp.name} (custody-gated)
After=network-online.target locksmith-edge-input.service
Requires=locksmith-edge-input.service
Wants=network-online.target
RequiresMountsFor={root}
ConditionPathExists={root}/custody/{comp.name}.ready
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=simple
User={comp.user}
Group={comp.user}
UMask=0077
RuntimeDirectory={comp.name}
RuntimeDirectoryMode=0750
{env_file}ExecStartPre=+/usr/bin/python3 -I {GUARD} {instance} {comp.name}
ExecStart=/usr/bin/env {words} {unit_literal(comp.command)}
WorkingDirectory={root}/{comp.name}
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
KillMode=control-group
{SANDBOX}
MemoryDenyWriteExecute={"no" if comp.jit else "yes"}
ReadWritePaths={root}/{comp.name} /run/{comp.name}

[Install]
WantedBy=multi-user.target
"""


def firewall(components: list[sitefile.Component]) -> str:
    rules = ["iifname lo accept", "ct state established,related accept"]
    ports: list[int] = []
    for comp in components:
        for rule in comp.ingress:
            ports.append(rule.port)
            for family in ("ip", "ip6"):
                nets = [s for s in rule.sources if _family(s) == family]
                if nets:
                    rules.append(
                        f"{family} saddr {{ {', '.join(nets)} }} tcp dport {rule.port} accept"
                    )
    if ports:
        rules.append(
            f"tcp dport {{ {', '.join(str(p) for p in sorted(set(ports)))} }} reject"
        )
    body = "".join(f"    {rule};\n" for rule in rules)
    # add-then-delete replaces the table on every nft version, first boot included.
    return (
        f"table inet {TABLE} {{}}\ndelete table inet {TABLE}\n"
        f"table inet {TABLE} {{\n  chain input {{\n"
        f"    type filter hook input priority 0; policy accept;\n{body}  }}\n}}\n"
    )


def _family(cidr: str) -> str:
    return "ip" if ipaddress.ip_network(cidr).version == 4 else "ip6"


def sysusers(site: sitefile.Site, components: list[sitefile.Component]) -> str:
    lines, seen = [], set()
    for comp in components:
        if comp.user not in seen:
            seen.add(comp.user)
            home = f"{site.state_root}/{comp.name}/home"
            lines.append(
                f'u {comp.user} - "Locksmith edge {comp.name}" {home} /usr/sbin/nologin'
            )
    return "\n".join(lines) + "\n"


def components_json(site: sitefile.Site, instance: sitefile.Instance) -> str:
    data = {
        "instance": instance.name,
        "state_root": site.state_root,
        "require_zfs": site.require_zfs,
        "components": {c.name: {"user": c.user} for c in instance.components},
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def render(site: sitefile.Site, instance_name: str, output: Path) -> None:
    instance = {i.name: i for i in site.instances}[instance_name]
    # Refuse a previous render or a populated runtime tree.
    output.mkdir(parents=True, exist_ok=False)
    files = {
        "etc/locksmith-edge/instance": instance.name + "\n",
        "etc/locksmith-edge/components.json": components_json(site, instance),
        "etc/locksmith-edge/input.nft": firewall(instance.components),
        "etc/sysusers.d/locksmith-edge.conf": sysusers(site, instance.components),
        f"{UNITS}/locksmith-edge-input.service": INPUT_SERVICE,
    }
    for comp in instance.components:
        files[f"{UNITS}/locksmith-edge-{comp.name}.service"] = service(
            site, instance.name, comp
        )
    for relative, text in files.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    guard = output / GUARD.lstrip("/")
    guard.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__).with_name("state_check.py"), guard)
    guard.chmod(0o755)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("site", type=Path, help="site TOML file")
    parser.add_argument("instance", help="instance name from the site file")
    parser.add_argument("output", type=Path, help="new directory to create")
    args = parser.parse_args()
    try:
        site = sitefile.load(args.site)
        if args.instance not in {i.name for i in site.instances}:
            parser.error(f"no instance {args.instance!r} in {args.site}")
        render(site, args.instance, args.output)
    except sitefile.SiteError as err:
        print(f"render: {err}", file=sys.stderr)
        return 2
    except FileExistsError:
        print(
            f"render: {args.output} exists; render into a new directory",
            file=sys.stderr,
        )
        return 2
    print(
        f"inactive definitions rendered for {args.instance}; no state, receipts or activation"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
