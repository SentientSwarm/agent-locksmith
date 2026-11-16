"""systemd unit text for the edge render: the hardened sandbox and escaping."""

from __future__ import annotations

import sitefile

GUARD = "/usr/local/sbin/locksmith-edge-state-check"
NFT = "/etc/locksmith-edge/input.nft"

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
After=network-online.target locksmith-edge-input.service {guard_unit(comp)}
Requires=locksmith-edge-input.service {guard_unit(comp)}
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
{env_file}ExecStart=/usr/bin/env {words} {unit_literal(comp.command)}
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


def guard_unit(comp: sitefile.Component) -> str:
    return f"locksmith-edge-{comp.name}-guard.service"


def guard_service(site: sitefile.Site, instance: str, comp: sitefile.Component) -> str:
    """The storage and custody check, as root, in a unit of its own: the
    component's EnvironmentFile (and any LD_* or PATH in it) never reaches
    it. The component Requires= and follows it, so a failed check blocks
    the start, and it runs again before every restart."""
    return f"""[Unit]
Description=Locksmith edge {comp.name} storage and custody check
After=local-fs.target
RequiresMountsFor={site.state_root}

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I {GUARD} {instance} {comp.name}
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
"""
