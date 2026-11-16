#!/usr/bin/env python3
"""Render a secret-free, inactive native deployment; never runs systemctl."""
import argparse
from pathlib import Path
import shutil

ROOT = "/srv/edge-state"
IP = {"edge-locksmith": "10.250.4.10", "edge-pipelock": "10.250.4.11",
      "edge-brokers": "10.250.4.12"}
SERVICES = {
    "edge-locksmith": {
        "locksmith-prod": ("locksmith", "/usr/local/bin/locksmithd --config /srv/edge-state/locksmith-prod/config.yaml", True),
        "locksmith-staging": ("locksmith-staging", "/usr/local/bin/locksmithd --config /srv/edge-state/locksmith-staging/config.yaml", True),
    },
    "edge-pipelock": {
        "pipelock": ("pipelock", "/usr/local/bin/pipelock run --config /srv/edge-state/pipelock/config.yaml", False),
    },
    "edge-brokers": {
        "codex": ("codex-pool", "/usr/bin/node /opt/codex-multi-auth/scripts/codex-app-router.js --state /srv/edge-state/codex/router.json --status /srv/edge-state/codex/status.json", True),
        "teamclaude": ("teamclaude", "/usr/bin/node /opt/teamclaude/src/index.js server --headless", True),
        "token-monitor": ("token-monitor", "/usr/bin/node /opt/token-monitor/src/hub/server.js --host 10.250.4.12 --port 17321", True),
        "lf-scan": ("lfscan", "/opt/lf-scan/venv/bin/uvicorn app:app --app-dir /opt/lf-scan --host 10.250.4.12 --port 9100", True),
    },
}


def service(instance, component, user, command, environment):
    extra = ""
    assignments = [f"HOME={ROOT}/{component}/home"]
    if environment:
        extra += f"EnvironmentFile={ROOT}/{component}/service.env\n"
    if component == "codex":
        assignments += ["CODEX_HOME=/srv/edge-state/codex/home/.codex-terminal-pool",
                        "CODEX_MULTI_AUTH_DIR=/srv/edge-state/codex/home/.codex-terminal-pool/multi-auth"]
    if component == "teamclaude":
        assignments += ["TEAMROUTER_CONFIG=/srv/edge-state/teamclaude/teamclaude.json"]
    if component == "lf-scan":
        assignments += ["HF_HOME=/srv/edge-state/lf-scan/hf-cache"]
    if component == "token-monitor":
        assignments += ["TOKEN_MONITOR_DATA_FILE=/srv/edge-state/token-monitor/devices.json"]
    jit = "no" if instance == "edge-brokers" else "yes"
    return f"""[Unit]
Description=Edge {component} (custody-gated)
After=network-online.target edge-input.service
Requires=edge-input.service
Wants=network-online.target
RequiresMountsFor={ROOT}
ConditionPathExists={ROOT}/custody/{component}.ready
StartLimitIntervalSec=120
StartLimitBurst=3

[Service]
Type=simple
User={user}
Group={user}
UMask=0077
RuntimeDirectory={component}
RuntimeDirectoryMode=0750
Environment=HOME={ROOT}/{component}/home
{extra}ExecStartPre=+/usr/local/sbin/edge-state-check {instance} {component}
ExecStart=/usr/bin/env {' '.join(assignments)} {command}
WorkingDirectory={ROOT}/{component}
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
KillMode=control-group
NoNewPrivileges=yes
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
SystemCallArchitectures=native
MemoryDenyWriteExecute={jit}
ReadWritePaths={ROOT}/{component} /run/{component}
LimitNOFILE=65536
TasksMax=512
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


def firewall(instance):
    # This table exists INSIDE a container. Never flush the host/other tables.
    rules = ["iifname lo accept", "ct state established,related accept"]
    if instance == "edge-brokers":
        rules += ["ip saddr 10.250.1.0/24 tcp dport { 43210, 3456, 17321 } accept",
                  "ip saddr 10.250.4.10 tcp dport { 43210, 3456, 9100 } accept",
                  "tcp dport { 43210, 3456, 17321, 9100 } reject"]
    elif instance == "edge-locksmith":
        rules += ["ip saddr { 10.250.0.0/24, 10.250.1.0/24 } tcp dport 9200 accept",
                  "tcp dport { 9200, 9201, 9300 } reject"]
    else:
        rules += ["ip saddr { 10.250.0.0/24, 10.250.1.0/24, 10.250.4.10 } tcp dport 8888 accept",
                  "tcp dport 8888 reject"]
    return "destroy table inet edge_input\ntable inet edge_input {\n chain input {\n  type filter hook input priority 0; policy accept;\n  " + ";\n  ".join(rules) + ";\n }\n}\n"


def render(output, instance):
    # Refuse overwriting a previous render, especially a populated runtime tree.
    output.mkdir(parents=True, exist_ok=False)
    def write(relative, text):
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    # Leave /etc/systemd/system available for /dev/null masks and overrides.
    units = "usr/local/lib/systemd/system"
    write("etc/edge-instance", instance + "\n")
    write("etc/edge-input.nft", firewall(instance))
    write(f"{units}/edge-input.service", """[Unit]
Description=Container-local edge ingress restrictions
DefaultDependencies=no
After=local-fs.target
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/edge-input.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""")
    users = []
    for component, (user, command, env) in SERVICES[instance].items():
        users.append(f'u {user} - "Edge {component}" {ROOT}/{component}/home /usr/sbin/nologin')
        write(f"{units}/edge-{component}.service", service(instance, component, user, command, env))
    write("etc/sysusers.d/edge.conf", "\n".join(users) + "\n")
    if instance == "edge-brokers":
        for component, port in [("codex", 43210), ("teamclaude", 3456)]:
            # Different local addresses allow the same external/internal port.
            write(f"{units}/edge-{component}-relay.socket", f"""[Unit]
Description=Herd-only {component} relay socket
After=edge-input.service
Requires=edge-input.service
ConditionPathExists={ROOT}/custody/{component}.ready

[Socket]
ListenStream=10.250.4.12:{port}
FreeBind=yes
NoDelay=true

[Install]
WantedBy=sockets.target
""")
            write(f"{units}/edge-{component}-relay.service", f"""[Unit]
Description=Relay to authenticated loopback {component}
Requires=edge-{component}.service edge-input.service
After=edge-{component}.service edge-input.service

[Service]
ExecStartPre=+/usr/local/sbin/edge-state-check {instance} {component}
ExecStart=/usr/lib/systemd/systemd-socket-proxyd 127.0.0.1:{port}
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
CapabilityBoundingSet=
""")
    guard = output / "usr/local/sbin/edge-state-check"
    guard.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__).with_name("state_check.py"), guard)
    guard.chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance", choices=IP)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    render(args.output, args.instance)
    print(f"inactive definitions rendered for {args.instance}; no state, receipts or activation")


if __name__ == "__main__":
    main()
