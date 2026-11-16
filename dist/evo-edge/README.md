# evo-x2-1 edge, phase 5 (inactive bundle)

This bundle prepares native services; it does not contain credentials, start a
workload, or certify that migration is complete. The operator procedure is
[the custody runbook](../../docs/operations/evo-edge-custody.md).

| Container | Fixed address | Memory | Workloads |
| --- | --- | --- | --- |
| edge-locksmith | 10.250.4.10 | 2 GiB | prod 9200, staging 9300; admin operator-only |
| edge-pipelock | 10.250.4.11 | 1 GiB | Pipelock 8888 |
| edge-brokers | 10.250.4.12 | 3 GiB | Codex 43210, teamclaude 3456, token-monitor 17321, lf-scan 9100 |

`prepare.sh images:ubuntu/24.04/amd64` runs **on evo as root** and only
creates stopped containers and dedicated 64 GiB ZFS custody volumes. It refuses
existing names/volumes instead of adopting possibly live state. A partial failure
requires inspection; it never deletes or resets a container. It changes neither
zone ACLs nor network bridges, profiles, other projects, or herdr. No nesting.

`python3 render.py edge-brokers /a/new/output/directory` renders the files to
install at container root. Repeat for the other two roles. It refuses an existing
output directory. It creates no enabled unit links, credential files, custody
receipts, users or runtime state. Keep the output **inactive** until the runbook
gates pass. Installing files is not the same as starting the units.

Each unit requires `/srv/edge-state` to be a separately mounted ZFS filesystem
with a root-owned `.edge-state-id` containing its container name. The operator
creates a protected `custody/<component>.ready` containing
`<container>:<component>` only after that component's stop/move ceremony.
`state_check.py` rejects missing/wrong mounts, identities, untrusted permissions
and missing/wrong receipts. It cannot independently prove a remote pool stopped.
Protect the volume root and custody directory from service users.

The service definitions preserve `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, dedicated users, restricted capabilities and bounded
shutdown. Node/Python units allow writable executable mappings for V8/PyTorch;
Rust/Go units deny them. Native Linux binaries, Node packages and scanner
dependencies must be installed and checked separately, at the exact selected
revisions. No macOS executables or ARM64 Podman binaries can be reused on AMD64.

`edge-input.service` installs a table **inside each container**, never on evo.
Broker relays bind 10.250.4.12 and forward to loopback services, preserving the
router's enforced loopback requirement and original client authentication.
The container firewall restricts these ports to herd and, for broker requests,
Locksmith. Bridge ACL changes remain herd-ops-claude's responsibility.
Validate kernel/container nft capability before activation. No egress restriction
is falsely claimed here: temporary direct dependencies remain until AGENT-255.

The bundle does not yet implement cross-container Pipelock configuration push
(AGENT-137/D-16). Do not report that requirement complete based on these units.
It also does not resolve service relocation, token-monitor's secret, scanner
model availability/peak memory, or native MCP child-process dependencies.

Tests (standard-library Python; test roots are bounded and cleaned automatically):

```sh
python3 -m unittest discover -s dist/evo-edge/tests -v
shellcheck dist/evo-edge/prepare.sh
bash -n dist/evo-edge/prepare.sh
```

On studio, `python3 dist/evo-edge/drain_check.py codex` is a read-only process
gate. It deliberately refuses while this seat, the launchd router or other
pool-capable processes still run. It prints PIDs and categories, never arguments,
environment, tokens or file contents. A passing result is one prerequisite,
not permission to skip the runbook's transfer/credential-path audit.
