# evo-x2-1 edge custody and cutover

Prepared 2026-11-16 for herd-ops-claude and agent-locksmith. This is a staged
execution runbook. **No pool has moved. No destination is serving.**
John authorized the migration and downtime; the coordinator owns space movement,
source Codex drain, agent/herd endpoint changes and zone ACLs. Agent-locksmith
owns deployment and identity/token custody. Never restart herdr, edit
`agentbr0`/`agents_guard`, alter agents VMs, or change herd/services/hokigai from
this runbook. No secrets in messages, terminal output, Git, review artifacts or
ordinary logs. Do not run commands with shell tracing.

## 1. Placement, reachability, unresolved gates

| Instance | Address | Native units / listeners |
| --- | --- | --- |
| edge-locksmith | 10.250.4.10 | prod 9200, staging 9300, operator admin 9201 |
| edge-pipelock | 10.250.4.11 | Pipelock 8888 |
| edge-brokers | 10.250.4.12 | Codex 43210, teamclaude 3456, hub 17321, scanner 9100 |

Budget: 2/1/3 GiB respectively, 2 CPUs each, project edge (3 containers /
6 GiB), pool zfs. Each has a dedicated `edge-<role>-state` custom volume mounted
at `/srv/edge-state`. Scanner model load/scan peak memory must fit the broker
budget before cutover. A passing `/health` alone does not load scanner models.

Source inspection found Codex at `127.0.0.1:43210`, teamclaude at
`127.0.0.1:3456` with 3 accounts, and token-monitor-hub at
`100.88.45.123:17321`. Ports 7456/7457 are Open Design/preview and stay on
studio temporarily. The external guard has no port: it validates the external
Podman disk, then invokes layer8 autostart. The destination replaces that
macOS-only check with `edge-state-check`, never with a successful no-op.

The Codex router refuses a non-loopback host. Preserve it at loopback; the
container's systemd socket relay binds `.12:43210`. Teamclaude similarly keeps
loopback with a `.12:3456` relay. Preserve the existing router client key and
teamclaude proxy authentication; test missing/bad credentials fail. The relay
does not add TLS: it is restricted to the intended internal bridge clients.

Coordinator ACL requests, before declaring the respective clients usable:

- herd 10.250.1.0/24 -> `.12` TCP 43210, 3456, 17321 only. No herd access to
  scanner, staging or admin. Coordinator will open these after local serving
  validation; report local serving separately from end-to-end herd validation.
- `.10` -> `.12` TCP 43210, 3456, 9100. **The current edge ACL permits only
  8888 within edge; this additional edge-to-edge dependency is a cutover gate.**
- `.10` -> `.11:8888`. Any AGENT-137 config-push transport needs its own
  reviewed narrow rule; no new admin port is invented here.
- edge -> agents only for verified replacement endpoints. Coordinator supplied
  Piper `.0.254` and Rivet `.0.76`; these are not proof of which catalog
  listener they replace. Do not point Hermes ports at those IPs by inference.

Temporary direct catalog dependencies on prod (inventory, not proof each is
healthy): brokers; lf-scan; studio LM Studio 1234; Linear/Slack HTTPS;
spark-1/2 ComfyUI 8188; babynator-4 HTTPS; Open Design 7456/7457;
evo Hermes 8642,8651-8654 and hokigai 8787. Internet/LAN egress is presently
allowed but **evo's own LAN/tailnet IPs are explicitly rejected**, as are
10/8 destinations without exceptions. Get authoritative replacement addresses
and narrow ACL rules from the owning zones; the coordinator's broad LAN
allowance does not override those rejects. Rewrite host.docker.internal and
host.containers.internal to actual destinations. Never route agents directly
to studio as a workaround. Locksmith alone may reach LM Studio on studio.

Audit OAuth refresh, hosted MCP and native child-process dependencies as well as
catalog rows before installing a restrictive per-NIC egress ACL. After AGENT-255
and successful routing through Pipelock, deny direct egress except Pipelock and
the expressly required bridge DNS. Verify DNS cannot become a bypass.

AGENT-137/D-16 cross-container config push is **not implemented by this
inactive bundle**. Policy export exists (`locksmith egress policy --pipelock`)
but is not a push protocol. Implement/verify atomic validated delivery,
Pipelock reload behaviour and rollback before claiming that requirement done.

## 2. Inactive preparation (agent-locksmith)

Use the isolated branch's [bundle](../../dist/evo-edge/README.md). Fetch the
Ubuntu **container** image `images:ubuntu/24.04/amd64`; the cached AMD64 image
inspected on evo was a VM image and must not be used for system containers.
Copy only the secret-free bundle to evo, then run:

```sh
sudo bash prepare.sh images:ubuntu/24.04/amd64
sudo incus --project edge list --format csv -c ns4
```

Expected: exactly the named three instances, STOPPED. Inspect each device's
fixed IPv4 address and custody volume, `boot.autostart=false`, zfs root disk,
and absent nesting. The script refuses pre-existing names instead of adopting
them. If interrupted, inspect the partial state; do not delete it blindly or
rerun with force. This step does not start a container or workload.

Render each role to a new local directory (not an existing runtime directory):

```sh
python3 dist/evo-edge/render.py edge-locksmith /new/path/edge-locksmith
python3 dist/evo-edge/render.py edge-pipelock /new/path/edge-pipelock
python3 dist/evo-edge/render.py edge-brokers /new/path/edge-brokers
```

Install these files as container root only in the coordinated outage, after the
relevant source is stopped. Unit definitions are in `/usr/local/lib/systemd/system`;
reserve `/etc/systemd/system` for masks and overrides. Before installation,
`systemctl mask` every `edge-*.service` and `edge-*.socket` basename in the role,
then install the rendered tree and run `systemctl daemon-reload`. Confirm the
mask links still point to `/dev/null`. The bundle contains no application secrets
or activation links. Keep credentialed units **disabled and masked** until their
custody ceremony ends; unmask/start only the container-local `edge-input.service`
for firewall validation before that. Do not copy regular unit files over masks.
Booting an empty OS for package installation after source stop does not authorize
starting any credentialed unit. Do not install packages whose maintainer scripts
start pool software. No credentialed workload starts on evo while its source runs.

Packages: Python 3, util-linux (`findmnt`), nftables, rsync, CA roots; Node 24
for brokers. Install native AMD64 Locksmith/Pipelock at selected validated
revisions, with build identity recorded; source prod/staging are Locksmith
3.0.0 at add28a62c7dd539bb08068b98f2e77aee54f8c9d, Pipelock 2.3.0.
Do not opportunistically upgrade them during a custody move. Staging has bind-
mounted binary overrides: verify their own build identity rather than trusting
its OCI tag. Native MCP launches may also require node/python/uv tool runtimes.
Full binary CI/build-identity checks remain deployment gates.

Install the exact Codex multi-auth and teamclaude revisions already used on
studio under `/opt/codex-multi-auth` and `/opt/teamclaude`. Build/install Linux
dependencies; never move macOS `node_modules` or executables. Place token-monitor
code at `/opt/token-monitor` and scanner code/venv at `/opt/lf-scan`. Preserve
existing package lockfiles and scanner dependency versions, including the
Hugging Face compatibility pin; exercise scans, not just health. Do not carry
Open Design or its credentials into the broker by accident.

Inside each container, after mounting its correct empty custody volume, root
creates `/srv/edge-state/.edge-state-id` containing the exact instance name,
and `custody/`, both root-owned and not group/world-writable. Root directory
0755, marker 0644 and custody directory 0700 are sufficient. Run
`systemd-sysusers /etc/sysusers.d/edge.conf`; create each component's directory
and home owned by its unit user (0700). Do not make receipt files yet.
No service user may write the custody root, marker or receipt directory.
The guard must fail before a receipt exists. Test missing/wrong ZFS mounts.

Service state is under `/srv/edge-state/<component>`. Each environment-using
unit requires `service.env` there (root-owned, 0600, created only by the private
custody transfer, never from a Git template). Preserve only the required
settings; omit macOS PATHs and runtime helper PIDs. Final `/usr/bin/env` assignments
in ExecStart enforce HOME, CODEX_HOME/MULTI_AUTH_DIR, TEAMROUTER_CONFIG, HF_HOME
and the hub data path even if a migrated EnvironmentFile contains old values.
Token-monitor must use a transferred nonempty TOKEN_MONITOR_SECRET and
TOKEN_MONITOR_DATA_FILE=/srv/edge-state/token-monitor/devices.json; without a
secret its source code falls back to loopback and is not remotely serving.

Validate `systemd-analyze verify` inside each container with its binaries
installed, and `nft --check --file /etc/edge-input.nft` before starting the
container-local firewall. These rules must never be installed on evo itself.
Verify the socket-proxyd executable path exists. Keep the caller-owned zone ACL
separate from these container rules. The Node/Python units permit executable
writable mappings for their runtimes; this is deliberate, not Rust/Go policy.

## 3. Drain order and control seats (coordinator)

1. Move the remaining studio spaces (agentic-border, toiyaba, hermes-agents,
   kz-tenant-inference, agent-locksmith) to kz-herd `10.250.1.10` or swarm-herd
   `10.250.1.11`. VM Codex clients use the router via tunnels and must not read
   or refresh a local copy of studio's multi-auth state. Stop scheduling new
   studio sessions/reviewers before the drain. Do not restart herdr.
2. **Codex move control:** herd-ops-claude, still using studio teamclaude.
   Quit every remaining studio Codex/omp/opencode client and per-launch helper,
   then unload/disable the source router. Herd Codex will be down in between.
3. Move/start edge Codex and validate authentication/streaming/refresh. The
   coordinator changes the herd tunnels/endpoints and tests both VMs.
4. **Teamclaude move control:** an independent Codex seat on a herd VM through
   the newly validated edge router, expected agent-locksmith-codex. Claude
   agents, including herd-ops-claude, cannot control their own model outage.
5. Stop teamclaude and its clients, move its custody, start/validate edge
   teamclaude. Coordinator repoints the VM Claude clients and verifies recovery.

No timeout or absence of a reply counts as a passed drain. No source pool may
restart after its credential transfer. Rollback is another stop-and-move of
the **current** state, never a restore of pre-refresh tokens.

## 4. Exact Codex source checks and paths (coordinator runs on studio)

As jxstanford, **after** gracefully quitting studio pool-capable agents:

```sh
launchctl disable "gui/$(id -u)/com.jxstanford.agent-pools.codex"
launchctl bootout "gui/$(id -u)/com.jxstanford.agent-pools.codex"
python3 dist/evo-edge/drain_check.py codex
```

`bootout` is expected to succeed the first time; if the job was already removed,
inspect that condition rather than blindly swallowing every failure. The gate
must exit 0 and print PASS. It checks the job is unloaded and all visible users'
native Codex/omp/opencode clients, Node multi-auth/router scripts and rotation
helpers are gone. It does not print process arguments/environment. It has been
tested to refuse the live studio router and helpers. It kills nothing.

Independent PID-only checks (each should return no PIDs; pgrep exits 1 for none):

```sh
pgrep -x codex
pgrep -x omp
pgrep -x opencode
pgrep -f '[c]odex-multi-auth/scripts/(codex|codex-app-router)\.js'
pgrep -f '[r]untime-rotation[^ ]*\.(js|mjs)'
lsof -nP -iTCP:43210 -sTCP:LISTEN
```

Do not use `ps e`, `launchctl print` output, `pgrep -fl`, debug HTTP requests or
raw Podman inspect output in chat: those can reveal secrets. A process gate is
conservative, not a proof of hidden token copies. Inspect the credential path
inventory without displaying file contents:

```sh
find /Users/jxstanford/.codex-terminal-pool/multi-auth/runtime-shadow-homes \
  -type f \( -name auth.json -o -name accounts.json -o -name '*accounts*.json*' \) -print
find /Users/jxstanford/.codex-terminal-pool -maxdepth 1 \
  -type f \( -name auth.json -o -name accounts.json -o -name 'auth.json.*' -o -name 'accounts.json.*' \) -print
```

Custody includes these concrete paths, not just the router's JSON:

- `/Users/jxstanford/.codex-terminal-pool/multi-auth/` **entire tree**:
  `openai-codex-accounts.json`, its `.bak`, `.bak.1`, `.bak.2`,
  `runtime-shadow-homes/**/auth.json`, cache/usage and runtime helper records,
  and `refresh-leases/`. Do not leave shadow-home credential files behind.
- Top-level `.codex-terminal-pool/auth.json` and `accounts.json` and any
  credential-bearing backups if present. Preserve config needed by clients,
  but keep conversation sessions/tooling out of the credential move.
- `.config/agent-pools/` including `codex-router.json`, `codex-client.key`,
  `client.env`, `setup-backup-20261101/` and `relaunch-20261101/`. These may hold
  credential copies. They are private custody material, never a code artifact.
- Audit helper-owner records and `runtime-shadow-homes` for links/references to
  paths outside the tree before transfer. A symlink is not a moved credential.
  Account for any such referent or stop; never follow arbitrary links blindly.

Runtime records/leases refer to old studio PIDs/ports. After the verified drain,
do not start a destination helper from those records; use the new router's
normal startup. Archive stale lease/owner records inside the protected moved
volume only after checking the package's lease recovery behaviour. Do not
delete the account database or restore a backup to clear a lease.

## 5. Move protocol, not a standby copy (agent-locksmith / coordinator)

The source process gate must remain PASS, launchd disabled, and new studio
launches inhibited throughout the transfer. Verify the destination state paths
are absent/empty; never merge into an already used destination pool. A cross-
machine move necessarily transfers bytes; the protocol below removes each
successfully received source file and forbids destination activation until no
source credential files remain. An interrupted move leaves **both sides off**;
resume the same move, never start either side to see what happens.

After source Codex is stopped, the coordinator may boot the empty broker OS for
package/unit installation; all pool units stay masked and have no receipts.
Ensure receiver rsync and root-private component directories exist. Use an
existing authenticated SSH route to evo; do not open SSH from an agents VM.
Run transfer commands on studio, never on a token-using model control seat that
will lose its own pool halfway through.

The following uses rsync's verified remove-source-files path (available in the
installed studio rsync). SSH executes rsync inside the broker through Incus;
no pool files are staged on evo's ordinary host filesystem:

```sh
set -eu
rsync -a --checksum --remove-source-files --no-owner --no-group --quiet \
  --rsync-path='sudo incus --project edge exec edge-brokers -- rsync' \
  /Users/jxstanford/.codex-terminal-pool/multi-auth/ \
  evo-x2-1:/srv/edge-state/codex/home/.codex-terminal-pool/multi-auth/
rsync -a --checksum --remove-source-files --no-owner --no-group --quiet \
  --rsync-path='sudo incus --project edge exec edge-brokers -- rsync' \
  /Users/jxstanford/.config/agent-pools/ \
  evo-x2-1:/srv/edge-state/codex/agent-pools/
```

Move inventoried top-level auth/accounts files with the same flags to the
destination CODEX_HOME. Do not use a broad home-directory glob or omit files
merely because they look like backups. Confirm source `multi-auth` and
`agent-pools` contain **no files or symlinks**, only empty directories. Confirm
inventoried top-level credentials are absent. Re-run the process gate. Inspect
the destination account count and non-secret metadata locally without showing
tokens. Verify no unrelated process can read that directory.

On destination, relocate the moved `agent-pools/codex-router.json` to
`/srv/edge-state/codex/router.json` (a rename, not a second copy), retain host
127.0.0.1/port 43210/client key, and rewrite obsolete absolute paths privately.
Create the required private service.env from the source job's non-secret tuning
and custody settings; do not carry macOS PATH. The unit fixes CODEX_HOME to
`/srv/edge-state/codex/home/.codex-terminal-pool` and MULTI_AUTH_DIR below it.
Disable app binding/install and CLI auth sync as on studio; avoid creating
new independently refreshing per-client pools. chown only the codex component
tree to codex-pool, keeping receipts/root marker root-owned.

Only now create a root-owned, mode 0600 receipt:

```sh
# INSIDE edge-brokers, as root, only after the complete Codex ceremony:
printf '%s\n' 'edge-brokers:codex' > /srv/edge-state/custody/codex.ready
chmod 0600 /srv/edge-state/custody/codex.ready
/usr/local/sbin/edge-state-check edge-brokers codex
systemctl unmask edge-codex.service edge-codex-relay.socket edge-codex-relay.service
systemctl start edge-codex.service edge-codex-relay.socket
```

Start the container-local `edge-input.service` first (units require it). Check
both `127.0.0.1:43210` and `.12:43210`, authentication rejection and one
authenticated streamed request using a private credential file, never a token
on a command line. Then coordinator opens the agreed bridge ACL and proves both
herd VMs reach the same pool without local refresh helpers. Test the provider's
refresh path in a controlled account, serialized; no parallel refresh probe.
After acceptance enable the units/socket; only then consider container autostart.

## 6. Teamclaude move (controlled by independent herd Codex)

First prove that the control seat is on the new edge Codex pool, not studio
teamclaude. Stop new Claude launches, drain requests, quit studio/VM clients as
coordinated, then run on studio:

```sh
launchctl disable "gui/$(id -u)/com.karpeleslab.teamclaude"
launchctl bootout "gui/$(id -u)/com.karpeleslab.teamclaude"
python3 dist/evo-edge/drain_check.py teamclaude
pgrep -f '[t]eamclaude|[t]eamrouter'
lsof -nP -iTCP:3456 -sTCP:LISTEN
```

The gate must PASS; PID/listener checks must be empty. Inventory the actual
`TEAMROUTER_CONFIG` / legacy `TEAMCLAUDE_CONFIG` path first. Inspection found
`/Users/jxstanford/.config/teamclaude.json`; the renamed
`.config/teamrouter.json` takes precedence if later created. Move the selected
config, state/quota siblings, private certificates/keys and credential-bearing
backups using the same rsync remove-source-files protocol. Certificates sit
beside the config: inspect filenames in installed `src/mitm.js`, including
`teamclaude-ca.pem`, `teamclaude-leaf.pem`, `teamclaude-leaf.key` and CA private
keys. Retain trust identity; never generate a replacement CA silently.

Destination selected config is `/srv/edge-state/teamclaude/teamclaude.json`,
fixed by TEAMROUTER_CONFIG. It must retain all three accounts, account IDs,
selection/routing settings and proxy key; no re-import that refreshes accounts
while source exists. Put siblings beside it, create private service.env, chown
component to teamclaude. Verify source credential files absent and gate still
PASS. Root creates `custody/teamclaude.ready` with
`edge-brokers:teamclaude`, then unmask/start edge-teamclaude.service and relay
socket. Validate account count and auth rejection, streaming, quota/refresh
without revealing identities/tokens. Coordinator repoints both VM Claude paths,
proves recovery and only then enables persistence. Never restore the old JSON
to recover a failed rotated token.

## 7. Locksmith, Pipelock, scanner and hub state

The native services need the actual custody data, not just source YAML:

- Prod: Podman volumes `layer8-proxy_locksmith_data` (SQLite DB with WAL/SHM,
  credential/OAuth rows, identities, grants/bindings) and
  `layer8-proxy_locksmith_log`. Source binds are under
  `agents-stack/layer8-proxy-site/locksmith/` and `rendered/locksmith/`.
- Staging: `layer8-staging_locksmith_data`/`locksmith_log`, plus
  `~/.local/share/locksmith-staging/` config/operators/secrets and explicit
  binary overrides. Preserve independently; never merge DBs.
- Both depend on `LOCKSMITH_OAUTH_SEALING_KEY`,
  `LOCKSMITH_CREDENTIAL_SEALING_KEY`, operator credentials and upstream secrets.
  An intact DB with the wrong keys is a failed migration. Capture source
  runtime environment privately into the transfer stream while the stopped
  container metadata still exists; never dump `podman inspect` to output/logs.
- Pipelock config/logs and generated allowlist overrides from the site and
  `layer8-proxy_pipelock_log`; preserve 2.3.0 semantics rather than copy evo's
  older 2.2 binary. Retire the old host service only after canary/cutover.
- lf-scan token/HF token and `layer8-proxy_lf_scan_hf_cache`. Source image
  exposes **9100**, but the current catalog's `lf-scan` upstream says 8080.
  Verify the actual listener and correct the relocated registration to
  `.12:9100` through the operator API, with explicit grants preserved.
- token-monitor: source launchd label `com.jxstanford.token-monitor-hub`,
  code `~/devel/3p/token-monitor`, data file normally `data/devices.json`,
  plus its hub secret/config. Verify overrides before moving. Do not move the
  7456/7457 Open Design processes under the mistaken token-monitor label.

Before stopping layer8 containers, disable/unload
`com.sentientswarm.layer8` and stop its babysitter/autostart script so it cannot
restart them during the move. Confirm the source containers are stopped and
no `locksmithd` refresher remains in the Podman VM. Shut down gracefully;
checkpoint SQLite only after the daemon stops, preserve WAL if checkpoint does
not complete, and run SQLite integrity checks privately. Move volume contents
with remove-source-files inside the source VM through an authenticated receiver;
do not export a live DB or leave a runnable standby copy. Audit mount ownership
and active bind sources from the actual containers: source prod's compose labels
refer to backup override files, not simply the checked-out compose override.

Native configs must use the moved data/log/operator/TLS/secret paths. Keep prod
and staging separate users and state. Bind admin/staging to loopback or operator
UDS, never enable a zone-wide administrative listener. Preserve existing
sealing material, public identities, selected accounts, agent bearer hashes,
and finite grants; no bulk re-enrollment. Validate a representative agent from
each zone against canary endpoints before coordinator cutover.

Stop/disable the token-monitor source job before moving its state, then set
its destination data path/secret. Stop source scanner/Pipelock before their
native counterparts. Root issues each receipt separately, using the exact
component names from the rendered units. Do not create wildcard receipts.

Inspect evo's legacy `locksmith.service` identity/config separately and
preserve required nonoverlapping identities through a reviewed operator import.
Do not overwrite the migrated prod DB with this older host state, or enable
its inline-key config in the new container.

## 8. Acceptance, coordinator handoff and retirement

Agent-locksmith sends **local edge serving** only after:

- Expected native versions, dedicated users, readonly filesystem hardening,
  correct persistent mounts, no nesting and no startup without custody receipts.
- `/livez`, `/readyz`, auth refusal and authorized routing, multi-account
  selection, representative long streaming, and controlled serialized refresh.
- Scanner real input/output scans under the 3 GiB broker budget, no missing
  model/cache/secret; native MCP child runtime and hosted callbacks verified.
- Broker listeners and loopback relays, container-local ingress restriction,
  validated Pipelock policy/config push, and explicit temporary direct exceptions.
- Source pools still stopped/disabled, credential files moved, no source
  per-pane helpers or auto-restart. No tokens in evidence.

Coordinator then opens agreed bridge ACLs, changes herd client endpoints and
agents_guard/agents ACL/forwarder, and runs zone-to-edge canaries. Verify agents
cannot reach studio LAN/tailnet or any broker/admin/scanner directly. Confirm
the remaining **Locksmith-to-LM-Studio** exception works without granting
agents a studio route. Report end-to-end acceptance separately.

Only after that acceptance retire evo `locksmith.service`, `pipelock.service`
and studio layer8/broker jobs/state per AGENT-258; remove obsolete forwarder
through the coordinator. Remove old inline secret configs with the credential
owner's retirement procedure, never print them. Do not remove the shared
Podman VM, registry or external disk simply because layer8 moved. Keep only
nonsecret migration evidence in Git/vault. Quarantined stale credential backups
must not become a rollback pool; handle their retirement privately.

Rollback after any provider refresh requires stopping the destination first
and moving its **latest** custody back under the same gates. Do not reactivate
source launchd or restore pre-migration tokens as a shortcut.

## Evidence and remaining validation

The standard-library tests cover refusal on missing/wrong ZFS mounts, wrong
volume/receipt, unsafe marker permissions/symlinks, traversal, inactive render
and process classification (including Node CLI paths). Their bounded temporary
directories are automatically removed. Source-side live gate correctly refused
the still-loaded Codex router and studio helpers without revealing credentials.
Host/container-specific systemd, nft capability, package, model and real
credential/refresh acceptance remain future checks while services are inactive.
