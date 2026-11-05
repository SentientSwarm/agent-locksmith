# Native MCP lifecycle and migration (AGENT-202)

AGENT-202 introduced the typed native MCP lifecycle at `/mcp/{connection}`.
It authenticates every operation, applies current connection policy/account
selection, isolates session identity, and uses finite joined session ownership.
That original stage returned an empty tool list and denied every tool call.
Current manual native connections support reviewed finite listing and committed
dispatch for explicit None/live sealed-bearer selections, plus fixed context and
truthful callable schemas. Ordinary HTTP forwarding cannot invoke a native
registration. Use the current guides linked below for setup and authority.

This public projection keeps the root at 2.8.0, with no per-issue version bump.
Native provider consent, definition activation and broader schema mediation
remain staged work. This local capability does not make 3.0.0 ready
or authorize deployment, merging, tagging or publication.

## Protocol-aware agent guidance (bounded AGENT-209)

Authenticated `/skill` preserves each eligible connection's discovery type and
public path, with separate HTTP and native recipes. Native consumers initialize,
list complete callable schemas and construct only public arguments; fixed context
and finite grants remain operator-owned. A native connection named `codex` gets
no personalized HTTP Codex recipe. Read [skill guidance](../agent-integration/skill-reference.md)
for current repair, cache/authentication and uncertainty boundaries.

This rendering correction adds no migration, config, SDK, authority or credential
source. Existing HTTP calls stay compatible; rebuild/restart to load the embedded
text. Full AGENT-209 onboarding and live-provider prerequisites remain open.

## Optional compact facade (bounded AGENT-210)

An explicit `compact:true` MCP configuration adds `/mcp/{connection}/compact` and
conditional `compact_path` discovery. The shared session/authority/dispatcher
serves local search, complete describe receipts and committed invoke. Read the
[public compact contract](../agent-integration/compact-mcp.md) before opting in.
A toggle clears existing connection/bootstrap, account and per-tool authority.
A pre-compact daemon fails startup with stored true metadata; all daemon listener
availability is affected. The old CLI can read JSON through a new daemon. Reupgrade
and deliberate authority repair are covered separately. No migration/version bump,
provider acceptance or model efficiency claim is added.

## Upgrade and recovery

Stop all daemons using the database. Take a SQLite-consistent backup plus the
matching config, operator/certificate files and separately protected sealing
keys using your established recovery process. Never copy an active SQLite main
file alone while its WAL has pending state. Keep the prior binaries with the
backup; do not place secrets in command logs or issue evidence.

Startup applies real migration0011 before listeners. Existing registrations
become `protocol: http`; existing account references, reviewed HTTP grants,
revocations and migration receipts remain intact. New registration identities
and native authority epochs do not grant any tool or infer a native connection.
An actual pre-0011 binary refuses this upgraded state through SQLx's unknown
applied-migration check before either agent or admin listener opens.

The daemon holds a process-lifetime `<database>.daemon.lock` advisory file lock.
Equivalent ordinary relative/absolute paths resolve to the same lock. A second
daemon using that state refuses before listeners. The file's presence alone is
not a held lock; do not delete or replace it while a daemon is running. Hard-link
aliases and distributed/network-filesystem locking are not a supported sharing
mechanism. Run one daemon per database.

To roll back, stop the new daemon and restore the complete pre-upgrade backup
with its matching old binary/config. Do not remove migration rows or point the
old binary at upgraded state. New native sessions are ephemeral and never survive
a restart. Restart the new version to recover fresh native capacity normally.

HTTP account X/X/Y routing remains available under existing explicit selections.
Changing a registration's protocol, MCP config, upstream or egress clears its
connection grants, bootstrap scopes and selections atomically. Reapprove them
deliberately; never flatten native registrations to HTTP in an external export.
The existing CLI `export` exports agent policy, not a connection catalog; use
operator registration reads to retain protocol/config in catalog backups.

## Verification boundary

Saved checks use actual disposable daemon/CLI state, verified TLS Rust and
Python clients, receiving-process counters, current-state/body/database waits,
capacity/recovery, mTLS/bearer identity and old-binary migration refusal. See
[development checks and remaining assertions](../../development/native-mcp.md).
Independent acceptance is recorded at an immutable candidate; a draft builder
run is not QA/reviewer acceptance.

The separate198 outbound response adapter and199 joined-session controls retain
their own adverse tests. At the original202 stage only session ownership was reached.
[206A operator preparation](../operator/native-tool-review.md) now reaches bounded
selected-account observation; [current agent calls](../agent-integration/native-mcp.md)
use finite reviewed grants and committed dispatch. The
[fixed-context guide](../operator/native-context.md) covers protected values,
callable schemas and safe diagnosis. Full AGENT-203/206/207/208 and provider
acceptance retain their broader prerequisites. Full T09/T12 and G1/G3 remain open;
G0/G2/G4, optimized/platform builds and packaged recovery remain separate gates.
No live provider, model usage, release asset or installed service is tested by
the local debug lifecycle smoke.

Start with [operator setup](../operator/native-mcp.md) and
[agent requests](../agent-integration/native-mcp.md).
