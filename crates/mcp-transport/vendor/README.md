# Pinned SDK ownership adaptation

`rmcp/` is the complete published rmcp 3.7.0 crate, Apache-2.0 (see
[LICENSE](rmcp/LICENSE)). `upstream.json` records its registry archive SHA256
and every original file hash. `ownership.patch` is the complete authored delta;
only four upstream source files change. The registry/cache is never modified.
No SDK version change is included.

The patch exposes the existing worker's abort handle without transferring its
join handle; passes manager cancellation through the existing initialization
select; lets the manager supervise the complete tower session task; and owns,
reaps, aborts and joins handler/send tasks at service shutdown. Existing response
drain order/timeouts remain intact. A failed service-task join is reported to
the manager as unconfirmed completion. It must retain capacity in that case.
An initial-response hook lets the manager retain cleanup custody until the
final initialize event is consumed. Default hooks preserve stock spawning,
token behavior and the one-event initial response.

Verify the complete vendored bytes and authored delta from the repository root:

```sh
python3 crates/mcp-transport/vendor/check.py
cargo metadata --locked --manifest-path crates/mcp-transport/Cargo.toml --format-version 1
```

The metadata's rmcp package must resolve to this local vendor directory. Cargo
only honors patches at the consuming root: downstream integration must copy
this manifest's `[patch.crates-io]` entry with the appropriate path. Compile-time
use of the added hooks prevents silently building this manager with stock rmcp.
The separate crate lock covers its enabled client and server features; root
Locksmith dependencies remain unchanged. Run both manifests' tests, especially
the accepted client body/framing/deadline regressions, after any patch update.

Third-party files preserve upstream sizes and layout for auditable provenance.
New Locksmith ownership code is in `src/sessions/`, outside this package.
Abort/join confirms termination of owned Rust futures, not rollback of submitted
DB/remote effects or independently spawned application tasks. Tokio runtime
shutdown is process teardown, not an application cleanup receipt.
