# Locksmith bounded MCP transport

AGENT-198 prerequisite library; not yet wired into Locksmith's daemon or CLI.
See the [design, configuration and diagnostics](../../docs/development/mcp-transport.md).
No root version bump, new network listener, migration or native routing is
introduced. Existing HTTP and selected-account authority are unchanged.

Uses the public rmcp3.7.0 transport hook, reqwest0.13.2 and sse-stream0.2.6,
matching the accepted S1 lock. No patched registry, vendored SDK or fork.
The library is MIT. rmcp is Apache-2.0; reqwest and sse-stream are
MIT OR Apache-2.0. Dependency licenses remain their own; Cargo.lock pins the
complete graph. The root's existing reqwest0.12 remains independent.

```rust,no_run
use locksmith_mcp_transport::{Client, Limits};
use rmcp::ServiceExt;

async fn connect() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // The embedding application installs its normal Rustls crypto provider.
    let client = Client::new(Limits::default(), vec![])?;
    let service = Client::client_config()
        .serve(client.transport("https://example.invalid/mcp", None)).await?;
    service.cancel().await?;
    Ok(())
}
```

`None` here represents an explicitly permitted public endpoint, not an auth
fallback. Supply only the credential selected by the embedding authority
layer. Additional PEM roots can be converted with reqwest::Certificate;
certificate/hostname verification cannot be disabled through this API.
The supplied transport disables automatic replay/reconnect and permits one
GET attempt per transport. Direct client clones share one GET attempt; failure
or cancellation consumes it. Deliberately creating another transport or client
starts a fresh budget. Direct use of
the trait with a different SDK worker configuration does not inherit that
worker policy. Do not use the stock default worker configuration in production.

From the repository root, with Rust1.94 and Python3 available:

```sh
cargo test --locked --manifest-path crates/mcp-transport/Cargo.toml -- --test-threads=1
cargo clippy --locked --manifest-path crates/mcp-transport/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path crates/mcp-transport/Cargo.toml --check
cargo test --locked --manifest-path crates/mcp-transport/Cargo.toml --test sdk_smoke -- --nocapture --test-threads=1
```

The separate manifest keeps native prerequisites out of the daemon dependency
graph until AGENT-202 integrates them. Consequently root `cargo test --all`
does not run these tests; CI runs both manifests explicitly. Test fixtures
bind loopback ephemeral ports, use generated certificates/synthetic identity,
and terminate their child receivers. No provider credentials or owner service
are required. `original` is a retained unsafe-SDK observation, while
`regression` requires rejection by the repaired adapter.
