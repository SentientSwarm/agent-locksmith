# Concepts

User-level mental models for working with locksmith. They describe the current release; the [CLI reference](../reference/cli-reference.md) and [architecture](architecture.md) pages give the operational detail.

Pages:

- [`trust-boundary.md`](trust-boundary.md) — who holds what credential, why
- [`kind-taxonomy.md`](kind-taxonomy.md) — model / tool / infra (Phase E)
- [`agent-identity-and-acl.md`](agent-identity-and-acl.md) — per-agent bearer + allowlist + audit attribution
- [`per-agent-credentials.md`](per-agent-credentials.md) — per-agent credential overrides + OAuth session labels (Phase G), and when not to use them
- [`oauth-flow.md`](oauth-flow.md) — end-to-end OAuth flow (codex / copilot / anthropic-oauth / google-gemini-cli / qwen-cli): bootstrap, refresh, per-request hot path, and the codex-specific `ChatGPT-Account-ID` injection (Phase G2)
- [`migrating-account-bindings.md`](migrating-account-bindings.md) — offline reviewed migration to finite HTTP grants and explicit accounts
- [`egress-and-inspection.md`](egress-and-inspection.md) — egress modes (`pipelock` / `external` / none), brokered routes, TLS interception vs per-route CAs, and the prompt-injection classifier gap
- [`architecture.md`](architecture.md) — daemon composition, request flow and where state lives
- [`threat-model.md`](threat-model.md) — what Locksmith protects against, what it does not, and which controls cover which threats

The [error envelope](../reference/error-envelope.md) is now a reference page.
