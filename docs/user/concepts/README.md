# Concepts

User-level mental models for working with locksmith. Distilled from the stack technical spec at `agents-stack/docs/spec/v<X.Y.Z>.md`.

Authoritative versioned design lives in the stack spec; these pages exist to make the concepts accessible to users without requiring the formal spec.

Pages:

- [`trust-boundary.md`](trust-boundary.md) — who holds what credential, why
- [`kind-taxonomy.md`](kind-taxonomy.md) — model / tool / infra (Phase E)
- [`agent-identity-and-acl.md`](agent-identity-and-acl.md) — per-agent bearer + allowlist + audit attribution
- [`error-envelope.md`](error-envelope.md) — uniform §4.7.9 wire shape, existence-leak Q-8
- [`per-agent-credentials.md`](per-agent-credentials.md) — per-agent credential overrides + OAuth session labels (Phase G), and when not to use them
