# Changelog

## Unreleased

### Internal

- Use a guarded match for inherited OAuth default-session selection to satisfy
  current-stable Clippy. Existing explicit labels and non-OAuth sources retain
  their behavior.

### Breaking changes

- Credentialed requests require an explicitly selected account for each allowed
  agent. Missing bindings deny access; unavailable selected credentials fail
  closed. Locksmith no longer falls back to a registration default, another
  OAuth session, or an unauthenticated upstream.
- Credentialed legacy routes require a registered agent identity. Clearing a
  binding removes access instead of restoring a default account. Direct
  file-backed bindings require an explicit sealed-snapshot import.

### Upgrade and verification

- Back up a consistent database, preview and review the reference-only mapping,
  apply the selected bindings, then verify the cutover and restart. Existing
  explicit selections are preserved; ambiguous mappings need operator input.
  Follow [the migration guide](docs/user/concepts/migrating-account-bindings.md).
- [The repeatable daemon/CLI smoke](docs/development/explicit-account-bindings-smoke.md)
  covers account attribution, zero-dispatch denials, migration and the documented
  setup commands using synthetic accounts. It does not establish live provider
  compatibility, installed-deployment acceptance, a version tag or publication.
- The binding-repair change guide distinguishes accepted D1 work from remote
  integration and release status.
