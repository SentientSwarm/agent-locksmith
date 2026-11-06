# Slack callback setup and upgrade

Register the exact configured HTTPS redirect with the Slack app, for example
`https://callback.example.test/oauth/callback/slack`. Route that public authority
to the configured TLS callback listener without rewriting the path or Host.
Do not append or synthesize an issuer parameter in a proxy or browser link.

The dedicated route permits an absent response `iss` only for a Slack profile
whose pending sealed attempt expects that exact received authority and path.
Different issuers cannot share the same dedicated received URI. Configuration
checks canonical origins, including host case and default HTTPS port spelling.
A supplied `iss` must equal the configured issuer; empty, malformed, wrong or
duplicate parameters refuse. Wrong routes/Host, forwarded headers and ambiguous
request targets refuse before exchange. State, current owner/client generation,
registration revision, profile digest and attempt deadline are still checked.

The legacy `/oauth/callback` route remains supported with a mandatory exact
issuer, including for Slack. Controlled and hosted Linear retain mandatory
issuer checks. A dedicated request cannot substitute for a generic redirect
bound to an older attempt. Failed preclaim validation does not consume that
attempt; it also does not authorize reusing a code or starting another attempt.

## Existing deployment

The redirect URI participates in the full profile digest. Do not edit sealed
rows or reuse an old client binding under a changed redirect. Use authenticated
operator access and retain the existing database, operator credential and both
sealing keys. This change adds no database migration or token import.

1. Stop new attempts and let owned operations finish or cancel them. While the
   old daemon and old configuration are still usable, retire the old generation:
   `locksmith oauth client retire slack --profile slack-reader --client-generation 1`.
   This permanently invalidates its pending attempts and managed accounts.
2. Stop and join the old daemon and callback routing. Configure the registered
   dedicated redirect and a strictly larger `client_generation`, for example 2.
   Restart the upgraded daemon with the retained database and keys. Validate
   TLS routing independently; readiness alone does not attest provider acceptance.
3. Read `locksmith --format json tool get slack`. Use its current
   `definition_control.revision` to deactivate the old pin, then read it again
   and reactivate against the new profile:

   ```sh
   locksmith tool deactivate-definition slack --if-match OLD_DEFINITION_REVISION
   locksmith --format json tool get slack
   locksmith tool activate-definition slack --if-match NEW_DEFINITION_REVISION \
     --oauth-profile slack-reader --contract-policy finite-v2
   ```

   Activation may precede consent without native grants. If selected tools and
   compact exposure are required later, supply the actual reviewed selection
   explicitly; no example tool name establishes a provider contract.
4. Seal the client using the supported stdin path, never an argument or YAML:

   ```sh
   locksmith oauth client set slack --profile slack-reader --client-generation 2 \
     --secret-stdin < protected-client-secret
   locksmith oauth client status slack --profile slack-reader --client-generation 2
   locksmith --format json oauth account-status slack --label account-new
   ```

5. Use the observed integer `config_revision` without guessing. Begin one fresh
   attempt only when ready to open its private URL:

   ```sh
   locksmith oauth connect slack --label account-new --profile slack-reader \
     --client-generation 2 --redirect-profile callback \
     --expected-config-revision CONFIG_REVISION \
     --scopes search:read.public,channels:history
   locksmith oauth attempt-status slack ATTEMPT_ID
   locksmith --format json oauth account-status slack --label account-new
   ```

Use the configured redirect profile identifier if it differs from `callback`.
Keep URL/code/state private. A successful callback still needs checked workspace
and user identity before account publication; publication grants no MCP tools.
Fresh selection, observation, review and grants remain separate as described in
[the Slack guide](slack-oauth.md). Retired generations cannot be revived by a
rollback, repeated set or deletion. Do not bootstrap a second database or key set
to evade that state.

## Offline smoke and limits

With the [tested build profile](../../development/build-identity.md), run
`cargo test --test oauth_consent_process_test callback_issuer -- --test-threads=1 --nocapture`.
Invented TLS receivers cover dedicated absent/exact issuer, malformed/wrong
issuer, wrong route/Host, unchanged state on refusal, one-use state, stale custody,
legacy and controlled behavior, and an independent wrong-challenge rejection.
Consent unit checks cover canonical redirect collisions and client rebinding.
These controls do not prove live Slack acceptance, S256 enforcement or tool schema
compatibility. The 600-second attempt deadline and normal sealed-account lifetime
are unchanged; this feature creates no 72-hour product custody limit.
