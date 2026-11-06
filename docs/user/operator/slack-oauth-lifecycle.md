# Slack OAuth lifecycle and upgrades

Use the [Slack OAuth guide](slack-oauth.md) for profile configuration, customer
activation, consent and finite grants. The following operations retain that
owner, profile and client-generation binding.

## Renewal and retirement

Manual `oauth refresh slack --label account-x --if-match REVISION` uses existing
owned refresh custody. Omitted refresh fields retain an existing refresh token;
explicit null/malformed/error after claim leaves uncertainty, never restores an
old possibly consumed pair. Pending refresh cannot replay after crash/restart.
Disconnect uncertain custody and complete fresh consent deliberately. Successful
refresh requires reobserve/review/regrant and fresh sessions; reconnect also requires
reselection. There is no background refresh for this managed profile.

`oauth client retire slack --profile slack-reader --client-generation 1` permanently
retires that owner/profile generation and invalidates matching pending attempts and
accounts. Metadata inspection/retirement remains available after connection removal
or key loss. A replacement requires a larger configured generation and restart,
deliberate definition deactivation/reactivation against that profile, then a new
sealed client and fresh consent/selection/review/grants. Repeating or deleting an
old generation cannot revive it. Client status `configured` confirms a live store
reference; it does not decrypt the value or attest provider acceptance.
Live references participate in the existing credential-store sweep protection.

## Upgrade from the former resource

A real Slack profile using the former resource `https://mcp.slack.com/mcp` now
refuses configuration validation. After any required retirement below, change it to `https://mcp.slack.com`;
keep the connection upstream at `/mcp`. Resource changes alter the profile digest,
so old client/account/definition bindings cannot be reused silently. If such
bindings exist, retire the old client generation with the prior daemon and its
old configuration before changing the resource or upgrading. Then use a larger
configured generation, restart and deliberately deactivate/reactivate the
pin, reseal the client and complete new consent/selection/review/grants. This
configuration correction adds no migration and never rewrites stored custody.
Existing controlled/hosted Linear and historical local Slack fixtures retain
their resource and endpoint behavior.

## Dedicated callback upgrade

Changing a legacy redirect to `/oauth/callback/slack` changes the full profile
digest. Follow [callback setup and upgrade](slack-callback.md): retire the old
client generation under its old config first, then rebind a larger generation
and reactivate deliberately. Preserve the database and sealing keys.

## Schema compatibility

Migration 0021 preserves prior account ciphertext and incarnation highwater,
introduces client-reference metadata in the existing store and extends the existing
selection/promotion guards. Back up the database normally before upgrade; old
schema 20 daemons refuse it before listeners. There is no supported downgrade or
proof-account import. Existing Linear kinds and default-v1 serialization remain.

## Deadlines and offline verification

Token requests retain 30s/3s request/connect limits; fixed Slack identity 5s/3s and
native 10s/3s remain distinct from owned outer deadlines. Closed `deadline`/`http`
diagnostics preserve known classifications without raw error strings; `http` does
not identify TLS/connect/provider cause. An outer `operation_deadline` can win
first. No automatic retry is inferred. Historical unknown failures remain unknown.
Token metadata failures expose [closed field-specific reasons](slack-token-diagnostics.md)
through owned attempt/refresh status; strict acceptance and historical evidence remain unchanged.

The executable offline smoke is `cargo test --test oauth_consent_process_test slack_ -- --nocapture`.
It creates only invented local TLS processes and joins them; use the repository's
[tested build profile](../../development/build-identity.md). Provider acceptance,
installation and live customer receiving remain separate.
