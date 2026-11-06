# Hosted Linear accounts for native MCP

The shipping daemon supports the fixed `linear-hosted-v1` OAuth profile through
its existing owner-bound account, selection and finite native-grant interfaces.
The distinct `linear-hosted-fixture-v1` profile exercises that same policy against
a local HTTPS twin. Fixture results establish local behavior; live shipping
provider adoption and release remain separate. The experimental proof's encrypted
grant is not a production account and has no supported import path.

## Configure a profile and callback

Use an already registered public client with S256 and `read` access. Supply the
expected workspace and user UUIDs from trusted operator information. No dynamic
client registration, discovery, confidential client, scope expansion or implicit
endpoint override occurs. The real profile fixes these exact provider URLs:

```yaml
oauth_consent:
  callback:
    address: 127.0.0.1:19444
    cert_path: ./callback.pem
    key_path: ./callback.key
  profiles:
    - id: linear-reader
      kind: linear-hosted-v1
      client_id: REPLACE_WITH_REGISTERED_PUBLIC_CLIENT
      client_generation: 1
      issuer: https://mcp.linear.app
      authorization_endpoint: https://mcp.linear.app/authorize
      token_endpoint: https://mcp.linear.app/token
      resource: https://mcp.linear.app/mcp/readonly
      redirect_profile_id: public-callback
      redirect_uri: https://callback.example.test/oauth/callback
      expected_workspace: 00000000-0000-0000-0000-000000000041
      expected_user: 00000000-0000-0000-0000-000000000042
      ca_path: ./provider-ca.pem
      selected_tools: [get_project, get_issue]
```

All identifiers above are invented. Supply the existing OAuth sealing key through
its secure environment source. It is independent of the stored-bearer key. The
CA file adds trusted certificates to normal roots; TLS verification stays on.
Profiles and native-dispatch CA bytes are loaded at startup; consent/token clients
read the configured CA file when created. At most eight profiles are allowed.
Empty or duplicate selected names, more than 32 names, or names longer than 128 UTF-8
bytes/containing controls are refused. Profile kind, exact endpoint/client/
generation, identities, redirect and selected names are part of the profile digest.

The listener remains TLS on literal `127.0.0.1` or `[::1]` with a nonzero port.
The advertised hosted redirect may have a different public HTTPS authority, but
must have the exact `/oauth/callback` path and no user information, query or
fragment. Arrange an appropriate route and certificate independently; Locksmith
does not provision a tunnel, DNS record or public listener. Preserve the configured
Host authority end to end. Forwarded and X-Forwarded headers are refused. A
callback for one attempt cannot substitute another configured profile's authority.
The original controlled profile still requires its redirect to equal its local bind.

For offline verification, use `kind: linear-hosted-fixture-v1`, put issuer,
`/authorize`, `/token` and `/mcp/readonly` on the same literal-loopback HTTPS origin,
and use a trusted test CA. This is a separately identified fixture kind, not a
way to redirect real hosted credentials. Public callback separation can be tested
by an explicit local TLS client route without changing machine DNS.

## Connect and delegate deliberately

Create an enabled manual native tool using the normal operator API. Its upstream,
PKCE template and read scope must match the chosen profile exactly. For the above
invented configuration, PUT `/admin/operator/tools/linear` with:

```json
{
  "description": "Selected Linear read tools",
  "upstream": "https://mcp.linear.app/mcp/readonly",
  "protocol": "mcp_streamable_http",
  "egress": "direct",
  "mcp": {"protocol_version": "2025-11-25", "compact": true},
  "auth": {
    "kind": "oauth_pkce",
    "client_id": "REPLACE_WITH_REGISTERED_PUBLIC_CLIENT",
    "redirect_uri": "https://callback.example.test/oauth/callback",
    "scopes": ["read"],
    "auth_url": "https://mcp.linear.app/authorize",
    "token_url": "https://mcp.linear.app/token"
  }
}
```

A fixture registration additionally needs `allow_private_destination: true` in
`mcp`. Hosted profiles are manual-native only: neither a legacy HTTP registration
nor a promoted definition substitutes for this explicit setup.

Use the existing operator authentication and UDS or admin HTTPS transport:

```sh
locksmith --format json oauth account-status linear --label account-x
# Supply the returned config_revision, not this example placeholder.
locksmith --format json oauth connect linear --label account-x \
  --profile linear-reader --client-generation 1 --redirect-profile public-callback \
  --expected-config-revision CONFIG_REVISION
locksmith --format json oauth attempt-status linear ATTEMPT_ID
locksmith --format json oauth account-status linear --label account-x
```

Open the returned private authorization URL manually. An attempt lasts at most
600 seconds. The callback requires its one-time state and matching issuer, and
exactly one code or denial. Tokens remain quarantined until both workspace and
user identities pass. `connected_unbound` creates no agent selection, review,
grant or enabled flag. Hosted account status reports `linear_hosted_v1`; the twin
reports `linear_hosted_fixture_v1`. [The response schema](oauth-account-response-v1.schema.json)
retains the same owner-bound revision and lifecycle fields.

Grant the agent's connection ACL, then use the current account revision:

```sh
locksmith agent select-oauth AGENT linear --label account-x --if-match REVISION
```

Continue with [native OAuth selection and repair](native-oauth.md) and
[finite tool observation/review/grants](native-tool-review.md). Only the owning
operator can select or prepare this account. Both standard and compact clients
must open a fresh session, discover the finite callable tools and read each full
schema before constructing arguments. Explicit protected context and the reviewed
contract control arguments; OAuth consent does not supply a project grant.

## Selected catalog and wire policy

A hosted observation scans a complete bounded catalog before publishing anything:
no more than 256 total names across four pages, no duplicate name (including omitted
tools), repeated cursor or missing selected name. Every selected tool must satisfy
the explicitly selected full [finite contract policy](native-contract-policy.md).
Absent registration policy remains v1; hosted identity or vendor name never opts
a connection into v2. Its JSON values and canonical
observed digest are preserved; unsupported selected schemas are refused, never
rewritten into a weaker schema. SDK normalization that would drop tool fields is
also refused. The selected manifest stays at most 32 tools/48KiB. This does not
promise that a future real Linear catalog fits those rules.

A completed observation includes:

```json
{"projection":{"policy":"explicit_profile_tools_v1","total":53,"selected":2,"omitted":51}}
```

These counts appear alongside `manifest.tools` only after complete pagination.
Omitted tools cannot be reviewed, granted or dispatched through this observation.
Changing the selected-name list changes profile authority and requires explicit
account repair; it cannot silently adopt existing custody. Controlled/None/bearer registrations keep their original complete 32-tool
catalog policy unless explicitly selecting a finite-v2 registration subset;
see [customer selection](native-contract-policy.md#explicit-customer-catalog-selection).

Native transport retains 256 KiB response/chunk,64KiB SSE-event,8192 JSON-unit,
32-depth,128-event and1MiB aggregate client limits, with 10s request/3s connect.
Hosted SSE returns on the first complete response after bounded notifications;
it does not validate a later tail or establish EOF. Wrong IDs/session changes and
server requests refuse. Consent identity uses its existing 5s/3s, 512 KiB and 32768-unit
bounds, and refuses pagination, structured identity content, unsupported schemas
or mismatched IDs. Both paths pin MCP 2025-11-25. A successful tool result remains
subject to the existing 32 KiB result/16content/16KiB text and output-schema checks.

Provider project public IDs and canonical UUIDs are different namespaces; issue
identifiers likewise differ from opaque IDs. Select task values from trusted
operator context and the received schema. There is no suffix/name fallback or
provider-specific dispatcher. Generic shipping tool results do not independently
prove workspace membership or a project/issue relationship.

## Refresh, failures and upgrade

Hosted token requests have a 30s request limit within the existing 40s owned
operation; controlled token requests remain 5s. Refresh is explicit and owner/
revision-bound. Optional refresh and expiry remain optional; missing expiry is
unknown, not a fabricated hour. An omitted refresh response may retain only the
exact claimed previous refresh token. Present invalid metadata, conflicting read
scope/resource/client/issuer, or an OAuth error in HTTP 200 refuses.

```sh
locksmith oauth refresh linear --label account-x --if-match REVISION
locksmith oauth disconnect linear --label account-x --if-match NEW_REVISION
```

A refresh claim immediately invalidates old native authority. After success,
observe/review/regrant and open fresh sessions; after disconnect/reconnect, select
the new account incarnation as well. Pending uncertainty after a timeout/crash
requires explicit reconnect, never an automatic refresh retry. No token or refresh
value appears in account output. Native dispatch decrypts only the access token.

Migration 0019 preserves existing encrypted bytes, optional metadata and historical
incarnation highwater while adding the two hosted kinds. Older schema-18 daemons
refuse the upgraded database before becoming available. Reopen with the current
binary; downgrade requires an untouched complete prior snapshot under
[sealed-state recovery](sealed-state-recovery.md). Controlled consent, legacy HTTP
and local definition promotion remain separate supported paths. Hosted accounts
cannot enter legacy bootstrap, automatic refresh or legacy HTTP token resolution.
