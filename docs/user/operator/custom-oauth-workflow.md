# Activate and use a declared OAuth service

First configure a [declared profile](custom-oauth.md). These commands use the
existing operator credential and isolated admin socket. Example paths, identity,
scopes and tool names are invented; use the service's real documented contract.
`LOCKSMITH_ADMIN_URL` must be unset when selecting the socket explicitly.

Create a local integration definition from the
[controlled definition example](../../../definitions/customer-controlled.example.json).
Choose your own `local.*` ID, `oauth_provider` auth profile and exact
`required_scopes` matching the declared profile. Import and create the disabled pin:

```sh
locksmith --socket ./admin.sock integration import --file ./customer-definition.json
locksmith --socket ./admin.sock tool from-definition customer --definition local.customer --revision 1 --auth-profile controlled --upstream https://api.example.test/mcp
locksmith --socket ./admin.sock tool get customer
```

Use the returned `definition_control.revision` as `PIN_REVISION`. The OAuth
profile must match the exact MCP endpoint and required scopes. Activation does
not perform consent or create grants. Active pin changes require disable/reset;
stale revisions and changed profiles refuse without acquiring authority.

```sh
locksmith --socket ./admin.sock tool activate-definition customer --if-match "$PIN_REVISION" --compact --oauth-profile customer --contract-policy finite-v2 --selected-tool inspect_catalog --selected-tool read_record
```

Explicit selected finite-v2 catalogs scan the complete bounded catalog (up to
256 tools/four pages), preserve selected schemas and declare omissions; unsupported
selected schemas refuse. Default full-catalog behavior remains bounded to 32.
Actual catalog/schema compatibility is a separate prerequisite for tool use.

For `client_secret_post`, provision through normal sealed credential custody.
Use a protected stdin source; never put a secret in arguments or reports. `none`
requires no client binding and must skip this command.

```sh
locksmith --socket ./admin.sock oauth client set customer --profile customer --client-generation 1 --secret-stdin < ./protected-client-input
locksmith --socket ./admin.sock oauth account-status customer --label reader
```

Use the fresh numeric `config_revision` for `CONFIG_REVISION`:

```sh
locksmith --socket ./admin.sock oauth connect customer --label reader --profile customer --client-generation 1 --redirect-profile customer --expected-config-revision "$CONFIG_REVISION" --scopes catalog:inspect,records:read
```

The returned authorization URL contains private state. Deliver it through an
approved private browser handoff. A consent attempt lasts 600 seconds; this is
not an account lifetime. Poll the supported attempt status using its private
attempt ID; a browser message alone is not success. No automatic retries occur.
A successful account remains unbound until deliberately selected.

```sh
locksmith --socket ./admin.sock oauth account-status customer --label reader
locksmith --socket ./admin.sock agent select-oauth "$AGENT_ID" customer --label reader --if-match "$ACCOUNT_REVISION"
```

The agent also needs the explicit connection ACL. Observe, review and grant
finite tools using [native tool review](../../development/native-tool-review.md).
Both native facades consume the same selected account, typed identity, current
profile, reviewed schemas and committed grants. Omitted/ungranted tools are not
callable. A declaration never grants a tool by itself.

Manual refresh uses the fresh account revision and exact same contract:

```sh
locksmith --socket ./admin.sock oauth refresh customer --label reader --if-match "$ACCOUNT_REVISION"
```

Refresh independently verifies identity before commit. Scope evidence remains
mandatory. Omitted refresh token retains the old credential; an explicit null
refresh value refuses. After a pending or unknown outcome, read status; never
replay a consumed refresh. Follow the existing reobserve/review/regrant repair
steps after version changes. Reconnect requires reselection. Sealed account
persistence survives restart without importing a different custody format.

The operator response schema is
[oauth-account-response-v1](oauth-account-response-v1.schema.json). A custom
account includes its typed `verified_subject`; historical named profiles do not.
Disconnect and confidential-client retirement remain local revocation operations,
not a provider revocation or proof of remote cleanup.
