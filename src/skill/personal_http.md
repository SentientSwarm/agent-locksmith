### HTTP audit-debug recipe (operator-facing)

For 403 `tool_not_allowed` or a selected-source 503, your operator can trace:

```
locksmith audit query --agent {{public_id}} \
  --since-ms <ms>
```

For 403, security denies appear with `event=authz_denied` and
`details.reason` distinguishes `account_binding_missing` from `not_in_allowlist`
or `in_denylist`. For a missing binding, diagnose first:

```
locksmith agent credentials list {{public_id}}
locksmith agent set-credential {{public_id}} <tool> --auth 'bearer=<ENV_VAR>'
```

Choose the intended source reference deliberately; do not widen the ACL to
repair missing selection. Selected-source 503s require source diagnosis as
explained above, without alternate-account/default/unauthenticated retries.
For a 503, inspect proxy events: `credential_unavailable` uses
`details.credential_cause`; OAuth failures use `details.oauth_cause`, and
activation failures use `details.cause`.
The query above includes both security and proxy events. 401s
appear with `event=auth_failure` and `details.reason` carrying the
specific failure mode (`missing_credential`, `malformed_token`,
`wrong_namespace`, `unknown_public_id`, `secret_mismatch`, `expired`).
