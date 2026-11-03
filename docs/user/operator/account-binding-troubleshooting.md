# Troubleshoot explicit account access

Check caller identity, ACL and selected source in that order. A healthy alternate
account or ready daemon does not repair an unavailable selected account.

| Observation | Meaning and action |
| --- | --- |
| 401 `invalid_credential` or `expired` | Present a real registered agent token/certificate. Wrong, expired or revoked credentials must be replaced through normal enrollment. Do not use the operator token on the agent listener. |
| 401 `agent_identity_required` | Credentialed legacy route lacks registered-agent identity. Configure the admin database/listener, register an agent, authenticate it and select its source. `/readyz` also diagnoses credentialed identityless configurations. |
| 403 `tool_not_allowed` | Check the agent's `grants_reviewed` and finite allowlist/denylist, then `agent credentials list`. Missing/cleared binding denies even if the catalog has a healthy credential. Set the intended binding explicitly. |
| 404 `tool_not_found` | Current registration is missing or disabled after the ACL gate. Operator checks the catalog; DB-backed requests cannot use a same-name YAML fallback. |
| 503 `connection_not_active` | Saved configuration differs from runtime. Operator checks `tool get` / `model get`, repairs refresh failure, and repeats the intended write or restarts the deployment. No request reached upstream. |
| 503 `connection_activation_failed` on an admin write | The write was saved (`saved: true`) but refresh failed. Read it before retrying; do not assume rollback. Unrelated active connections can still work. |
| 503 `credential_unresolved` | Selection metadata/repository or selected env/stored/op source is unavailable. Check the selected reference and daemon-side custody; do not choose another account automatically. Missing and empty env values both fail. |
| 503 OAuth error | Check selected label, client/endpoints, sealing key and session state. Repair/rebootstrap that chosen session. Reconcile conflicting selections sharing its label before refresh; old placeholder bindings need deliberate re-selection. |
| Migration exit 5 `migration_conflict` | Inventory, selected subset or post-state changed. Keep the failed plan as evidence, generate and review a fresh preview. Never delete receipts/revision or recreate a cleared binding from an old plan. |
| Migration exit 2 / 1 | Invalid input / database-schema-access failure. Use the current tool/format and existing current-schema database. Errors intentionally omit SQL/source contents. |
| `skip` / owner-mapping reason | Unsupported transformation/file, ambiguous reference, ACL/status denial or identityless route. Repair through normal operator setup if intended, then preview again. Do not edit proposal AuthSpecs. |

For 403, audit `not_in_allowlist` needs a finite allowlist update after destination
review; `account_binding_missing` needs an explicit account selection. An
unreviewed legacy agent needs the `preview --grants` cutover. Adding a registration
or setting a binding never grows the allowlist. Deleting/recreating a name or
changing its destination removes old authority, so deliberately approve both
pieces again. `agent modify --allowlist` replaces the entire list; preserve all
intended names. Denylist still wins.

Use the actual public ID returned by agent registration:

```sh
locksmith agent get "$AGENT_ID"
locksmith agent credentials list "$AGENT_ID"
locksmith agent set-credential "$AGENT_ID" accounts --auth bearer=CHOSEN_ENV
locksmith audit query --agent "$AGENT_ID" --tool accounts --limit 100
```

Commands require `LOCKSMITH_OP_TOKEN` and the configured admin UDS/HTTPS endpoint.
Inspect references, `auth_source`, selected OAuth label, outcome and error class;
never paste bearer tokens, provider values, sealed blobs, database backups or
operator-bootstrap output into a report. Reference metadata can also be private.

Verify a benign request at the receiving upstream. Count operations and confirm
the chosen account, then exercise a clear/broken selection and confirm **zero**
added receiving requests/operations. A forwarded upstream 401 is not a safe
zero-dispatch denial. Restore the deliberate selection and verify success.

The [saved smoke](../../development/explicit-account-bindings-smoke.md) rehearses
these controls locally, including actual process restart. For upgrade backup,
read-only preview, reviewed apply and rollback consequences, follow
[migrating account bindings](../concepts/migrating-account-bindings.md).
