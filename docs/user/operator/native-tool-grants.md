# Prepare or revoke finite native grants

First [observe and review the exact tool contract](native-tool-review.md).
The following workflow continues that guide; all placeholders must be replaced
with exact current response values. Prepared grants do not enable tool calls.

## Prepare or revoke finite grants

Read the current state and `grant_revision`:

```sh
locksmith --format json agent mcp-grants show sample --agent AGENT_ID > grants-state.json
```

The response has top-level `source`, `observation`, `grant_revision`, `tools`,
`prepared_only` and `callable`. `tools` contains the currently prepared finite
`{name, contract_digest}` entries, not every observed tool. Selected response
fields are illustrated below; other observation fields, including the complete
manifest, are omitted from this excerpt. Strings and numbers are placeholders:

```json
{"source":{"instance":"CURRENT_INSTANCE","revision":1,"account_key":"CURRENT_ACCOUNT_KEY","agent_epoch":1},"observation":{"generation":"CURRENT_GENERATION"},"grant_revision":"CURRENT_GRANT_REVISION","tools":[{"name":"read_record","contract_digest":"REVIEWED_CONTRACT_DIGEST"}],"prepared_only":true,"callable":false}
```

Use `.source`, `.observation.generation` and `.grant_revision` from the current
`grants-state.json`. The write field is named `revision`, even though the show
response field is `grant_revision`. If no set exists, the latter is JSON null.
For one reviewed tool, this optional `jq` example constructs the strict write
body without manually retyping these values (requires `jq`):

```sh
jq -n --slurpfile state grants-state.json --slurpfile reviewed reviewed.json \
  '{source:$state[0].source,generation:$state[0].observation.generation,revision:$state[0].grant_revision,tools:[{name:$reviewed[0].contract.tool.name,contract_digest:$reviewed[0].contract_digest}]}' > grants.json
```

Confirm the current observation is fresh and still contains the reviewed tool.
A changed source, generation, revision or contract refuses the write; the command
above does not bypass these checks. An illustrative `grants.json` for an absent
set is:

```json
{"source":{"instance":"FROM_GET","revision":1,"account_key":"FROM_GET","agent_epoch":1},"generation":"FROM_OBSERVE","revision":null,"tools":[{"name":"read_record","contract_digest":"FROM_REVIEW"}]}
```

```sh
locksmith --format json agent mcp-grants replace sample --agent AGENT_ID --file grants.json
```

`revision: null` creates an absent set only; it is never a wildcard. All entries
must match current reviewed contracts and a fresh complete observation. A mixed
valid/invalid set refuses atomically. Use the current preconditions and an empty
`tools` array to revoke. Existing `agent unset-credential` also clears that
agent/connection's prepared grants, without contacting a provider.

Changes to a tool's description/schema/annotations invalidate its prepared
entries. Unchanged tools survive unrelated drift. A removed tool returning with
identical content needs deliberate regrant. Changing/removing a selection clears
only that agent/connection's grants; reselecting an old account does not restore
them. Name recreation has a new instance identity. Destination/protocol/MCP
config changes also clear the prepared observations/reviews and existing
connection authority. Metadata or disable/re-enable changes require a new
observation; unchanged contracts can retain prepared grants after refresh.

Observations become stale after 60 seconds and after every daemon restart.
Re-observe before review/grant writes. No background observation refresh runs.
409 means a source/generation/grant revision changed: read again and review the
new state. 429 means all eight preparation slots are busy. Other static errors
identify unsupported input, source, destination, trust or incomplete upstream
observation. Correct that cause; do not interpret prepared state as readiness.
