# Integration definition activation and upgrade

Operators can import immutable definitions, create disabled exact pins and
explicitly activate supported local customer profiles. API and CLI share the
same authenticated backend. [Start here](../operator/integration-definitions.md).
This is part of planned3.0.0, with no independent tag or publication.

Migration 0012 originally added immutable definition storage and offline pins.
Current migration 0018 permits constrained local None/live StoredBearer/controlled
OAuth promotion and matching explicit selections. It imports nothing, creates
no account/grant/selection and rewrites no sealed custody or highwater. Existing
manual HTTP/native paths retain their behavior. `mcp.definition_activation` is
server-managed; general PUT/enable/credential/seed writers cannot set it.

Back up the complete database and retain matching old binaries before upgrading.
Follow [sealed-state recovery](../operator/sealed-state-recovery.md), including
no-OAuth-key quarantine and clearing selections for **all** owners (revoked
owners included) before a recovered daemon can replay provider refresh.

A schema 17 daemon refuses schema 18 before **all** listeners,
including unrelated HTTP services. The new strict configuration field is also
incompatible with older parsers. Rollback requires stopping the successor and
restoring an untouched whole prior snapshot with matching binaries; reupgrade
is the other supported route. Never delete migration rows or strip activation
metadata to force an old executable to open current data. The older 11→12 refusal
is retained historical evidence, not this migration's runtime proof.

Inspect `tool get NAME` after startup. Disabled pins remain disabled; promotion
is deliberate and cannot be inferred from candidate/fixture verification labels.
Every real activation/deactivation changes configuration authority. Rebuild ACL,
selection, observation, finite review/grants and sessions afterward. Exact-state
current-CAS retries only resync runtime. Controlled profile/token/root changes
retain their separate repair requirements. A new definition revision does not
rewrite existing pins. Deactivation retains owned sealed accounts and does not
claim remote revocation.

Full AGENT-203, provider AGENT-194/195/196/200, integrated AGENT-208 and release
gates remain open.
The local customer matrix and independent evidence must be attributed to their
actual candidate and command; historical manual SDK results are not proof of
current definition activation.

Definitions ship in 3.0.0 and keep the existing HTTP and native prerequisites.
Historical offline acceptance is not a runtime result.
