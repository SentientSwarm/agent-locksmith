# Historical HTTP grant diagnostics

These are historical risk observations, not acceptance results for the projected
D4 candidate. At the D1 baseline the diagnostic reported 21/23 safe contracts:
legacy unrestricted-agent authority grew when a new registration appeared, and
a deliberately persisted disable could leave a stale runtime catalog callable.
D4 finite grants and coherent activation/admission address those boundaries.
The diagnostic is not substituted for the saved current acceptance tests.

## Findings and scope

| Historical observation | Required contract |
| --- | --- |
| A restricted caller was denied a new name while an unrestricted legacy caller gained access. | Reviewed finite grants cannot grow when a registration is added. |
| Disabling a DB row directly left its old runtime snapshot callable; refresh denied it. | Current persisted/runtime equality must gate admission, and a saved activation failure must be reported honestly. This fault model does not show that an ordinary successful disable call was broken. |
| Grant removal and revocation denied the next request with zero upstream operations. | Preserve next-admission authority; do not claim cancellation of already-admitted work. |
| Correct selected OAuth label remained isolated; missing/degraded selected state did not use a healthy default. | Preserve account selection and fail closed without alternate-account retry. |

## Reproduce against the real application

For the historical 21/23 result, use the public D1 baseline `ce6491d1` and its
existing `examples/local_risk_proofs/` diagnostic, not a claim that the current
D4 implementation should fail. In a disposable source/test environment:

```sh
git rev-parse HEAD
env -u LOCKSMITH_LOCAL_PROOF_MISSING \
  LOCKSMITH_LOCAL_PROOF_SELECTED=proof-selected \
  LOCKSMITH_LOCAL_PROOF_EMPTY= \
  cargo run --locked --example local_risk_proofs
```

The historical result exits 1 because of the two documented D4 findings. It uses
actual bearer authentication, SQLite, repositories, runtime catalog and proxy
handlers with synthetic local HTTP/token endpoints and temporary databases.
It does not establish live provider or installed-deployment compatibility. The
original older 5d606d5 diagnostic had 16/23 safe contracts and five additional
D1 credential fallback failures; those are historical too, not current behavior.

For current acceptance, run the unchanged
[saved process smoke](../development/explicit-account-bindings-smoke.md) and
focused grant/activation tests on the received candidate. Keep actual revision,
environment, command, exit and scope separate from these historical counts.
