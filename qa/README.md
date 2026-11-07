# Locksmith QA: smoke and UAT

Black-box qualification of Locksmith as users run it. Cases drive the real
`locksmith` and `locksmithd` binaries through the CLI and HTTP only; they never
import Locksmith code or write its database to set up state. The cargo test
suite stays the unit and integration layer.

## Run

```sh
cargo +1.94.0 build --locked --release --bins
uv venv --python 3.13 .qa-venv
uv pip install --python .qa-venv/bin/python -r qa/requirements.txt
.qa-venv/bin/python qa/run.py --bins target/release --mode pr --out /path/to/new/evidence-dir
```

`--out` must not exist. `-k EXPR` selects cases with pytest's filter and marks
the run `release_ready: false`. Harness self-tests:
`QA_BINS=target/release .qa-venv/bin/python -m pytest -c qa/pytest.ini qa/tests`.

## What a run does

1. Checks `qa/surface.yaml` against the source: every route literal in `src/`
   and every `locksmith` leaf command must have an entry, and every entry must
   exist. A mismatch fails the run.
2. Starts target T1 in a short-lived temporary directory: the shipped reference
   API (`examples/http-account-service.py`) as the upstream, a freshly minted
   operator, and `locksmithd` with a minimal config.
3. Runs the cases under `qa/smoke/`.
4. Maps results onto the contract, applies the gate, scans the evidence bundle
   for secrets and writes the report.

## Statuses and gate

Each case ends `PASS`, `FAIL`, `NOT_EXERCISED` or `NOT_APPLICABLE`. Skipped,
deselected or never-run cases are `NOT_EXERCISED`; nothing absent reads as a
pass.

| Mode | Fails on |
|---|---|
| `pr` | any FAIL, a contract mismatch, a per-area floor not met, a redaction hit, zero cases |
| `release` | all of the above, plus any NOT_EXERCISED case or contract entry |

A contract entry is exercised only when a passing positive case covers it and
passing refusal cases produce every refusal code the entry lists.

## Writing a case

```python
@pytest.mark.case("SMK-PROXY-004", area="PROXY", kind="refusal",
                  covers=["agent.ANY./api/{tool_name}/{*path}"], codes=["tool_not_allowed"])
def test_unallowlisted_tool_is_403(t1, caller):
    ...
```

- IDs: `SMK-<AREA>-<nnn>` for smoke, `UAT-<persona>-<journey>-CP<n>` for UAT.
- `kind`: `positive`, `refusal` or `corner`. `covers` names contract entry IDs.
  `codes` lists the refusal codes the case asserts.
- A case encodes the documented promise. When product and docs disagree the
  case fails and a ticket decides which one changes; never edit a case or a
  doc to make a failure pass.
- Assert zero dispatch for refusals with `t1.upstream_counts()`.

## Evidence

The bundle holds `manifest.json` (commit, tree state, mode, both binaries'
`--build-info`, counts), `results.json`, `report.md` and per-case transcripts
under `cases/<ID>/`. Transcripts pass through redaction first: the operator
token, every secret-named field in CLI output, the synthetic credentials and
the work directory path are registered as canaries. The final scan also looks
for token, bearer, argon2, private-key and OAuth code/state shapes; any hit
fails the run. Never put real tokens, auth URLs, secret-store contents,
provider payloads or private host details into evidence.

## Known gaps and waivers

A contract entry may be listed under `known_gaps` with a reason, a ticket and
an expiry at most 30 days out; while unexpired it reports `NOT_APPLICABLE`.
Only the owner approves a known gap or waiver, by approving the PR that adds it.
