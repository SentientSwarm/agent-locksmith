# Prepare a nonpublishing native candidate

`.github/workflows/native-validation.yml` is a separate pull-request/manual lane.
It has read-only repository permissions,45-minute native jobs,10-minute aggregate
and one cancelable concurrency group per calling workflow and PR/ref. It does not
publish, tag, create releases, use deployment environments, or receive provider
credentials. The tag release workflow calls it (`workflow_call`) and publishes its
`native-complete` aggregate unchanged; see [Branching and releases](branching.md). Preparing this lane is not permission to
push a branch, open a PR or dispatch Actions.

## Source and native runners

The workflow checks out the actual event commit with persisted credentials off.
The externally supplied `GITHUB_SHA` must equal observed clean Git HEAD; the
receipt records that revision/tree, Cargo.lock digest and Cargo version. A branch
name, arbitrary input ref or a binary's own version cannot supply expected source.

| Target | Required native runner | Actual machine |
| --- | --- | --- |
| x86_64-unknown-linux-gnu | ubuntu-24.04 | Linux/x86_64 |
| aarch64-unknown-linux-gnu | ubuntu-24.04-arm | Linux/aarch64 |
| x86_64-apple-darwin | macos-15-intel | Darwin/x86_64 |
| aarch64-apple-darwin | macos-15 | Darwin/arm64 |

These labels are proposed standard native runners, not evidence of current
scheduling. Before external launch, reconcile the [official runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and record actual image OS/version. The advertised disk is not measured free
space. No paid larger runner, emulation or cross-compilation is selected. Actual
uname architecture and Rust host must match the target. Darwin also checks
[Apple's translation flag](https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment):
translated or unknown results refuse; documented ENOENT means native.

Rust 1.94.0 uses `--locked --release --bins --target TARGET`, with the documented
Darwin host build-override. The bounded build child measures disk before Cargo,
requires 8 GiB available, observes a 2 GiB stop floor and 6 GiB target-growth limit,
and times out after 1800 s. These are conservative proposed refusal bounds, not
proof a standard runner fits. Resource measurements include actual free/target
highwaters; sampling can lag growth. Insufficient runners fail rather than
silently choosing a larger class. No local build is authorized by this document.

## Same bytes from build through smoke to upload

Build captures the CLI/daemon to a fresh candidate directory **outside** the Git
worktree. Their native executable headers must match the target. No Cargo runs
after capture. Smoke verifies checksums and exact clean role/version/revision
using the existing build verifier, then executes version/help and a real isolated
daemon. It creates disposable local operator state, disables seed/provider/admin/
proxy inheritance, checks live version, readiness and supported operator agent
status, then requires graceful zero-exit shutdown and absent owned process group.
No normal account store, external provider or owner service is used. Loopback HTTP
limits the complete wire response to 32 KiB and body to 16 KiB, with an absolute 1 s
operation deadline. Readiness shares its 15 s deadline across header/body reads;
trickling data cannot renew either deadline. Truncated HTTP framing refuses even
when the received prefix is complete JSON.

Failed startup/status/shutdown never creates a successful smoke receipt. Private
operator files/tokens and daemon logs are not uploaded. The bounded command helper
withholds child diagnostics; Cargo output is discarded and its nonzero exit/resource
refusal is retained as closed failure evidence. This limits compiler diagnosis;
it is not a claim that compilation succeeded. Candidate receipts record completed
steps only. Version/help alone and supplied JSON alone are insufficient smoke.

Hashes before/after smoke bind the actual executed candidate bytes. Uploads carry
those same files and curated metadata. Aggregation rehashes all eight downloaded
files, requires every target/job/receipt, checks provenance/architecture/resources/
checksums/smoke/joins, and writes SHA256SUMS plus validation.json. Missing, skipped,
canceled, failed, extra, swapped, replaced, malformed or incomplete evidence refuses.
An expected failed-quality model result has no role in this native checker.

Candidate artifacts are named by run attempt; successful complete evidence is
`native-complete-ATTEMPT`, incomplete closed metadata is separately labeled.
Checksums/self-reported identity and CI receipts are consistency evidence, not a
signature or proof against a malicious compiler/workflow. Actual native claims
require the real four jobs, not invented local metadata.

## Public checker interface

All commands use Python3.11+ and the standard library. `--help` opens no product
state. `--output` must be outside the source worktree; build/aggregate require a
fresh directory. Smoke continues only that job's frozen build directory.

```sh
python3 -B scripts/native-validate.py build --target "$TARGET" \
  --expected-revision "$EXPECTED_COMMIT" --output "$CANDIDATE"
python3 -B scripts/native-validate.py smoke --target "$TARGET" \
  --expected-revision "$EXPECTED_COMMIT" --output "$CANDIDATE"
python3 -B scripts/native-validate.py aggregate --job-result success \
  --directory "$DOWNLOADED_CANDIDATES" --output "$COMPLETE_CANDIDATE" \
  --expected-revision "$EXPECTED_COMMIT"
```

Build/smoke are real executable operations requiring the caller's authority.
Offline consumers use invented artifact files with **aggregate only**, or isolated
fake collaborators in repository tests. See [exact artifact fields](native-artifacts.md).
Exit 0 means the requested bounded operation passed; exit 1 is a closed refusal;
usage errors exit 2. Failure JSON has `state:failed`, static `stage`/`error` and,
if persistence fails, `receipt:unavailable`. No paths or child output appear.

Local fixture checks, using an already installed PyYAML 6.0.3 for workflow parsing:

```sh
python3 -B -m unittest discover -s tests/native_validation -p 'test_*.py' -v
python3 -B -m unittest discover -s tests -p build_identity_verifier_test.py -v
```

The tests reuse existing checksum/identity and release artifact-flow expectations,
with invented executable/HTTP/header/process results. They establish contract
behavior only; they do not build Rust, schedule Actions, execute optimized native
product files or establish platform acceptance. No dependency installation is
needed in the prepared local environment. The native workflow itself needs no
PyYAML package.

## Remaining release gates

This lane requires `scripts/verify-build.py` and embedded build identity, both
already on `main`. A successful run is consistency evidence for one revision; it
is not authority to merge, tag or publish. Final packaged extraction, migration,
recovery and customer UAT remain AGENT-213, and platform execution does not clear
unrelated live, provider, quality, owner or publication gates. Published v2.8.0
metadata has four CLI assets and no daemon assets; releases from 3.0.0 publish
all eight validated binaries. An exact-tag locally built
prior daemon needs its own measured source, toolchain and hash record; never call
the unreleased feature base the last published release or invent a published pair.
