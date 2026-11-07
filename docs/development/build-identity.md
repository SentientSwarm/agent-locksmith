# Inspect and verify build identity

Both executables expose their build identity without loading configuration,
opening state, reading credentials or contacting a daemon:

```sh
locksmith --build-info
locksmithd --build-info
```

The JSON has exactly `name`, `version` and `build`. `name` identifies the binary
role (`locksmith` or `locksmithd`), even if the file has been renamed. `version`
is the package version; it is not a Git revision. `build` contains `revision`
(a full lowercase 40-character Git commit, or null) and `source_state`
(`clean`, `dirty` or `unknown`). Short `--version` output (`<name> <version>`) is unchanged for `locksmith` and
now also available from `locksmithd`.
The unauthenticated daemon `/version` response retains `name: agent-locksmith`
and `version`, and adds the same `build` object.

Identity describes the source at build time. The build script reevaluates Git
on every Cargo invocation, including reused targets, and verifies that the
canonical package directory is the Git worktree root. Tracked changes, index
changes, submodule changes and nonignored untracked files make it `dirty`.
Ignored build outputs do not. Missing/failing Git, a malformed revision or an
archive beneath an unrelated parent repository yields null/`unknown`.
Inherited `GIT_*` selectors are removed from the helper's Git commands. No
environment or archive revision override is supported. Runtime environment
variables cannot replace the embedded identity.

## Build with the tested recipe

Use Rust 1.94.0 and the platform's compiler/linker tools. This selects the compiler
used in local validation; it does not declare a minimum supported Rust version.
The native build keeps the usual `target/release` layout and is the same on every
build host:

```sh
cargo +1.94.0 build --locked --release --bins
# binaries: target/release/{locksmith,locksmithd}
```

The manifest keeps symbols in release build-time artifacts
(`[profile.release.build-override] strip = false`). It applies only to host build
scripts and proc-macros; runtime optimization and the shipped binaries' profile
are unchanged. Without it, a macOS host can fail to load a stripped host
proc-macro during the build. No per-command override is needed.

With Rust 1.94.0, target support and dependencies already cached, the
explicit-target macOS ARM64 command is:

```sh
cargo +1.94.0 build --locked --offline --release --bins \
  --target aarch64-apple-darwin
# binaries: target/aarch64-apple-darwin/release/{locksmith,locksmithd}
```

`--target` changes Cargo's artifact mode and output directory. Do not use a
native `target/release` file as evidence of an explicit-target build. The offline
command needs an installed toolchain/target and cached dependencies. Ordinary
commands without `--offline` may obtain dependencies, and rustup may obtain a
missing toolchain.

Local validation on macOS ARM64 covers native and explicit `aarch64-apple-darwin`
optimized pairs, checked with the captured-file verifier below. It does not
establish Linux or other cross-platform builds, or the other release assets.

CI selects `dtolnay/rust-toolchain@1.94.0`. The tag-triggered release workflow is
not changed here; aligning its toolchain is separate release work. That workflow
publishes a release and must not be used as a test dispatch. See
[release policy](branching.md).

## Check captured binaries

Use Python 3.11 or newer and the repository's verifier. Select the expected
package version and full commit independently from your build record, not from
the files being verified. For example, after capturing a native build, with the
expected version in `EXPECTED_VERSION` and the expected commit in
`EXPECTED_COMMIT`:

```sh
mkdir artifacts
cp target/release/locksmith artifacts/locksmith-darwin-arm64
cp target/release/locksmithd artifacts/locksmithd-darwin-arm64
(cd artifacts && shasum -a 256 locksmith-darwin-arm64 locksmithd-darwin-arm64 > SHA256SUMS)
python3 scripts/verify-build.py \
  --cli artifacts/locksmith-darwin-arm64 \
  --daemon artifacts/locksmithd-darwin-arm64 \
  --checksums artifacts/SHA256SUMS \
  --expected-version "$EXPECTED_VERSION" --expected-revision "$EXPECTED_COMMIT"
```

`SHA256SUMS` lines are lowercase SHA-256, two spaces, then the file basename, as
printed by `shasum -a 256` or `sha256sum`. The current release workflow publishes
only the CLI assets, so the daemon file comes from your own captured build. Both entries are checked before either file executes.
The verifier requires the correct role, expected version/revision and clean
state, then rehashes both files. Missing, corrupt, mixed, stale, dirty, unknown
or ambiguous inputs refuse with exit 1; usage errors exit 2. Successful output
is JSON with `verified: true` and scope `files`. Inspection is bounded to five
seconds and 16 KiB combined output per process; owned children are reaped.

Optionally pass `--version-response version.json` containing a separately
collected daemon `/version` response. This checks the same expected identity
and reports scope `files_and_supplied_version_response`; it does not fetch the
response or establish that it came from a live daemon. A live check must record
the launched binary's hash and process ownership, use the intended verified TLS
endpoint, and retain the response and shutdown evidence separately.

## Evidence and limits

Checksums and self-reported identity are consistency checks, not signatures or
proof of a trusted compiler. Retain an independent build receipt: selected full
commit, pre/post source/lock/vendor hashes, source cleanliness, actual compiler
and target, effective profile/flags, Cargo artifact reuse and captured file
hashes. Keep private paths and environment values out of distributable receipts.
Concurrent source mutation invalidates a clean build claim; capture files before
another build overwrites them. Ignored or external inputs require their own
receipt and are not covered by Git cleanliness.

The tested recipe makes compiler selection explicit. It does not change release
asset names, the package version, runtime profiles, the publication route or
deployment behavior. Native macOS ARM64 evidence remains separate from
cross-platform acceptance. See [release policy](branching.md).

## Diagnose a mismatch

Two builds can have the same package version and different commits. Compare each
role against the independently expected full commit; agreement between siblings
alone is insufficient. A retained older daemon must also fail acceptance when
its live `/version` is checked against the newer expected commit.

For a reused target, capture the files before rebuilding. A tracked edit, staging
that same edit, restoring it, and adding/removing a nonignored source file all
require a fresh build-time identity evaluation. If Git fails, the next build
reports unknown even when the target contains an earlier clean artifact; after
Git recovers, rebuild and recapture both files. A successful build with unknown
identity is inspectable but cannot pass this verifier's clean-source requirement.
Do not relabel a retained file with a newer receipt or infer its source from the
current checkout after a build.

## Nonpublishing native candidates

The separate [native validation lane](native-validation.md) prepares explicit
native runner execution and binds the same tested/hashed/uploaded CLI+daemon bytes.
Local invented fixture checks do not establish native scheduling or optimized
product success. Tag publication and final packaged UAT remain separate.
