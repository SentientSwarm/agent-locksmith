# Native candidate artifact contract v1

This is the public consistency-check input contract. Invented files can exercise
it offline; a successful invented fixture is **not** actual platform execution.
Real native claims require the four workflow jobs and actual smoke receipts.
The checker is `scripts/native-validate.py aggregate`; it does not execute supplied
artifact binaries. Build/smoke operations execute code and require separate authority.

## Directory and source

Use the four target/suffix mappings in [native validation](native-validation.md).
For each target, the input directory contains exactly seven regular nonsymlink
files, without subdirectories:

- `locksmith-SUFFIX`, `locksmithd-SUFFIX` — the same executed, hashed bytes;
- `TARGET.json` — complete provenance as below;
- `TARGET.build.json` — same object minus `smoke`, state `built_not_smoked`;
- `TARGET.resources.json` — exactly its `resources` object;
- `TARGET.smoke.json` — `{"stage":"complete","daemon_started":true,"cleanup":{"joined":true,"exit":0,"forced":false}}`;
- `TARGET.sha256` — exactly the two basename hashes, lowercase 64-hex, two spaces,
  then basename, one entry per line. No duplicate/extra checksum entries.

Thus the complete input has 28 files/eight binary assets. The filesystem set,
JSON object keys and typed metadata are exact. Missing/extra/duplicate/malformed
metadata, changed bytes, wrong native headers or unsuccessful matrix status refuse.
The checker never normalizes or repairs artifacts. JSON is bounded 64 KiB per file;
checksums 128 KiB. No private operator files, logs, certificates or state databases.

Expected source is independently observed from the **clean current repository**,
not taken from candidate records: full Git HEAD/tree, SHA256 of Cargo.lock, Cargo
package version. `--expected-revision` is an external full 40-hex expectation and
must equal that observed HEAD. Use the selected candidate commit, never a branch
name or fixture's own revision. The example's invented hashes/compiler facts
must be replaced by your independent expectations for a real candidate. Artifact
filename/role/version agreement alone is insufficient.

## Complete one-target example

```json
{
  "state": "smoked_candidate",
  "source": {
    "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "tree": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "lock_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "version": "3.0.0"
  },
  "host": {
    "system": "Linux", "machine": "x86_64", "runner": "ubuntu-24.04",
    "target": "x86_64-unknown-linux-gnu", "translation": false,
    "image": {"ImageOS": "ubuntu24", "ImageVersion": "20261030.1"},
    "rust": {
      "binary": "rustc", "release": "1.94.0",
      "commit-hash": "dddddddddddddddddddddddddddddddddddddddd",
      "commit-date": "2026-03-01", "host": "x86_64-unknown-linux-gnu",
      "LLVM version": "21.1.8"
    }
  },
  "flags": ["+1.94.0","build","--locked","--release","--bins","--target","x86_64-unknown-linux-gnu"],
  "files": {
    "locksmith-linux-amd64": "REPLACE_WITH_ACTUAL_FILE_SHA256",
    "locksmithd-linux-amd64": "REPLACE_WITH_ACTUAL_FILE_SHA256"
  },
  "resources": {
    "entry_floor": 8589934592, "stop_floor": 2147483648,
    "growth_limit": 6442450944, "timeout_seconds": 1800,
    "entry_free": 10737418240, "initial_target_bytes": 0,
    "peak_target_growth": 1024, "minimum_free": 9663676416,
    "process": {"joined": true, "exit": 0, "forced": false}
  },
  "smoke": {
    "startup": true, "live_version": true, "status": true, "operator_status": true,
    "cleanup": {"joined": true, "exit": 0, "forced": false}
  }
}
```

All resource quantities and exit are exact JSON integers, never booleans/floats.
All success/cleanup/translation flags are exact JSON booleans; null/UNKNOWN does
not qualify. Source is identical across jobs. Host values must match the target
mapping; Rust fields are exactly the six displayed strings with release 1.94.0 and
matching host. Image OS/version are nonempty 1–128 ASCII letters/digits/dot/hyphen/
underscore. Darwin flags append `--config`, `profile.release.build-override.strip="none"`.
Successful build resources satisfy the fixed entry/stop/growth limits above; a
forced or unjoined process cannot qualify even if its parent exited zero.

For invented **nonexecuted** architecture controls, Linux files have 64-bit
a complete 64-byte fixed header with little-endian ELF magic/class/data, e_machine 62 for x86_64 or 183 for aarch64.
Darwin files have a complete 32-byte fixed header with little-endian 64-bit Mach-O magic 0xfeedfacf and cputype 0x01000007
for x86_64 or 0x0100000c for arm64. Truncated/universal/wrong headers refuse.
Header fixtures do not prove executable behavior: real smoke additionally runs
both files and checks independently expected clean build identity.

## Outputs and failure evidence

Exit 0 aggregate stdout is an object with `state:complete_native_candidate`,
observed `source`, exact four-string `targets` array, eight-name `files` hash map,
full per-target `provenance` map and a scope string. The fresh output directory
contains the eight unchanged files, SHA256SUMS and identical validation.json.
The per-target native artifacts remain separate build/smoke evidence.

`--job-result` accepts success/failure/cancelled/skipped; only actual success can
qualify. Other results fail even when files look complete. A fixture's supplied
success is an invented input, not an observed CI result. The workflow supplies
GitHub's actual combined native-job result. Per-target status does not waive the
required complete filesystem set or source/architecture/smoke checks.

Refusal exits 1 and emits closed `state:failed`, `stage:aggregate` and static
`error`; a failure-aggregate.json receipt is written when possible. Partial output
is never complete; workflow uploads only closed incomplete metadata on failure.
A failed native smoke keeps its static stage and actual cleanup facts separately,
never rewrites failure into success. No retry, upload, tag or publication is
performed by the local checker. See the [execution boundary](native-validation.md).
