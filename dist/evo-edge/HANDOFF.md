# Phase 5a teamclaude handoff

Codex has already moved. Coordinator report `wt_xhkj8w0hzeey` confirms 74
custody files verified, source empty/router disabled, edge `.12:43210` serving,
studio compatibility loaded, both VM tunnels repointed (herd `7e0595f`), and a
fresh VM Codex execution passed. PR #169 was merged as `a0213b3` by John.
Do not rerun the Codex mover, installer, inactive render, or preflight canary.
The corrected Codex mover is retained for review/history; its empty-destination
precondition deliberately prevents using it against the serving pool.

Teamclaude remains on studio until this ceremony. The detached worker lets
herd-ops start its own outage without relying on that Claude connection to
drive the remaining commands. The existing source launchd job, selected config
and installed 1.1.27 package are inspected privately by the worker. Destination
1.1.27 must already be installed at `/opt/teamclaude`; the worker checks source
code parity before draining. It never reinstalls a package or changes Codex.

Use the reviewed bundle directory and its `SHA256SUMS` from the handoff receipt.
From **studio-1**, fetch it through the existing swarm-herd SSH forward:

```sh
# Set bundle to the exact directory name in the handoff receipt.
: "${bundle:?Set bundle from the reviewed handoff receipt}"
mkdir -p "$HOME/.local/share/edge-phase5-handoff"
scp -P 2223 -r "evo-x2-1:/home/jxstanford/.local/share/edge-phase5-handoff/$bundle" \
  "$HOME/.local/share/edge-phase5-handoff/"
cd "$HOME/.local/share/edge-phase5-handoff/$bundle"
shasum -a 256 -c SHA256SUMS
```

Before starting, stop new Claude launches/requests on studio and both herd VMs;
the coordinator owns that freeze and subsequent VM tunnel repoints. Confirm the
config selection and any extra historical/alternate custody locations privately.
The worker scans selected-config siblings, both `teamclaude*`/`teamrouter*`
families in its directory and `~/.config`, including certificates, leaf/private
keys, state, quota, logs and backups. Pass any additional *files* with repeated
`--custody-path /absolute/path`; directories, symlinks, hard links and leftover
config locks refuse and require private reconciliation before another attempt.
`--inventory-complete` attests that those locations cover all source custody
and no other launcher can restart/refill it. It is not automatic discovery of
arbitrary credentials elsewhere in the filesystem.

Use a known working Claude Messages model. The worker tests it on source before
the outage. The default config below must match launchd's actual selection;
the worker refuses a mismatch. If the job does not start Node directly, add
`--node /absolute/path/to/node`. `--package /absolute/path/to/teamclaude` can
identify a nonstandard source installation. These paths contain no secrets.

```sh
: "${TEAMCLAUDE_CANARY_MODEL:?Set a known working Claude model name}"
python3 move-teamclaude.py --detach --canaries-approved --inventory-complete \
  --config /Users/jxstanford/.config/teamclaude.json \
  --model "$TEAMCLAUDE_CANARY_MODEL"
```

The launch returns immediately. Observe from any independent shell:

```sh
cat teamclaude-move-attempt/status
cat teamclaude-move-attempt/worker.log
```

Success is exactly
`LOCAL_SERVING_COMPAT_LOADED__AWAIT_COORDINATOR_ACCEPTANCE`. The worker:

1. Checks source/destination package parity, listener/inspection access, three
   stable account IDs, config selection, source canary and the existing certificate
   chain (coverage, key match and package's 30-day minimum validity).
2. Uses the supported `/teamclaude/drain` API and waits at most 120 seconds for
   zero requests. Disables the original launchd job, boots it out, and waits at
   most 30 seconds for registration disappearance. Already unloaded is accepted.
   The process/open-file/listener gate then must pass.
3. Moves each inventoried file with checksum verification and remove-source-files,
   checks source absence, re-scans supported locations and repeats the drain gate.
   Active config/state/certificates move into `/srv/edge-state/teamclaude`.
   Alternate/historical custody moves into root-only `teamclaude-history`, outside
   the service-writable tree. No intermediate host staging or source restart.
4. Verifies all moved hashes privately before rewriting only transport settings:
   loopback host, port 3456 and supported `proxy.trustLoopback=false` (required
   because socket-proxyd makes remote callers loopback). Existing keys, account
   IDs and routing settings remain. Disables package auto-update, fixes the
   destination config selector, issues the receipt and starts only teamclaude
   and its relay with the already-active container firewall.
5. Requires missing/bad-key 401s and completed Messages streams on both loopback
   and `.12:3456`, zero restarts and unchanged certificate identity. Explicitly
   enables then bootstraps `com.sentientswarm.edge-compat.teamclaude`, and requires
   the same auth/stream canaries through studio's real compatibility path.

The source worker has a 900-second work deadline. Each child runs in a separate
process group and is killed/reaped on timeout/cancellation. Cleanup is bounded
separately (allow up to another 13 minutes). Remote actions have a 300-second
alarm, serialize under a root-owned lock and use a revocation latch; late SSH
activation cannot restart a pool after successful cleanup. A remote activation
failure also stops/revokes/masks teamclaude itself. `edge-input` and Codex stay up.

For ordinary cancellation, send TERM to the PID in `teamclaude-move-attempt/pid`;
the handler runs cleanup. Do not use KILL during normal operation. A failed run
keeps the original source job disabled once drain has begun, attempts to unload
compatibility and stop/revoke/mask destination teamclaude, and records an explicit
unconfirmed-cleanup state if verification fails. **Never delete the attempt
directory or revocation latch to retry.** Inspect current custody privately and
write a separate recovery plan; never restore an old refreshed-token copy.
Preflight failure before drain leaves the running source alone.

Local success is the coordinator's signal to repoint **both** VM Claude tunnels
to `10.250.4.12:3456`, verify real authenticated streamed inference there and
through production Locksmith, verify quota/refresh behavior and denied agent-zone
access, then decide persistence. This script neither changes VM tunnels/zone
ACLs nor enables boot persistence. Phase 5b and studio's remaining proxy/scanner/
hub retirement are still outstanding.
