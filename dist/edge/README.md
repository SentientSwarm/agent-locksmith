# Edge packaging (systemd units in Incus system containers)

Tools that turn a private **site file** into the definitions for running
Locksmith and its optional companions (Pipelock, a classifier sidecar) as
hardened systemd services, one Incus system container per instance. The
operator guide is
[docs/user/operator/edge-packaging.md](../../docs/user/operator/edge-packaging.md).

Everything here is standard-library Python 3.11+ and generic. Hosts,
addresses, CIDRs and commands belong in your site file, kept in your own
private repository, never here.

| File | Does |
|---|---|
| `site.example.toml` | Example site file with placeholder names and addresses. |
| `sitefile.py` | Loads and validates a site file; unknown keys, duplicate names, unsafe paths, bad CIDRs and control characters are errors. |
| `incus.py` | Prints a bash script that creates one stopped container and one state volume per instance. Runs nothing. |
| `render.py` | Writes one instance's units, sysusers, ingress nft table, `components.json` and root guard into a new directory. Activates nothing. |
| `state_check.py` | The root guard each unit runs before start (installed as `/usr/local/sbin/locksmith-edge-state-check`). |
| `install_model.py`, `models.toml` | Installs a pinned classifier model into an offline Hugging Face cache, under your own HF token for gated models. |

None of these tools starts a container or a service, creates a custody
receipt or handles a Locksmith credential.

## Tests

```bash
python3 -m unittest discover -s dist/edge/tests
```

CI runs them in the `test` job.
