# Worked example — sealed secrets via systemd-creds (T5.5)

End-to-end recipe for an Agent Locksmith deployment where **no upstream
credential ever lives in operator-readable config**. systemd-creds owns
the encryption; Locksmith just reads the decrypted file at startup.

This is the recommended production shape on systemd hosts.

---

## Prerequisites

- systemd ≥ 250 (for `LoadCredentialEncrypted=` and `systemd-creds`)
- Linux host with TPM2 (recommended; without TPM2, systemd falls back to
  the host-bound master key at `/var/lib/systemd/credential.secret`)
- A `locksmith` system user + group (created by your packaging or
  `useradd -r -s /usr/sbin/nologin locksmith`)

## File layout this example assumes

```
/usr/local/bin/locksmithd                  # daemon binary
/etc/systemd/system/locksmith.service      # unit (from this example)
/etc/locksmith/config.yaml                 # daemon config (from this example)
/etc/locksmith/credentials/openai.enc      # encrypted blob (sealed via systemd-creds)
/etc/locksmith/operators.yaml              # operator credential hashes (M2)
/var/lib/locksmith/locksmith.db            # SQLite DB (locksmith-owned, 0600)
/var/log/locksmith/audit.jsonl             # JSONL audit mirror (M3)
/run/locksmith/admin.sock                  # admin UDS (M2)
/run/credentials/locksmith/openai_token    # systemd drops decrypted creds here at start
```

---

## 1. Seal the credential

```bash
# As root (systemd-creds writes to root-owned paths):
sudo bash dist/examples/sealed-secrets/seal-credential.sh \
    openai_token \
    /etc/locksmith/credentials/openai.enc
```

The script prompts for the credential plaintext, encrypts it with
`systemd-creds encrypt --name=openai_token`, and writes the result to
the destination path. The plaintext is never stored on disk.

`--name=openai_token` binds the blob to that exact credential name —
systemd refuses to load it under any other name, blunting a
mis-binding attack.

## 2. Install the unit

```bash
sudo install -m 0644 dist/examples/sealed-secrets/locksmith.service \
    /etc/systemd/system/locksmith.service
sudo systemctl daemon-reload
```

## 3. Install the config

```bash
sudo install -m 0644 -o locksmith -g locksmith \
    dist/examples/sealed-secrets/config.yaml \
    /etc/locksmith/config.yaml
```

Note `from_file_sealed: { path: "/run/credentials/locksmith/openai_token" }` —
this is the path systemd will create at service start, **not** the
encrypted blob's path.

## 4. Start the daemon

```bash
sudo systemctl enable --now locksmith
```

Verify the daemon is up and the credential resolved:

```bash
journalctl -u locksmith --since "1 min ago" | grep file-sealed
# Expect: "file-sealed credential resolved" with the path

curl -s http://127.0.0.1:9200/tools | jq
# Expect: the openai tool appears
```

If the openai tool does not appear in `/tools`, the credential failed
to resolve — degraded mode (per INF-4 / Q-17). Check `journalctl` for
warnings naming the path.

## 5. Rotate the credential

```bash
# Re-seal with the new value:
sudo bash dist/examples/sealed-secrets/seal-credential.sh \
    openai_token \
    /etc/locksmith/credentials/openai.enc

# Restart so Locksmith re-resolves at startup:
sudo systemctl restart locksmith
```

In-flight requests drain within `shutdown.drain_window_seconds`
(default 30s).

## 6. Verify the threat boundary

As an *unprivileged* user on the host:

```bash
cat /run/credentials/locksmith/openai_token
# → permission denied (mode 0400, owned by locksmith)

cat /etc/locksmith/credentials/openai.enc
# → reads bytes, but the file is encrypted: useless without the host's
#   TPM (or the systemd master key)
```

This satisfies the M5 acceptance bullet: **no operator can read the
upstream credential plaintext without sudo.**

---

## Troubleshooting

| Symptom | Diagnosis |
|---------|-----------|
| Tool absent from `/tools` after `systemctl restart` | `journalctl -u locksmith` will show "tool credential failed to resolve". Common: blob name mismatch between `--name=` (encrypt) and `LoadCredentialEncrypted=` (unit). |
| `file mode 0644 permits group or world read` | Locksmith refuses to read insecurely-permissioned credential files. systemd-creds normally drops them as 0400; if you wrote one manually, fix with `chmod 0600`. |
| `file-sealed credential resolved` not in logs | The tool may not declare `auth.value: from_file_sealed:` — check the config block. |
| Locksmith starts but TPM unavailable | systemd-creds falls back to `/var/lib/systemd/credential.secret`. That file is host-bound but not TPM-bound; restoring a backup of it on another machine breaks the binding by design. |

See `docs/v2/runbooks/m5-sealed-secrets.md` for the full operational guide.

See `docs/v2/threat-model.md` for what this protects against and what
it does not.
