# Reference inspection sidecar

`locksmith_inspector.py` runs ML classifiers for Locksmith's content
inspection (AGENT-254) behind a Unix socket:

- **PromptGuard 2** flags prompt injection and jailbreak text (rule
  `promptguard`, score at least `--threshold`, default 0.5).
- **CodeShield** flags insecure code in responses that contain a code fence
  (rule `codeshield`).

Both run through [LlamaFirewall](https://github.com/meta-llama/PurpleLlama).
This is a reference implementation: any process that speaks the wire
protocol below works.

## Model licence

The model weights are **not** shipped with Locksmith. PromptGuard 2 is
released under the Llama 4 Community License. Before installing, the
operator must read and accept that licence on Hugging Face
(`meta-llama/Llama-Prompt-Guard-2-86M`) and download the weights under their
own account. If you distribute a product that includes them, the licence
requires you to display "Built with Llama".

## Install

```bash
sudo install -d -o locksmith -g locksmith /opt/locksmith-inspector
sudo -u locksmith python3 -m venv /opt/locksmith-inspector/venv
sudo -u locksmith /opt/locksmith-inspector/venv/bin/pip install llamafirewall
sudo -u locksmith /opt/locksmith-inspector/venv/bin/llamafirewall configure  # downloads the weights after you accept the licence
sudo install -o locksmith -m 0644 locksmith_inspector.py /opt/locksmith-inspector/
sudo install -m 0644 locksmith-inspector.service /etc/systemd/system/
sudo systemctl enable --now locksmith-inspector
```

The unit runs with `PrivateNetwork=yes` and `HF_HUB_OFFLINE=1`, so the
weights must already be in the `locksmith` user's Hugging Face cache
(`llamafirewall configure` above puts them there). It starts before
`locksmith.service`, but model loading can outlast Locksmith's startup:
scans in that window fail to connect and follow `on_error`.

Run the sidecar as the **same user as `locksmithd`**. Text sent for
scanning may contain secrets, so Locksmith checks the uid of the process
serving the socket and refuses any other.

Sharing that uid puts the sidecar inside Locksmith's trust boundary.
Install `locksmithd` root-owned and execute-only:

```bash
sudo install -o root -g root -m 0711 locksmithd /usr/local/bin/
```

The kernel then makes the daemon non-dumpable from the moment it starts,
so the sidecar can't read its environment (the sealing keys) or memory.
A compromised sidecar can still stop `locksmithd`, and it sees every text
sent for scanning; treat it as having every secret the service account
can reach (AGENT-288).

## Configure Locksmith

```yaml
inspection:
  sidecars:
    - name: promptguard
      socket: /run/locksmith-inspector/inspector.sock
      timeout_ms: 1000
  routes:
    - route: web-search
      response:
        scanners: [injection, "sidecar:promptguard"]
```

A policy whose only scanners are `injection` or sidecars defaults to
`flag`. Set `on_hit` to act on a hit. A sidecar that can't be reached,
answers with an error or misses `timeout_ms` is a scanner error, and the
route's `on_error` decides what happens. Sidecars do not run on streamed
(SSE) responses, so a streamed reply is a scanner error too.

A classifier scores whole texts, and the raw body is one of the texts
Locksmith sends it, so a sidecar hit can't be cut out of a JSON body:
under `on_hit: redact` it blocks the body, and the audit row carries
`redaction_incomplete: true`. Use `flag` or `block` with sidecars.

Setting `on_hit: redact` or `block` also makes `on_error` default to
`fail_closed`. The route then refuses replies while the sidecar is down,
and refuses every SSE reply. Use the sidecar on routes that don't stream,
or set `on_error: fail_open` to forward what the sidecar can't judge
(which also forwards compressed and oversized replies unscanned).

## Wire protocol

Each scan is one HTTP/1.1 request on its own connection:

```
POST /scan
{"direction": "request" | "response", "text": "..."}

200 {"hits": [{"rule": "promptguard", "start": 0, "end": 42, "score": 0.97}]}
```

`start` and `end` are UTF-8 byte offsets into `text`. Any status other
than 200, or a hit outside the text, is an error.

## Smoke test

`./smoke.sh` starts the sidecar on a temporary socket and scans one
injection and one clean text. It needs llamafirewall and the weights
installed, it is not part of `cargo test`, and it prints the time the two
scans took.
