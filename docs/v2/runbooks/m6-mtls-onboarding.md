# M6 — mTLS Onboarding Runbook

**Audience:** operators bringing up an mTLS-authenticated Locksmith fleet for the first time.

**Covers:** CA setup, agent + operator cert provisioning, daemon config, the bootstrap-only listener for onboarding agents that don't yet have certs.

Pair with `docs/v2/runbooks/m6-mtls-migration.md` if you're moving an existing bearer-only fleet to mTLS, and `docs/v2/runbooks/m6-mtls-revocation.md` for incident response.

---

## 1. Decide your CA story

Two production-grade options:

- **smallstep / step-ca** — recommended for new deployments. Has built-in CRL distribution and a clean ACME-style provisioner story. See `dist/examples/smallstep/`.
- **Existing internal CA** — works as long as the CA bundle is PEM-encoded and the agents present client certs that chain back. CRL distribution is your problem.

Do NOT use a public CA for client certs. The trust boundary is "anything the configured CA bundle attests to is a valid agent identity"; a public CA attests to far too much.

---

## 2. Provision the agent CA bundle

Drop the PEM CA bundle at a path readable by the locksmith user:

```bash
sudo install -m 0644 -o locksmith -g locksmith \
    agents-ca.crt /etc/locksmith/agents-ca.crt
```

Reference it from the daemon config:

```yaml
listen:
  auth_mode: mtls           # or `both` during migration
  mtls:
    ca_bundle_path: "/etc/locksmith/agents-ca.crt"
    crl_url: "https://step-ca.example.com/crl"
    crl_refresh_interval_seconds: 600
    blocklist_path: "/etc/locksmith/blocklist"
```

Restart the daemon after editing — `mtls.ca_bundle_path` is listener-shape config (R-N5).

---

## 3. Provision agent certs

For each agent host, mint a leaf cert from the agent CA. The CN (or SAN) becomes the cert_identity Locksmith will look up.

```bash
step ca certificate "agent-7" cert.pem key.pem \
    --provisioner agent-onboarding \
    --not-after 168h
```

Place the cert + key on the agent host with mode 0600 owned by whatever user makes outbound requests to Locksmith.

---

## 4. Onboard the agent

Per D-10, registering an agent doesn't require operator credentials — only a bootstrap token. The bootstrap-only listener (T6.8) is the right surface for this:

```bash
# Operator-side: mint a single-use bootstrap token.
TOKEN=$(locksmith bootstrap mint --single-use --format json | jq -r .token)

# Agent-side: register without any other credentials.
curl -X POST https://locksmith.example.com:9202/admin/agent/register \
    --cacert /etc/locksmith/agents-ca.crt \
    -H 'content-type: application/json' \
    -d "$(jq -n --arg t "$TOKEN" '{bootstrap_token: $t, name: "agent-7"}')"
```

Then bind the cert_identity to the new agent (#79):

```bash
locksmith agent set-cert-identity <public_id> agent-7
```

Inspect the binding via `locksmith agent get <public_id>` — the response carries the `cert_identity` field. To clear a binding (rotation, decommission, or operator error), pass `--clear`:

```bash
locksmith agent set-cert-identity <public_id> --clear
```

---

## 5. Onboard the operator (T6.7)

Operators with cert-identity access skip the bearer-token rotation cadence. Issue them a leaf cert:

```bash
step ca certificate "alice@example.com" alice.crt alice.key \
    --provisioner operator-onboarding
```

Add `cert_identity` to their entry in `operators.yaml`:

```yaml
operators:
  - name: alice
    public_id: "lkop_..."
    token_hash: "$argon2id$..."
    cert_identity: "alice@example.com"
```

The bearer path stays available — operators can use either; both resolve to the same `OperatorIdentity`.

---

## 6. Verify

```bash
# Agent-side, with cert in CWD:
curl --cacert /etc/locksmith/agents-ca.crt \
     --cert ./cert.pem --key ./key.pem \
     https://locksmith.example.com:9200/api/openai/v1/models

# Should succeed. Then check the audit row:
locksmith audit query --event proxy_request --limit 1 --format json | jq
# auth_method: "mtls"  (after listener wiring lands; see §8 below)
```

---

## 7. The bootstrap-only listener

The `listen.bootstrap_only` block (T6.8) accepts ONLY `POST /admin/agent/register`. Operators of mtls-only deployments use it for agent onboarding.

```yaml
listen:
  bootstrap_only:
    enabled: true
    host: "0.0.0.0"
    port: 9202
    cert_path: "/etc/locksmith/tls/bootstrap.crt"
    key_path: "/etc/locksmith/tls/bootstrap.key"
```

Network policy locks down reach. Tailscale-only access is a common pattern.

---

## 8. v0.7.0 scope note

The cert-validation infrastructure (validator, CRL, blocklist, authenticator, audit threading) is fully landed and tested. The agent listener bind path that requires client certs at TLS handshake is the one piece deferred to v0.7.x — full client-cert acceptance through axum-server's `RustlsConfig` requires custom `ClientCertVerifier` + peer-cert injection into request extensions. Until that lands:

- `MtlsAuthenticator::authenticate_cert` is callable in-process.
- The bootstrap-only listener IS bound and functional (no client-cert acceptance needed).
- `auth_mode` config parses and is observable via `state.config.load().listen.auth_mode`.
- Tests cover the validator + authenticator + audit flows end-to-end.

The wiring step is "plumb the rustls peer cert through to a middleware that calls MtlsAuthenticator." Tracked as a v0.7.x follow-up.

---

*Continue to `m6-mtls-migration.md` if you're rolling this out to an existing bearer fleet, or `m6-mtls-revocation.md` for incident response.*
