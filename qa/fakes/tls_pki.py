"""TLS helpers for the TLS smoke area: per-target PKI files, client contexts, audit reads.

Certificates come from fakes.pki; this module adds identity-only leaves (no
subject CN) so SAN DNS and SAN URI identity mapping can be reached, writes
PEM files into a target's work directory, and wraps HTTPS calls so a TLS
handshake refusal is recorded as evidence instead of raising.
"""

from __future__ import annotations

import datetime as dt
import ssl
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from fakes.pki import CA, DAY, Issued
from harness.target import SECRET_KEYS


def nameless_client(
    ca: CA, dns: tuple[str, ...] = (), uris: tuple[str, ...] = ()
) -> Issued:
    """A client leaf with an empty subject, so identity comes from the SAN."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    sans: list[x509.GeneralName] = [x509.DNSName(d) for d in dns]
    sans += [x509.UniformResourceIdentifier(u) for u in uris]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - DAY)
        .not_valid_after(now + 30 * DAY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(sans), critical=True)
        .sign(ca.key, hashes.SHA256())
    )
    return Issued(cert=cert, key=key)


def write_pem(work: Path, name: str, data: bytes) -> Path:
    """Write a PEM into a work directory before the daemon starts (overlay time)."""
    path = work / "tls" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def server_files(work: Path, ca: CA, server: Issued, prefix: str) -> dict[str, str]:
    """Write the CA bundle and a server cert/key; return their paths."""
    return {
        "ca": str(write_pem(work, f"{prefix}-ca.pem", ca.cert_pem())),
        "cert": str(write_pem(work, f"{prefix}-server.crt", server.cert_pem())),
        "key": str(write_pem(work, f"{prefix}-server.key", server.key_pem())),
    }


def client_context(
    target, ca_path: str, client: Issued | None = None, name: str = "client"
):
    """An SSL context trusting ca_path and, when given, presenting `client`."""
    ctx = ssl.create_default_context(cafile=ca_path)
    if client is not None:
        cert = target.write_file(f"tls/{name}.crt", client.cert_pem())
        key = target.write_file(f"tls/{name}.key", client.key_pem())
        ctx.load_cert_chain(str(cert), str(key))
    return ctx


def _register_secrets(target, value) -> None:
    """Register secret-named response fields as canaries before anything is recorded.

    target.http() records the response body without harvesting it (target.cli()
    does harvest), so a bootstrap register response would leak the agent token.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if key in SECRET_KEYS and isinstance(item, str):
                target.canaries.add(item, f"https-{key}")
            else:
                _register_secrets(target, item)
    elif isinstance(value, list):
        for item in value:
            _register_secrets(target, item)


def https(target, method: str, path: str, port: int, ctx, token=None, **kwargs):
    """target.http over TLS; returns (HttpResult, None) or (None, refusal text)."""
    base = f"https://127.0.0.1:{port}"
    try:
        result = target.http(
            method,
            path,
            base=base,
            context=ctx,
            timeout=10,
            token=token,
            record=False,
            **kwargs,
        )
    except (OSError, ssl.SSLError) as err:
        text = f"{type(err).__name__}: {getattr(err, 'reason', err)}"
        target.bundle.transcript(
            target.current_case,
            "tls",
            f"{method} {path} on :{port}\n--- refused at TLS\n{text}",
        )
        return None, text
    _register_secrets(target, result.json)
    auth = " (bearer)" if token is not None else ""
    target.bundle.transcript(
        target.current_case,
        "http",
        f"{method} {base}{path}{auth}\n--- {result.status}\n{result.text[:4000]}",
    )
    return result, None


def serial_hex(issued: Issued) -> str:
    """Lowercase, whole-byte hex, as `openssl x509 -noout -serial` prints it (lowercased)."""
    text = format(issued.serial, "x")
    return text if len(text) % 2 == 0 else "0" + text


def mtls_failures(target, since_ms: int) -> list[dict]:
    """Security-class mTLS refusal rows written since since_ms (via `locksmith audit query`)."""
    rows = target.cli(
        "audit",
        "query",
        "--event-class",
        "security",
        "--since-ms",
        str(since_ms),
        "--limit",
        "200",
    )
    assert rows.code == 0, rows.err
    return [r for r in (rows.json or []) if str(r.get("event", "")).startswith("mtls_")]


def wait_for(predicate, timeout: float, step: float = 0.25):
    """Poll predicate until it returns a truthy value or timeout; return the last value."""
    deadline = time.monotonic() + timeout
    value = predicate()
    while not value and time.monotonic() < deadline:
        time.sleep(step)
        value = predicate()
    return value


def now_ms() -> int:
    return int(time.time() * 1000)


def enrol(target, name: str, account: str, identity: str | None = None) -> dict:
    """Register an agent granted `accounts`, select `account`, optionally bind a cert identity."""
    reg = target.cli("agent", "register", "--name", name, "--allowlist", "accounts")
    assert reg.code == 0, reg.err
    agent = {"id": reg.json["public_id"], "token": reg.json["token"], "name": name}
    bind = target.cli(
        "agent",
        "set-credential",
        agent["id"],
        "accounts",
        "--auth",
        f"bearer={account}",
    )
    assert bind.code == 0, bind.err
    if identity is not None:
        cert = target.cli("agent", "set-cert-identity", agent["id"], identity)
        assert cert.code == 0, cert.err
    return agent


def accounts_tool(target) -> None:
    put = target.cli(
        "tool",
        "put",
        "accounts",
        "--upstream",
        target.upstream_url,
        "--auth",
        "bearer=SMOKE_X",
        "--egress",
        "direct",
    )
    assert put.code == 0, put.err
