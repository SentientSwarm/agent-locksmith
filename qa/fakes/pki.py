"""Disposable test PKI: CAs, server and client certificates, and CRLs.

Everything is generated per run with ECDSA P-256 keys and written by the
caller into a target's work directory; nothing here is evidence.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DAY = dt.timedelta(days=1)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


@dataclass
class Issued:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def serial(self) -> int:
        return self.cert.serial_number

    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def key_pem(self) -> bytes:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())


@dataclass
class CA(Issued):
    name: str = "qa-ca"
    crl_number: int = field(default=0)

    @classmethod
    def create(cls, name: str = "qa-ca") -> CA:
        key = ec.generate_private_key(ec.SECP256R1())
        now = _now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(name)).issuer_name(_name(name))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - DAY).not_valid_after(now + 30 * DAY)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        return cls(cert=cert, key=key, name=name)

    def _leaf(self, cn: str, sans: list[x509.GeneralName], usage: x509.ObjectIdentifier,
              days: int = 30) -> Issued:
        key = ec.generate_private_key(ec.SECP256R1())
        now = _now()
        builder = (
            x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(self.cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - DAY).not_valid_after(now + days * DAY)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                           critical=False)
        )
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        return Issued(cert=builder.sign(self.key, hashes.SHA256()), key=key)

    def server(self, hosts: tuple[str, ...] = ("localhost", "127.0.0.1")) -> Issued:
        sans: list[x509.GeneralName] = []
        for host in hosts:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(host)))
            except ValueError:
                sans.append(x509.DNSName(host))
        return self._leaf(hosts[0], sans, ExtendedKeyUsageOID.SERVER_AUTH)

    def client(self, cn: str, dns: tuple[str, ...] = (), uris: tuple[str, ...] = ()) -> Issued:
        sans: list[x509.GeneralName] = [x509.DNSName(d) for d in dns]
        sans += [x509.UniformResourceIdentifier(u) for u in uris]
        return self._leaf(cn, sans, ExtendedKeyUsageOID.CLIENT_AUTH)

    def crl(self, revoked: tuple[int, ...] = (), next_update_days: int = 7) -> bytes:
        """A signed PEM CRL with a fresh, increasing CRL number."""
        self.crl_number += 1
        now = _now()
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.cert.subject)
            .last_update(now - dt.timedelta(minutes=1))
            .next_update(now + next_update_days * DAY)
            .add_extension(x509.CRLNumber(self.crl_number), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                           critical=False)
        )
        for serial in revoked:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
            )
        return builder.sign(self.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
