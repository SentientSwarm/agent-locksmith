import socket
import ssl
import threading
from pathlib import Path

from cryptography import x509

from fakes.pki import CA


def test_server_and_client_certs_complete_a_mutual_tls_handshake(tmp_path: Path):
    ca = CA.create()
    server, client = ca.server(), ca.client("qa-agent", dns=("qa-agent.local",))
    for name, data in {"ca.pem": ca.cert_pem(), "s.pem": server.cert_pem(), "s.key": server.key_pem(),
                       "c.pem": client.cert_pem(), "c.key": client.key_pem()}.items():
        (tmp_path / name).write_bytes(data)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(tmp_path / "s.pem", tmp_path / "s.key")
    sctx.load_verify_locations(tmp_path / "ca.pem")
    sctx.verify_mode = ssl.CERT_REQUIRED
    cctx = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))
    cctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "c.key")
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    seen = {}

    def serve():
        conn, _ = listener.accept()
        with sctx.wrap_socket(conn, server_side=True) as tls:
            seen["peer"] = tls.getpeercert()
            tls.recv(1)

    thread = threading.Thread(target=serve)
    thread.start()
    with socket.create_connection(("127.0.0.1", port)) as raw, cctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
        tls.send(b"x")
    thread.join(5)
    listener.close()
    assert dict(x[0] for x in seen["peer"]["subject"])["commonName"] == "qa-agent"


def test_crl_lists_revoked_serials_with_increasing_numbers():
    ca = CA.create()
    leaf = ca.client("qa-agent")
    first = x509.load_pem_x509_crl(ca.crl())
    second = x509.load_pem_x509_crl(ca.crl(revoked=(leaf.serial,)))
    assert first.is_signature_valid(ca.cert.public_key())
    assert second.get_revoked_certificate_by_serial_number(leaf.serial) is not None
    number = x509.CRLNumber
    assert second.extensions.get_extension_for_class(number).value.crl_number == 2
