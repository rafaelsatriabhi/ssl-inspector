"""Offline tests: we build our own CA and run a local TLS server, so no internet needed."""

import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.inspector import InspectionError, inspect, parse_target
from app.main import app

NOW = dt.datetime.now(dt.timezone.utc)


# --- helpers ---------------------------------------------------------------


def make_cert(cn, issuer_cert=None, issuer_key=None, *, ca=False, days=90, start=None, key=None, sans=("localhost",)):
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = start or NOW - dt.timedelta(days=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def pki(tmp_path):
    root, root_key = make_cert("Test Root CA", ca=True, days=3650, sans=())
    inter, inter_key = make_cert("Test Intermediate CA", root, root_key, ca=True, days=1825, sans=())
    return tmp_path, (root, root_key), (inter, inter_key)


def serve(tmp_path, chain, key):
    """Start a one-shot-per-connection TLS server on a random port; returns the port."""
    certfile = tmp_path / "server.pem"
    certfile.write_bytes(b"".join(pem(c) for c in chain))
    keyfile = tmp_path / "server.key"
    keyfile.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.set_ciphers("ALL:@SECLEVEL=0")  # let us serve deliberately weak keys
    ctx.load_cert_chain(certfile, keyfile)

    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def loop():
        while True:
            conn, _ = listener.accept()
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass  # client rejected us on purpose during verification

    threading.Thread(target=loop, daemon=True).start()
    return port


@pytest.fixture(autouse=True)
def allow_localhost(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")


# --- parse_target -------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", ("example.com", 443)),
        ("  Example.com:8443 ", ("example.com", 8443)),
        ("https://example.com/some/path?q=1", ("example.com", 443)),
        ("https://[::1]:9443", ("::1", 9443)),
    ],
)
def test_parse_target(raw, expected):
    assert parse_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "https://", "example.com:notaport"])
def test_parse_target_rejects_garbage(raw):
    with pytest.raises(ValueError):
        parse_target(raw)


# --- full inspections against the local server --------------------------------


def test_trusted_chain_gets_a_good_grade(pki):
    tmp_path, (root, _), (inter, inter_key) = pki
    leaf, leaf_key = make_cert("localhost", inter, inter_key)
    port = serve(tmp_path, [leaf, inter], leaf_key)
    cafile = tmp_path / "root.pem"
    cafile.write_bytes(pem(root))

    report = inspect("localhost", port, cafile=str(cafile))

    assert report.trusted, report.verify_error
    assert [c.role for c in report.chain] == ["leaf", "intermediate"]
    assert report.chain[0].common_name == "localhost"
    assert report.chain[0].sans == ["localhost"]
    assert report.chain[0].key_type == "EC (secp256r1)"
    assert report.chain[1].is_ca
    assert report.tls_version == "TLSv1.3"
    assert report.grade == "A+", report.findings


def test_untrusted_chain_is_an_f(pki):
    tmp_path, _, (inter, inter_key) = pki
    leaf, leaf_key = make_cert("localhost", inter, inter_key)
    port = serve(tmp_path, [leaf, inter], leaf_key)

    report = inspect("localhost", port)  # system CA store doesn't know our root

    assert not report.trusted
    assert report.grade == "F"
    assert report.findings[0].severity == "critical"


def test_hostname_mismatch_is_detected(pki):
    tmp_path, (root, _), (inter, inter_key) = pki
    leaf, leaf_key = make_cert("other.example", inter, inter_key, sans=("other.example",))
    port = serve(tmp_path, [leaf, inter], leaf_key)
    cafile = tmp_path / "root.pem"
    cafile.write_bytes(pem(root))

    report = inspect("localhost", port, cafile=str(cafile))

    assert not report.trusted
    assert "mismatch" in report.verify_error.lower()


def test_expiring_soon_and_weak_key(pki):
    tmp_path, (root, _), (inter, inter_key) = pki
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    leaf, leaf_key = make_cert("localhost", inter, inter_key, key=weak, days=10)
    port = serve(tmp_path, [leaf, inter, root], leaf_key)
    cafile = tmp_path / "root.pem"
    cafile.write_bytes(pem(root))

    report = inspect("localhost", port, cafile=str(cafile))

    messages = " | ".join(f.message for f in report.findings)
    assert report.grade == "F"
    assert "1024-bit RSA" in messages
    assert "expires in" in messages
    assert "sends the root certificate" in messages
    assert report.chain[2].role == "root"


def test_private_targets_blocked_by_default(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS")
    with pytest.raises(InspectionError, match="non-public"):
        inspect("127.0.0.1", 443)


# --- HTTP API ------------------------------------------------------------------


def test_api_errors():
    client = TestClient(app)
    assert client.get("/api/inspect", params={"target": ""}).status_code == 400
    r = client.get("/api/inspect", params={"target": "127.0.0.1:1"})
    assert r.status_code == 502
    assert "refused" in r.json()["detail"].lower()


# --- grading rules ----------------------------------------------------------------


def _report(**overrides):
    from app.inspector import describe_cert
    from app.models import InspectionReport

    leaf, _ = make_cert("example.com", sans=("example.com",))
    fields = dict(
        host="example.com", port=443, ip="93.184.216.34", tls_version="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256", cipher_bits=128, trusted=True, verify_error=None,
        chain=[describe_cert(leaf, "leaf")],
    )
    return InspectionReport(**(fields | overrides))


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({}, "A+"),
        ({"tls_version": "TLSv1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256"}, "A"),
        ({"tls_version": "TLSv1.2", "cipher": "AES256-GCM-SHA384"}, "B"),  # no forward secrecy
        ({"tls_version": "TLSv1", "cipher": "ECDHE-RSA-AES256-SHA"}, "C"),
        ({"trusted": False, "verify_error": "self-signed certificate"}, "F"),
    ],
)
def test_grade_caps(overrides, expected):
    from app.grading import grade

    _, result, findings = grade(_report(**overrides))
    assert result == expected, findings
