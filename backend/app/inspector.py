"""Connect to a TLS server and describe its certificate chain and connection."""

import datetime as dt
import ipaddress
import os
import socket
import ssl
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app.grading import grade
from app.models import CertInfo, InspectionReport

DEFAULT_TIMEOUT = 8.0


class InspectionError(Exception):
    """A problem worth showing to the user, e.g. DNS failure or refused connection."""


def parse_target(raw: str) -> tuple[str, int]:
    """Accept 'example.com', 'example.com:8443' or 'https://example.com/path'."""
    raw = raw.strip()
    if not raw:
        raise ValueError("Target is empty")
    if "://" not in raw:
        raw = "//" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port or 443
    except ValueError as e:
        raise ValueError(f"Invalid target: {e}") from None
    if not parts.hostname:
        raise ValueError("Could not find a hostname in the target")
    return parts.hostname, port


def _resolve(host: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise InspectionError(f"Could not resolve {host}") from None
    ip = infos[0][4][0]
    # This server will connect wherever the user asks, so by default refuse
    # internal addresses (a classic SSRF hole). Set ALLOW_PRIVATE_TARGETS=1
    # to inspect services on your own network.
    if os.environ.get("ALLOW_PRIVATE_TARGETS") != "1":
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            raise InspectionError(f"{host} resolves to non-public address {ip}")
    return ip


def _permissive_context(cafile: str | None = None) -> ssl.SSLContext:
    """Default context that still talks to obsolete servers: an inspector
    has to connect to bad configurations in order to report them."""
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    return ctx


def _handshake(ip: str, host: str, port: int, context: ssl.SSLContext, timeout: float) -> ssl.SSLSocket:
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        return context.wrap_socket(sock, server_hostname=host)
    except BaseException:
        sock.close()
        raise


def _peer_chain_der(tls: ssl.SSLSocket) -> list[bytes]:
    """The chain exactly as the server sent it, leaf first."""
    if hasattr(tls, "get_unverified_chain"):  # Python 3.13+
        return [bytes(c) for c in tls.get_unverified_chain()]
    try:  # Python 3.10-3.12 has the same feature as a private method
        import _ssl

        return [c.public_bytes(_ssl.ENCODING_DER) for c in tls._sslobj.get_unverified_chain()]
    except AttributeError:
        return [tls.getpeercert(binary_form=True)]


def _cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _key_info(cert: x509.Certificate) -> tuple[str, int | None]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC ({key.curve.name})", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    return type(key).__name__, None


def describe_cert(cert: x509.Certificate, role: str, now: dt.datetime | None = None) -> CertInfo:
    now = now or dt.datetime.now(dt.timezone.utc)

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = [str(n) for n in san_ext.get_values_for_type(x509.DNSName)]
        sans += [str(n) for n in san_ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []

    try:
        is_ca = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        is_ca = False

    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # unsupported/legacy algorithms
        sig_hash = None

    key_type, key_size = _key_info(cert)
    return CertInfo(
        role=role,
        subject=cert.subject.rfc4514_string(),
        common_name=_cn(cert.subject),
        issuer=cert.issuer.rfc4514_string(),
        issuer_common_name=_cn(cert.issuer),
        serial_number=format(cert.serial_number, "X"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        days_remaining=(cert.not_valid_after_utc - now).days,
        signature_algorithm=getattr(cert.signature_algorithm_oid, "_name", cert.signature_algorithm_oid.dotted_string),
        signature_hash=sig_hash,
        key_type=key_type,
        key_size=key_size,
        sans=sans,
        is_ca=is_ca,
        self_signed=cert.issuer == cert.subject,
        sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    )


def _roles(certs: list[x509.Certificate]) -> list[str]:
    roles = []
    for i, cert in enumerate(certs):
        if i == 0:
            roles.append("leaf")
        elif cert.issuer == cert.subject:
            roles.append("root")
        else:
            roles.append("intermediate")
    return roles


def inspect(
    host: str,
    port: int = 443,
    timeout: float = DEFAULT_TIMEOUT,
    cafile: str | None = None,
) -> InspectionReport:
    ip = _resolve(host, port)

    # Pass 1: accept any certificate so we can show broken setups too.
    loose = _permissive_context()
    loose.check_hostname = False
    loose.verify_mode = ssl.CERT_NONE
    try:
        with _handshake(ip, host, port, loose, timeout) as tls:
            tls_version = tls.version()
            cipher_name, _, cipher_bits = tls.cipher() or (None, None, None)
            chain_der = _peer_chain_der(tls)
    except (TimeoutError, socket.timeout):
        raise InspectionError(f"Timed out connecting to {host}:{port}") from None
    except ConnectionRefusedError:
        raise InspectionError(f"Connection refused by {host}:{port}") from None
    except ssl.SSLError as e:
        hint = ""
        if e.reason and "HANDSHAKE_FAILURE" in e.reason:
            hint = " (the server may only offer ciphers too old for this OpenSSL build, e.g. RC4 or 3DES)"
        raise InspectionError(f"TLS handshake failed: {e.reason or e}{hint}") from None
    except OSError as e:
        raise InspectionError(f"Could not connect to {host}:{port}: {e.strerror or e}") from None

    # Pass 2: verify the chain and hostname. Protocol and key strength are
    # graded separately, so only the certificate check decides "trusted".
    strict = _permissive_context(cafile)
    trusted, verify_error = True, None
    try:
        with _handshake(ip, host, port, strict, timeout):
            pass
    except ssl.SSLCertVerificationError as e:
        trusted, verify_error = False, e.verify_message or str(e)
    except (ssl.SSLError, OSError) as e:
        trusted, verify_error = False, str(e)

    certs = [x509.load_der_x509_certificate(der) for der in chain_der]
    chain = [describe_cert(c, role) for c, role in zip(certs, _roles(certs))]

    report = InspectionReport(
        host=host,
        port=port,
        ip=ip,
        tls_version=tls_version,
        cipher=cipher_name,
        cipher_bits=cipher_bits,
        trusted=trusted,
        verify_error=verify_error,
        chain=chain,
    )

    report.score, report.grade, report.findings = grade(report)
    return report
