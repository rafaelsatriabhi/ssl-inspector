"""Turn an inspection into an A+..F grade, loosely modelled on SSL Labs.

Everything starts at 100 points. Problems either subtract points or put a
ceiling ("cap") on the grade, e.g. an expired certificate is always an F no
matter how good the rest of the setup is.
"""

import datetime as dt

from app.models import Finding, InspectionReport

GRADES = ["F", "D", "C", "B", "A", "A+"]  # worst to best

WEAK_HASHES = {"md5", "sha1"}
LEGACY_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
MAX_PUBLIC_VALIDITY_DAYS = 398  # browser limit for publicly trusted certs


def _score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    if score >= 35:
        return "D"
    return "F"


def grade(report: InspectionReport) -> tuple[int, str, list[Finding]]:
    findings: list[Finding] = []
    score = 100
    caps: list[str] = []

    def critical(msg: str, cap: str = "F") -> None:
        findings.append(Finding(severity="critical", message=msg))
        caps.append(cap)

    def warning(msg: str, points: int) -> None:
        nonlocal score
        findings.append(Finding(severity="warning", message=msg))
        score -= points

    def info(msg: str) -> None:
        findings.append(Finding(severity="info", message=msg))

    # --- trust ---------------------------------------------------------------
    if not report.trusted:
        critical(f"Certificate is not trusted: {report.verify_error}")

    # --- leaf certificate ---------------------------------------------------
    leaf = report.chain[0] if report.chain else None
    if leaf is None:
        critical("Server did not present a certificate")
    else:
        if leaf.days_remaining < 0:
            critical(f"Certificate expired {-leaf.days_remaining} days ago")
        elif leaf.days_remaining <= 14:
            warning(f"Certificate expires in {leaf.days_remaining} days", 20)
        elif leaf.days_remaining <= 30:
            warning(f"Certificate expires in {leaf.days_remaining} days", 10)

        if leaf.not_before > dt.datetime.now(dt.timezone.utc):
            critical("Certificate is not valid yet")

        if not leaf.sans:
            warning("Certificate has no Subject Alternative Names; modern browsers ignore the CN", 15)

        lifetime = (leaf.not_after - leaf.not_before).days
        if lifetime > MAX_PUBLIC_VALIDITY_DAYS:
            info(f"Validity period is {lifetime} days; public CAs may not exceed {MAX_PUBLIC_VALIDITY_DAYS}")

    # --- every certificate the server sent ----------------------------------
    for cert in report.chain:
        name = cert.common_name or cert.subject
        # A root's self-signature is never checked, so its hash doesn't matter.
        if cert.role != "root" and cert.signature_hash in WEAK_HASHES:
            critical(f"{name} is signed with weak hash {cert.signature_hash.upper()}")
        if cert.key_type == "RSA" and cert.key_size and cert.key_size < 2048:
            critical(f"{name} uses a weak {cert.key_size}-bit RSA key")
        if cert.role == "root":
            info(f"Server sends the root certificate ({name}); clients must already trust it, so sending it only wastes bytes")

    # --- protocol and cipher ------------------------------------------------
    version = report.tls_version or ""
    if version in LEGACY_PROTOCOLS:
        critical(f"Negotiated obsolete protocol {version}", cap="C")
    elif version == "TLSv1.2":
        warning("TLS 1.3 was not negotiated (TLS 1.2 is still acceptable)", 5)

        cipher = report.cipher or ""
        if "ECDHE" not in cipher and "DHE" not in cipher:
            critical(f"Cipher {cipher} has no forward secrecy", cap="B")
        if "GCM" not in cipher and "CHACHA20" not in cipher:
            warning(f"Cipher {cipher} uses CBC mode instead of AEAD", 10)

    if report.cipher_bits is not None and report.cipher_bits < 128:
        critical(f"Cipher strength is only {report.cipher_bits} bits", cap="C")

    score = max(score, 0)
    result = _score_to_grade(score)
    if any(f.severity == "warning" for f in findings):
        caps.append("A")  # A+ is reserved for a setup with nothing to fix
    for cap in caps:
        if GRADES.index(cap) < GRADES.index(result):
            result = cap

    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.severity])
    return score, result, findings
