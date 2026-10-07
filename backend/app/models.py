"""Response shapes shared by the inspector, grader and API."""

import datetime as dt

from pydantic import BaseModel


class CertInfo(BaseModel):
    role: str  # "leaf", "intermediate" or "root"
    subject: str
    common_name: str | None
    issuer: str
    issuer_common_name: str | None
    serial_number: str
    not_before: dt.datetime
    not_after: dt.datetime
    days_remaining: int
    signature_algorithm: str
    signature_hash: str | None
    key_type: str
    key_size: int | None
    sans: list[str]
    is_ca: bool
    self_signed: bool
    sha256_fingerprint: str


class Finding(BaseModel):
    severity: str  # "critical", "warning" or "info"
    message: str


class InspectionReport(BaseModel):
    host: str
    port: int
    ip: str
    tls_version: str | None
    cipher: str | None
    cipher_bits: int | None
    trusted: bool
    verify_error: str | None
    chain: list[CertInfo]
    grade: str = "?"
    score: int = 0
    findings: list[Finding] = []
