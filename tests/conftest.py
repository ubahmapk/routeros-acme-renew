from __future__ import annotations

import datetime as dt

import arrow
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = arrow.get("2026-11-03T12:00:00Z")
HOST = "router.example.com"


def make_cert(
    issuer_org: str = "Let's Encrypt",
    age_days: int = 1,
    key: ec.EllipticCurvePrivateKey | None = None,
    host: str = HOST,
) -> x509.Certificate:
    key = key or ec.generate_private_key(ec.SECP256R1())
    start = NOW.shift(days=-age_days).datetime
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )


def key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


@pytest.fixture
def cert_factory():
    return make_cert
