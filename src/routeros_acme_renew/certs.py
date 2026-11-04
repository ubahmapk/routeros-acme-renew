"""Inspect certificates: age, issuer, fingerprints, key matching, and what a host is serving."""

from __future__ import annotations

import socket
import ssl

import arrow
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from .errors import RenewError


def load_leaf(pem: bytes) -> x509.Certificate:
    """First certificate in a PEM bundle (the leaf, in a fullchain file)."""
    return x509.load_pem_x509_certificates(pem)[0]


def cert_age_days(cert: x509.Certificate, now: arrow.Arrow | None = None) -> int:
    """Whole days since the certificate's notBefore."""
    now = now or arrow.utcnow()
    return (now - arrow.get(cert.not_valid_before_utc)).days


def is_production_lets_encrypt(cert: x509.Certificate) -> bool:
    """True for a real Let's Encrypt issuer; False for staging or anything else."""
    orgs = [a.value for a in cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)]
    text = " ".join(str(o) for o in orgs)
    return "Let's Encrypt" in text and "STAGING" not in text.upper()


def renewal_decision(
    cert: x509.Certificate, renew_days: int, force: bool, now: arrow.Arrow | None = None
) -> tuple[bool, str]:
    """Return (should_renew, human-readable reason)."""
    age = cert_age_days(cert, now)
    if force:
        return True, "forced"
    if not is_production_lets_encrypt(cert):
        return True, "router is not serving a production Let's Encrypt certificate"
    if age >= renew_days:
        return True, f"certificate is {age} days old (threshold {renew_days})"
    return False, f"certificate is {age} days old (threshold {renew_days})"


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def key_matches(cert: x509.Certificate, key_pem: bytes) -> bool:
    key = serialization.load_pem_private_key(key_pem, password=None)
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    return key.public_key().public_bytes(der, spki) == cert.public_key().public_bytes(der, spki)


def covers_host(cert: x509.Certificate, host: str) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    return host.lower() in {n.lower() for n in san.get_values_for_type(x509.DNSName)}


def reachable(host: str, ports: list[int], timeout: float = 3.0) -> bool:
    """True only if the name resolves and every port accepts a TCP connection."""
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except OSError:
            return False
    return True


def served_cert(host: str, port: int, timeout: float = 5.0) -> x509.Certificate:
    """Fetch whatever certificate the host serves, without trusting it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        ctx.wrap_socket(raw, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise RenewError(f"{host}:{port} did not present a certificate")
    return x509.load_der_x509_certificate(der)
