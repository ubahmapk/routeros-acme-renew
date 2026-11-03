from __future__ import annotations

import datetime as dt

import arrow
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

import routeros_acme_renew as r

NOW = arrow.get("2026-11-03T12:00:00Z")


def make_cert(issuer_org: str, age_days: int, key=None) -> x509.Certificate:
    key = key or ec.generate_private_key(ec.SECP256R1())
    start = NOW.shift(days=-age_days).datetime
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "router.example.com")])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )


def test_young_production_cert_is_left_alone():
    renew, _ = r.renewal_decision(make_cert("Let's Encrypt", 10), 60, False, NOW)
    assert renew is False


def test_old_production_cert_is_renewed():
    renew, reason = r.renewal_decision(make_cert("Let's Encrypt", 60), 60, False, NOW)
    assert renew is True and "60 days" in reason


def test_self_signed_cert_is_renewed_even_when_young():
    renew, _ = r.renewal_decision(make_cert("MikroTik", 1), 60, False, NOW)
    assert renew is True


def test_staging_cert_is_not_treated_as_production():
    cert = make_cert("(STAGING) Let's Encrypt", 1)
    assert r.is_production_lets_encrypt(cert) is False
    assert r.renewal_decision(cert, 60, False, NOW)[0] is True


def test_force_renews_a_young_cert():
    assert r.renewal_decision(make_cert("Let's Encrypt", 1), 60, True, NOW)[0] is True


def test_key_matches():
    key = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert("Let's Encrypt", 1, key)

    def pem(k):
        return k.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    assert r.key_matches(cert, pem(key)) is True
    assert r.key_matches(cert, pem(other)) is False


def test_parse_cert_names_ignores_common_name_field():
    terse = (
        " 0 K  T name=acme-20261001-010101.crt_0 common-name=router.example.com\n"
        " 1    T name=acme-20261001-010101.crt_1 common-name=E7\n"
        " 2       name=other.crt_0 common-name=x\n"
    )
    assert r.parse_cert_names(terse, "acme") == ["acme-20261001-010101.crt_0", "acme-20261001-010101.crt_1"]


@pytest.mark.parametrize("host", ["-oProxyCommand=x.example.com", "a b.example.com", "router", "r;ls.example.com"])
def test_settings_reject_bad_hosts(host):
    with pytest.raises(ValidationError):
        r.Settings(host=host, ssh_user="acme", email="me@example.com")


def test_settings_reject_bad_user():
    with pytest.raises(ValidationError):
        r.Settings(host="router.example.com", ssh_user="-oFoo", email="me@example.com")


def test_missing_aws_env():
    assert r.missing_aws_env({"AWS_ACCESS_KEY_ID": "x"}) == ["AWS_SECRET_ACCESS_KEY"]
    assert r.missing_aws_env({"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y"}) == []
