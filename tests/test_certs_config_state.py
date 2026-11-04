from __future__ import annotations

import stat

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError

from conftest import HOST, NOW, key_pem, make_cert
from routeros_acme_renew import certs
from routeros_acme_renew.config import Settings
from routeros_acme_renew.state import PendingStore, State, write_private


def test_young_production_cert_is_left_alone():
    assert certs.renewal_decision(make_cert(age_days=10), 60, False, NOW)[0] is False


def test_old_production_cert_is_renewed():
    renew, reason = certs.renewal_decision(make_cert(age_days=60), 60, False, NOW)
    assert renew is True and "60 days" in reason


def test_self_signed_cert_is_renewed_even_when_young():
    assert certs.renewal_decision(make_cert("MikroTik", 1), 60, False, NOW)[0] is True


def test_staging_cert_is_not_treated_as_production():
    cert = make_cert("(STAGING) Let's Encrypt", 1)
    assert certs.is_production_lets_encrypt(cert) is False
    assert certs.renewal_decision(cert, 60, False, NOW)[0] is True


def test_force_renews_a_young_cert():
    assert certs.renewal_decision(make_cert(age_days=1), 60, True, NOW)[0] is True


def test_key_matches():
    key, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(key=key)
    assert certs.key_matches(cert, key_pem(key)) is True
    assert certs.key_matches(cert, key_pem(other)) is False


def test_covers_host():
    cert = make_cert(host=HOST)
    assert certs.covers_host(cert, HOST.upper()) is True
    assert certs.covers_host(cert, "other.example.com") is False


@pytest.mark.parametrize("host", ["-oProxyCommand=x.example.com", "a b.example.com", "router", "r;ls.example.com"])
def test_settings_reject_bad_hosts(host):
    with pytest.raises(ValidationError):
        Settings(host=host, ssh_user="acme", email="me@example.com")


@pytest.mark.parametrize("user", ["-oFoo", "a b", "x;y", ""])
def test_settings_reject_bad_users(user):
    with pytest.raises(ValidationError):
        Settings(host=HOST, ssh_user=user, email="me@example.com")


def test_write_private_is_owner_only_and_replaces(tmp_path):
    target = tmp_path / "secret"
    write_private(target, b"one")
    write_private(target, b"two")
    assert target.read_bytes() == b"two"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not (tmp_path / "secret.tmp").exists()


def test_state_dirs_are_private_and_separate_per_environment(tmp_path):
    prod, stg = State.for_env(tmp_path, False), State.for_env(tmp_path, True)
    prod.ensure()
    assert prod.root != stg.root
    assert stat.S_IMODE(prod.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(prod.certs_dir.stat().st_mode) == 0o700


def test_pending_store_roundtrip(tmp_path):
    store = PendingStore(tmp_path / "p.json")
    rec = {"zone_id": "Z1", "name": "_acme-challenge.x.example.com", "value": "abc"}
    assert store.all() == []
    store.add(rec)
    store.add(rec)  # idempotent
    assert store.all() == [rec]
    store.remove(rec)
    assert store.all() == []
