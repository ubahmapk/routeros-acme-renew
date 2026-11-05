from __future__ import annotations

import socket
import ssl
import stat
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import ValidationError

from conftest import HOST, NOW, key_pem, make_cert
from routeros_acme_renew import certs
from routeros_acme_renew.config import Settings
from routeros_acme_renew.errors import NoCertificateError
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


@pytest.mark.parametrize("address", ["172.16.2.1", "fd00::1", "guard.lan.example.com"])
def test_settings_accept_an_ip_or_fqdn_address(address):
    assert Settings(host=HOST, ssh_user="acme", email="me@example.com", address=address).address == address


@pytest.mark.parametrize("address", ["-oProxyCommand=x", "a b", "172.16.2", "rtr;ls"])
def test_settings_reject_bad_addresses(address):
    with pytest.raises(ValidationError):
        Settings(host=HOST, ssh_user="acme", email="me@example.com", address=address)


def test_target_is_the_address_when_given_else_the_host():
    plain = Settings(host=HOST, ssh_user="acme", email="me@example.com")
    pinned = Settings(host=HOST, ssh_user="acme", email="me@example.com", address="172.16.2.1")
    assert plain.target == HOST
    assert pinned.target == "172.16.2.1"


def listening_socket() -> tuple[socket.socket, int]:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    return srv, srv.getsockname()[1]


def test_reachable_is_true_only_when_every_port_accepts():
    srv, port = listening_socket()
    try:
        assert certs.reachable("127.0.0.1", [port]) is True
    finally:
        srv.close()
    assert certs.reachable("127.0.0.1", [port]) is False


def test_reachable_is_false_for_a_name_that_does_not_resolve():
    assert certs.reachable("nonexistent.invalid", [443]) is False


def serve_one_tls_client(tmp_path, cert, key) -> tuple[int, dict]:
    """Start a one-shot local TLS server. Returns its port and a dict that records the SNI name it saw."""
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key_pem(key))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    seen: dict = {}

    def record_sni(sock, server_name, context) -> None:
        seen["sni"] = server_name

    ctx.sni_callback = record_sni
    srv, port = listening_socket()

    def accept() -> None:
        conn, _ = srv.accept()
        try:
            ctx.wrap_socket(conn, server_side=True).close()
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=accept, daemon=True).start()
    return port, seen


def test_served_cert_connects_to_the_address_and_sends_the_host_name_as_sni(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = make_cert(key=key)
    port, seen = serve_one_tls_client(tmp_path, cert, key)

    got = certs.served_cert("router.example.com", port, address="127.0.0.1")

    assert certs.fingerprint(got) == certs.fingerprint(cert)
    assert seen["sni"] == "router.example.com"


def test_served_cert_without_an_address_needs_the_name_to_resolve():
    with pytest.raises(OSError):
        certs.served_cert("nonexistent.invalid", 443)


def test_a_failed_tls_handshake_means_the_router_serves_no_certificate():
    srv, port = listening_socket()

    def accept_and_hang_up() -> None:
        conn, _ = srv.accept()
        conn.close()
        srv.close()

    threading.Thread(target=accept_and_hang_up, daemon=True).start()

    with pytest.raises(NoCertificateError):
        certs.served_cert("router.example.com", port, address="127.0.0.1")


def test_a_refused_connection_is_not_mistaken_for_no_certificate():
    srv, port = listening_socket()
    srv.close()

    with pytest.raises(OSError) as info:
        certs.served_cert("router.example.com", port, address="127.0.0.1")

    assert not isinstance(info.value, NoCertificateError)
