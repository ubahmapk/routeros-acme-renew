from __future__ import annotations

import re

import pytest

from conftest import HOST, make_cert
from routeros_acme_renew.config import Settings
from routeros_acme_renew.deploy import deploy, parse_cert_names, preflight
from routeros_acme_renew.errors import NoCertificateError, RenewError

OLD = "acme-20250101-000000.crt_0"


class FakeRouter:
    """Records commands and models the parts of RouterOS that matter; fails any command containing `fail_on`.

    `key_attached=False`: a key import that silently did nothing. `late_key_polls=N`: the key shows up only on the
    (N+1)th look. `set_rejections=N`: the first N `set`s of the new certificate are silently refused, as RouterOS
    does right after an import (the SSH command succeeds, only the router's log shows the error).
    `allowed_sources`: the www-ssl `available-from` list.
    """

    def __init__(self, fail_on=None, key_attached=True, late_key_polls=0, set_rejections=0, allowed_sources=None):
        self.commands: list[str] = []
        self.files: dict[str, bytes] = {}
        self.fail_on = fail_on
        self.imported: list[str] = []
        self.key_attached, self.late_key_polls, self.key_polls = key_attached, late_key_polls, 0
        self.set_rejections, self.set_calls = set_rejections, 0
        self.allowed_sources = allowed_sources
        self.service_cert = "old-service-cert"

    def put(self, remote_name, data):
        self.files[remote_name] = data

    def run(self, command):
        self.commands.append(command)
        if self.fail_on and self.fail_on in command:
            raise RenewError(f"router rejected {command}")
        if command.startswith(":put"):
            return f"{self.service_cert}\n"
        if m := re.fullmatch(r"/ip service set \[find name=www-ssl\] certificate=(\S+)", command):
            name = m.group(1)
            if name.endswith(".crt_0"):
                self.set_calls += 1
                if self.set_calls <= self.set_rejections:
                    return ""  # refused, but the command still "succeeds"
            self.service_cert = name
            return ""
        if "print terse where name=www-ssl" in command:
            sources = f" available-from={self.allowed_sources}" if self.allowed_sources else ""
            return f" 0 name=www-ssl port=443 proto=tcp{sources} certificate={self.service_cert}\n"
        if (m := re.search(r"import file-name=(\S+)\.crt ", command)) and m:
            self.imported = [f"{m.group(1)}.crt_0", f"{m.group(1)}.crt_1"]
        if "print terse" in command:
            if m := re.search(r'where name="([^"]+)"', command):  # an exact-name lookup, as the key check does
                self.key_polls += 1
                has_key = self.key_attached and self.key_polls > self.late_key_polls
                return f" 0 {'KLT' if has_key else 'LT'} name={m.group(1)} common-name=x"
            names = [OLD, *self.imported]
            return "\n".join(f" {i} KLT name={n} common-name=x" for i, n in enumerate(names))
        return ""


@pytest.fixture
def settings():
    return Settings(host=HOST, ssh_user="acme", email="me@example.com")


def run_deploy(router, settings, served):
    leaf = make_cert()
    deploy(router, settings, b"CRT", b"KEY", leaf, 443, fetch=lambda h, p, a: served(leaf), sleep=lambda s: None)


def test_parse_cert_names_ignores_the_common_name_field():
    terse = (
        " 0 K  T name=acme-20261001-010101.crt_0 common-name=router.example.com\n"
        " 1    T name=acme-20261001-010101.crt_1 common-name=E7\n"
        " 2       name=other.crt_0 common-name=x\n"
    )
    assert parse_cert_names(terse, "acme-") == ["acme-20261001-010101.crt_0", "acme-20261001-010101.crt_1"]


def test_success_switches_verifies_and_removes_only_the_old_certs(settings):
    router = FakeRouter()

    run_deploy(router, settings, served=lambda leaf: leaf)

    base = next(n for n in router.files if n.endswith(".crt"))[: -len(".crt")]
    assert f"/ip service set [find name=www-ssl] certificate={base}.crt_0" in router.commands
    assert f'/certificate remove [find name="{OLD}"]' in router.commands
    assert not any(f'name="{base}' in c for c in router.commands if "remove" in c)
    assert any(c.startswith("/file remove") for c in router.commands)


def test_wrong_certificate_served_rolls_back_and_cleans_up(settings):
    router = FakeRouter()

    with pytest.raises(RenewError, match="not serving the new certificate"):
        run_deploy(router, settings, served=lambda leaf: make_cert())

    assert "/ip service set [find name=www-ssl] certificate=old-service-cert" in router.commands
    removed = [c for c in router.commands if c.startswith("/certificate remove")]
    assert removed and all(OLD not in c for c in removed)  # the new, bad ones go; the old cert stays


def test_rollback_failure_is_reported_with_the_original_error_chained(settings):
    router = FakeRouter(fail_on="certificate=old-service-cert")

    with pytest.raises(RenewError, match="rollback also failed") as info:
        run_deploy(router, settings, served=lambda leaf: make_cert())

    assert "not serving the new certificate" in str(info.value.__cause__)


def test_failed_import_leaves_the_service_alone_and_cleans_up(settings):
    router = FakeRouter(fail_on=".key passphrase")

    with pytest.raises(RenewError):
        run_deploy(router, settings, served=lambda leaf: leaf)

    assert not any("/ip service set" in c for c in router.commands)
    assert any(c.startswith("/certificate remove") for c in router.commands)
    assert any(c.startswith("/file remove") for c in router.commands)


def test_preflight_returns_the_certificate_www_ssl_uses_now():
    router = FakeRouter()

    assert preflight(router) == "old-service-cert"
    assert router.commands == [":put [/ip service get [find name=www-ssl] certificate]"]


def test_preflight_explains_an_unreadable_service():
    with pytest.raises(RenewError, match="cannot read the www-ssl service"):
        preflight(FakeRouter(fail_on=":put"))


def test_verification_connects_to_the_address_but_keeps_the_host_name():
    settings = Settings(host=HOST, ssh_user="acme", email="me@example.com", address="172.16.2.1")
    leaf = make_cert()
    seen = []

    def fetch(host, port, address):
        seen.append((host, port, address))
        return leaf

    deploy(FakeRouter(), settings, b"CRT", b"KEY", leaf, 443, fetch=fetch, sleep=lambda s: None)

    assert seen[0] == (HOST, 443, "172.16.2.1")


def index_of_service_set(router: FakeRouter) -> int:
    return next(i for i, c in enumerate(router.commands) if c.startswith("/ip service set") and ".crt_0" in c)


def test_the_service_is_only_set_after_the_router_reports_the_private_key(settings):
    router = FakeRouter(late_key_polls=3)
    leaf = make_cert()

    deploy(router, settings, b"CRT", b"KEY", leaf, 443, fetch=lambda h, p, a: leaf, sleep=lambda s: None)

    polls = [i for i, c in enumerate(router.commands) if c.startswith("/certificate print terse where name=")]
    assert len(polls) == 4  # three looks without the key, then one with it
    assert polls[-1] < index_of_service_set(router)


def test_a_missing_private_key_is_reported_and_the_service_is_never_touched(settings):
    router = FakeRouter(key_attached=False)

    with pytest.raises(RenewError, match="no private key"):
        run_deploy(router, settings, served=lambda leaf: leaf)

    assert not any(c.startswith("/ip service set") for c in router.commands)
    assert any(c.startswith("/certificate remove") for c in router.commands)
    assert any(c.startswith("/file remove") for c in router.commands)


def test_the_service_setting_is_retried_until_the_router_reports_it_took(settings):
    # RouterOS can refuse the first `set` right after an import and still let the SSH command succeed.
    router = FakeRouter(set_rejections=2)
    leaf = make_cert()

    deploy(router, settings, b"CRT", b"KEY", leaf, 443, fetch=lambda h, p, a: leaf, sleep=lambda s: None)

    sets = [c for c in router.commands if c.startswith("/ip service set") and ".crt_0" in c]
    assert len(sets) == 3  # two silently refused, the third took
    assert router.service_cert.endswith(".crt_0")
    assert not any(c.startswith("/ip service set") and "old-service-cert" in c for c in router.commands)  # no rollback


def test_a_certificate_the_router_never_accepts_fails_clearly_and_rolls_back(settings):
    router = FakeRouter(set_rejections=99)

    with pytest.raises(RenewError, match="would not accept .* as the www-ssl certificate"):
        run_deploy(router, settings, served=lambda leaf: leaf)

    assert router.service_cert == "old-service-cert"
    assert any(c.startswith("/certificate remove") for c in router.commands)
    assert any(c.startswith("/file remove") for c in router.commands)


def test_the_final_error_says_what_the_router_last_did_when_it_refuses_the_handshake(settings):
    router = FakeRouter()
    leaf = make_cert()

    def fetch(host, port, address):
        raise NoCertificateError("172.16.2.1:443 presented no certificate (handshake refused)")

    with pytest.raises(RenewError, match="last check: NoCertificateError: .*handshake refused"):
        deploy(router, settings, b"CRT", b"KEY", leaf, 443, fetch=fetch, sleep=lambda s: None)


def test_the_final_error_says_when_the_router_serves_a_different_certificate(settings):
    with pytest.raises(RenewError, match="serves another certificate"):
        run_deploy(FakeRouter(), settings, served=lambda leaf: make_cert())


def refusing_fetch(host, port, address):
    raise ConnectionResetError("Connection reset by peer")


def test_a_failed_verification_names_the_ranges_www_ssl_accepts(settings):
    router = FakeRouter(allowed_sources="172.16.2.0/24")
    leaf = make_cert()

    with pytest.raises(RenewError, match=r"only accepts connections from 172\.16\.2\.0/24.*this machine's address"):
        deploy(router, settings, b"CRT", b"KEY", leaf, 443, fetch=refusing_fetch, sleep=lambda s: None)


def test_without_a_source_restriction_the_failure_adds_no_such_hint(settings):
    router = FakeRouter(allowed_sources=None)
    leaf = make_cert()

    with pytest.raises(RenewError) as info:
        deploy(router, settings, b"CRT", b"KEY", leaf, 443, fetch=refusing_fetch, sleep=lambda s: None)

    assert "only accepts connections" not in str(info.value)
    assert "ConnectionResetError" in str(info.value)
