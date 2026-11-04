from __future__ import annotations

import re

import pytest

from conftest import HOST, make_cert
from routeros_acme_renew.config import Settings
from routeros_acme_renew.deploy import deploy, parse_cert_names
from routeros_acme_renew.errors import RenewError

OLD = "acme-20250101-000000.crt_0"


class FakeRouter:
    """Records commands; fails any command containing `fail_on`."""

    def __init__(self, fail_on=None):
        self.commands: list[str] = []
        self.files: dict[str, bytes] = {}
        self.fail_on = fail_on
        self.imported: list[str] = []

    def put(self, remote_name, data):
        self.files[remote_name] = data

    def run(self, command):
        self.commands.append(command)
        if self.fail_on and self.fail_on in command:
            raise RenewError(f"router rejected {command}")
        if command.startswith(":put"):
            return "old-service-cert\n"
        if (m := re.search(r"import file-name=(\S+)\.crt ", command)) and m:
            self.imported = [f"{m.group(1)}.crt_0", f"{m.group(1)}.crt_1"]
        if "print terse" in command:
            names = [OLD, *self.imported]
            return "\n".join(f" {i} K  T name={n} common-name=x" for i, n in enumerate(names))
        return ""


@pytest.fixture
def settings():
    return Settings(host=HOST, ssh_user="acme", email="me@example.com")


def run_deploy(router, settings, served):
    leaf = make_cert()
    deploy(router, settings, b"CRT", b"KEY", leaf, 443, fetch=lambda h, p: served(leaf), sleep=lambda s: None)


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
