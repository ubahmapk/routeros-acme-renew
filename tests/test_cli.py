from __future__ import annotations

import pytest
from typer.testing import CliRunner

from conftest import HOST, make_cert
from routeros_acme_renew import cli
from routeros_acme_renew.cli import app
from routeros_acme_renew.errors import NoCertificateError, RenewError

runner = CliRunner()
ADDRESS = "172.16.2.1"
ARGS = ["--host", HOST, "--ssh-user", "acme", "--email", "a@example.com", "--address", ADDRESS]


def test_unreachable_router_is_a_quiet_skip():
    result = runner.invoke(app, ["--host", "nonexistent.invalid", "--ssh-user", "acme", "--email", "a@example.com"])
    assert result.exit_code == 0
    assert "not reachable" in result.output


def test_unreachable_message_names_the_address_too():
    result = runner.invoke(
        app,
        ["--host", "nonexistent.invalid", "--address", "127.0.0.1", "--https-port", "1", "--ssh-port", "1"]
        + ["--ssh-user", "acme", "--email", "a@example.com"],
    )
    assert result.exit_code == 0
    assert "(127.0.0.1) is not reachable" in result.output


def test_invalid_host_is_rejected_before_any_network_use():
    result = runner.invoke(
        app, ["--host", "-oProxyCommand=x.example.com", "--ssh-user", "acme", "--email", "a@example.com"]
    )
    assert result.exit_code == 1


def test_invalid_address_is_rejected_before_any_network_use():
    result = runner.invoke(
        app, ["--host", HOST, "--address", "-oProxyCommand=x", "--ssh-user", "acme"] + ["--email", "a@example.com"]
    )
    assert result.exit_code == 1


@pytest.fixture
def wired(monkeypatch):
    """Pretend the router is reachable and serving a self-signed cert; record where everything connects."""
    calls = {"reachable": None, "served": None, "router": None, "obtain": 0, "aws": 0}

    def reachable(target, ports):
        calls["reachable"] = (target, ports)
        return True

    def served_cert(host, port, address=None):
        calls["served"] = (host, port, address)
        return make_cert("MikroTik", 1)

    class FakeRouter:
        def __init__(self, target, port, user, key_file=None):
            calls["router"] = (target, port, user)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def run(self, command):
            return "old-cert\n"

    def obtain(*args, **kwargs):
        calls["obtain"] += 1
        calls["obtain_args"] = args
        raise RenewError("stop here")

    def session(*args, **kwargs):
        calls["aws"] += 1
        raise AssertionError("AWS must not be touched yet")

    monkeypatch.setattr(cli, "reachable", reachable)
    monkeypatch.setattr(cli, "served_cert", served_cert)
    monkeypatch.setattr(cli, "Router", FakeRouter)
    monkeypatch.setattr(cli, "obtain", obtain)
    monkeypatch.setattr(cli.boto3, "Session", session)
    return calls


def test_the_address_is_used_for_every_connection_and_shown_in_the_output(wired):
    result = runner.invoke(app, [*ARGS, "--dry-run"])

    assert result.exit_code == 0
    assert wired["reachable"][0] == ADDRESS
    assert wired["served"] == (HOST, 443, ADDRESS)
    assert wired["router"] == (ADDRESS, 22, "acme")
    assert f"{HOST} ({ADDRESS}): renewing" in result.output


def test_a_router_with_no_certificate_yet_is_renewed_not_an_error(wired, monkeypatch):
    def no_certificate(host, port, address=None):
        raise NoCertificateError("handshake refused")

    monkeypatch.setattr(cli, "served_cert", no_certificate)

    result = runner.invoke(app, [*ARGS, "--dry-run"])

    assert result.exit_code == 0
    assert "not serving a certificate yet" in result.output
    assert wired["router"] is not None  # carried on to the SSH check


def test_with_no_certificate_the_ca_order_gets_an_empty_router_fingerprint(wired, monkeypatch, tmp_path):
    class FakeSession:
        def get_credentials(self):
            return object()

        def client(self, *args, **kwargs):
            return object()

    def no_certificate(host, port, address=None):
        raise NoCertificateError("handshake refused")

    monkeypatch.setattr(cli, "served_cert", no_certificate)
    monkeypatch.setattr(cli.boto3, "Session", lambda *a, **k: FakeSession())

    runner.invoke(app, [*ARGS, "--state-dir", str(tmp_path)])

    assert wired["obtain"] == 1
    assert wired["obtain_args"][-1] == ""


def test_a_dry_run_proves_ssh_login_without_touching_aws_or_the_ca(wired):
    result = runner.invoke(app, [*ARGS, "--dry-run"])

    assert result.exit_code == 0
    assert "SSH login works" in result.output
    assert wired["aws"] == 0
    assert wired["obtain"] == 0


@pytest.mark.parametrize("extra", [[], ["--dry-run"]])
def test_a_failed_ssh_check_stops_before_any_certificate_is_ordered(wired, monkeypatch, extra):
    class Refusing:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            raise RenewError("host key not trusted")

        def __exit__(self, *exc):
            return None

    monkeypatch.setattr(cli, "Router", Refusing)

    result = runner.invoke(app, [*ARGS, *extra])

    assert result.exit_code == 1
    assert "Router check failed" in result.output
    assert wired["obtain"] == 0
    assert wired["aws"] == 0


def test_after_a_good_ssh_check_a_real_run_goes_on_to_order_the_certificate(wired, monkeypatch, tmp_path):
    class FakeSession:
        def get_credentials(self):
            return object()

        def client(self, *args, **kwargs):
            return object()

    monkeypatch.setattr(cli.boto3, "Session", lambda *a, **k: FakeSession())

    result = runner.invoke(app, [*ARGS, "--state-dir", str(tmp_path)])

    assert wired["obtain"] == 1  # reached only after the SSH check passed
    assert result.exit_code == 1
    assert "stop here" in result.output
