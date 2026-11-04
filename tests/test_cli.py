from __future__ import annotations

from typer.testing import CliRunner

from routeros_acme_renew.cli import app

runner = CliRunner()


def test_unreachable_router_is_a_quiet_skip():
    result = runner.invoke(app, ["--host", "nonexistent.invalid", "--ssh-user", "acme", "--email", "a@example.com"])
    assert result.exit_code == 0
    assert "not reachable" in result.output


def test_invalid_host_is_rejected_before_any_network_use():
    result = runner.invoke(
        app, ["--host", "-oProxyCommand=x.example.com", "--ssh-user", "acme", "--email", "a@example.com"]
    )
    assert result.exit_code == 1
