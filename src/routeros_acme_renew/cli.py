"""Command line entry point.

1. Skip quietly (exit 0) if the router is not reachable from here.
2. Skip if the certificate the router is serving is a production Let's Encrypt
   certificate younger than --renew-days.
3. Otherwise get a certificate (ACME DNS-01 via Route 53), upload and import it over
   SSH/SFTP, point `www-ssl` at it, and check that the router now serves it. If it
   does not, put the previous certificate back.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Annotated

import arrow
import boto3
import typer
from pydantic import ValidationError

from .acme_flow import LE_PRODUCTION, LE_STAGING
from .certs import fingerprint, reachable, renewal_decision, served_cert
from .config import Settings
from .deploy import deploy
from .errors import RenewError
from .renew import obtain
from .route53 import Route53Dns
from .router import Router
from .state import DEFAULT_STATE_DIR, PendingStore, State

app = typer.Typer(add_completion=False, help=__doc__, pretty_exceptions_show_locals=False)


def _fail(message: str) -> typer.Exit:
    typer.secho(message, fg=typer.colors.RED, err=True)
    return typer.Exit(1)


@app.command()
def main(
    host: Annotated[str, typer.Option(envvar="ROUTER_HOST", help="FQDN of the router, e.g. router.example.com.")],
    ssh_user: Annotated[str, typer.Option(envvar="ROUTER_SSH_USER", help="RouterOS user for SSH (key auth).")],
    email: Annotated[str, typer.Option(envvar="ACME_EMAIL", help="Contact address registered with the ACME CA.")],
    ssh_key: Annotated[Path | None, typer.Option(envvar="ROUTER_SSH_KEY", help="SSH key file; default is ssh-agent or ~/.ssh.")] = None,
    zone_id: Annotated[str | None, typer.Option(envvar="AWS_HOSTED_ZONE_ID", help="Route 53 hosted zone ID; default is auto-detect.")] = None,
    renew_days: Annotated[int, typer.Option(min=1, max=89, help="Renew when the served cert is this old.")] = 60,
    https_port: Annotated[int, typer.Option(help="Port www-ssl listens on.")] = 443,
    ssh_port: Annotated[int, typer.Option(help="Router SSH port.")] = 22,
    state_dir: Annotated[Path, typer.Option(envvar="ROUTEROS_ACME_STATE_DIR", help="Where account and certificate files are kept.")] = DEFAULT_STATE_DIR,
    staging: Annotated[bool, typer.Option(help="Use the Let's Encrypt staging CA (untrusted certs; for testing).")] = False,
    force: Annotated[bool, typer.Option(help="Renew even if the certificate is young.")] = False,
    dry_run: Annotated[bool, typer.Option(help="Run the checks, report the decision, change nothing.")] = False,
) -> None:  # fmt: skip
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    try:
        settings = Settings(host=host, ssh_user=ssh_user, email=email)
    except ValidationError as exc:
        raise _fail(f"Invalid settings:\n{exc}") from exc

    # 1. Can we reach the router from wherever we are right now?
    if not reachable(settings.host, [https_port, ssh_port]):
        typer.echo(f"{settings.host} is not reachable from here; skipping certificate check.")
        raise typer.Exit(0)

    # 2. How old is the certificate it is serving?
    try:
        current = served_cert(settings.host, https_port)
    except (OSError, RenewError) as exc:
        raise _fail(f"Could not read the certificate from {settings.host}:{https_port}: {exc}") from exc
    renew, reason = renewal_decision(current, renew_days, force)
    if not renew:
        typer.echo(f"{settings.host}: certificate OK, {reason}.")
        raise typer.Exit(0)
    typer.echo(f"{settings.host}: renewing, {reason}.")
    if dry_run:
        typer.echo("Dry run: nothing changed.")
        raise typer.Exit(0)

    # 3. Renew and replace.
    session = boto3.Session()
    if session.get_credentials() is None:
        raise _fail(
            "No AWS credentials found (run under `op run --env-file ...` or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)."
        )
    state = State.for_env(state_dir, staging)
    state.ensure()
    dns = Route53Dns(
        session.client("route53", region_name=os.environ.get("AWS_REGION", "us-east-1")),
        PendingStore(state.pending),
        zone_id,
    )
    try:
        dns.sweep()
        crt_pem, key_pem, leaf = obtain(
            settings, state, LE_STAGING if staging else LE_PRODUCTION, dns, renew_days, fingerprint(current)
        )
        with Router(settings.host, ssh_port, settings.ssh_user, ssh_key) as router:
            deploy(router, settings, crt_pem, key_pem, leaf, https_port)
    except RenewError as exc:
        raise _fail(f"Renewal failed: {exc}") from exc
    typer.secho(
        f"{settings.host}: new certificate installed (expires {arrow.get(leaf.not_valid_after_utc).humanize()}).",
        fg=typer.colors.GREEN,
    )


if __name__ == "__main__":
    app()
