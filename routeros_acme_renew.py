#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "typer>=0.12",
#     "pydantic>=2.6",
#     "arrow>=1.3",
#     "cryptography>=42",
# ]
# ///
"""Renew a Let's Encrypt certificate for a MikroTik RouterOS `www-ssl` service.

Designed to run unattended from a laptop (for example from a daily update script):

1. Skip quietly (exit 0) if the router is not reachable from here.
2. Skip if the certificate the router is serving is a production Let's
   Encrypt certificate younger than --renew-days.
3. Otherwise get a certificate with lego (DNS-01 via Route 53), upload and
   import it over SSH/SCP, point `www-ssl` at it, and check that the router
   now serves it. If it does not, put the previous certificate back.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated

import arrow
import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, Field, ValidationError, field_validator

app = typer.Typer(add_completion=False, help=__doc__)

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)
NAME_RE = re.compile(r"(?:^|\s)name=(\S+)")
REQUIRED_AWS_ENV = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
DEFAULT_STATE_DIR = Path.home() / ".local" / "share" / "routeros-acme-renew"


class RenewError(RuntimeError):
    """A step failed in a way the operator needs to hear about."""


class Settings(BaseModel):
    """Validated inputs. Host and user end up in ssh arguments, so keep them strict."""

    host: str
    ssh_user: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")  # no leading '-': ssh would read it as an option
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    cert_prefix: str = Field(default="acme", pattern=r"^[A-Za-z0-9]+$")

    @field_validator("host")
    @classmethod
    def _valid_host(cls, v: str) -> str:
        if not HOST_RE.match(v):
            raise ValueError("must be a fully qualified DNS name such as router.example.com")
        return v.lower()


# --------------------------------------------------------------------------
# Pure helpers (unit tested)
# --------------------------------------------------------------------------


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


def parse_cert_names(terse: str, prefix: str) -> list[str]:
    """Pull certificate names out of `/certificate print terse` output."""
    names = NAME_RE.findall(terse)
    return [n for n in names if n.startswith(f"{prefix}-")]


def missing_aws_env(env: Mapping[str, str]) -> list[str]:
    return [k for k in REQUIRED_AWS_ENV if not env.get(k)]


# --------------------------------------------------------------------------
# Network and router helpers
# --------------------------------------------------------------------------


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


class Router:
    def __init__(self, settings: Settings, ssh_port: int) -> None:
        self.target = f"{settings.ssh_user}@{settings.host}"
        self.port = str(ssh_port)
        self.opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]

    def run(self, command: str) -> str:
        proc = subprocess.run(
            ["ssh", *self.opts, "-p", self.port, self.target, command],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if proc.returncode != 0:
            raise RenewError(f"ssh command failed ({command!r}): {proc.stderr.strip() or proc.stdout.strip()}")
        return proc.stdout

    def upload(self, local: Path, remote_name: str) -> None:
        proc = subprocess.run(
            ["scp", "-q", *self.opts, "-P", self.port, str(local), f"{self.target}:{remote_name}"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if proc.returncode != 0:
            raise RenewError(f"scp of {remote_name} failed: {proc.stderr.strip()}")


# --------------------------------------------------------------------------
# Certificate issuance
# --------------------------------------------------------------------------


def load_leaf(path: Path) -> x509.Certificate | None:
    if not path.is_file():
        return None
    return x509.load_pem_x509_certificates(path.read_bytes())[0]


def run_lego(settings: Settings, state: Path, staging: bool, renew_force: bool) -> None:
    lego = shutil.which("lego")
    if not lego:
        raise RenewError("lego not found on PATH (brew install lego)")
    cmd = [
        lego,
        "run",
        "--accept-tos",
        "--email", settings.email,
        "--dns", "route53",
        "--domains", settings.host,
        "--key-type", "EC256",
        "--path", str(state),
        "--server", "letsencrypt-staging" if staging else "letsencrypt",
    ]  # fmt: skip
    if renew_force:
        cmd.append("--renew-force")
    env = {**os.environ}
    env.setdefault("AWS_REGION", "us-east-1")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if subprocess.run(cmd, env=env, check=False).returncode != 0:
        raise RenewError("lego failed to obtain a certificate (see output above)")


def obtain_certificate(
    settings: Settings, state: Path, staging: bool, renew_days: int, router_fp: str
) -> tuple[Path, Path, x509.Certificate]:
    """Return (cert_path, key_path, leaf). Reuses a fresh local cert the router lacks."""
    certs = state / "certificates"
    crt, key = certs / f"{settings.host}.crt", certs / f"{settings.host}.key"
    local = load_leaf(crt)
    if local and key.is_file() and cert_age_days(local) < renew_days and fingerprint(local) != router_fp:
        typer.echo("A fresh certificate from an earlier run is already on disk; reusing it.")
    else:
        run_lego(settings, state, staging, renew_force=local is not None)
    leaf = load_leaf(crt)
    if leaf is None or not key.is_file():
        raise RenewError(f"expected {crt} and {key} after lego run")
    if not key_matches(leaf, key.read_bytes()):
        raise RenewError("private key does not match the issued certificate")
    return crt, key, leaf


# --------------------------------------------------------------------------
# Deployment
# --------------------------------------------------------------------------


def deploy(router: Router, settings: Settings, crt: Path, key: Path, leaf: x509.Certificate, https_port: int) -> None:
    base = f"{settings.cert_prefix}-{arrow.utcnow().format('YYYYMMDD-HHmmss')}"
    previous = router.run(":put [/ip service get [find name=www-ssl] certificate]").strip()
    switched = False
    try:
        router.upload(crt, f"{base}.crt")
        router.upload(key, f"{base}.key")
        router.run(f'/certificate import file-name={base}.crt passphrase=""')
        router.run(f'/certificate import file-name={base}.key passphrase=""')
        router.run(f"/ip service set [find name=www-ssl] certificate={base}.crt_0")
        switched = True

        want = fingerprint(leaf)
        for _ in range(5):
            time.sleep(2)
            try:
                if fingerprint(served_cert(settings.host, https_port)) == want:
                    break
            except (OSError, RenewError):
                continue
        else:
            raise RenewError("router is not serving the new certificate after the switch")
    except Exception:
        if switched:
            restore = previous or "none"
            router.run(f"/ip service set [find name=www-ssl] certificate={restore}")
            typer.secho(f"Rolled www-ssl back to {restore!r}.", fg=typer.colors.YELLOW)
        raise
    finally:
        try:
            router.run(f'/file remove [find name~"^{base}"]')
        except RenewError:
            pass  # the files are harmless; the real outcome is reported elsewhere

    # New certificate is live and verified: drop the older ones this tool created.
    listing = router.run(f'/certificate print terse where name~"^{settings.cert_prefix}-"')
    for name in parse_cert_names(listing, settings.cert_prefix):
        if not name.startswith(base):
            router.run(f'/certificate remove [find name="{name}"]')


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


@app.command()
def main(
    host: Annotated[str, typer.Option(envvar="ROUTER_HOST", help="FQDN of the router, e.g. router.example.com.")],
    ssh_user: Annotated[str, typer.Option(envvar="ROUTER_SSH_USER", help="RouterOS user for ssh/scp (key auth).")],
    email: Annotated[str, typer.Option(envvar="ACME_EMAIL", help="Contact address registered with the ACME CA.")],
    renew_days: Annotated[int, typer.Option(min=1, max=89, help="Renew when the served cert is this old.")] = 60,
    https_port: Annotated[int, typer.Option(help="Port www-ssl listens on.")] = 443,
    ssh_port: Annotated[int, typer.Option(help="Router SSH port.")] = 22,
    state_dir: Annotated[Path, typer.Option(envvar="ROUTEROS_ACME_STATE_DIR", help="Where lego keeps its data.")] = DEFAULT_STATE_DIR,
    staging: Annotated[bool, typer.Option(help="Use the Let's Encrypt staging CA (untrusted certs; for testing).")] = False,
    force: Annotated[bool, typer.Option(help="Renew even if the certificate is young.")] = False,
    dry_run: Annotated[bool, typer.Option(help="Run the checks, report the decision, change nothing.")] = False,
) -> None:  # fmt: skip
    try:
        settings = Settings(host=host, ssh_user=ssh_user, email=email)
    except ValidationError as exc:
        typer.secho(f"Invalid settings:\n{exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc

    # 1. Can we reach the router from wherever we are right now?
    if not reachable(settings.host, [https_port, ssh_port]):
        typer.echo(f"{settings.host} is not reachable from here; skipping certificate check.")
        raise typer.Exit(0)

    # 2. How old is the certificate it is serving?
    try:
        current = served_cert(settings.host, https_port)
    except (OSError, RenewError) as exc:
        typer.secho(
            f"Could not read the certificate from {settings.host}:{https_port}: {exc}", fg=typer.colors.RED, err=True
        )
        raise typer.Exit(1) from exc
    renew, reason = renewal_decision(current, renew_days, force)
    if not renew:
        typer.echo(f"{settings.host}: certificate OK, {reason}.")
        raise typer.Exit(0)
    typer.echo(f"{settings.host}: renewing, {reason}.")
    if dry_run:
        typer.echo("Dry run: nothing changed.")
        raise typer.Exit(0)

    # 3. Renew and replace.
    missing = missing_aws_env(os.environ)
    if missing:
        typer.secho(
            f"Missing environment: {', '.join(missing)} (run under `op run --env-file ...`).",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)
    state = state_dir.expanduser() / ("staging" if staging else "production")
    try:
        crt, key, leaf = obtain_certificate(settings, state, staging, renew_days, fingerprint(current))
        deploy(Router(settings, ssh_port), settings, crt, key, leaf, https_port)
    except (RenewError, subprocess.TimeoutExpired) as exc:
        typer.secho(f"Renewal failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc
    typer.secho(
        f"{settings.host}: new certificate installed (expires {arrow.get(leaf.not_valid_after_utc).humanize()}).",
        fg=typer.colors.GREEN,
    )


if __name__ == "__main__":
    app()
