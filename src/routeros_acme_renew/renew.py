"""Decide whether to ask the CA for a new certificate or reuse one we already hold."""

from __future__ import annotations

import logging

from cryptography import x509

from .acme_flow import issue
from .certs import cert_age_days, covers_host, fingerprint, key_matches, load_leaf
from .config import Settings
from .errors import RenewError
from .route53 import Route53Dns
from .state import State, write_private

log = logging.getLogger(__name__)


def obtain(
    settings: Settings,
    state: State,
    directory_url: str,
    dns: Route53Dns,
    renew_days: int,
    router_fingerprint: str,
) -> tuple[bytes, bytes, x509.Certificate]:
    """Return (fullchain_pem, key_pem, leaf).

    A fresh certificate from an earlier run that never reached the router is reused, so a failed
    deployment does not use up Let's Encrypt rate limit on every retry.
    """
    crt_path, key_path = state.cert_path(settings.host), state.key_path(settings.host)
    if crt_path.is_file() and key_path.is_file():
        chain, key = crt_path.read_bytes(), key_path.read_bytes()
        local = load_leaf(chain)
        if (
            cert_age_days(local) < renew_days
            and fingerprint(local) != router_fingerprint
            and covers_host(local, settings.host)
            and key_matches(local, key)
        ):
            log.info("Reusing a fresh certificate from an earlier run.")
            return chain, key, local

    issued = issue(settings, state, directory_url, dns)
    leaf = load_leaf(issued.fullchain_pem)
    if not covers_host(leaf, settings.host):
        raise RenewError(f"issued certificate does not cover {settings.host}")
    if not key_matches(leaf, issued.key_pem):
        raise RenewError("private key does not match the issued certificate")
    write_private(key_path, issued.key_pem)
    write_private(crt_path, issued.fullchain_pem)
    return issued.fullchain_pem, issued.key_pem, leaf
