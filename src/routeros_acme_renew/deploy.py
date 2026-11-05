"""Install a certificate on the router, prove it is being served, and undo the change if it is not."""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from typing import Protocol

import arrow
from cryptography import x509

from .certs import fingerprint, served_cert
from .config import Settings
from .errors import RenewError

log = logging.getLogger(__name__)

NAME_RE = re.compile(r"(?:^|\s)name=(\S+)")


class RouterLike(Protocol):
    def run(self, command: str) -> str: ...
    def put(self, remote_name: str, data: bytes) -> None: ...


def parse_cert_names(terse: str, prefix: str) -> list[str]:
    """Pull certificate names out of `/certificate print terse` output."""
    return [n for n in NAME_RE.findall(terse) if n.startswith(prefix)]


def preflight(router: RouterLike) -> str:
    """Cheap, read-only proof that we can log in and see the www-ssl service.

    Returns the name of the certificate www-ssl uses now (empty or "none" if it has none).
    """
    try:
        return router.run(":put [/ip service get [find name=www-ssl] certificate]").strip()
    except RenewError as exc:
        raise RenewError(
            f"cannot read the www-ssl service (is it present, and may this SSH user read it?): {exc}"
        ) from exc


def _remove_certs(router: RouterLike, name_prefix: str) -> None:
    listing = router.run(f'/certificate print terse where name~"^{name_prefix}"')
    for name in parse_cert_names(listing, name_prefix):
        router.run(f'/certificate remove [find name="{name}"]')


def deploy(
    router: RouterLike,
    settings: Settings,
    crt_pem: bytes,
    key_pem: bytes,
    leaf: x509.Certificate,
    https_port: int,
    fetch: Callable[[str, int, str | None], x509.Certificate] = served_cert,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    prefix = f"{settings.cert_prefix}-"
    base = f"{prefix}{arrow.utcnow().format('YYYYMMDD-HHmmss')}"
    previous = preflight(router)
    switched = False
    try:
        router.put(f"{base}.crt", crt_pem)
        router.put(f"{base}.key", key_pem)
        router.run(f'/certificate import file-name={base}.crt passphrase=""')
        router.run(f'/certificate import file-name={base}.key passphrase=""')
        router.run(f"/ip service set [find name=www-ssl] certificate={base}.crt_0")
        switched = True
        _wait_until_served(fetch, settings.host, https_port, settings.address, fingerprint(leaf), sleep)
    except Exception as exc:
        if switched:
            restore = previous or "none"
            try:
                router.run(f"/ip service set [find name=www-ssl] certificate={restore}")
            except RenewError as rollback_exc:
                raise RenewError(
                    f"deployment failed ({exc}) and the rollback also failed ({rollback_exc}); "
                    "www-ssl may still point at the new certificate"
                ) from exc
            log.warning("Rolled www-ssl back to %r.", restore)
        _best_effort(lambda: _remove_certs(router, base))
        raise
    finally:
        _best_effort(lambda: router.run(f'/file remove [find name~"^{base}"]'))

    # The new certificate is live and verified: drop the older ones this tool created.
    listing = router.run(f'/certificate print terse where name~"^{prefix}"')
    for name in parse_cert_names(listing, prefix):
        if not name.startswith(base):
            router.run(f'/certificate remove [find name="{name}"]')


def _wait_until_served(
    fetch: Callable[[str, int, str | None], x509.Certificate],
    host: str,
    port: int,
    address: str | None,
    want: str,
    sleep: Callable[[float], None],
) -> None:
    for _ in range(5):
        sleep(2)
        try:
            if fingerprint(fetch(host, port, address)) == want:
                return
        except (OSError, RenewError):
            continue
    raise RenewError("router is not serving the new certificate after the switch")


def _best_effort(action: Callable[[], object]) -> None:
    try:
        action()
    except Exception as exc:  # noqa: BLE001 - cleanup must never hide the real outcome
        log.warning("Cleanup step failed: %s", exc)
