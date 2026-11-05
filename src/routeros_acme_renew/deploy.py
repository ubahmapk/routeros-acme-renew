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
# `/certificate print terse` lines look like " 0 KLT name=... ": an index, the flags (K = has a private key), then fields.
KEY_FLAG_RE = re.compile(r"^\s*\d+\s+([A-Za-z ]*?)\s*name=", re.MULTILINE)
# The service's allowed source ranges: `available-from` on current RouterOS, `address` on older versions.
SOURCES_RE = re.compile(r"(?:available-from|address)=(\S+)")
SERVICE_CERT_CMD = ":put [/ip service get [find name=www-ssl] certificate]"
BIND_ATTEMPTS = 15
VERIFY_ATTEMPTS = 5


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
        return router.run(SERVICE_CERT_CMD).strip()
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
        leaf_name = f"{base}.crt_0"
        _wait_for_private_key(router, leaf_name, sleep)
        switched = True  # from here the service may point at the new certificate, so a failure rolls it back
        _bind_service(router, leaf_name, sleep)
        try:
            _wait_until_served(fetch, settings.host, https_port, settings.address, fingerprint(leaf), sleep)
        except RenewError as exc:
            sources = _allowed_sources(router)
            if sources:
                raise RenewError(
                    f"{exc}. www-ssl only accepts connections from {sources}; is this machine's address in that list?"
                ) from exc
            raise
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


def _wait_for_private_key(router: RouterLike, name: str, sleep: Callable[[float], None], attempts: int = 10) -> None:
    """Wait until the router reports ``name`` with its private key (the K flag).

    Also turns a key import that silently did nothing into a clear error.
    """
    for _ in range(attempts):
        match = KEY_FLAG_RE.search(router.run(f'/certificate print terse where name="{name}"'))
        if match and "K" in match.group(1):
            return
        sleep(1)
    raise RenewError(f"the router has {name} but no private key for it (did the key import fail?)")


def _bind_service(router: RouterLike, name: str, sleep: Callable[[float], None], attempts: int = BIND_ATTEMPTS) -> None:
    """Point www-ssl at certificate ``name`` and confirm by reading the setting back.

    Right after an import RouterOS can reject the `set` ("input does not match any value of certificate") because the
    certificate is not yet a valid choice. That error appears only in the router's log: the SSH command still looks
    successful. So a successful-looking `set` proves nothing; keep trying until the router reports the new value.
    """
    for _ in range(attempts):
        router.run(f"/ip service set [find name=www-ssl] certificate={name}")
        if router.run(SERVICE_CERT_CMD).strip() == name:
            return
        sleep(1)
    raise RenewError(
        f"the router would not accept {name} as the www-ssl certificate "
        "(its log says 'input does not match any value of certificate' when it refuses)"
    )


def _allowed_sources(router: RouterLike) -> str | None:
    """The source ranges www-ssl accepts, or None if there is no restriction or it cannot be read."""
    try:
        match = SOURCES_RE.search(router.run("/ip service print terse where name=www-ssl"))
    except RenewError:
        return None
    return match.group(1) if match else None


def _wait_until_served(
    fetch: Callable[[str, int, str | None], x509.Certificate],
    host: str,
    port: int,
    address: str | None,
    want: str,
    sleep: Callable[[float], None],
) -> None:
    """Wait for the router to serve the certificate with fingerprint ``want``, reporting the last thing it did."""
    last = "no check ran"
    for _ in range(VERIFY_ATTEMPTS):
        sleep(2)
        try:
            served = fingerprint(fetch(host, port, address))
            if served == want:
                return
            last = f"the router serves another certificate (sha256 {served[:12]}, expected {want[:12]})"
        except (OSError, RenewError) as exc:
            last = f"{type(exc).__name__}: {exc}"
    raise RenewError(f"router is not serving the new certificate after the switch (last check: {last})")


def _best_effort(action: Callable[[], object]) -> None:
    try:
        action()
    except Exception as exc:  # noqa: BLE001 - cleanup must never hide the real outcome
        log.warning("Cleanup step failed: %s", exc)
