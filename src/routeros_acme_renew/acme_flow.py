"""Talk to the ACME CA with the ``acme`` library (the one Certbot is built on), solving DNS-01 via Route 53."""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import josepy
import requests
from acme import challenges, client, crypto_util, errors, messages
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .config import Settings
from .errors import RenewError
from .route53 import Route53Dns
from .state import State, write_private

log = logging.getLogger(__name__)

LE_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
USER_AGENT = "routeros-acme-renew"
ORDER_TIMEOUT = datetime.timedelta(seconds=180)

_PEM = serialization.Encoding.PEM
_PKCS8 = serialization.PrivateFormat.PKCS8
_NO_ENCRYPTION = serialization.NoEncryption()


class DnsSolver(Protocol):
    def add_txt(self, name: str, value: str) -> Any: ...
    def remove_txt(self, record: Any) -> None: ...


@dataclass(frozen=True)
class Issued:
    fullchain_pem: bytes
    key_pem: bytes


def new_ec_key_pem() -> bytes:
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(_PEM, _PKCS8, _NO_ENCRYPTION)


def load_or_create_account_key(path: Path) -> ec.EllipticCurvePrivateKey:
    if path.is_file():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise RenewError(f"{path} is not an EC key")
        return key
    key = ec.generate_private_key(ec.SECP256R1())
    write_private(path, key.private_bytes(_PEM, _PKCS8, _NO_ENCRYPTION))
    return key


def build_network(key: ec.EllipticCurvePrivateKey) -> client.ClientNetwork:
    # The library defaults to RS256; an EC P-256 account key must sign with ES256.
    return client.ClientNetwork(josepy.JWKEC(key=key), alg=josepy.ES256, user_agent=USER_AGENT)


def register(acme: client.ClientV2, state: State, email: str) -> None:
    """Use the stored ACME account, or create one. Creating one accepts the CA's terms of service."""
    if state.account_json.is_file():
        regr = messages.RegistrationResource.json_loads(state.account_json.read_text())
        regr = acme.query_registration(regr)
    else:
        try:
            regr = acme.new_account(messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True))
        except errors.ConflictError as exc:  # key already registered, but we lost the account URL
            regr = acme.query_registration(
                messages.RegistrationResource(body=messages.Registration(), uri=exc.location)
            )
    write_private(state.account_json, regr.json_dumps().encode())


def pick_dns01(authzr: messages.AuthorizationResource) -> messages.ChallengeBody:
    for challb in authzr.body.challenges:
        if isinstance(challb.chall, challenges.DNS01):
            return challb
    raise RenewError("the CA did not offer a DNS-01 challenge")


def solve(acme: Any, orderr: Any, host: str, dns: DnsSolver, deadline: datetime.datetime) -> Any:
    """Publish each challenge record, ask the CA to validate, finalize, and always clean the records up."""
    records: list[Any] = []
    try:
        for authzr in orderr.authorizations:
            challb = pick_dns01(authzr)
            response, validation = challb.response_and_validation(acme.net.key)
            records.append(dns.add_txt(challb.validation_domain_name(host), validation))
            acme.answer_challenge(challb, response)
        return acme.poll_and_finalize(orderr, deadline)
    finally:
        for record in records:
            try:
                dns.remove_txt(record)
            except RenewError as exc:
                log.warning("Challenge record cleanup failed (the next run retries it): %s", exc)


def issue(settings: Settings, state: State, directory_url: str, dns: Route53Dns) -> Issued:
    """Order a certificate for ``settings.host``. Returns the full chain and a new EC P-256 private key."""
    try:
        net = build_network(load_or_create_account_key(state.account_key))
        acme = client.ClientV2(client.ClientV2.get_directory(directory_url, net), net)
        register(acme, state, settings.email)
        key_pem = new_ec_key_pem()
        orderr = acme.new_order(crypto_util.make_csr(key_pem, [settings.host]))
        final = solve(acme, orderr, settings.host, dns, datetime.datetime.now() + ORDER_TIMEOUT)
    except (errors.Error, requests.RequestException) as exc:
        raise RenewError(f"ACME request failed: {exc}") from exc
    return Issued(final.fullchain_pem.encode(), key_pem)
