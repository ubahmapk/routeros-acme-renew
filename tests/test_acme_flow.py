from __future__ import annotations

import datetime as dt
import os
from types import SimpleNamespace

import josepy
import pytest
from acme import challenges, messages
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import HOST
from routeros_acme_renew import acme_flow
from routeros_acme_renew.errors import RenewError


def order_with(*challs):
    body = messages.ChallengeBody(chall=challs[0], uri="https://acme.test/chall/1", status=messages.STATUS_PENDING)
    authz = messages.AuthorizationResource(
        body=messages.Authorization(
            identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=HOST), challenges=(body,)
        ),
        uri="https://acme.test/authz/1",
    )
    return SimpleNamespace(authorizations=[authz]), body


class FakeAcme:
    def __init__(self, events, fail_on_answer=False):
        self.net = SimpleNamespace(key=josepy.JWKEC(key=ec.generate_private_key(ec.SECP256R1())))
        self.events, self.fail_on_answer = events, fail_on_answer

    def answer_challenge(self, challb, response):
        self.events.append("answer")
        if self.fail_on_answer:
            raise RuntimeError("CA said no")

    def poll_and_finalize(self, orderr, deadline):
        self.events.append("finalize")
        return SimpleNamespace(fullchain_pem="CHAIN")


class FakeDns:
    def __init__(self, events, fail_remove=False):
        self.events, self.fail_remove, self.added = events, fail_remove, []

    def add_txt(self, name, value):
        self.events.append("add")
        self.added.append((name, value))
        return {"name": name, "value": value}

    def remove_txt(self, record):
        self.events.append("remove")
        if self.fail_remove:
            raise RenewError("route53 down")


DEADLINE = dt.datetime.now() + dt.timedelta(seconds=5)


def test_solve_publishes_then_answers_then_finalizes_then_cleans_up():
    events: list[str] = []
    orderr, _ = order_with(challenges.DNS01(token=os.urandom(32)))
    dns = FakeDns(events)

    result = acme_flow.solve(FakeAcme(events), orderr, HOST, dns, DEADLINE)

    assert result.fullchain_pem == "CHAIN"
    assert events == ["add", "answer", "finalize", "remove"]
    name, value = dns.added[0]
    assert name == f"_acme-challenge.{HOST}"
    assert len(value) == 43  # base64url SHA-256 of the key authorization


def test_solve_still_cleans_up_when_the_ca_rejects_the_challenge():
    events: list[str] = []
    orderr, _ = order_with(challenges.DNS01(token=os.urandom(32)))

    with pytest.raises(RuntimeError, match="CA said no"):
        acme_flow.solve(FakeAcme(events, fail_on_answer=True), orderr, HOST, FakeDns(events), DEADLINE)

    assert events == ["add", "answer", "remove"]


def test_solve_does_not_mask_the_result_when_cleanup_fails():
    events: list[str] = []
    orderr, _ = order_with(challenges.DNS01(token=os.urandom(32)))

    result = acme_flow.solve(FakeAcme(events), orderr, HOST, FakeDns(events, fail_remove=True), DEADLINE)

    assert result.fullchain_pem == "CHAIN"


def test_pick_dns01_requires_a_dns_challenge():
    orderr, _ = order_with(challenges.HTTP01(token=os.urandom(32)))
    with pytest.raises(RenewError, match="DNS-01"):
        acme_flow.pick_dns01(orderr.authorizations[0])


def test_account_key_is_created_once_and_reused(tmp_path):
    path = tmp_path / "account.key"
    first = acme_flow.load_or_create_account_key(path)
    second = acme_flow.load_or_create_account_key(path)
    assert first.public_key().public_numbers() == second.public_key().public_numbers()
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_account_network_signs_with_es256(tmp_path):
    net = acme_flow.build_network(acme_flow.load_or_create_account_key(tmp_path / "k"))
    assert net.alg is josepy.ES256
