from __future__ import annotations

import base64
import io

import paramiko
import pytest

from routeros_acme_renew import router as router_mod
from routeros_acme_renew.errors import RenewError

IMPORT_OK = (
    "certificates-imported: 1\n"
    "private-keys-imported: 0\n"
    "files-imported: 1\n"
    "decryption-failures: 0\n"
    "keys-with-no-certificate: 0\n"
)


class FakeStream:
    def __init__(self, text: str, status: int = 0) -> None:
        self._text = text
        self.channel = type("Chan", (), {"recv_exit_status": lambda _self: status})()

    def read(self) -> bytes:
        return self._text.encode()

    def close(self) -> None:
        pass


class FakeSftp:
    def __init__(self, store: dict[str, bytes], fail: bool = False) -> None:
        self.store, self.fail = store, fail

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def putfo(self, fh: io.BytesIO, name: str) -> None:
        if self.fail:
            raise OSError("disk full")
        self.store[name] = fh.read()


class FakeClient:
    def __init__(self, out="", err="", status=0, fail_sftp=False) -> None:
        self.out, self.err, self.status, self.fail_sftp = out, err, status, fail_sftp
        self.files: dict[str, bytes] = {}
        self.commands: list[str] = []
        self.connected_with: dict | None = None
        self.policy = None

    def load_system_host_keys(self) -> None:
        pass

    def set_missing_host_key_policy(self, policy) -> None:
        self.policy = policy

    def connect(self, host, **kwargs) -> None:
        self.connected_with = {"host": host, **kwargs}

    def exec_command(self, command, timeout=None):
        self.commands.append(command)
        return FakeStream(""), FakeStream(self.out, self.status), FakeStream(self.err)

    def open_sftp(self) -> FakeSftp:
        return FakeSftp(self.files, self.fail_sftp)

    def close(self) -> None:
        pass


def make_router(monkeypatch, **client_kwargs) -> tuple[router_mod.Router, FakeClient]:
    fake = FakeClient(**client_kwargs)
    monkeypatch.setattr(router_mod.paramiko, "SSHClient", lambda: fake)
    return router_mod.Router("router.example.com", 22, "acme"), fake


def test_unknown_host_keys_are_rejected_not_auto_added(monkeypatch):
    _, fake = make_router(monkeypatch)
    assert isinstance(fake.policy, paramiko.RejectPolicy)


def test_normal_import_summary_is_not_mistaken_for_an_error(monkeypatch):
    router, _ = make_router(monkeypatch, out=IMPORT_OK)
    assert router.run('/certificate import file-name=x.crt passphrase=""') == IMPORT_OK


@pytest.mark.parametrize(
    "text",
    [
        "failure: file doesn't exist\n",
        "bad command name foo (line 1 column 1)\n",
        "no such item (4)\n",
        "syntax error (line 1 column 9)\n",
    ],
)
def test_routeros_error_text_raises_even_with_exit_status_zero(monkeypatch, text):
    router, _ = make_router(monkeypatch, out=text)
    with pytest.raises(RenewError, match="rejected"):
        router.run("/anything")


def test_nonzero_exit_status_raises(monkeypatch):
    router, _ = make_router(monkeypatch, err="boom", status=1)
    with pytest.raises(RenewError, match="boom"):
        router.run("/anything")


def test_put_uploads_bytes(monkeypatch):
    router, fake = make_router(monkeypatch)
    router.put("acme-1.crt", b"PEM")
    assert fake.files == {"acme-1.crt": b"PEM"}


def test_put_failure_is_a_renew_error(monkeypatch):
    router, _ = make_router(monkeypatch, fail_sftp=True)
    with pytest.raises(RenewError, match="upload of acme-1.crt failed"):
        router.put("acme-1.crt", b"PEM")


def test_connects_to_the_target_it_was_given(monkeypatch):
    router, fake = make_router(monkeypatch)
    with router:
        pass
    assert fake.connected_with["host"] == "router.example.com"


def test_connects_to_an_ip_target_so_known_hosts_is_checked_under_that_ip(monkeypatch):
    _, fake = make_router(monkeypatch)
    with router_mod.Router("172.16.2.1", 22, "acme"):
        pass
    assert fake.connected_with["host"] == "172.16.2.1"


class FakeAgentKey:
    def __init__(self, blob: bytes) -> None:
        self._blob = blob

    def asbytes(self) -> bytes:
        return self._blob


def fake_agent(monkeypatch, *blobs: bytes) -> list[FakeAgentKey]:
    keys = [FakeAgentKey(b) for b in blobs]

    class Agent:
        def get_keys(self):
            return keys

    monkeypatch.setattr(router_mod.paramiko, "Agent", Agent)
    return keys


def public_key_file(tmp_path, blob: bytes, name="guard.pub"):
    path = tmp_path / name
    path.write_text(f"ssh-ed25519 {base64.b64encode(blob).decode()} 1P Ed25519 SSH Key\n")
    return path


def test_without_a_key_every_agent_key_and_key_file_is_tried(monkeypatch):
    router, fake = make_router(monkeypatch)
    with router:
        pass
    assert fake.connected_with["allow_agent"] is True
    assert fake.connected_with["look_for_keys"] is True
    assert "pkey" not in fake.connected_with


def test_a_public_key_file_selects_exactly_that_agent_key(monkeypatch, tmp_path):
    keys = fake_agent(monkeypatch, b"other-key", b"the-right-key", b"third-key")
    _, fake = make_router(monkeypatch)
    pub = public_key_file(tmp_path, b"the-right-key")

    with router_mod.Router("172.16.2.1", 22, "acme", key_file=pub):
        pass

    assert fake.connected_with["pkey"] is keys[1]
    assert fake.connected_with["allow_agent"] is False  # offering other keys is what makes RouterOS hang up
    assert fake.connected_with["look_for_keys"] is False


def test_a_public_key_file_that_is_not_in_the_agent_is_a_clear_error(monkeypatch, tmp_path):
    fake_agent(monkeypatch, b"other-key")
    make_router(monkeypatch)
    pub = public_key_file(tmp_path, b"missing-key")

    with (
        pytest.raises(RenewError, match="no key in the ssh-agent matches"),
        router_mod.Router("172.16.2.1", 22, "acme", key_file=pub),
    ):
        pass


def test_a_private_key_file_is_used_directly_and_alone(monkeypatch, tmp_path):
    _, fake = make_router(monkeypatch)
    # Anything that is not an OpenSSH public key line is treated as a private key file; the content is irrelevant here.
    private = tmp_path / "id_ed25519"
    private.write_text("opaque private key file contents\n")

    with router_mod.Router("172.16.2.1", 22, "acme", key_file=private):
        pass

    assert fake.connected_with["key_filename"] == str(private)
    assert fake.connected_with["allow_agent"] is False
    assert "pkey" not in fake.connected_with


def test_authentication_gets_a_longer_timeout_than_the_connection_so_a_person_can_approve(monkeypatch):
    router, fake = make_router(monkeypatch)
    with router:
        pass
    assert fake.connected_with["timeout"] == 5.0
    assert fake.connected_with["auth_timeout"] == 60.0


def test_an_authentication_timeout_is_not_blamed_on_the_router_rejecting_the_key(monkeypatch):
    router, fake = make_router(monkeypatch)

    def slow(host, **kwargs):
        raise paramiko.AuthenticationException("Authentication timeout.")

    fake.connect = slow
    with pytest.raises(RenewError, match="approve it sooner") as info, router:
        pass
    assert "rejected the key" not in str(info.value)


def test_a_dropped_connection_during_auth_explains_how_to_name_the_key(monkeypatch):
    router, fake = make_router(monkeypatch)

    def dropped(host, **kwargs):
        raise paramiko.SSHException("No existing session")

    fake.connect = dropped
    with pytest.raises(RenewError, match="--ssh-key"), router:
        pass


def test_connect_failure_hints_at_known_hosts(monkeypatch):
    router, fake = make_router(monkeypatch)

    def refuse(host, **kwargs):
        raise paramiko.SSHException("Server 'router.example.com' not found in known_hosts")

    fake.connect = refuse
    with pytest.raises(RenewError, match="trust the host key first"), router:
        pass
