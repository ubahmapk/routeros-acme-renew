from __future__ import annotations

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


def test_connect_failure_hints_at_known_hosts(monkeypatch):
    router, fake = make_router(monkeypatch)

    def refuse(host, **kwargs):
        raise paramiko.SSHException("Server 'router.example.com' not found in known_hosts")

    fake.connect = refuse
    with pytest.raises(RenewError, match="trust the host key first"), router:
        pass
