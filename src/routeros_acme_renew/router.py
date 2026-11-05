"""SSH and SFTP to RouterOS with paramiko."""

from __future__ import annotations

import base64
import binascii
import io
import re
from pathlib import Path
from types import TracebackType
from typing import Self

import paramiko

from .errors import RenewError

# RouterOS does not reliably set a non-zero exit status, so also look for its error text.
_ERROR_LINE = re.compile(
    r"^\s*(failure|error|bad command name|syntax error|no such item|expected end of command|invalid value)",
    re.IGNORECASE | re.MULTILINE,
)


def public_key_blob(path: Path) -> bytes | None:
    """The key bytes from an OpenSSH public key file, or None if ``path`` is not one (so: a private key)."""
    try:
        parts = path.read_text().split()
    except (OSError, UnicodeDecodeError):
        return None
    if len(parts) < 2 or not re.match(r"^(ssh-|ecdsa-|sk-)", parts[0]):
        return None
    try:
        return base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        return None


def agent_key(blob: bytes, source: Path) -> paramiko.PKey:
    """The ssh-agent key whose public half is ``blob``."""
    try:
        keys = paramiko.Agent().get_keys()
    except paramiko.SSHException as exc:
        raise RenewError(f"cannot read keys from the ssh-agent (is SSH_AUTH_SOCK set?): {exc}") from exc
    for key in keys:
        if key.asbytes() == blob:
            return key
    raise RenewError(f"no key in the ssh-agent matches {source} (is SSH_AUTH_SOCK set, and is the key available?)")


class Router:
    """Context manager around one SSH connection.

    ``target`` is the name or IP actually connected to. paramiko looks the host key up in ~/.ssh/known_hosts
    under that same string, so it must already be trusted there. ~/.ssh/config is not read.
    """

    def __init__(
        self,
        target: str,
        port: int,
        user: str,
        key_file: Path | None = None,
        timeout: float = 5.0,
        auth_timeout: float = 60.0,
    ) -> None:
        # `timeout` covers the TCP connect and SSH banner. `auth_timeout` is longer on purpose: with the 1Password
        # ssh-agent, signing waits for a person to approve the request.
        self.target, self.port, self.user, self.key_file = target, port, user, key_file
        self.timeout, self.auth_timeout = timeout, auth_timeout
        self._client = paramiko.SSHClient()
        self._client.load_system_host_keys()
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())

    def _auth_options(self) -> dict:
        """How to authenticate.

        With a key given, use only that key: a public key file picks the matching key from the ssh-agent, a private
        key file is used directly. Without one, paramiko offers every agent key in turn, and RouterOS drops the
        connection after the first one it rejects.
        """
        if self.key_file is None:
            return {"allow_agent": True, "look_for_keys": True}
        path = self.key_file.expanduser()
        blob = public_key_blob(path)
        if blob is not None:
            return {"pkey": agent_key(blob, path), "allow_agent": False, "look_for_keys": False}
        return {"key_filename": str(path), "allow_agent": False, "look_for_keys": False}

    def __enter__(self) -> Self:
        try:
            self._client.connect(
                self.target,
                port=self.port,
                username=self.user,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.auth_timeout,
                **self._auth_options(),
            )
        except (paramiko.SSHException, OSError) as exc:
            text, hint = str(exc), ""
            if "known_hosts" in text:
                hint = f" (trust the host key first: ssh {self.user}@{self.target})"
            elif "Authentication timeout" in text:
                hint = (
                    " (no reply to the signing request; if 1Password asked to approve the SSH key, approve it sooner)"
                )
            elif "No existing session" in text or isinstance(exc, paramiko.AuthenticationException):
                hint = " (the router rejected the key; name the right one with --ssh-key, a public key file for an agent key)"
            raise RenewError(f"could not connect to {self.target}:{self.port} over SSH: {exc}{hint}") from exc
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self._client.close()

    def run(self, command: str, timeout: float = 60.0) -> str:
        """Run one RouterOS command and return its output; raise RenewError if it failed."""
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            stdin.close()
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            status = stdout.channel.recv_exit_status()
        except (paramiko.SSHException, OSError) as exc:
            raise RenewError(f"ssh command failed ({command!r}): {exc}") from exc
        if status != 0 or _ERROR_LINE.search(out) or _ERROR_LINE.search(err):
            raise RenewError(f"RouterOS rejected {command!r}: {(err or out).strip() or f'exit status {status}'}")
        return out

    def put(self, remote_name: str, data: bytes) -> None:
        """Upload bytes to a file in the router's root directory."""
        try:
            with self._client.open_sftp() as sftp:
                sftp.putfo(io.BytesIO(data), remote_name)
        except (paramiko.SSHException, OSError) as exc:
            raise RenewError(f"upload of {remote_name} failed: {exc}") from exc
