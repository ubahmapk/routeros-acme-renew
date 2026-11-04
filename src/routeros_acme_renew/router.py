"""SSH and SFTP to RouterOS with paramiko."""

from __future__ import annotations

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


class Router:
    """Context manager around one SSH connection. Host keys must already be in ~/.ssh/known_hosts."""

    def __init__(self, host: str, port: int, user: str, key_file: Path | None = None, timeout: float = 5.0) -> None:
        self.host, self.port, self.user, self.key_file, self.timeout = host, port, user, key_file, timeout
        self._client = paramiko.SSHClient()
        self._client.load_system_host_keys()
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())

    def __enter__(self) -> Self:
        try:
            self._client.connect(
                self.host,
                port=self.port,
                username=self.user,
                key_filename=str(self.key_file) if self.key_file else None,
                allow_agent=True,
                look_for_keys=True,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
        except (paramiko.SSHException, OSError) as exc:
            hint = f" (trust the host key first: ssh {self.user}@{self.host})" if "known_hosts" in str(exc) else ""
            raise RenewError(f"could not connect to {self.host}:{self.port} over SSH: {exc}{hint}") from exc
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
