"""On-disk state: ACME account, issued certificate and key, and unfinished DNS challenge records."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict

DEFAULT_STATE_DIR = Path.home() / ".local" / "share" / "routeros-acme-renew"


def write_private(path: Path, data: bytes) -> None:
    """Write a file readable only by the owner, replacing any existing one atomically."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


@dataclass(frozen=True)
class State:
    """Everything lives under <base>/<staging|production>, so a staging cert is never deployed as a real one."""

    root: Path

    @classmethod
    def for_env(cls, base: Path, staging: bool) -> State:
        return cls(base.expanduser() / ("staging" if staging else "production"))

    @property
    def account_key(self) -> Path:
        return self.root / "account.key"

    @property
    def account_json(self) -> Path:
        return self.root / "account.json"

    @property
    def pending(self) -> Path:
        return self.root / "pending-challenges.json"

    @property
    def certs_dir(self) -> Path:
        return self.root / "certificates"

    def cert_path(self, host: str) -> Path:
        return self.certs_dir / f"{host}.crt"

    def key_path(self, host: str) -> Path:
        return self.certs_dir / f"{host}.key"

    def ensure(self) -> None:
        for d in (self.root, self.certs_dir):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)


class PendingRecord(TypedDict):
    zone_id: str
    name: str
    value: str


class PendingStore:
    """DNS challenge records we created and have not yet confirmed removed.

    An entry is written *before* the record is created, so a run that dies midway
    (kill, sleep, lost network) leaves a note the next run can act on.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def all(self) -> list[PendingRecord]:
        if not self.path.is_file():
            return []
        return json.loads(self.path.read_text())

    def _save(self, records: list[PendingRecord]) -> None:
        write_private(self.path, json.dumps(records, indent=2).encode())

    def add(self, record: PendingRecord) -> None:
        records = self.all()
        if record not in records:
            self._save([*records, record])

    def remove(self, record: PendingRecord) -> None:
        self._save([r for r in self.all() if r != record])
