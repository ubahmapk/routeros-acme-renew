from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, Field, field_validator

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


class Settings(BaseModel):
    """Validated inputs. Host and user end up in ssh arguments and RouterOS commands, so keep them strict."""

    host: str
    # No leading '-': ssh would read it as an option.
    ssh_user: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    cert_prefix: str = Field(default="acme", pattern=r"^[A-Za-z0-9]+$")
    # Where to connect when `host` (the certificate name) does not resolve from here.
    address: str | None = None

    @field_validator("host")
    @classmethod
    def _valid_host(cls, v: str) -> str:
        if not HOST_RE.match(v):
            raise ValueError("must be a fully qualified DNS name such as router.example.com")
        return v.lower()

    @field_validator("address")
    @classmethod
    def _valid_address(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            if not HOST_RE.match(v):
                raise ValueError("must be an IP address or a fully qualified DNS name") from None
            return v.lower()
        return v

    @property
    def target(self) -> str:
        """What every connection (TCP check, TLS read, SSH) goes to: the address if given, else the host name."""
        return self.address or self.host
