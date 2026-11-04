from __future__ import annotations

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

    @field_validator("host")
    @classmethod
    def _valid_host(cls, v: str) -> str:
        if not HOST_RE.match(v):
            raise ValueError("must be a fully qualified DNS name such as router.example.com")
        return v.lower()
