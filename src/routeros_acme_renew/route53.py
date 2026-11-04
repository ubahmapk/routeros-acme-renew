"""DNS-01 TXT records in Route 53.

Careful with the record set at ``_acme-challenge.<host>``: Route 53 UPSERT replaces the *whole* set, so we
read what is there, add or remove only our own value, and refuse to touch a CNAME (delegated validation).
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError, WaiterError

from .errors import RenewError
from .state import PendingRecord, PendingStore

log = logging.getLogger(__name__)

DEFAULT_TTL = 60
WAITER_CONFIG = {"Delay": 5, "MaxAttempts": 24}


@contextmanager
def _aws_errors(action: str) -> Iterator[None]:
    try:
        yield
    except (BotoCoreError, ClientError, WaiterError) as exc:
        raise RenewError(f"Route 53 {action} failed: {exc}") from exc


def _quote(value: str) -> str:
    return f'"{value}"'


class Route53Dns:
    def __init__(self, client: Any, pending: PendingStore, zone_id: str | None = None) -> None:
        self.client = client
        self.pending = pending
        self.zone_id = zone_id

    # -- lookups ---------------------------------------------------------

    def find_zone_id(self, fqdn: str) -> str:
        """The public hosted zone with the longest name that contains ``fqdn``."""
        if self.zone_id:
            return self.zone_id
        labels = fqdn.rstrip(".").lower().split(".")
        with _aws_errors("zone lookup"):
            for i in range(len(labels) - 1):  # never a bare TLD
                candidate = ".".join(labels[i:]) + "."
                resp = self.client.list_hosted_zones_by_name(DNSName=candidate, MaxItems="5")
                for zone in resp["HostedZones"]:
                    if zone["Name"].lower() == candidate and not zone.get("Config", {}).get("PrivateZone", False):
                        return zone["Id"].split("/")[-1]
        raise RenewError(f"no public Route 53 hosted zone found for {fqdn} (set AWS_HOSTED_ZONE_ID?)")

    def _record_set(self, zone_id: str, name: str, rtype: str) -> dict[str, Any] | None:
        resp = self.client.list_resource_record_sets(
            HostedZoneId=zone_id, StartRecordName=name, StartRecordType=rtype, MaxItems="1"
        )
        for rs in resp["ResourceRecordSets"]:
            if rs["Name"].rstrip(".").lower() == name.rstrip(".").lower() and rs["Type"] == rtype:
                return rs
        return None

    # -- changes ---------------------------------------------------------

    def _change(self, action: str, zone_id: str, name: str, values: list[str], ttl: int) -> str:
        resp = self.client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Comment": "routeros-acme-renew",
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": name,
                            "Type": "TXT",
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": v} for v in values],
                        },
                    }
                ],
            },
        )
        return resp["ChangeInfo"]["Id"]

    def _wait_insync(self, change_id: str) -> None:
        self.client.get_waiter("resource_record_sets_changed").wait(Id=change_id, WaiterConfig=WAITER_CONFIG)

    def add_txt(self, name: str, value: str) -> PendingRecord:
        """Add ``value`` to the TXT set at ``name`` (keeping any other values) and wait until it is live."""
        zone_id = self.find_zone_id(name)
        with _aws_errors("TXT create"):
            if self._record_set(zone_id, name, "CNAME"):
                raise RenewError(f"{name} is a CNAME; delegated DNS-01 validation is not supported")
            existing = self._record_set(zone_id, name, "TXT")
            values = [rr["Value"] for rr in existing["ResourceRecords"]] if existing else []
            if _quote(value) not in values:
                values.append(_quote(value))
            record: PendingRecord = {"zone_id": zone_id, "name": name, "value": value}
            self.pending.add(record)  # before the change, so a crash leaves a note
            change_id = self._change("UPSERT", zone_id, name, values, existing["TTL"] if existing else DEFAULT_TTL)
            self._wait_insync(change_id)
        return record

    def remove_txt(self, record: PendingRecord) -> None:
        """Remove only our value. The record set is deleted only if ours was the last value."""
        zone_id, name, value = record["zone_id"], record["name"], record["value"]
        with _aws_errors("TXT cleanup"):
            existing = self._record_set(zone_id, name, "TXT")
            if existing:
                current = [rr["Value"] for rr in existing["ResourceRecords"]]
                remaining = [v for v in current if v != _quote(value)]
                if len(remaining) != len(current):
                    if remaining:
                        self._change("UPSERT", zone_id, name, remaining, existing["TTL"])
                    else:
                        self._change("DELETE", zone_id, name, current, existing["TTL"])
        self.pending.remove(record)

    def sweep(self) -> None:
        """Remove challenge records left behind by an earlier run that did not finish."""
        for record in self.pending.all():
            log.info("Removing leftover challenge record %s", record["name"])
            try:
                self.remove_txt(record)
            except RenewError as exc:
                log.warning("Could not remove leftover record %s: %s", record["name"], exc)
