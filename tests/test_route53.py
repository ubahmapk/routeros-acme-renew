from __future__ import annotations

import datetime as dt

import boto3
import pytest
from botocore.stub import ANY, Stubber

from routeros_acme_renew.errors import RenewError
from routeros_acme_renew.route53 import Route53Dns
from routeros_acme_renew.state import PendingStore

ZONE = "Z123"
NAME = "_acme-challenge.router.example.com"
CHANGE = {"Id": "/change/C1", "Status": "PENDING", "SubmittedAt": dt.datetime(2026, 1, 1, tzinfo=dt.UTC)}
INSYNC = {"ChangeInfo": {**CHANGE, "Status": "INSYNC"}}


@pytest.fixture
def aws():
    client = boto3.client("route53", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y")
    with Stubber(client) as stub:
        yield client, stub
    stub.assert_no_pending_responses()


def rrsets(*sets):
    return {"ResourceRecordSets": list(sets), "IsTruncated": False, "MaxItems": "1"}


def txt(*values, ttl=300):
    return {"Name": NAME + ".", "Type": "TXT", "TTL": ttl, "ResourceRecords": [{"Value": v} for v in values]}


def list_params(rtype):
    return {"HostedZoneId": ZONE, "StartRecordName": NAME, "StartRecordType": rtype, "MaxItems": "1"}


def change_params(action, values, ttl):
    return {
        "HostedZoneId": ZONE,
        "ChangeBatch": {
            "Comment": "routeros-acme-renew",
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": NAME,
                        "Type": "TXT",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": v} for v in values],
                    },
                }
            ],
        },
    }


def make(aws, tmp_path, zone_id=ZONE):
    client, stub = aws
    return Route53Dns(client, PendingStore(tmp_path / "pending.json"), zone_id), stub


def test_add_keeps_existing_values_and_waits_for_insync(aws, tmp_path):
    dns, stub = make(aws, tmp_path)
    stub.add_response("list_resource_record_sets", rrsets(), list_params("CNAME"))
    stub.add_response("list_resource_record_sets", rrsets(txt('"other"')), list_params("TXT"))
    stub.add_response(
        "change_resource_record_sets", {"ChangeInfo": CHANGE}, change_params("UPSERT", ['"other"', '"new"'], 300)
    )
    stub.add_response("get_change", INSYNC, {"Id": ANY})

    record = dns.add_txt(NAME, "new")

    assert record == {"zone_id": ZONE, "name": NAME, "value": "new"}
    assert dns.pending.all() == [record]


def test_add_refuses_a_cname(aws, tmp_path):
    dns, stub = make(aws, tmp_path)
    stub.add_response(
        "list_resource_record_sets",
        rrsets({"Name": NAME + ".", "Type": "CNAME", "TTL": 60, "ResourceRecords": [{"Value": "x.other.net"}]}),
        list_params("CNAME"),
    )
    with pytest.raises(RenewError, match="CNAME"):
        dns.add_txt(NAME, "new")
    assert dns.pending.all() == []


def test_remove_leaves_other_values_in_place(aws, tmp_path):
    dns, stub = make(aws, tmp_path)
    record = {"zone_id": ZONE, "name": NAME, "value": "new"}
    dns.pending.add(record)
    stub.add_response("list_resource_record_sets", rrsets(txt('"other"', '"new"')), list_params("TXT"))
    stub.add_response("change_resource_record_sets", {"ChangeInfo": CHANGE}, change_params("UPSERT", ['"other"'], 300))

    dns.remove_txt(record)

    assert dns.pending.all() == []


def test_remove_deletes_the_set_when_ours_is_the_last_value(aws, tmp_path):
    dns, stub = make(aws, tmp_path)
    record = {"zone_id": ZONE, "name": NAME, "value": "new"}
    dns.pending.add(record)
    stub.add_response("list_resource_record_sets", rrsets(txt('"new"', ttl=60)), list_params("TXT"))
    stub.add_response("change_resource_record_sets", {"ChangeInfo": CHANGE}, change_params("DELETE", ['"new"'], 60))

    dns.remove_txt(record)

    assert dns.pending.all() == []


def test_remove_is_a_noop_when_the_value_is_already_gone(aws, tmp_path):
    dns, stub = make(aws, tmp_path)
    record = {"zone_id": ZONE, "name": NAME, "value": "new"}
    dns.pending.add(record)
    stub.add_response("list_resource_record_sets", rrsets(), list_params("TXT"))

    dns.remove_txt(record)

    assert dns.pending.all() == []


def test_sweep_removes_leftovers_and_keeps_notes_for_failures(aws, tmp_path):
    dns, stub = make(aws, tmp_path)
    gone = {"zone_id": ZONE, "name": NAME, "value": "old1"}
    stuck = {"zone_id": ZONE, "name": NAME, "value": "old2"}
    dns.pending.add(gone)
    dns.pending.add(stuck)
    stub.add_response("list_resource_record_sets", rrsets(), list_params("TXT"))
    stub.add_client_error("list_resource_record_sets", "AccessDenied")

    dns.sweep()

    assert dns.pending.all() == [stuck]


def test_zone_lookup_picks_the_longest_public_zone(aws, tmp_path):
    dns, stub = make(aws, tmp_path, zone_id=None)
    stub.add_response(
        "list_hosted_zones_by_name",
        {"HostedZones": [], "IsTruncated": False, "MaxItems": "5"},
        {"DNSName": "_acme-challenge.router.example.com.", "MaxItems": "5"},
    )
    stub.add_response(
        "list_hosted_zones_by_name",
        {"HostedZones": [], "IsTruncated": False, "MaxItems": "5"},
        {"DNSName": "router.example.com.", "MaxItems": "5"},
    )
    zone = {"Id": "/hostedzone/ZPUB", "Name": "example.com.", "CallerReference": "r", "Config": {"PrivateZone": False}}
    private = {**zone, "Id": "/hostedzone/ZPRIV", "Config": {"PrivateZone": True}}
    stub.add_response(
        "list_hosted_zones_by_name",
        {"HostedZones": [private, zone], "IsTruncated": False, "MaxItems": "5"},
        {"DNSName": "example.com.", "MaxItems": "5"},
    )

    assert dns.find_zone_id(NAME) == "ZPUB"


def test_zone_lookup_failure_is_a_clear_error(aws, tmp_path):
    dns, stub = make(aws, tmp_path, zone_id=None)
    # "x.invalid" has a single candidate, "x.invalid."; the bare TLD is never queried.
    stub.add_response("list_hosted_zones_by_name", {"HostedZones": [], "IsTruncated": False, "MaxItems": "5"})
    with pytest.raises(RenewError, match="no public Route 53 hosted zone"):
        dns.find_zone_id("x.invalid")
