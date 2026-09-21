"""The write-ahead ledger: ordering and idempotency."""

import json

import boto3
import pytest
from botocore.stub import ANY, Stubber

from irlib import incidents


@pytest.fixture
def ddb(monkeypatch):
    client = boto3.client("dynamodb", region_name="us-east-1")
    with Stubber(client) as stubber:
        monkeypatch.setattr(incidents, "_client", lambda c=None: client)
        yield stubber


def _conditional_failure(stubber, operation):
    stubber.add_client_error(
        operation,
        service_error_code="ConditionalCheckFailedException",
        http_status_code=400,
    )


def test_begin_action_records_prior_state_before_returning(ddb):
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return {}

    ddb.client.put_item = capture
    state, record = incidents.begin_action(
        "inc-1", "network-isolate#i-0abc", "network-isolate", "i-0abc",
        prior_state={"securityGroups": ["sg-1", "sg-2"]},
    )

    assert state == incidents.PROCEED
    item = captured["Item"]
    assert item["Status"]["S"] == incidents.STATUS_PENDING
    # The prior state is persisted up front; without it nothing could be released.
    assert json.loads(item["PriorState"]["S"]) == {"securityGroups": ["sg-1", "sg-2"]}
    assert captured["ConditionExpression"] == "attribute_not_exists(RecordId)"


def test_completed_action_is_skipped_on_a_retry(ddb):
    """A re-run must not repeat work that already finished."""
    _conditional_failure(ddb, "put_item")
    ddb.add_response(
        "get_item",
        {
            "Item": {
                "IncidentId": {"S": "inc-1"},
                "RecordId": {"S": "ACTION#network-isolate#i-0abc"},
                "Status": {"S": incidents.STATUS_DONE},
                "Result": {"S": json.dumps({"securityGroupId": "sg-q"})},
            }
        },
        None,
    )
    state, record = incidents.begin_action(
        "inc-1", "network-isolate#i-0abc", "network-isolate", "i-0abc"
    )
    assert state == incidents.SKIP
    assert record["Result"]["securityGroupId"] == "sg-q"


def test_interrupted_action_is_retried_with_the_original_prior_state(ddb):
    """A PENDING record means we died mid-action. The first capture stays authoritative."""
    _conditional_failure(ddb, "put_item")
    ddb.add_response(
        "get_item",
        {
            "Item": {
                "IncidentId": {"S": "inc-1"},
                "RecordId": {"S": "ACTION#network-isolate#i-0abc"},
                "Status": {"S": incidents.STATUS_PENDING},
                "PriorState": {"S": json.dumps({"securityGroups": ["sg-original"]})},
            }
        },
        None,
    )
    state, record = incidents.begin_action(
        "inc-1", "network-isolate#i-0abc", "network-isolate", "i-0abc",
        prior_state={"securityGroups": ["sg-quarantine"]},
    )
    assert state == incidents.RETRY
    assert record["PriorState"]["securityGroups"] == ["sg-original"]


def test_opening_the_same_incident_twice_is_a_recurrence(ddb):
    """GuardDuty re-emits a finding id, and the incident id derives from it."""
    _conditional_failure(ddb, "put_item")
    ddb.add_response(
        "get_item",
        {"Item": {"IncidentId": {"S": "inc-1"}, "Status": {"S": "OPEN"}}},
        None,
    )
    state, _ = incidents.open_incident("inc-1", {"FindingId": "f-1"})
    assert state == "EXISTS"


def test_open_incident_creates_when_absent(ddb):
    ddb.add_response("put_item", {}, {"TableName": ANY, "Item": ANY, "ConditionExpression": ANY})
    state, item = incidents.open_incident("inc-1", {"FindingId": "f-1", "FindingType": "T"})
    assert state == "CREATED"
    assert item["FindingId"] == "f-1"


def test_severity_survives_the_round_trip_as_json(ddb):
    """DynamoDB has no float type; blobs are stored as JSON text."""
    captured = {}
    ddb.client.put_item = lambda **kw: captured.update(kw) or {}
    incidents.open_incident("inc-1", {"FindingId": "f-1", "summary": {"severity": 8.5}})
    assert json.loads(captured["Item"]["Attributes"]["S"])["summary"]["severity"] == 8.5


def test_complete_and_fail_set_a_terminal_status(ddb):
    for operation, call, expected in (
        ("update_item", incidents.complete_action, incidents.STATUS_DONE),
        ("update_item", incidents.fail_action, incidents.STATUS_FAILED),
    ):
        captured = {}
        ddb.client.update_item = lambda **kw: captured.update(kw) or {}
        call("inc-1", "k", "payload")
        assert captured["ExpressionAttributeValues"][":s"]["S"] == expected


def test_list_actions_is_ordered_oldest_first(ddb):
    ddb.add_response(
        "query",
        {
            "Items": [
                {"RecordId": {"S": "ACTION#b"}, "StartedAt": {"S": "2026-09-21T12:00:02Z"},
                 "Action": {"S": "imds"}, "Status": {"S": "DONE"}},
                {"RecordId": {"S": "ACTION#a"}, "StartedAt": {"S": "2026-09-21T12:00:01Z"},
                 "Action": {"S": "network"}, "Status": {"S": "DONE"}},
            ]
        },
        None,
    )
    actions = incidents.list_actions("inc-1")
    assert [a["Action"] for a in actions] == ["network", "imds"]
