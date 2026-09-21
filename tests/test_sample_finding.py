"""The committed sample finding, end to end.

events/guardduty-ec2-finding.json names i-REPLACE_ME. GuardDuty's own sample
findings behave the same way - they reference fake resource ids. The pipeline
has to degrade all the way to a notification without ever pointing a mutating
call at that id, and without claiming it contained anything.
"""

import boto3
import pytest
from botocore.stub import Stubber

from conftest import load_lambda
from irlib import findings, incidents, policy

verify = load_lambda("verify")
enrich = load_lambda("enrich")
decide = load_lambda("decide")
alert = load_lambda("alert")

EVENT = {
    "incidentId": "test-finding-ir-pipeline",
    "findingId": "test-finding-ir-pipeline",
    "detectorId": "example",
    "accountId": "123456789012",
    "region": "us-east-1",
}


@pytest.fixture
def quiet_ledger(monkeypatch):
    class Accepts:
        def __getattr__(self, _name):
            return lambda **kwargs: {}

    monkeypatch.setattr(incidents, "_client", lambda c=None: Accepts())


def test_fake_instance_id_never_becomes_a_target(monkeypatch, quiet_ledger, sample_event):
    detail = sample_event["detail"]
    api_finding = {
        "SchemaVersion": "2.0",
        "Id": detail["id"],
        "Type": detail["type"],
        "Severity": detail["severity"],
        "AccountId": detail["accountId"],
        "Region": detail["region"],
        "Arn": detail["arn"],
        "CreatedAt": detail["createdAt"],
        "UpdatedAt": detail["updatedAt"],
        "Title": detail["title"],
        "Description": detail["description"],
        "Resource": {
            "ResourceType": "Instance",
            "InstanceDetails": {"InstanceId": "i-REPLACE_ME"},
        },
        "Service": {"Archived": False, "ResourceRole": "ACTOR", "DetectorId": "example"},
    }

    client = boto3.client("guardduty", region_name="us-east-1")
    with Stubber(client) as stubber:
        monkeypatch.setattr(findings, "_client", lambda c=None: client)
        stubber.add_response("get_findings", {"Findings": [api_finding]}, None)
        verified = verify.handler(dict(EVENT), None)

    assert verified["targets"]["instanceIds"] == []
    assert verified["targets"]["rejectedInstanceIds"] == ["i-REPLACE_ME"]



def test_enrichment_degrades_to_production_without_an_instance(monkeypatch):
    """No usable id means no DescribeInstances call at all."""
    calls = []
    monkeypatch.setattr(
        enrich, "ec2_client", type("Boom", (), {"describe_instances": lambda self, **k: calls.append(k)})()
    )
    result = enrich.handler(
        {"accountId": "123456789012", "finding": {"targets": {"instanceIds": []}}}, None
    )
    assert calls == []
    assert result["environment"] == "production"
    assert result["environmentSource"] == "default-enrichment-unavailable"
    assert result["errors"]


def test_enrichment_survives_a_describe_failure(monkeypatch):
    """A terminated instance must not stop the finding reaching a human."""

    class Boom:
        def describe_instances(self, **_kwargs):
            raise RuntimeError("InvalidInstanceID.NotFound")

    monkeypatch.setattr(enrich, "ec2_client", Boom())
    result = enrich.handler(
        {"accountId": "123456789012", "finding": {"targets": {"instanceIds": ["i-0123456789abcdef0"]}}},
        None,
    )
    assert result["environment"] == "production"
    assert result["instance"] is None
    assert "InvalidInstanceID.NotFound" in result["errors"][0]


def test_decide_downgrades_auto_contain_when_there_is_nothing_to_contain(quiet_ledger):
    """Otherwise the alert would claim containment that never happened."""
    result = decide.handler(
        {
            "incidentId": "inc-1",
            "findingId": "test-finding-ir-pipeline",
            "finding": {
                "summary": {
                    "type": "Backdoor:EC2/C&CActivity.B!DNS",
                    "severity": 8.0,
                    "resourceType": "Instance",
                    "resourceRole": "ACTOR",
                },
                "targets": {"instanceIds": [], "rejectedInstanceIds": ["i-REPLACE_ME"], "accessKey": None},
            },
            "enrichment": {"environment": "production", "environmentSource": "default-missing-tag"},
        },
        None,
    )
    assert result["decision"] == "NOTIFY"
    assert result["downgradedFrom"] == "AUTO_CONTAIN"
    assert "i-REPLACE_ME" in result["downgradeReason"]
    assert result["actions"] == []


def test_notification_is_still_sent_and_says_nothing_was_contained(monkeypatch, quiet_ledger):
    published = {}

    class FakeSns:
        def publish(self, **kwargs):
            published.update(kwargs)
            return {"MessageId": "m-1"}

    monkeypatch.setattr(alert, "sns_client", FakeSns())
    alert.handler(
        {
            "notifyKind": "NOTIFY",
            "incidentId": "test-finding-ir-pipeline",
            "findingId": "test-finding-ir-pipeline",
            "accountId": "123456789012",
            "region": "us-east-1",
            "finding": {
                "summary": {
                    "type": "Backdoor:EC2/C&CActivity.B!DNS",
                    "severity": 8.0,
                    "title": "t",
                    "description": "d",
                    "createdAt": "2026-09-14T12:00:00.000Z",
                },
                "targets": {"instanceIds": [], "rejectedInstanceIds": ["i-REPLACE_ME"]},
            },
            "enrichment": {"environment": "production", "environmentSource": "default-missing-tag"},
            "decision": {
                "decision": "NOTIFY",
                "ruleId": "auto-contain-high-confidence",
                "policyVersion": 1,
                "downgradedFrom": "AUTO_CONTAIN",
                "downgradeReason": "The finding named no resource this pipeline can act on.",
                "actions": [],
            },
        },
        None,
    )

    assert published, "a notification must go out even when nothing can be contained"
    assert len(published["Subject"]) <= 100 and published["Subject"].isascii()
    message = published["Message"]
    assert "No containment was performed" in message
    assert "Downgraded from AUTO_CONTAIN" in message
    assert "i-REPLACE_ME" in message and "sample findings reference fake resources" in message


def test_the_sample_finding_would_otherwise_have_been_contained():
    """Confirms the degradation above is doing real work, not hiding a NOTIFY."""
    result = policy.evaluate("Backdoor:EC2/C&CActivity.B!DNS", 8.0, "production", "Instance", "ACTOR")
    assert result["decision"] == "AUTO_CONTAIN"


def test_enrichment_describes_every_named_instance(monkeypatch):
    """An attack sequence names a group, and containment maps over all of them."""
    calls = []

    class Ec2:
        def describe_instances(self, **kwargs):
            calls.append(kwargs["InstanceIds"])
            return {
                "Reservations": [
                    {"Instances": [
                        {"InstanceId": instance_id, "VpcId": "vpc-1",
                         "Tags": [{"Key": "Environment", "Value": "Production"}]}
                        for instance_id in kwargs["InstanceIds"]
                    ]}
                ]
            }

        def describe_instance_attribute(self, **_kwargs):
            return {}

    class Asg:
        def describe_auto_scaling_instances(self, **_kwargs):
            return {"AutoScalingInstances": []}

    monkeypatch.setattr(enrich, "ec2_client", Ec2())
    monkeypatch.setattr(enrich, "autoscaling_client", Asg())

    result = enrich.handler(
        {
            "accountId": "123456789012",
            "finding": {"targets": {"instanceIds": ["i-0111111111aaaaaaa", "i-0222222222bbbbbbb"]}},
        },
        None,
    )
    assert result["instanceCount"] == 2
    assert [i["instanceId"] for i in result["instances"]] == [
        "i-0111111111aaaaaaa", "i-0222222222bbbbbbb"
    ]
    # One batched call, not one per instance.
    assert calls[0] == ["i-0111111111aaaaaaa", "i-0222222222bbbbbbb"]


def test_one_terminated_instance_does_not_lose_the_others(monkeypatch):
    """DescribeInstances fails the whole request if any id is unknown."""
    attempts = []

    class Ec2:
        def describe_instances(self, **kwargs):
            ids = kwargs["InstanceIds"]
            attempts.append(ids)
            if len(ids) > 1 or ids == ["i-0999999999ccccccc"]:
                raise RuntimeError("InvalidInstanceID.NotFound")
            return {"Reservations": [{"Instances": [{"InstanceId": ids[0], "VpcId": "vpc-1"}]}]}

        def describe_instance_attribute(self, **_kwargs):
            return {}

    class Asg:
        def describe_auto_scaling_instances(self, **_kwargs):
            return {"AutoScalingInstances": []}

    monkeypatch.setattr(enrich, "ec2_client", Ec2())
    monkeypatch.setattr(enrich, "autoscaling_client", Asg())

    result = enrich.handler(
        {
            "accountId": "123456789012",
            "finding": {"targets": {"instanceIds": ["i-0111111111aaaaaaa", "i-0999999999ccccccc"]}},
        },
        None,
    )
    assert [i["instanceId"] for i in result["instances"]] == ["i-0111111111aaaaaaa"]
    assert any("i-0999999999ccccccc" in error for error in result["errors"])
    # Batch first, then one at a time.
    assert len(attempts) == 3


def test_enrichment_is_bounded_for_a_wide_sequence(monkeypatch):
    class Ec2:
        def describe_instances(self, **kwargs):
            return {"Reservations": [{"Instances": [
                {"InstanceId": i, "VpcId": "vpc-1"} for i in kwargs["InstanceIds"]
            ]}]}

        def describe_instance_attribute(self, **_kwargs):
            return {}

    class Asg:
        def describe_auto_scaling_instances(self, **_kwargs):
            return {"AutoScalingInstances": []}

    monkeypatch.setattr(enrich, "ec2_client", Ec2())
    monkeypatch.setattr(enrich, "autoscaling_client", Asg())

    many = [f"i-{n:017x}" for n in range(60)]
    result = enrich.handler(
        {"accountId": "123456789012", "finding": {"targets": {"instanceIds": many}}}, None
    )
    assert result["instanceCount"] == enrich.MAX_ENRICHED_INSTANCES
    assert any("enriched the first" in error for error in result["errors"])
