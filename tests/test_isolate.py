"""Interim containment: the write-ahead invariant.

Phase 2 replaces this function, but the ordering assertion is the one that has
to survive: the record naming the original security groups must be persisted
before the call that replaces them, or a failure mid-action leaves an instance
that can never be released.
"""

import json

import pytest

from conftest import load_lambda
from irlib import incidents

isolate = load_lambda("isolate")

EVENT = {
    "incidentId": "inc-1",
    "finding": {"targets": {"instanceIds": ["i-0123456789abcdef0"]}},
    "enrichment": {"instance": {"vpcId": "vpc-0abc", "securityGroups": ["sg-web", "sg-db"]}},
}


@pytest.fixture
def calls(monkeypatch):
    """One ordered log across both clients, so ordering can be asserted."""
    log = []

    class Ledger:
        def put_item(self, **kwargs):
            log.append(("ledger.put_item", kwargs))
            return {}

        def update_item(self, **kwargs):
            log.append(("ledger.update_item", kwargs))
            return {}

        def get_item(self, **kwargs):
            log.append(("ledger.get_item", kwargs))
            return {}

    class Ec2:
        def describe_security_groups(self, **kwargs):
            log.append(("ec2.describe_security_groups", kwargs))
            return {"SecurityGroups": [{"GroupId": "sg-quarantine", "IpPermissionsEgress": []}]}

        def modify_instance_attribute(self, **kwargs):
            log.append(("ec2.modify_instance_attribute", kwargs))
            return {}

    monkeypatch.setattr(incidents, "_client", lambda c=None: Ledger())
    monkeypatch.setattr(isolate, "ec2_client", Ec2())
    return log


def test_prior_state_is_recorded_before_the_mutating_call(calls):
    isolate.handler(dict(EVENT), None)
    names = [name for name, _ in calls]

    write_ahead = names.index("ledger.put_item")
    mutation = names.index("ec2.modify_instance_attribute")
    assert write_ahead < mutation, "the ledger write must precede the security group swap"

    recorded = json.loads(calls[write_ahead][1]["Item"]["PriorState"]["S"])
    assert recorded["securityGroups"] == ["sg-web", "sg-db"]
    assert recorded["vpcId"] == "vpc-0abc"


def test_completion_is_recorded_after_the_mutating_call(calls):
    isolate.handler(dict(EVENT), None)
    names = [name for name, _ in calls]
    assert names.index("ec2.modify_instance_attribute") < names.index("ledger.update_item")


def test_a_failed_action_is_marked_failed_and_re_raised(monkeypatch):
    log = []

    class Ledger:
        def put_item(self, **kwargs):
            log.append(("put", kwargs))
            return {}

        def update_item(self, **kwargs):
            log.append(("update", kwargs))
            return {}

    class Ec2:
        def describe_security_groups(self, **_kwargs):
            return {"SecurityGroups": [{"GroupId": "sg-q", "IpPermissionsEgress": []}]}

        def modify_instance_attribute(self, **_kwargs):
            raise RuntimeError("UnauthorizedOperation")

    monkeypatch.setattr(incidents, "_client", lambda c=None: Ledger())
    monkeypatch.setattr(isolate, "ec2_client", Ec2())

    with pytest.raises(RuntimeError, match="UnauthorizedOperation"):
        isolate.handler(dict(EVENT), None)

    # Nothing is rolled back; the ledger records the failure for the notification.
    status = log[-1][1]["ExpressionAttributeValues"][":s"]["S"]
    assert status == incidents.STATUS_FAILED


def test_an_already_isolated_instance_is_not_isolated_twice(monkeypatch):
    class Ledger:
        def put_item(self, **_kwargs):
            from botocore.exceptions import ClientError

            raise ClientError(
                {"Error": {"Code": "ConditionalCheckFailedException", "Message": "exists"}},
                "PutItem",
            )

        def get_item(self, **_kwargs):
            return {
                "Item": {
                    "Status": {"S": incidents.STATUS_DONE},
                    "Result": {"S": json.dumps({"securityGroupId": "sg-quarantine"})},
                }
            }

    mutations = []

    class Ec2:
        def modify_instance_attribute(self, **kwargs):
            mutations.append(kwargs)
            return {}

        def describe_security_groups(self, **_kwargs):
            return {"SecurityGroups": [{"GroupId": "sg-q", "IpPermissionsEgress": []}]}

    monkeypatch.setattr(incidents, "_client", lambda c=None: Ledger())
    monkeypatch.setattr(isolate, "ec2_client", Ec2())

    result = isolate.handler(dict(EVENT), None)
    assert mutations == [], "a completed action must not be repeated"
    assert result["actions"][0]["status"] == "SKIPPED"


def test_refuses_to_act_without_a_usable_instance_id(calls):
    with pytest.raises(ValueError, match="No actionable instance"):
        isolate.handler({"incidentId": "inc-1", "finding": {"targets": {"instanceIds": []}},
                         "enrichment": {"instance": {}}}, None)


def test_refuses_to_act_without_a_vpc(calls):
    with pytest.raises(ValueError, match="No VPC id"):
        isolate.handler(
            {
                "incidentId": "inc-1",
                "finding": {"targets": {"instanceIds": ["i-0123456789abcdef0"]}},
                "enrichment": {"instance": {"securityGroups": []}},
            },
            None,
        )
