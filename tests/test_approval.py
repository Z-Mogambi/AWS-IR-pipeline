"""The approval callback.

The security property here is that possession of the task token is not consent.
SendTaskSuccess is an IAM-authorised API call, so an attacker who intercepts
the notification still cannot approve anything.
"""

import pytest

from conftest import load_lambda
from irlib import incidents

alert = load_lambda("alert")
decide = load_lambda("decide")

TOKEN = "AAAAKgAAAAIAAAAAAAAAAexample-task-token"


def build_event(kind="APPROVAL_REQUIRED", token=TOKEN, timeout=3600):
    return {
        "notifyKind": kind,
        "taskToken": token,
        "executionArn": "arn:aws:states:us-east-1:111122223333:execution:ir:abc",
        "incidentId": "inc-1",
        "findingId": "f-1",
        "accountId": "111122223333",
        "region": "us-east-1",
        "finding": {
            "summary": {"type": "Backdoor:EC2/C&CActivity.B", "severity": 8.0,
                        "title": "t", "description": "d", "createdAt": "2026-09-21T12:00:00Z"},
            "targets": {"instanceIds": ["i-0123456789abcdef0"]},
        },
        "enrichment": {"environment": "production", "environmentSource": "tag"},
        "decision": {
            "decision": "APPROVAL_REQUIRED",
            "ruleId": "default-production",
            "policyVersion": 1,
            "actions": ["evidence", "network", "credentials", "imds"],
            "approvalTimeoutSeconds": timeout,
            "approvalTimeoutAction": "Escalate",
        },
    }


@pytest.fixture
def published(monkeypatch):
    sent = {}

    class FakeSns:
        def publish(self, **kwargs):
            sent.update(kwargs)
            return {"MessageId": "m-1"}

    monkeypatch.setattr(alert, "sns_client", FakeSns())
    monkeypatch.setattr(incidents, "list_actions", lambda *_a, **_k: [])
    return sent


def test_the_notification_carries_both_callback_commands(published):
    alert.handler(build_event(), None)
    message = published["Message"]
    assert "aws stepfunctions send-task-success" in message
    assert "aws stepfunctions send-task-failure" in message
    assert TOKEN in message


def test_the_notification_says_the_token_alone_is_not_enough(published):
    """The anti-spoofing property, stated where the reader will see it."""
    alert.handler(build_event(), None)
    message = published["Message"]
    assert "states:SendTaskSuccess" in message
    assert "is not enough to approve anything" in message


def test_the_planned_actions_are_listed_before_anyone_approves(published):
    alert.handler(build_event(), None)
    message = published["Message"]
    assert "Planned actions: evidence, network, credentials, imds" in message
    assert "NO ACTION HAS BEEN TAKEN" in message


def test_the_finding_summary_is_included(published):
    alert.handler(build_event(), None)
    message = published["Message"]
    assert "Backdoor:EC2/C&CActivity.B" in message
    assert "i-0123456789abcdef0" in message
    assert "production" in message


def test_the_expiry_is_stated(published):
    alert.handler(build_event(timeout=1800), None)
    assert "expires in 1800 seconds" in published["Message"]


def test_a_missing_token_is_reported_not_faked(published):
    """Better an unusable notification than one that looks actionable and is not."""
    alert.handler(build_event(token=None), None)
    message = published["Message"]
    assert "no callback token" in message
    assert "send-task-success" not in message


def test_a_timeout_notification_says_nothing_was_changed(published):
    alert.handler(build_event(kind="APPROVAL_TIMED_OUT"), None)
    message = published["Message"]
    assert "NOBODY ANSWERED" in message
    assert "not consent" in message
    assert "Nothing has been changed" in message


def test_a_declined_notification_says_nothing_was_changed(published):
    event = build_event(kind="APPROVAL_DENIED")
    event["error"] = {"Error": "Declined", "Cause": "not our instance"}
    alert.handler(event, None)
    assert "DECLINED" in published["Message"]
    assert "Nothing has been changed" in published["Message"]


def test_the_release_request_asks_about_releasing_not_containing(published):
    alert.handler(build_event(kind="RELEASE_APPROVAL"), None)
    message = published["Message"]
    assert "release this incident" in message
    assert "send-task-success" in message


@pytest.mark.parametrize("kind", ["APPROVAL_REQUIRED", "APPROVAL_TIMED_OUT", "APPROVAL_DENIED",
                                  "RELEASE_APPROVAL", "RELEASED"])
def test_every_approval_subject_fits_sns_limits(published, kind):
    alert.handler(build_event(kind=kind), None)
    subject = published["Subject"]
    assert len(subject) <= 100 and subject.isascii()


# --- the timeout policy -----------------------------------------------------


def test_the_timeout_travels_in_the_decision(monkeypatch):
    """ASL cannot interpolate a template parameter into a numeric field, so the
    approval state reads it with TimeoutSecondsPath."""
    monkeypatch.setattr(decide, "APPROVAL_TIMEOUT_SECONDS", 900)
    monkeypatch.setattr(decide, "APPROVAL_TIMEOUT_ACTION", "Escalate")
    monkeypatch.setattr(incidents, "update_incident", lambda *_a, **_k: None)

    result = decide.handler(
        {
            "incidentId": "inc-1",
            "finding": {
                "summary": {"type": "Behavior:EC2/NetworkPortUnusual", "severity": 5.0,
                            "resourceType": "Instance", "resourceRole": "ACTOR"},
                "targets": {"instanceIds": ["i-0123456789abcdef0"]},
            },
            "enrichment": {"environment": "production"},
        },
        None,
    )
    assert result["decision"] == "APPROVAL_REQUIRED"
    assert result["approvalTimeoutSeconds"] == 900
    assert result["approvalTimeoutAction"] == "Escalate"
