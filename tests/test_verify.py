"""Verify: the trust boundary.

Every target containment can act on is derived here from what GetFindings
returns, so these tests cover the ways that re-fetch can disagree with the
event that triggered the run.
"""

import boto3
import pytest
from botocore.stub import Stubber

from conftest import load_lambda
from irlib import findings, incidents

verify = load_lambda("verify")

EVENT = {
    "incidentId": "finding-0001",
    "findingId": "finding-0001",
    "detectorId": "detector-0001",
    "accountId": "111122223333",
    "region": "us-east-1",
}


@pytest.fixture
def guardduty(monkeypatch):
    client = boto3.client("guardduty", region_name="us-east-1")
    with Stubber(client) as stubber:
        monkeypatch.setattr(findings, "_client", lambda c=None: client)
        yield stubber


@pytest.fixture
def ledger(monkeypatch):
    """Accept every ledger write and record it, so ordering can be asserted."""
    calls = []

    class Recorder:
        def put_item(self, **kwargs):
            calls.append(("put_item", kwargs))
            return {}

        def update_item(self, **kwargs):
            calls.append(("update_item", kwargs))
            return {}

        def get_item(self, **kwargs):
            calls.append(("get_item", kwargs))
            return {}

    monkeypatch.setattr(incidents, "_client", lambda c=None: Recorder())
    return calls


def test_happy_path_derives_targets_from_the_fetched_finding(guardduty, ledger, finding_factory):
    guardduty.add_response(
        "get_findings",
        {"Findings": [finding_factory()]},
        {"DetectorId": "detector-0001", "FindingIds": ["finding-0001"]},
    )
    result = verify.handler(dict(EVENT), None)

    assert result["summary"]["type"] == "Backdoor:EC2/C&CActivity.B!DNS"
    assert result["summary"]["severity"] == 8.0
    assert result["targets"]["instanceIds"] == ["i-0123456789abcdef0"]
    assert any(call[0] == "put_item" for call in ledger), "the incident must be opened"


def test_missing_finding_is_rejected(guardduty, ledger):
    guardduty.add_response("get_findings", {"Findings": []}, None)
    with pytest.raises(findings.FindingNotFound):
        verify.handler(dict(EVENT), None)


def test_archived_finding_is_rejected(guardduty, ledger, finding_factory):
    """Extended Threat Detection ignores archived findings; so do we."""
    guardduty.add_response("get_findings", {"Findings": [finding_factory(archived=True)]}, None)
    with pytest.raises(findings.FindingArchived):
        verify.handler(dict(EVENT), None)


def test_wrong_finding_id_is_rejected(guardduty, ledger, finding_factory):
    guardduty.add_response(
        "get_findings", {"Findings": [finding_factory(finding_id="some-other-finding")]}, None
    )
    with pytest.raises(verify.FindingMismatch, match="returned"):
        verify.handler(dict(EVENT), None)


def test_account_mismatch_is_rejected(guardduty, ledger, finding_factory):
    guardduty.add_response(
        "get_findings", {"Findings": [finding_factory(account_id="999988887777")]}, None
    )
    with pytest.raises(verify.FindingMismatch, match="accountId"):
        verify.handler(dict(EVENT), None)


def test_region_mismatch_is_rejected(guardduty, ledger, finding_factory):
    guardduty.add_response(
        "get_findings", {"Findings": [finding_factory(region="eu-west-1")]}, None
    )
    with pytest.raises(verify.FindingMismatch, match="region"):
        verify.handler(dict(EVENT), None)


def test_malformed_instance_id_is_not_passed_on(guardduty, ledger, finding_factory):
    """A sample finding names a fake instance; it must not become a target."""
    guardduty.add_response(
        "get_findings", {"Findings": [finding_factory(instance_id="i-REPLACE_ME")]}, None
    )
    result = verify.handler(dict(EVENT), None)
    assert result["targets"]["instanceIds"] == []
    assert result["targets"]["rejectedInstanceIds"] == ["i-REPLACE_ME"]


def test_oversized_finding_is_truncated_before_storage(guardduty, ledger, finding_factory):
    """DynamoDB items cap at 400 KB; the unabridged copy goes to S3 in Phase 2."""
    huge = finding_factory()
    huge["Service"]["RuntimeDetails"] = {"Process": {"Name": "x" * 250_000}}
    guardduty.add_response("get_findings", {"Findings": [huge]}, None)

    verify.handler(dict(EVENT), None)
    stored = [c for c in ledger if c[0] == "put_item"][0][1]["Item"]["Attributes"]["S"]
    assert '"truncated": true' in stored


def test_camel_case_eventbridge_payloads_also_parse(sample_event):
    """EventBridge delivers camelCase; GetFindings returns PascalCase.

    Both shapes have to yield the same summary, so fixtures captured from
    either source can be used interchangeably.
    """
    detail = sample_event["detail"]
    summary = findings.summarize(detail)
    assert summary["type"] == "Backdoor:EC2/C&CActivity.B!DNS"
    assert summary["severity"] == 8.0
    assert summary["resourceType"] == "Instance"
