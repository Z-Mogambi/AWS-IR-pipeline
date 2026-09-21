"""Router: idempotency and the identifiers it hands on."""

import json
from datetime import datetime, timezone

import pytest
from botocore.stub import ANY, Stubber

from conftest import load_lambda
from irlib import findings

router = load_lambda("router")


@pytest.fixture
def stub():
    with Stubber(router.sfn_client) as stubber:
        yield stubber


def test_execution_is_named_after_the_finding(stub, sample_event):
    stub.add_response(
        "start_execution",
        {
            "executionArn": "arn:aws:states:us-east-1:111122223333:execution:test:x",
            "startDate": datetime.now(timezone.utc),
        },
        {"stateMachineArn": ANY, "name": "test-finding-ir-pipeline", "input": ANY},
    )
    result = router.handler(sample_event, None)
    assert result["status"] == "STARTED"
    assert result["executionName"] == "test-finding-ir-pipeline"


def test_duplicate_finding_is_logged_not_raised(stub, sample_event):
    """GuardDuty re-emits the same finding id as activity recurs."""
    stub.add_client_error("start_execution", service_error_code="ExecutionAlreadyExists")
    result = router.handler(sample_event, None)
    assert result["status"] == "DUPLICATE"
    assert result["findingId"] == "test-finding-ir-pipeline"


def test_other_client_errors_still_raise(stub, sample_event):
    stub.add_client_error("start_execution", service_error_code="StateMachineDoesNotExist")
    with pytest.raises(Exception):
        router.handler(sample_event, None)


def test_router_passes_identifiers_only_never_the_finding_body(stub, sample_event):
    captured = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return {
            "executionArn": "arn:aws:states:us-east-1:111122223333:execution:test:x",
            "startDate": datetime.now(timezone.utc),
        }

    router.sfn_client.start_execution = capture
    try:
        router.handler(sample_event, None)
    finally:
        del router.sfn_client.start_execution

    payload = json.loads(captured["input"])
    assert set(payload) == {
        "incidentId",
        "findingId",
        "detectorId",
        "accountId",
        "region",
        "source",
        "eventTime",
    }
    # The whole point: the finding body does not travel with the execution.
    assert "type" not in payload and "resource" not in payload
    assert payload["detectorId"] == "example"
    assert payload["accountId"] == "123456789012"  # as committed in the fixture


def test_missing_finding_id_is_rejected_without_starting_anything():
    result = router.handler({"detail": {}}, None)
    assert result["status"] == "REJECTED"


def test_missing_detector_id_is_rejected():
    result = router.handler({"detail": {"id": "abc"}}, None)
    assert result["status"] == "REJECTED"
    assert "detector" in result["reason"]


@pytest.mark.parametrize(
    "detail,expected",
    [
        ({"type": "AttackSequence:EC2/CompromisedInstanceGroup"}, "sequence"),
        ({"type": "Impact:IAMUser/CostHarvesting", "resource": {"resourceType": "AccessKey"}}, "accesskey"),
        ({"type": "Backdoor:EC2/C&CActivity.B", "resource": {"resourceType": "Instance"}}, "instance"),
    ],
)
def test_classify_source(detail, expected):
    assert router.classify_source(detail) == expected


# --- execution name rules ----------------------------------------------------


def test_execution_name_is_capped_at_eighty_characters():
    assert len(findings.execution_name("f" * 200)) == 80


def test_execution_name_strips_illegal_characters():
    assert findings.execution_name("ab/cd+ef:gh i") == "ab-cd-ef-gh-i"


def test_execution_name_is_stable_for_a_finding_id():
    assert findings.execution_name("abc-123") == findings.execution_name("abc-123")


def test_incident_id_matches_the_execution_name():
    """Both derive from the finding id, so the ledger is idempotent too."""
    assert findings.incident_id("a/b") == findings.execution_name("a/b")
