"""Shared test setup.

The Lambda functions all live in files called lambda_function.py, so they are
loaded by path under distinct module names rather than imported. Each one
builds its boto3 clients and reads its environment at import time, so the
environment has to be in place before the first load.
"""

import importlib.util
import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAYER = ROOT / "layers" / "common" / "python"
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

sys.path.insert(0, str(LAYER))

# Fake, non-functional values. Nothing in this suite reaches AWS: every client
# is either stubbed with botocore's Stubber or monkeypatched out.
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("INCIDENTS_TABLE", "test-incidents")
os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:111122223333:test-alerts")
os.environ.setdefault(
    "SFN_STATE_MACHINE_ARN", "arn:aws:states:us-east-1:111122223333:stateMachine:test"
)
os.environ.setdefault("ACCOUNT_ENVIRONMENT_MAP", "")
os.environ.setdefault("PROTECTED_ROLE_NAMES", "")
os.environ.setdefault("PIPELINE_ROLE_PREFIX", "ir-pipeline-")

_LOADED = {}


def load_lambda(name):
    """Load src/<name>/lambda_function.py under its own module name."""
    if name not in _LOADED:
        path = ROOT / "src" / name / "lambda_function.py"
        spec = importlib.util.spec_from_file_location(f"{name}_lambda_function", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _LOADED[name] = module
    return _LOADED[name]


@pytest.fixture(scope="session")
def sample_event():
    """The committed EventBridge fixture, which names a fake instance id."""
    with (ROOT / "events" / "guardduty-ec2-finding.json").open() as handle:
        return json.load(handle)


@pytest.fixture
def finding_factory():
    """Build a GetFindings-shaped finding.

    Keys are PascalCase because that is what the API actually returns, and
    botocore's Stubber validates responses against the real service model - so
    a fixture that drifts from the API shape fails here rather than in
    production. irlib.findings normalises them to the camelCase field names
    used throughout the GuardDuty documentation.
    """

    def build(
        finding_id="finding-0001",
        finding_type="Backdoor:EC2/C&CActivity.B!DNS",
        severity=8.0,
        instance_id="i-0123456789abcdef0",
        account_id="111122223333",
        region="us-east-1",
        archived=False,
        resource_type="Instance",
        resource_role="ACTOR",
        extra_service=None,
        resource=None,
    ):
        service = {
            "Archived": archived,
            "DetectorId": "detector-0001",
            "ResourceRole": resource_role,
            "Count": 1,
        }
        service.update(extra_service or {})

        if resource is None:
            resource = {"ResourceType": resource_type}
            if instance_id:
                resource["InstanceDetails"] = {"InstanceId": instance_id}

        return {
            "SchemaVersion": "2.0",
            "Id": finding_id,
            "Type": finding_type,
            "Severity": severity,
            "AccountId": account_id,
            "Region": region,
            "Partition": "aws",
            "Title": f"Test finding {finding_id}",
            "Description": "Synthetic finding used by the test suite.",
            "CreatedAt": "2026-09-21T12:00:00.000Z",
            "UpdatedAt": "2026-09-21T12:00:00.000Z",
            "Arn": (
                f"arn:aws:guardduty:{region}:{account_id}:detector/detector-0001"
                f"/finding/{finding_id}"
            ),
            "Resource": resource,
            "Service": service,
        }

    return build
