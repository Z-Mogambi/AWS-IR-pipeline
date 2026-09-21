"""Start one Step Functions execution per GuardDuty finding.

The Router passes identifiers only - account, Region, detector id, finding id -
and never the finding body. The first state re-fetches the finding from
GuardDuty, so nothing downstream can be steered by the contents of an
EventBridge event.

The execution is named after the finding id. GuardDuty re-emits the same id as
activity recurs, so a repeat event collides on ExecutionAlreadyExists and is
logged as a duplicate instead of starting a second containment run.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

from irlib import findings

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sfn_client = boto3.client("stepfunctions")
STATE_MACHINE_ARN = os.environ["SFN_STATE_MACHINE_ARN"]


def classify_source(detail):
    """Which branch this finding belongs to, for the phases that add more."""
    finding_type = detail.get("type") or ""
    if finding_type.startswith("AttackSequence:"):
        return "sequence"
    if (detail.get("resource") or {}).get("resourceType") == "AccessKey":
        return "accesskey"
    return "instance"


def handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")

    detail = event.get("detail") or {}
    finding_id = detail.get("id")
    if not finding_id:
        logger.error("Event has no detail.id; nothing to route.")
        return {"status": "REJECTED", "reason": "missing finding id"}

    detector_id = findings.detector_id_from_detail(detail)
    if not detector_id:
        logger.error(f"Could not determine a detector id for finding {finding_id}.")
        return {"status": "REJECTED", "reason": "missing detector id"}

    execution_input = {
        "incidentId": findings.incident_id(finding_id),
        "findingId": finding_id,
        "detectorId": detector_id,
        "accountId": detail.get("accountId") or event.get("account"),
        "region": detail.get("region") or event.get("region"),
        "source": classify_source(detail),
        "eventTime": event.get("time"),
    }
    name = findings.execution_name(finding_id)

    try:
        response = sfn_client.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=name,
            input=json.dumps(execution_input),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ExecutionAlreadyExists":
            logger.info(
                f"Duplicate finding {finding_id}: execution {name} already exists. "
                "GuardDuty re-emits a finding id as activity recurs; ignoring."
            )
            return {"status": "DUPLICATE", "executionName": name, "findingId": finding_id}
        logger.error(f"Error starting Step Functions execution for {finding_id}: {exc}")
        raise

    logger.info(f"Started execution {response['executionArn']} for finding {finding_id}")
    return {
        "status": "STARTED",
        "executionArn": response["executionArn"],
        "executionName": name,
        "findingId": finding_id,
    }
