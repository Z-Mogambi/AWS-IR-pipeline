"""Interim network containment.

Phase 2 replaces this function with per-incident security groups, the
untracked-flow technique, and per-ENI application. Until then it keeps the
pipeline working end to end, with the write-ahead record added so the original
group membership is already being captured - without it, nothing isolated in
this phase could ever be released.

Known gaps, all addressed in Phase 2:
  * the quarantine group is shared, so two concurrent incidents race on it;
  * ModifyInstanceAttribute(Groups=...) only moves the primary ENI;
  * swapping groups does not sever connections the VPC is already tracking, so
    an established reverse shell survives this.
"""

import json
import logging

import boto3

from irlib import incidents

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")
QUARANTINE_SG_NAME = "quarantine-sg"


def handler(event, context):
    logger.info(f"Isolating: {json.dumps(event)}")

    incident_id = event["incidentId"]
    targets = (event.get("finding") or {}).get("targets") or {}
    instance = (event.get("enrichment") or {}).get("instance") or {}

    instance_ids = targets.get("instanceIds") or []
    if not instance_ids:
        raise ValueError("No actionable instance id; Decide should have downgraded this.")
    instance_id = instance_ids[0]

    vpc_id = instance.get("vpcId")
    if not vpc_id:
        raise ValueError(f"No VPC id for {instance_id}; cannot place a quarantine group.")

    original_groups = instance.get("securityGroups") or []
    action_key = f"network-isolate#{instance_id}"

    state, record = incidents.begin_action(
        incident_id,
        action_key,
        action="network-isolate",
        target=instance_id,
        prior_state={"securityGroups": original_groups, "vpcId": vpc_id},
    )
    if state == incidents.SKIP:
        logger.info(f"{instance_id} was already isolated for this incident.")
        return _result(instance_id, "SKIPPED", record.get("Result", {}).get("securityGroupId"))

    try:
        quarantine_sg_id = ensure_quarantine_group(vpc_id)
        ec2_client.modify_instance_attribute(InstanceId=instance_id, Groups=[quarantine_sg_id])
    except Exception as exc:  # noqa: BLE001 - record the failure, then re-raise
        incidents.fail_action(incident_id, action_key, exc)
        logger.error(f"Failed to isolate {instance_id}: {exc}")
        raise

    incidents.complete_action(
        incident_id,
        action_key,
        {"securityGroupId": quarantine_sg_id, "replacedGroups": original_groups},
    )
    logger.info(f"Isolated {instance_id} behind {quarantine_sg_id}")
    return _result(instance_id, "DONE", quarantine_sg_id)


def _result(instance_id, status, security_group_id):
    return {
        "actions": [
            {
                "action": "network-isolate",
                "target": instance_id,
                "status": status,
                "detail": f"security group {security_group_id}",
            }
        ]
    }


def ensure_quarantine_group(vpc_id):
    """Find or create the shared quarantine group and strip its egress."""
    existing = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [QUARANTINE_SG_NAME]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )["SecurityGroups"]

    if existing:
        group = existing[0]
    else:
        created = ec2_client.create_security_group(
            GroupName=QUARANTINE_SG_NAME,
            Description="Incident response quarantine. No ingress or egress.",
            VpcId=vpc_id,
        )
        # New groups are eventually consistent; wait before describing.
        ec2_client.get_waiter("security_group_exists").wait(GroupIds=[created["GroupId"]])
        group = ec2_client.describe_security_groups(GroupIds=[created["GroupId"]])["SecurityGroups"][0]
        logger.info(f"Created {QUARANTINE_SG_NAME} {group['GroupId']} in {vpc_id}")

    # Every new security group gets an allow-all egress rule. Remove it so the
    # instance cannot reach a C2 endpoint or exfiltrate.
    if group.get("IpPermissionsEgress"):
        ec2_client.revoke_security_group_egress(
            GroupId=group["GroupId"], IpPermissions=group["IpPermissionsEgress"]
        )
        logger.info(f"Revoked egress on {group['GroupId']}")

    return group["GroupId"]
