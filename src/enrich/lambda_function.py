"""Add EC2 context and decide which environment the instance belongs to.

Enrichment is best effort by design. If DescribeInstances fails, or the finding
names an instance that no longer exists, this returns a degraded result rather
than raising: a finding whose instance has vanished still has to reach a human.
The environment falls back to production in that case, so the degraded path is
never the more permissive one.
"""

import json
import logging

import boto3

from irlib import envresolve

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")


def handler(event, context):
    logger.info(f"Enriching: {json.dumps(event)}")

    account_id = event.get("accountId")
    instance_ids = (event.get("finding") or {}).get("targets", {}).get("instanceIds") or []
    errors = []
    instance = None

    if instance_ids:
        try:
            instance = describe_instance(instance_ids[0])
        except Exception as exc:  # noqa: BLE001 - enrichment must never stop the run
            errors.append(f"DescribeInstances failed for {instance_ids[0]}: {exc}")
            logger.warning(errors[-1])
    else:
        errors.append("Finding named no usable instance id.")
        logger.warning(errors[-1])

    environment, source = envresolve.resolve(
        account_id=account_id,
        tags=(instance or {}).get("tags"),
    )
    if instance is None and source == "default-missing-tag":
        source = "default-enrichment-unavailable"

    result = {
        "environment": environment,
        "environmentSource": source,
        "instance": instance,
        "errors": errors,
    }
    logger.info(
        f"Enrichment complete: environment={environment} ({source}) "
        f"instance={'yes' if instance else 'no'} errors={len(errors)}"
    )
    return result


def describe_instance(instance_id):
    """Return the slice of DescribeInstances the pipeline actually uses.

    Passing the whole reservation onward would push a large, mostly unused blob
    through every remaining state and toward the 256 KB payload limit.
    """
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    reservations = response.get("Reservations") or []
    if not reservations or not reservations[0].get("Instances"):
        raise ValueError(f"Instance {instance_id} not found")

    raw = json.loads(json.dumps(reservations[0]["Instances"][0], default=str))
    interfaces = [
        {
            "networkInterfaceId": eni.get("NetworkInterfaceId"),
            "groups": [g.get("GroupId") for g in eni.get("Groups") or []],
            "subnetId": eni.get("SubnetId"),
            "privateIpAddress": eni.get("PrivateIpAddress"),
            "publicIp": (eni.get("Association") or {}).get("PublicIp"),
        }
        for eni in raw.get("NetworkInterfaces") or []
    ]

    return {
        "instanceId": raw.get("InstanceId"),
        "instanceType": raw.get("InstanceType"),
        "state": (raw.get("State") or {}).get("Name"),
        "vpcId": raw.get("VpcId"),
        "subnetId": raw.get("SubnetId"),
        "imageId": raw.get("ImageId"),
        "launchTime": raw.get("LaunchTime"),
        "publicIpAddress": raw.get("PublicIpAddress"),
        "privateIpAddress": raw.get("PrivateIpAddress"),
        "iamInstanceProfileArn": (raw.get("IamInstanceProfile") or {}).get("Arn"),
        "securityGroups": [g.get("GroupId") for g in raw.get("SecurityGroups") or []],
        "networkInterfaces": interfaces,
        "tags": raw.get("Tags") or [],
        "metadataOptions": raw.get("MetadataOptions") or {},
    }
