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
autoscaling_client = boto3.client("autoscaling")

# An attack sequence can name a large group of instances. Enrichment is bounded
# so a wide sequence cannot time the function out; the containment cap in the
# decision is a separate, smaller limit.
MAX_ENRICHED_INSTANCES = 25


def handler(event, context):
    logger.info(f"Enriching: {json.dumps(event)}")

    account_id = event.get("accountId")
    named = (event.get("finding") or {}).get("targets", {}).get("instanceIds") or []
    instance_ids = named[:MAX_ENRICHED_INSTANCES]
    truncated = named[MAX_ENRICHED_INSTANCES:]
    errors = []

    if truncated:
        errors.append(
            f"The finding named {len(named)} instances; enriched the first "
            f"{MAX_ENRICHED_INSTANCES}. Not enriched: {truncated}"
        )
        logger.warning(errors[-1])

    instances = []
    if instance_ids:
        instances, describe_errors = describe_instances(instance_ids)
        errors.extend(describe_errors)
    else:
        errors.append("Finding named no usable instance id.")
        logger.warning(errors[-1])

    # The environment is a property of the incident, not of each instance, so
    # it is resolved from the first one that could be described. A sequence
    # spanning environments resolves to whatever the first instance says; the
    # account map is the way to make that deterministic.
    first = instances[0] if instances else None
    environment, source = envresolve.resolve(
        account_id=account_id,
        tags=(first or {}).get("tags"),
    )
    if first is None and source == "default-missing-tag":
        source = "default-enrichment-unavailable"

    result = {
        "environment": environment,
        "environmentSource": source,
        # `instance` stays for the single-instance path; `instances` is what the
        # containment Map iterates over.
        "instance": first,
        "instances": instances,
        "instanceCount": len(instances),
        "errors": errors,
    }
    logger.info(
        f"Enrichment complete: environment={environment} ({source}) "
        f"instances={len(instances)}/{len(named)} errors={len(errors)}"
    )
    return result


def describe_instances(instance_ids):
    """Describe them in one call, falling back to one at a time.

    DescribeInstances fails the whole request if any id is unknown, which for a
    sequence naming a terminated instance would lose every other instance too.
    """
    errors = []
    try:
        return [_summarise(raw) for raw in _fetch(instance_ids)], errors
    except Exception as exc:  # noqa: BLE001 - enrichment must never stop the run
        logger.warning(f"Batch DescribeInstances failed ({exc}); retrying one at a time.")

    instances = []
    for instance_id in instance_ids:
        try:
            instances.extend(_summarise(raw) for raw in _fetch([instance_id]))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"DescribeInstances failed for {instance_id}: {exc}")
            logger.warning(errors[-1])
    return instances, errors


def _fetch(instance_ids):
    response = ec2_client.describe_instances(InstanceIds=instance_ids)
    found = [
        instance
        for reservation in response.get("Reservations") or []
        for instance in reservation.get("Instances") or []
    ]
    if not found:
        raise ValueError(f"No instances found for {instance_ids}")
    return found


def _summarise(raw_instance):
    """Return the slice of DescribeInstances the pipeline actually uses.

    Passing the whole reservation onward would push a large, mostly unused blob
    through every remaining state and toward the 256 KB payload limit - and an
    attack sequence multiplies that by the number of instances.
    """
    raw = json.loads(json.dumps(raw_instance, default=str))
    instance_id = raw.get("InstanceId")
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
        "blockDeviceMappings": raw.get("BlockDeviceMappings") or [],
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
        # Release has to restore these, and DescribeInstances does not return
        # them - they only come from DescribeInstanceAttribute.
        **instance_attributes(instance_id),
        **autoscaling_membership(instance_id),
    }


def instance_attributes(instance_id):
    """The three protection settings that evidence collection will change."""
    wanted = {
        "disableApiTermination": "disableApiTermination",
        "disableApiStop": "disableApiStop",
        "instanceInitiatedShutdownBehavior": "instanceInitiatedShutdownBehavior",
    }
    found = {}
    for field, attribute in wanted.items():
        try:
            response = ec2_client.describe_instance_attribute(
                InstanceId=instance_id, Attribute=attribute
            )
            found[field] = (response.get(attribute[0].upper() + attribute[1:]) or {}).get("Value")
        except Exception as exc:  # noqa: BLE001 - enrichment is best effort
            logger.warning(f"Could not read {attribute} for {instance_id}: {exc}")
            found[field] = None
    return found


def autoscaling_membership(instance_id):
    """Whether an Auto Scaling group would replace this instance once isolated.

    A group using ELB health checks fails an unreachable instance and
    terminates it, taking the evidence with it, so evidence collection detaches
    it first. The API is authoritative; the aws:autoscaling:groupName tag is
    writable by anyone who can tag the instance.
    """
    try:
        response = autoscaling_client.describe_auto_scaling_instances(InstanceIds=[instance_id])
        records = response.get("AutoScalingInstances") or []
        if not records:
            return {"autoScalingGroupName": None, "autoScalingHealthCheckType": None}
        group_name = records[0].get("AutoScalingGroupName")
        groups = autoscaling_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[group_name]
        ).get("AutoScalingGroups") or []
        return {
            "autoScalingGroupName": group_name,
            "autoScalingHealthCheckType": groups[0].get("HealthCheckType") if groups else None,
            "autoScalingTargetGroupArns": groups[0].get("TargetGroupARNs") if groups else [],
        }
    except Exception as exc:  # noqa: BLE001 - enrichment is best effort
        logger.warning(f"Could not read Auto Scaling membership for {instance_id}: {exc}")
        return {"autoScalingGroupName": None, "autoScalingHealthCheckType": None}
