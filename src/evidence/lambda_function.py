"""Preserve evidence and stop the instance disappearing, before anything is cut off.

Everything here runs before network isolation, for three reasons:

* an isolated instance can no longer be reached by the SSM agent, so anything
  that needs the agent has to happen first;
* an Auto Scaling group using ELB health checks will fail the instance the
  moment it stops answering and replace it, destroying the evidence - so it is
  detached before it goes quiet;
* snapshots taken after isolation still capture the disk, but the volume
  protections have to be in place before anything can terminate it.

Each step goes through incidents.run_action, which writes the prior state to
the ledger before the call and marks it done afterwards. A retried execution
skips whatever already completed.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from irlib import incidents

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")
s3_client = boto3.client("s3")
autoscaling_client = boto3.client("autoscaling")
elbv2_client = boto3.client("elbv2")
guardduty_client = boto3.client("guardduty")

EVIDENCE_BUCKET = os.environ.get("EVIDENCE_BUCKET", "")
ENABLE_MEMORY_CAPTURE = os.environ.get("ENABLE_MEMORY_CAPTURE", "false").lower() == "true"

# DescribeTargetGroups has no reverse lookup from an instance, so the target
# groups have to be walked. Bounded so a large account cannot time the function
# out; anything beyond this is reported rather than silently ignored.
MAX_TARGET_GROUPS_SCANNED = 100


def handler(event, context):
    logger.info(f"Collecting evidence: {json.dumps(event)}")

    incident_id = event["incidentId"]
    instance = (event.get("enrichment") or {}).get("instance") or {}
    instance_id = instance.get("instanceId")
    if not instance_id:
        raise ValueError("No instance to collect evidence from; Decide should have downgraded this.")

    performed = []

    def step(key, action, perform, prior_state=None, best_effort=False):
        result = incidents.run_action(
            incident_id, f"{key}#{instance_id}", action, instance_id,
            perform, prior_state=prior_state, best_effort=best_effort,
        )
        performed.append(result)
        return result

    # 1. Capture what we know before changing anything.
    step("evidence-store", "evidence-store",
         lambda prior: store_evidence(incident_id, event, instance))

    # 2. Protections first: they are what stops the instance vanishing while
    #    the slower steps below run.
    step("protect-termination", "protect-termination",
         lambda prior: set_attribute(instance_id, DisableApiTermination={"Value": True}),
         prior_state={"disableApiTermination": instance.get("disableApiTermination")})

    step("protect-stop", "protect-stop",
         lambda prior: set_attribute(instance_id, DisableApiStop={"Value": True}),
         prior_state={"disableApiStop": instance.get("disableApiStop")})

    step("shutdown-behavior", "shutdown-behavior",
         lambda prior: set_attribute(
             instance_id, InstanceInitiatedShutdownBehavior={"Value": "stop"}),
         prior_state={"instanceInitiatedShutdownBehavior":
                      instance.get("instanceInitiatedShutdownBehavior")})

    volumes = block_devices(instance)
    if volumes:
        step("preserve-volumes", "preserve-volumes",
             lambda prior: preserve_volumes(instance_id, volumes),
             prior_state={"blockDeviceMappings": volumes})

    # 3. Snapshots, tagged so they can be found by incident later.
    step("snapshot", "snapshot", lambda prior: snapshot(incident_id, instance_id))

    # 4. Take it out of anything that would replace or keep routing to it.
    asg_name = instance.get("autoScalingGroupName")
    if asg_name:
        step("asg-detach", "asg-detach",
             lambda prior: detach_from_asg(asg_name, instance_id),
             prior_state={"autoScalingGroupName": asg_name,
                          "healthCheckType": instance.get("autoScalingHealthCheckType")})

    step("elb-deregister", "elb-deregister",
         lambda prior: deregister_targets(instance_id),
         best_effort=True)

    # 5. Best effort: a scan that cannot start must not stop containment.
    step("malware-scan", "malware-scan",
         lambda prior: start_malware_scan(event, instance_id),
         best_effort=True)

    # 6. Label the instance so it is obvious in the console.
    step("tag-instance", "tag-instance", lambda prior: tag_instance(incident_id, instance_id))

    if ENABLE_MEMORY_CAPTURE:
        step("memory-capture", "memory-capture",
             lambda prior: capture_memory(incident_id, instance_id), best_effort=True)

    logger.info(f"Evidence complete for {instance_id}: {[p['status'] for p in performed]}")
    return {"actions": performed, "instanceId": instance_id}


# --- individual steps -------------------------------------------------------


def store_evidence(incident_id, event, instance):
    """Write the finding and the instance description to the evidence bucket.

    The bucket carries a default Object Lock retention, so these objects cannot
    be deleted or overwritten for the configured period without the governance
    bypass permission - which nothing in this pipeline has.
    """
    if not EVIDENCE_BUCKET:
        raise RuntimeError("EVIDENCE_BUCKET is not set")

    prefix = f"{incident_id}/{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    written = []
    for name, body in (
        ("finding.json", event.get("finding") or {}),
        ("instance.json", instance),
    ):
        key = f"{prefix}/{name}"
        s3_client.put_object(
            Bucket=EVIDENCE_BUCKET,
            Key=key,
            Body=json.dumps(body, default=str, indent=2).encode("utf-8"),
            ContentType="application/json",
        )
        written.append(key)
    return {"bucket": EVIDENCE_BUCKET, "keys": written}


def set_attribute(instance_id, **attribute):
    """ModifyInstanceAttribute accepts one attribute per call."""
    ec2_client.modify_instance_attribute(InstanceId=instance_id, **attribute)
    return {"applied": {k: v for k, v in attribute.items()}}


def block_devices(instance):
    return [
        {"deviceName": mapping.get("DeviceName"),
         "volumeId": (mapping.get("Ebs") or {}).get("VolumeId"),
         "deleteOnTermination": (mapping.get("Ebs") or {}).get("DeleteOnTermination")}
        for mapping in instance.get("blockDeviceMappings") or []
        if (mapping.get("Ebs") or {}).get("VolumeId")
    ]


def preserve_volumes(instance_id, volumes):
    """Stop the disks going away with the instance."""
    mappings = [
        {"DeviceName": volume["deviceName"], "Ebs": {"DeleteOnTermination": False}}
        for volume in volumes
        if volume.get("deviceName")
    ]
    if mappings:
        ec2_client.modify_instance_attribute(InstanceId=instance_id, BlockDeviceMappings=mappings)
    return {"volumes": [v["volumeId"] for v in volumes]}


def snapshot(incident_id, instance_id):
    response = ec2_client.create_snapshots(
        InstanceSpecification={"InstanceId": instance_id, "ExcludeBootVolume": False},
        Description=f"IR evidence for incident {incident_id}",
        CopyTagsFromSource="volume",
        TagSpecifications=[
            {
                "ResourceType": "snapshot",
                "Tags": [
                    {"Key": "IncidentId", "Value": incident_id},
                    {"Key": "IRPipeline", "Value": "evidence"},
                ],
            }
        ],
    )
    return {"snapshotIds": [s["SnapshotId"] for s in response.get("Snapshots", [])]}


def detach_from_asg(asg_name, instance_id):
    """Detach without shrinking the group.

    ShouldDecrementDesiredCapacity=False means the group immediately launches a
    replacement, so production keeps its capacity while this instance is held
    for investigation.
    """
    autoscaling_client.detach_instances(
        AutoScalingGroupName=asg_name,
        InstanceIds=[instance_id],
        ShouldDecrementDesiredCapacity=False,
    )
    return {"autoScalingGroupName": asg_name, "decrementedCapacity": False}


def deregister_targets(instance_id):
    """Stop load balancers routing to the instance.

    Re-registration on release is deliberately left manual: putting a
    compromised instance back behind a load balancer is a decision for a human.
    """
    paginator = elbv2_client.get_paginator("describe_target_groups")
    deregistered, scanned, truncated = [], 0, False

    for page in paginator.paginate():
        for group in page.get("TargetGroups", []):
            if scanned >= MAX_TARGET_GROUPS_SCANNED:
                truncated = True
                break
            scanned += 1
            arn = group["TargetGroupArn"]
            if group.get("TargetType") not in (None, "instance"):
                continue
            try:
                health = elbv2_client.describe_target_health(
                    TargetGroupArn=arn, Targets=[{"Id": instance_id}]
                )
            except ClientError as exc:
                # Not registered in this group - the common case.
                if exc.response["Error"]["Code"] in ("InvalidTarget", "TargetGroupNotFound"):
                    continue
                raise
            for description in health.get("TargetHealthDescriptions", []):
                target = description.get("Target") or {}
                if target.get("Id") != instance_id:
                    continue
                elbv2_client.deregister_targets(TargetGroupArn=arn, Targets=[target])
                deregistered.append({"targetGroupArn": arn, "port": target.get("Port")})
        if truncated:
            break

    return {"deregistered": deregistered, "targetGroupsScanned": scanned, "truncated": truncated}


def start_malware_scan(event, instance_id):
    arn = (
        f"arn:aws:ec2:{event.get('region')}:{event.get('accountId')}:instance/{instance_id}"
    )
    response = guardduty_client.start_malware_scan(ResourceArn=arn)
    return {"scanId": response.get("ScanId"), "resourceArn": arn}


def tag_instance(incident_id, instance_id):
    tags = [
        {"Key": "IRPipeline:IncidentId", "Value": incident_id},
        {"Key": "IRPipeline:Status", "Value": "quarantined"},
        {"Key": "IRPipeline:QuarantinedAt", "Value": datetime.now(timezone.utc).isoformat()},
    ]
    ec2_client.create_tags(Resources=[instance_id], Tags=tags)
    return {"tags": tags}


def capture_memory(incident_id, instance_id):
    """Placeholder for SSM-based memory acquisition.

    Deliberately not implemented. A real capture needs an SSM document, a
    destination the instance can still reach, and an agent that is still
    running - and the next two states remove all three by isolating the network
    and disabling IMDS. Anything built here has to complete before those run,
    which is why the hook sits at the end of the evidence step rather than
    later in the chain.
    """
    # TODO: send an SSM document that dumps memory to the evidence bucket, and
    # wait for it to finish, before the network isolation state runs.
    logger.warning(
        f"Memory capture is enabled but not implemented; skipping for {instance_id}. "
        "Isolation and disabling IMDS both cut off the SSM agent, so any "
        "implementation has to complete inside this step."
    )
    return {"implemented": False, "incidentId": incident_id}
