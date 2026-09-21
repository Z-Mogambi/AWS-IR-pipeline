"""Undo containment, in the reverse of the order it was applied.

Everything here comes from the write-ahead ledger. Containment recorded the
prior state before each change, so release does not have to infer anything -
it replays those records backwards.

The order is the containment order reversed, and it matters for one hard
dependency: every ENI has to be moved back to its original security groups
before the per-incident quarantine group can be deleted, because a group still
attached to an interface cannot be deleted.

Two things are deliberately left to a human:

* Auto Scaling re-attachment. The group already launched a replacement, so
  re-attaching changes capacity; and putting a previously compromised instance
  back into a serving group is a decision, not a cleanup step.
* Load balancer re-registration, for the same reason.

Both are reported in the release notification as outstanding.

Like containment, every step goes through incidents.run_action, so a partially
completed release can be re-run and will skip what already succeeded.
"""

import json
import logging

import boto3
from botocore.exceptions import ClientError

from irlib import guard, incidents

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")
iam_client = boto3.client("iam")
route53resolver_client = boto3.client("route53resolver")

# Lower runs first. This is the containment order reversed.
RELEASE_ORDER = {
    "disable-imds": 10,
    "deny-instance-credentials": 20,
    "deny-older-sessions": 20,
    "deactivate-access-key": 30,
    "dns-block": 40,
    "nacl-backstop": 50,
    "eni-isolate": 60,
    # Must come after eni-isolate: a group attached to an interface cannot be
    # deleted.
    "quarantine-sg-create": 70,
    "preserve-volumes": 80,
    "shutdown-behavior": 90,
    "protect-stop": 91,
    "protect-termination": 92,
}

# Recorded for the audit trail, but nothing to undo.
NOTHING_TO_UNDO = {
    "evidence-store", "snapshot", "tag-instance", "malware-scan", "memory-capture",
    "quarantine-sg-open", "quarantine-sg-seal",
}

# Reversible only by a human.
MANUAL = {
    "asg-detach": "Re-attach the instance to its Auto Scaling group by hand. The group "
                  "already launched a replacement, so re-attaching changes capacity.",
    "elb-deregister": "Re-register the instance with its target groups by hand. Putting a "
                      "previously compromised instance back into a serving group is a decision.",
}


def handler(event, context):
    mode = event.get("mode", "load")
    incident_id = event["incidentId"]

    if mode == "load":
        return load(incident_id)
    if mode == "restore":
        return restore(incident_id)
    raise ValueError(f"Unknown mode {mode!r}")


def load(incident_id):
    """Read the ledger and describe what release would do, without doing it."""
    meta = incidents.get_meta(incident_id)
    if not meta:
        raise ValueError(f"No incident record for {incident_id!r}")

    actions = incidents.list_actions(incident_id)
    done = [a for a in actions if a.get("Status") == incidents.STATUS_DONE]

    plan, manual, ignored = [], [], []
    for record in sorted(done, key=_priority):
        action = record.get("Action")
        if action in MANUAL:
            manual.append({"action": action, "target": record.get("Target"),
                           "instruction": MANUAL[action]})
        elif action in RELEASE_ORDER:
            plan.append({"action": action, "target": record.get("Target")})
        else:
            ignored.append({"action": action, "target": record.get("Target")})

    return {
        "incidentId": incident_id,
        "findingId": meta.get("FindingId"),
        "findingType": meta.get("FindingType"),
        "environment": meta.get("Environment"),
        "plan": plan,
        "manualSteps": manual,
        "nothingToUndo": ignored,
        "actionCount": len(done),
    }


def _priority(record):
    return (RELEASE_ORDER.get(record.get("Action"), 999), record.get("StartedAt") or "")


def restore(incident_id):
    """Replay the ledger backwards."""
    actions = incidents.list_actions(incident_id)
    done = [
        record for record in actions
        if record.get("Status") == incidents.STATUS_DONE
        and record.get("Action") in RELEASE_ORDER
    ]

    performed = []
    for record in sorted(done, key=_priority):
        action = record.get("Action")
        handler_fn = HANDLERS.get(action)
        if not handler_fn:
            continue

        original_key = (record.get("RecordId") or "").removeprefix(incidents.ACTION_PREFIX)
        performed.append(
            incidents.run_action(
                incident_id,
                f"release#{original_key}",
                f"release:{action}",
                record.get("Target") or "",
                lambda prior, rec=record, fn=handler_fn: fn(rec),
                prior_state={"releasing": original_key},
                # One step failing must not strand the rest; the notification
                # reports exactly what did and did not come back.
                best_effort=True,
            )
        )

    manual = [
        {"action": r.get("Action"), "target": r.get("Target"), "instruction": MANUAL[r.get("Action")]}
        for r in actions
        if r.get("Action") in MANUAL and r.get("Status") == incidents.STATUS_DONE
    ]

    incidents.update_incident(incident_id, {"Status": "RELEASED"})
    logger.info(f"Released {incident_id}: {[p['status'] for p in performed]}")
    return {"actions": performed, "manualSteps": manual, "incidentId": incident_id}


# --- individual reversals ---------------------------------------------------


def _prior(record):
    prior = record.get("PriorState")
    if isinstance(prior, str):
        return json.loads(prior)
    return prior or {}


def _result(record):
    result = record.get("Result")
    if isinstance(result, str):
        return json.loads(result)
    return result or {}


def restore_imds(record):
    """Put every metadata setting back, not just the endpoint.

    Restoring HttpEndpoint alone would leave HttpTokens at whatever the API
    defaults to, which can silently downgrade an instance from IMDSv2-only.
    """
    prior = _prior(record)
    instance_id = record["Target"]
    arguments = {"InstanceId": instance_id, "HttpEndpoint": prior.get("httpEndpoint") or "enabled"}
    for field, key in (
        ("httpTokens", "HttpTokens"),
        ("httpPutResponseHopLimit", "HttpPutResponseHopLimit"),
        ("instanceMetadataTags", "InstanceMetadataTags"),
        ("httpProtocolIpv6", "HttpProtocolIpv6"),
    ):
        if prior.get(field) is not None:
            arguments[key] = prior[field]

    ec2_client.modify_instance_metadata_options(**arguments)
    return {"restored": arguments}


def remove_role_deny(record):
    prior = _prior(record)
    role_name = prior.get("roleName") or record.get("Target")
    policy_name = prior.get("policyName")
    if not role_name or not policy_name:
        return {"skipped": "the ledger did not record a role and policy name"}

    guard.assert_role_actionable(role_name, context="release")

    if prior.get("existedBefore"):
        # A policy of the same name was already there before containment ran.
        # Deleting it would remove something that was not ours.
        return {"skipped": f"{policy_name} existed on {role_name} before containment"}

    try:
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except iam_client.exceptions.NoSuchEntityException:
        return {"alreadyGone": True, "roleName": role_name, "policyName": policy_name}
    return {"deleted": policy_name, "roleName": role_name}


def reactivate_access_key(record):
    """Only if it was active before. A key deliberately disabled stays disabled."""
    prior = _prior(record)
    if prior.get("status") != "Active":
        return {"skipped": f"the key was {prior.get('status')!r} before containment"}

    iam_client.update_access_key(
        UserName=prior["userName"], AccessKeyId=prior["accessKeyId"], Status="Active"
    )
    return {"reactivated": prior["accessKeyId"]}


def unblock_domains(record):
    result = _result(record)
    domains = result.get("domains") or []
    domain_list_id = result.get("domainListId")
    if not domains or not domain_list_id:
        return {"skipped": "no domains recorded"}

    route53resolver_client.update_firewall_domains(
        FirewallDomainListId=domain_list_id, Operation="REMOVE", Domains=domains
    )
    # The VPC association is left in place: other incidents may still rely on
    # it, and an empty block list is harmless.
    return {"removed": domains, "associationLeftInPlace": result.get("associationId")}


def remove_nacl_entries(record):
    result = _result(record)
    removed, missing = [], []
    for entry in result.get("entries") or []:
        try:
            ec2_client.delete_network_acl_entry(
                NetworkAclId=entry["networkAclId"],
                RuleNumber=entry["ruleNumber"],
                Egress=entry["egress"],
            )
            removed.append(entry)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidNetworkAclEntry.NotFound":
                missing.append(entry)
                continue
            raise
    return {"removed": removed, "alreadyGone": missing}


def restore_interface_groups(record):
    prior = _prior(record)
    groups = prior.get("groups") or []
    eni_id = record["Target"]
    if not groups:
        return {"skipped": f"no original groups recorded for {eni_id}"}

    ec2_client.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=groups)
    return {"networkInterfaceId": eni_id, "groups": groups}


def delete_quarantine_group(record):
    """Delete the per-incident group. Safe only once every ENI is back."""
    group_id = _result(record).get("groupId")
    if not group_id:
        return {"skipped": "no group id recorded"}
    if _result(record).get("created") is False:
        # It was reused rather than created by this incident.
        pass

    try:
        ec2_client.delete_security_group(GroupId=group_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "InvalidGroup.NotFound":
            return {"alreadyGone": True, "groupId": group_id}
        if code == "DependencyViolation":
            # Something is still using it. Report rather than force.
            return {"stillInUse": True, "groupId": group_id}
        raise
    return {"deleted": group_id}


def restore_volume_lifecycle(record):
    prior = _prior(record)
    mappings = [
        {"DeviceName": volume["deviceName"],
         "Ebs": {"DeleteOnTermination": bool(volume.get("deleteOnTermination"))}}
        for volume in prior.get("blockDeviceMappings") or []
        if volume.get("deviceName")
    ]
    if not mappings:
        return {"skipped": "no block device mappings recorded"}

    ec2_client.modify_instance_attribute(
        InstanceId=record["Target"], BlockDeviceMappings=mappings
    )
    return {"restored": mappings}


def _restore_attribute(record, prior_key, argument, default):
    prior = _prior(record)
    value = prior.get(prior_key)
    if value is None:
        value = default
    ec2_client.modify_instance_attribute(
        InstanceId=record["Target"], **{argument: {"Value": value}}
    )
    return {argument: value}


HANDLERS = {
    "disable-imds": restore_imds,
    "deny-instance-credentials": remove_role_deny,
    "deny-older-sessions": remove_role_deny,
    "deactivate-access-key": reactivate_access_key,
    "dns-block": unblock_domains,
    "nacl-backstop": remove_nacl_entries,
    "eni-isolate": restore_interface_groups,
    "quarantine-sg-create": delete_quarantine_group,
    "preserve-volumes": restore_volume_lifecycle,
    "shutdown-behavior": lambda r: _restore_attribute(
        r, "instanceInitiatedShutdownBehavior", "InstanceInitiatedShutdownBehavior", "stop"
    ),
    "protect-stop": lambda r: _restore_attribute(r, "disableApiStop", "DisableApiStop", False),
    "protect-termination": lambda r: _restore_attribute(
        r, "disableApiTermination", "DisableApiTermination", False
    ),
}
