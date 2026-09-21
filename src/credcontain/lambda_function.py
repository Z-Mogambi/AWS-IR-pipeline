"""Invalidate a compromised role's credentials. The only holder of iam:PutRolePolicy.

Network isolation does nothing about credentials that have already been stolen:
the attacker is using them from their own machine, not from the instance. The
fix is an inline Deny on the role, conditioned on the session that issued them.

For an EC2 instance role that condition is `ec2:SourceInstanceARN`. The key is
"included in the request context whenever the role session is created by an
Amazon EC2 instance", so it is a property of the credentials themselves and
travels with them wherever they are used. Pinning the Deny to one instance ARN
therefore kills exactly that instance's credentials and leaves every other
instance sharing the role working.

What this deliberately does NOT do is deny on `aws:TokenIssueTime` for an EC2
role. That invalidates every session issued before now - including those of
every other instance on the role - and IMDS keeps handing out the revoked
credentials until they expire, so the instances break and stay broken. The
token-issue-time template below is for non-EC2 role sessions only, and carries
a `Null` guard on `ec2:SourceInstanceARN` so it cannot take effect on an EC2
session even if it is pointed at the wrong role.

This function is small on purpose. It is the most dangerous code in the stack:
anything able to call it can write an inline policy onto a role. Accordingly it
takes no policy structure from its input, builds documents from fixed templates,
re-derives the target role from AWS rather than trusting upstream state, refuses
anything that is not a pure Deny, and reads the policy back after writing it.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone

import boto3

from irlib import guard, incidents

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2_client = boto3.client("ec2")
iam_client = boto3.client("iam")

VERIFY_WRITTEN_POLICIES = os.environ.get("VERIFY_WRITTEN_POLICIES", "true").lower() == "true"

# Both instance id forms, anchored. Anything else is refused outright - this
# value ends up inside an ARN in a policy document.
INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8}(?:[0-9a-f]{9})?$")

# iam:PutRolePolicy accepts [\w+=,.@-]+ up to 128 characters.
POLICY_NAME_PREFIX = "IR-Quarantine-"
ROLE_NAME_RE = re.compile(r"^[\w+=,.@-]{1,64}$")

METHOD_INSTANCE = "deny-instance-credentials"
METHOD_SESSIONS = "deny-older-sessions"


class RefusedError(Exception):
    """The request did not pass validation. Nothing was written."""


def handler(event, context):
    logger.info(f"Credential containment: {json.dumps(event)}")

    incident_id = event["incidentId"]
    targets = (event.get("finding") or {}).get("targets") or {}
    instance_ids = targets.get("instanceIds") or []
    access_key = targets.get("accessKey") or {}

    if instance_ids:
        return contain_instance_credentials(event, incident_id, instance_ids[0])

    if access_key.get("userType") == "AssumedRole" and access_key.get("userName"):
        return contain_role_sessions(event, incident_id, access_key["userName"])

    logger.info("Nothing for credential containment to act on.")
    return {"actions": [], "method": None, "skipped": "no role-based credential to contain"}


# --- the EC2 instance path --------------------------------------------------


def contain_instance_credentials(event, incident_id, instance_id):
    """Deny everything this one instance's credentials can do, wherever they are used."""
    if not INSTANCE_ID_RE.match(instance_id or ""):
        raise RefusedError(f"Refusing to act on a malformed instance id: {instance_id!r}")

    account_id = event.get("accountId")
    region = event.get("region")
    if not account_id or not region:
        raise RefusedError("Account id and region are required to build the instance ARN.")

    # Re-derived from AWS, not taken from upstream state. This function is the
    # one that must not be steerable by whatever an earlier state produced.
    role_name = role_for_instance(instance_id)
    if not role_name:
        logger.warning(f"{instance_id} has no instance profile; nothing to deny.")
        return {"actions": [], "method": METHOD_INSTANCE,
                "skipped": "instance has no instance profile"}

    instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}"
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "IRQuarantineDenyCompromisedInstanceCredentials",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {"ArnEquals": {"ec2:SourceInstanceARN": instance_arn}},
            }
        ],
    }

    return write_policy(
        incident_id=incident_id,
        role_name=role_name,
        policy_name=policy_name_for(instance_id),
        document=document,
        method=METHOD_INSTANCE,
        action_key=f"deny-instance-credentials#{instance_id}",
        detail={"instanceArn": instance_arn, "instanceId": instance_id},
    )


def role_for_instance(instance_id):
    """Read the instance's profile from EC2, then the role from IAM."""
    reservations = ec2_client.describe_instances(InstanceIds=[instance_id]).get("Reservations") or []
    if not reservations or not reservations[0].get("Instances"):
        raise RefusedError(f"Instance {instance_id} not found; refusing to guess a role.")

    profile_arn = (reservations[0]["Instances"][0].get("IamInstanceProfile") or {}).get("Arn")
    if not profile_arn:
        return None

    profile_name = profile_arn.rsplit("/", 1)[-1]
    profile = iam_client.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
    roles = profile.get("Roles") or []
    if not roles:
        return None
    return roles[0]["RoleName"]


# --- the non-EC2 role session path ------------------------------------------


def contain_role_sessions(event, incident_id, role_name):
    """Deny sessions issued before now, for a role that is not an EC2 instance role."""
    issued_before = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "IRQuarantineDenyOlderSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {"aws:TokenIssueTime": issued_before},
                    # Refuses to take effect on an EC2 instance session even if
                    # this is somehow pointed at an EC2 role. IMDS would keep
                    # serving the revoked credentials until they expired,
                    # breaking every instance on the role.
                    "Null": {"ec2:SourceInstanceARN": "true"},
                },
            }
        ],
    }

    return write_policy(
        incident_id=incident_id,
        role_name=role_name,
        policy_name=policy_name_for(role_name),
        document=document,
        method=METHOD_SESSIONS,
        action_key=f"deny-older-sessions#{role_name}",
        detail={"issuedBefore": issued_before, "roleName": role_name},
    )


# --- the one place that writes ----------------------------------------------


def policy_name_for(suffix):
    name = f"{POLICY_NAME_PREFIX}{suffix}"[:128]
    if not re.fullmatch(r"[\w+=,.@-]+", name):
        raise RefusedError(f"Refusing to write a policy with an unsafe name: {name!r}")
    return name


def assert_deny_only(document):
    """A document this function writes must be a pure Deny.

    This is the guard that makes holding iam:PutRolePolicy tolerable. Anything
    that is not a Deny - or is missing an Effect at all - is refused before the
    call, and checked again after it.
    """
    statements = document.get("Statement")
    if not isinstance(statements, list) or not statements:
        raise RefusedError("Refusing a policy document with no statements.")
    for statement in statements:
        if statement.get("Effect") != "Deny":
            raise RefusedError(
                f"Refusing to write a policy containing a non-Deny statement: "
                f"{statement.get('Sid') or statement.get('Effect')!r}"
            )
    return document


def write_policy(incident_id, role_name, policy_name, document, method, action_key, detail):
    if not ROLE_NAME_RE.match(role_name or ""):
        raise RefusedError(f"Refusing to act on a malformed role name: {role_name!r}")

    # Never the pipeline's own roles, the configured break-glass roles, or a
    # service-linked role.
    guard.assert_role_actionable(role_name, context=f"credential containment for {incident_id}")

    assert_deny_only(document)

    def perform(prior):
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(document),
        )
        written = verify_written(role_name, policy_name)
        return {"roleName": role_name, "policyName": policy_name, "method": method,
                "verified": written, **detail}

    result = incidents.run_action(
        incident_id,
        action_key,
        method,
        role_name,
        perform,
        prior_state={"roleName": role_name, "policyName": policy_name,
                     "existedBefore": policy_exists(role_name, policy_name)},
    )
    logger.info(f"{method} applied to role {role_name} as {policy_name}")
    return {"actions": [result], "method": method, "roleName": role_name,
            "policyName": policy_name}


def policy_exists(role_name, policy_name):
    """So release knows whether to delete the policy or leave it alone."""
    try:
        iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        return True
    except iam_client.exceptions.NoSuchEntityException:
        return False


def verify_written(role_name, policy_name):
    """Read back what was actually stored and re-check it is Deny-only.

    The brief asks for a check that alerts if a policy this pipeline wrote
    contains an Allow. Doing it immediately after the write, on the document
    IAM actually stored, catches it at the only moment it can still be acted on.
    """
    if not VERIFY_WRITTEN_POLICIES:
        return {"checked": False}

    stored = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    document = stored["PolicyDocument"]
    if isinstance(document, str):
        document = json.loads(document)

    try:
        assert_deny_only(document)
    except RefusedError as exc:
        logger.error(
            f"ALERT: the policy {policy_name} stored on {role_name} is not Deny-only: {exc}"
        )
        raise

    return {"checked": True, "denyOnly": True, "statements": len(document["Statement"])}
