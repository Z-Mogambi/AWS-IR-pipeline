"""Containment for findings whose resource is an access key.

Three kinds of credential turn up behind a GuardDuty AccessKey finding, and
they need different handling:

* a long-lived IAM user key - deactivated here, which is reversible;
* an EC2 instance role session - handled by src/credcontain, which pins a Deny
  to that instance's ARN;
* any other role session - also src/credcontain, denying sessions issued before
  now.

Only the first is done in this function, because it is the only one that does
not need iam:PutRolePolicy. Keeping that permission in exactly one small,
single-purpose function is worth the extra state in the machine.

GuardDuty AI Protection findings arrive here too: they carry resourceType
AccessKey. The response policy notifies on them by default, except for
CostHarvesting, which needs a human.
"""

import json
import logging

import boto3

from irlib import findings, guard, incidents

logger = logging.getLogger()
logger.setLevel(logging.INFO)

iam_client = boto3.client("iam")

METHOD_DEACTIVATE_KEY = "deactivate-access-key"
METHOD_INSTANCE = "deny-instance-credentials"
METHOD_SESSIONS = "deny-older-sessions"


def classify(access_key):
    """Work out which containment method applies, without doing anything."""
    if not access_key:
        return {"method": None, "reason": "the finding names no access key"}

    user_type = access_key.get("userType")
    user_name = access_key.get("userName")

    if user_type == "IAMUser":
        if not user_name:
            return {"method": None, "reason": "IAM user key with no user name"}
        return {"method": METHOD_DEACTIVATE_KEY, "userName": user_name,
                "accessKeyId": access_key.get("accessKeyId")}

    if user_type in ("AssumedRole", "Role", "AssumedRoleUser"):
        instance_id = access_key.get("derivedInstanceId") or findings.instance_id_from_principal(
            access_key.get("principalId")
        )
        if instance_id:
            return {"method": METHOD_INSTANCE, "instanceId": instance_id, "roleName": user_name}
        return {"method": METHOD_SESSIONS, "roleName": user_name}

    return {"method": None, "reason": f"unhandled user type {user_type!r}"}


def handler(event, context):
    logger.info(f"Identity containment: {json.dumps(event)}")

    incident_id = event["incidentId"]
    access_key = ((event.get("finding") or {}).get("targets") or {}).get("accessKey") or {}
    plan = classify(access_key)

    if plan["method"] != METHOD_DEACTIVATE_KEY:
        # The role paths belong to src/credcontain, which runs before this
        # state. Report the classification so the notification can explain it.
        logger.info(f"Nothing for this function to do: {plan}")
        return {"actions": [], "classification": plan}

    user_name = plan["userName"]
    access_key_id = plan["accessKeyId"]
    if not access_key_id:
        return {"actions": [], "classification": {**plan, "reason": "no access key id"}}

    # A break-glass user's key is exactly the one not to deactivate.
    guard.assert_role_actionable(user_name, context=f"identity containment for {incident_id}")

    def perform(prior):
        iam_client.update_access_key(
            UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
        )
        return {"userName": user_name, "accessKeyId": access_key_id, "status": "Inactive"}

    result = incidents.run_action(
        incident_id,
        f"deactivate-access-key#{access_key_id}",
        METHOD_DEACTIVATE_KEY,
        access_key_id,
        perform,
        prior_state=read_prior_status(user_name, access_key_id),
    )
    return {"actions": [result], "classification": plan}


def read_prior_status(user_name, access_key_id):
    """Record the key's status before changing it, so release can restore it.

    A key that was already inactive must not be reactivated on release.
    """
    try:
        for key in iam_client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
            if key.get("AccessKeyId") == access_key_id:
                return {"userName": user_name, "accessKeyId": access_key_id,
                        "status": key.get("Status")}
    except Exception as exc:  # noqa: BLE001 - recording is best effort
        logger.warning(f"Could not read the prior status of {access_key_id}: {exc}")
    return {"userName": user_name, "accessKeyId": access_key_id, "status": None}
