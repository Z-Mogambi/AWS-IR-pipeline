"""Apply the response policy. Pure function, no AWS calls.

This is the only place a containment decision is made. It runs before the
Phase 6 AI triage and its output is never revisited, which is what keeps the
model advisory: whatever the model says later, the action set was already
fixed here by a rule in a reviewable file.
"""

import json
import logging
import os

from irlib import incidents, policy

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ACTIONABLE = ("AUTO_CONTAIN", "APPROVAL_REQUIRED")

# Step Functions cannot take a timeout from a template parameter directly, so
# the value travels in the decision and the approval state reads it with
# TimeoutSecondsPath.
APPROVAL_TIMEOUT_SECONDS = int(os.environ.get("APPROVAL_TIMEOUT_SECONDS", "3600"))
APPROVAL_TIMEOUT_ACTION = os.environ.get("APPROVAL_TIMEOUT_ACTION", "Escalate")

# An attack sequence names a group of instances. Containing a handful
# automatically is one thing; containing a whole Auto Scaling group or every
# instance built from one AMI is an outage, so above this many a human decides.
MAX_AUTO_CONTAIN_INSTANCES = int(os.environ.get("MAX_AUTO_CONTAIN_INSTANCES", "3"))
CONTAINMENT_CONCURRENCY = int(os.environ.get("CONTAINMENT_CONCURRENCY", "2"))


def handler(event, context):
    logger.info(f"Deciding: {json.dumps(event)}")

    summary = (event.get("finding") or {}).get("summary") or {}
    targets = (event.get("finding") or {}).get("targets") or {}
    enrichment = event.get("enrichment") or {}

    decision = policy.evaluate(
        finding_type=summary.get("type"),
        severity=summary.get("severity") or 0.0,
        environment=enrichment.get("environment") or "production",
        resource_type=summary.get("resourceType"),
        resource_role=summary.get("resourceRole"),
    )

    decision = _downgrade_if_no_target(decision, targets)
    decision = _cap_bulk_containment(decision, targets)
    decision = _mark_escalation(decision, targets)
    decision["environmentSource"] = enrichment.get("environmentSource")
    decision["maxConcurrency"] = CONTAINMENT_CONCURRENCY
    decision["approvalTimeoutSeconds"] = APPROVAL_TIMEOUT_SECONDS
    # In production the default is to escalate, not to contain: nobody
    # answering an approval request is not consent to act.
    decision["approvalTimeoutAction"] = APPROVAL_TIMEOUT_ACTION

    incidents.update_incident(
        event["incidentId"],
        {"Decision": decision["decision"], "DecisionDetail": decision},
    )

    logger.info(
        f"Decision for {event.get('findingId')}: {decision['decision']} "
        f"via {decision['ruleId']} (policy v{decision['policyVersion']})"
    )
    return decision


def _cap_bulk_containment(decision, targets):
    """Above the cap, an attack sequence needs a human rather than a Map state.

    AttackSequence findings name a group of resources that share an Auto
    Scaling group, instance profile, launch template, CloudFormation stack, AMI
    or VPC. Containing three compromised instances is incident response;
    containing thirty because they share an AMI is an outage.
    """
    if decision["decision"] != "AUTO_CONTAIN":
        return decision

    instance_ids = targets.get("instanceIds") or []
    if len(instance_ids) <= MAX_AUTO_CONTAIN_INSTANCES:
        return decision

    capped = dict(decision)
    capped["decision"] = "APPROVAL_REQUIRED"
    capped["downgradedFrom"] = "AUTO_CONTAIN"
    capped["downgradeReason"] = (
        f"The finding names {len(instance_ids)} instances, above the "
        f"MaxAutoContainInstances cap of {MAX_AUTO_CONTAIN_INSTANCES}. "
        "Containing this many at once needs a human decision."
    )
    capped["instanceCount"] = len(instance_ids)
    logger.warning(capped["downgradeReason"])
    return capped


def _mark_escalation(decision, targets):
    """A known-vulnerable, internet-reachable resource is the worst combination.

    VULNERABILITY means Inspector found CVEs on a resource in the sequence;
    REACHABILITY means one is reachable from the internet. Either alone is
    common. Both together says the way in is known and open, so the incident is
    marked escalated in the record and the notification.
    """
    sequence = targets.get("sequence")
    if not sequence:
        return decision

    marked = dict(decision)
    marked["escalated"] = bool(sequence.get("escalated"))
    marked["sequenceIndicators"] = sequence.get("indicatorKeys") or []
    if marked["escalated"]:
        marked["escalationReason"] = (
            "The sequence carries both VULNERABILITY and REACHABILITY indicators: "
            "a resource with known CVEs that is reachable from the internet."
        )
        logger.warning(marked["escalationReason"])
    return marked


def _downgrade_if_no_target(decision, targets):
    """Never claim we will contain something we cannot name.

    A finding can arrive with no usable instance id - the instance was already
    terminated, or the finding is a sample referencing a fake resource. Saying
    AUTO_CONTAIN there would produce an alert asserting containment that never
    happened, which is worse than saying plainly that there is nothing to act on.
    """
    if decision["decision"] not in ACTIONABLE:
        return decision
    if targets.get("instanceIds"):
        return decision
    if targets.get("accessKey"):
        return decision  # Phase 3 acts on the key itself.

    downgraded = dict(decision)
    downgraded["decision"] = "NOTIFY"
    downgraded["actions"] = []
    for flag in ("doEvidence", "doNetwork", "doCredentials", "doImds"):
        downgraded[flag] = False
    downgraded["downgradedFrom"] = decision["decision"]
    downgraded["downgradeReason"] = (
        "The finding named no resource this pipeline can act on."
        + (f" Rejected ids: {targets['rejectedInstanceIds']}." if targets.get("rejectedInstanceIds") else "")
    )
    logger.warning(downgraded["downgradeReason"])
    return downgraded
