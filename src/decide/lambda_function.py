"""Apply the response policy. Pure function, no AWS calls.

This is the only place a containment decision is made. It runs before the
Phase 6 AI triage and its output is never revisited, which is what keeps the
model advisory: whatever the model says later, the action set was already
fixed here by a rule in a reviewable file.
"""

import json
import logging

from irlib import incidents, policy

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ACTIONABLE = ("AUTO_CONTAIN", "APPROVAL_REQUIRED")


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
    decision["environmentSource"] = enrichment.get("environmentSource")

    incidents.update_incident(
        event["incidentId"],
        {"Decision": decision["decision"], "DecisionDetail": decision},
    )

    logger.info(
        f"Decision for {event.get('findingId')}: {decision['decision']} "
        f"via {decision['ruleId']} (policy v{decision['policyVersion']})"
    )
    return decision


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
