"""Publish the incident notification to SNS.

One function serves every outcome - notify-only, approval needed, contained,
containment failed, verification failed - because the alert must go out on the
paths where something went wrong just as reliably as on the happy one. The
`notifyKind` field in the state machine says which.

The message never claims an action happened unless the ledger says it did. The
previous version told every reader "the instance has been automatically
isolated if it was a production instance" regardless of whether isolation ran,
or succeeded.
"""

import json
import logging
import os

import boto3

from irlib import incidents

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns_client = boto3.client("sns")
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

# SNS subjects are capped at 100 characters and must be printable ASCII on a
# single line. Build one that always fits rather than risking InvalidParameter.
MAX_SUBJECT = 100

HEADLINE = {
    "VERIFY_FAILED": "COULD NOT VERIFY",
    "PIPELINE_ERROR": "PIPELINE ERROR",
    "NOTIFY": "NOTIFY",
    "APPROVAL_REQUIRED": "APPROVAL NEEDED",
    "CONTAINED": "CONTAINED",
    "CONTAINMENT_FAILED": "CONTAINMENT FAILED",
}


def safe_subject(text):
    ascii_only = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text)
    collapsed = " ".join(ascii_only.split())
    if len(collapsed) <= MAX_SUBJECT:
        return collapsed
    return collapsed[: MAX_SUBJECT - 3] + "..."


def handler(event, context):
    logger.info(f"Notifying: {json.dumps(event)}")

    kind = event.get("notifyKind", "NOTIFY")
    summary = (event.get("finding") or {}).get("summary") or {}
    targets = (event.get("finding") or {}).get("targets") or {}
    enrichment = event.get("enrichment") or {}
    decision = event.get("decision") or {}
    containment = event.get("containment") or {}
    error = event.get("error") or {}

    environment = enrichment.get("environment", "unknown")
    instances = targets.get("instanceIds") or []
    instance_label = ", ".join(instances) if instances else "no actionable instance"

    subject = safe_subject(
        f"[{HEADLINE.get(kind, kind)}][{environment}] "
        f"{summary.get('type') or 'GuardDuty finding'} - {instance_label}"
    )
    message = build_message(kind, event, summary, targets, enrichment, decision, containment, error)

    sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    logger.info(f"Published {kind} notification for incident {event.get('incidentId')}")

    return {"status": "SENT", "kind": kind, "subject": subject}


def build_message(kind, event, summary, targets, enrichment, decision, containment, error):
    lines = [
        f"Incident:    {event.get('incidentId')}",
        f"Finding:     {event.get('findingId')}",
        f"Type:        {summary.get('type')}",
        f"Severity:    {summary.get('severity')} ({decision.get('severityBand', 'unknown')})",
        f"Account:     {event.get('accountId')}   Region: {event.get('region')}",
        f"Environment: {enrichment.get('environment', 'unknown')} "
        f"(source: {enrichment.get('environmentSource', 'unknown')})",
        f"First seen:  {summary.get('createdAt')}",
        "",
        f"Title:       {summary.get('title')}",
        f"Description: {summary.get('description')}",
        "",
    ]

    if targets.get("instanceIds"):
        lines.append(f"Instances:   {', '.join(targets['instanceIds'])}")
    if targets.get("rejectedInstanceIds"):
        lines.append(
            f"Ignored ids: {', '.join(targets['rejectedInstanceIds'])} "
            "(not a valid instance id - sample findings reference fake resources)"
        )
    if targets.get("domains"):
        lines.append(f"Domains:     {', '.join(targets['domains'])}")
    if targets.get("remoteIps"):
        lines.append(f"Remote IPs:  {', '.join(targets['remoteIps'])}")
    lines.append("")

    lines.append("DECISION")
    lines.append(f"  {decision.get('decision', 'n/a')} by rule {decision.get('ruleId', 'n/a')} "
                 f"(response policy v{decision.get('policyVersion', 'n/a')})")
    if decision.get("ruleDescription"):
        lines.append(f"  {decision['ruleDescription']}")
    if decision.get("downgradedFrom"):
        lines.append(f"  Downgraded from {decision['downgradedFrom']}: {decision.get('downgradeReason')}")
    if decision.get("actions"):
        lines.append(f"  Planned actions: {', '.join(decision['actions'])}")
    lines.append("")

    if kind == "VERIFY_FAILED":
        lines += [
            "THE FINDING COULD NOT BE VERIFIED",
            "  GuardDuty returned no matching finding, the finding is archived, or its",
            "  identifiers did not match the event. No action was taken. Investigate by hand.",
            f"  Error: {error.get('Error')}",
            f"  Cause: {str(error.get('Cause'))[:800]}",
        ]
    elif kind == "APPROVAL_REQUIRED":
        lines += [
            "NO ACTION HAS BEEN TAKEN - a human decision is required.",
            "  Phase 4 replaces this notice with a callback token you can approve or reject.",
        ]
    elif kind == "PIPELINE_ERROR":
        lines += [
            "THE PIPELINE ITSELF FAILED - treat this finding as untriaged.",
            f"  Error: {error.get('Error')}",
            f"  Cause: {str(error.get('Cause'))[:800]}",
        ]
    elif kind == "CONTAINED":
        lines.append("ACTIONS PERFORMED")
        lines += _action_lines(event.get("incidentId"), containment)
    elif kind == "CONTAINMENT_FAILED":
        lines += [
            "CONTAINMENT DID NOT COMPLETE - this incident is partially contained.",
            "  Nothing was rolled back. What did and did not happen:",
        ]
        lines += _action_lines(event.get("incidentId"), containment)
        lines += [
            f"  Error: {error.get('Error')}",
            f"  Cause: {str(error.get('Cause'))[:800]}",
        ]
    else:
        lines.append("No containment was performed for this finding.")

    return "\n".join(lines)


def _action_lines(incident_id, containment):
    """Report what the ledger says happened, not what we intended.

    On a partial failure the state document has no containment result at all -
    the task raised before returning - so the write-ahead records are the only
    truthful account of which actions completed and which did not.
    """
    records = []
    if incident_id:
        try:
            records = incidents.list_actions(incident_id)
        except Exception as exc:  # noqa: BLE001 - never fail a notification
            logger.warning(f"Could not read the incident ledger for {incident_id}: {exc}")

    if records:
        lines = []
        for record in records:
            detail = record.get("Error") or json.dumps(record.get("Result") or {}, sort_keys=True)
            lines.append(
                f"  [{record.get('Status', '?')}] {record.get('Action')} "
                f"on {record.get('Target')} - {str(detail)[:200]}"
            )
        return lines

    performed = (containment or {}).get("actions") or []
    if not performed:
        return ["  (no action records found - assume nothing was changed)"]
    return [
        f"  [{a.get('status', '?')}] {a.get('action')} on {a.get('target')}"
        + (f" - {a['detail']}" if a.get("detail") else "")
        for a in performed
    ]
