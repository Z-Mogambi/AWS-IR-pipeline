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

from irlib import incidents, metrics

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
    "APPROVAL_TIMED_OUT": "APPROVAL TIMED OUT",
    "APPROVAL_DENIED": "APPROVAL DENIED",
    "RELEASE_APPROVAL": "RELEASE APPROVAL NEEDED",
    "RELEASED": "RELEASED",
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
    triage = event.get("triage") or {}
    error = event.get("error") or {}

    environment = enrichment.get("environment", "unknown")
    instances = targets.get("instanceIds") or []
    instance_label = ", ".join(instances) if instances else "no actionable instance"

    # Either the sequence indicators or a prompt attack inside the finding.
    escalated = "[ESCALATED]" if (decision.get("escalated") or triage.get("escalated")) else ""
    subject = safe_subject(
        f"[{HEADLINE.get(kind, kind)}]{escalated}[{environment}] "
        f"{summary.get('type') or 'GuardDuty finding'} - {instance_label}"
    )
    message = build_message(kind, event, summary, targets, enrichment, decision, containment,
                            triage, error)

    sns_client.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message)
    logger.info(f"Published {kind} notification for incident {event.get('incidentId')}")

    timings = record_timings(event, kind, summary, environment)
    return {"status": "SENT", "kind": kind, "subject": subject, "timings": timings}


def record_timings(event, kind, summary, environment):
    """Measure from the finding's createdAt, and record it on the incident.

    Both figures include GuardDuty's own detection and delivery latency, which
    is usually the largest part of the total and is not something this pipeline
    controls. That is the honest number: a responder cares how long the
    attacker had, not how fast the state machine ran.

    Never raises - a metric must not cost a notification that already went out.
    """
    incident_id = event.get("incidentId")
    created_at = summary.get("createdAt")
    timings = {}

    try:
        timings[metrics.TIME_TO_NOTIFY] = metrics.seconds_between(created_at)

        if kind in ("CONTAINED", "CONTAINMENT_FAILED") and incident_id:
            finished = metrics.containment_completed_at(incidents.list_actions(incident_id))
            timings[metrics.TIME_TO_CONTAIN] = metrics.seconds_between(created_at, finished)

        metrics.emit(
            timings,
            environment=environment,
            finding_type=summary.get("type"),
            extra={"incidentId": incident_id, "notifyKind": kind},
        )

        measured = {k: v for k, v in timings.items() if v is not None}
        if measured and incident_id:
            incidents.update_incident(incident_id, {"Timings": measured})
        return measured
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"Could not record timings for {incident_id}: {exc}")
        return timings


def build_message(kind, event, summary, targets, enrichment, decision, containment, triage,
                  error):
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

    if targets.get("sequence"):
        lines += sequence_lines(targets["sequence"], decision)

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

    lines += triage_lines(triage)

    if kind == "VERIFY_FAILED":
        lines += [
            "THE FINDING COULD NOT BE VERIFIED",
            "  GuardDuty returned no matching finding, the finding is archived, or its",
            "  identifiers did not match the event. No action was taken. Investigate by hand.",
            f"  Error: {error.get('Error')}",
            f"  Cause: {str(error.get('Cause'))[:800]}",
        ]
    elif kind in ("APPROVAL_REQUIRED", "RELEASE_APPROVAL"):
        lines += approval_lines(kind, event)
    elif kind == "APPROVAL_TIMED_OUT":
        lines += [
            f"NOBODY ANSWERED within {decision.get('approvalTimeoutSeconds', '?')} seconds.",
            f"  Timeout action: {decision.get('approvalTimeoutAction', 'Escalate')}.",
            "  Nobody answering is not consent, so in production the default is to",
            "  escalate rather than contain. Nothing has been changed.",
        ]
    elif kind == "APPROVAL_DENIED":
        lines += [
            "THE REQUEST WAS DECLINED. Nothing has been changed.",
            f"  Reason: {str(error.get('Cause'))[:500]}",
        ]
    elif kind == "RELEASED":
        lines.append("ACTIONS REVERSED")
        lines += _action_lines(event.get("incidentId"), containment)
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


def triage_lines(triage):
    """Render the model's view, clearly marked as advisory.

    It is printed after the decision, never before, so a reader sees what the
    pipeline did and why before they see what a model thought about it.
    """
    if not triage:
        return []

    if triage.get("escalated"):
        return [
            "AI TRIAGE: ESCALATED, NOT PERFORMED",
            f"  {triage.get('reason')}",
            "",
        ]

    if not triage.get("available"):
        return [
            "AI TRIAGE: unavailable",
            f"  {triage.get('reason', 'no reason given')}",
            "  This changes nothing: the decision above was made without it.",
            "",
        ]

    return [
        "AI TRIAGE (advisory - it did not influence the decision above)",
        f"  Summary:      {triage.get('summary')}",
        f"  Attack stage: {triage.get('attack_stage')}",
        f"  Blast radius: {triage.get('blast_radius')}",
        f"  Model suggests: {triage.get('recommended_action')} "
        f"(confidence {triage.get('confidence')})",
        f"  Rationale:    {triage.get('rationale')}",
        "",
    ]


def sequence_lines(sequence, decision):
    """Render an Extended Threat Detection attack sequence.

    A sequence is a correlated group of signals across several resources, so
    the summary and indicators are the part a responder reads first - not the
    individual signals.
    """
    lines = [
        "ATTACK SEQUENCE",
        f"  {sequence.get('description') or '(no description)'}",
        f"  Sequence id: {sequence.get('uid')}",
        f"  {sequence.get('signalCount', 0)} signal(s) across "
        f"{sequence.get('resourceCount', 0)} resource(s)",
    ]

    if sequence.get("instanceIds"):
        lines.append(f"  EC2 instances: {', '.join(sequence['instanceIds'])}")

    for indicator in sequence.get("indicators") or []:
        lines.append(
            f"    [{indicator.get('key')}] {indicator.get('title') or ''} "
            f"{_render_values(indicator.get('values'))}".rstrip()
        )

    if decision.get("escalated"):
        lines += [
            "",
            "  ESCALATED: " + (decision.get("escalationReason") or ""),
        ]
    lines.append("")
    return lines


def _render_values(values):
    """Indicator values are usually strings, but some carry nested structure.

    SUSPICIOUS_NETWORK, for instance, is documented with a mapping of network
    name to tags, so anything non-string is serialised rather than assumed.
    """
    if not values:
        return ""
    rendered = [v if isinstance(v, str) else json.dumps(v, sort_keys=True) for v in values]
    return "(" + ", ".join(rendered[:5]) + ")"


def approval_lines(kind, event):
    """Render the callback as commands that require IAM credentials to run.

    The task token is not, on its own, an authorisation. SendTaskSuccess is an
    IAM-authorised API call, so an attacker who intercepts this email still
    cannot approve anything without credentials carrying states:SendTaskSuccess
    on this state machine. That is deliberately the whole approval mechanism:
    no HTTP endpoint, no reply-to-approve, nothing that turns possession of the
    token into consent.
    """
    token = event.get("taskToken")
    if not token:
        return ["NO ACTION HAS BEEN TAKEN - a human decision is required.",
                "  (no callback token was supplied with this notification)"]

    what = "release this incident" if kind == "RELEASE_APPROVAL" else "carry out the actions above"
    return [
        f"NO ACTION HAS BEEN TAKEN. To {what}, run:",
        "",
        "  aws stepfunctions send-task-success \\",
        f"    --task-token '{token}' \\",
        "    --task-output '{\"approved\": true, \"approver\": \"YOUR NAME\"}'",
        "",
        "To decline:",
        "",
        "  aws stepfunctions send-task-failure \\",
        f"    --task-token '{token}' \\",
        "    --error Declined --cause 'why you declined'",
        "",
        f"  Execution: {event.get('executionArn', 'unknown')}",
        f"  This request expires in {(event.get('decision') or {}).get('approvalTimeoutSeconds', '?')}"
        " seconds.",
        "  Both commands require IAM credentials with states:SendTaskSuccess or",
        "  states:SendTaskFailure on this state machine. Holding the token alone",
        "  is not enough to approve anything.",
    ]


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
