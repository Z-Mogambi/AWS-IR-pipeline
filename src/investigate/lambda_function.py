"""Optional: ask GuardDuty Investigation to analyse an attack sequence.

Off by default, and only ever used for attack sequences - a sequence is the one
finding shape where correlating across an account is worth a preview API call
and one of a small daily quota.

The API is in preview, with real constraints that are handled explicitly rather
than surfacing as a stack trace:

* 10 investigations per account per day, 100 in total;
* administrator account only - a member account gets 403;
* ten Regions only;
* it needs the AI_ANALYST feature enabled on the detector.

Every one of those is a reason to skip and carry on, never to fail the
incident. The results are advisory, exactly like the model triage.
"""

import json
import logging
import os
import time

from irlib import sigv4

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ENABLED = os.environ.get("ENABLE_GUARDDUTY_INVESTIGATION", "false").lower() == "true"

# Bounded so a stuck investigation cannot hold a Step Functions execution open.
MAX_POLLS = int(os.environ.get("INVESTIGATION_MAX_POLLS", "10"))
POLL_SECONDS = int(os.environ.get("INVESTIGATION_POLL_SECONDS", "15"))

TERMINAL_STATUSES = {"COMPLETED", "SUCCEEDED", "FAILED", "CANCELLED", "ERROR"}


def endpoint(region):
    return f"https://guardduty.{region}.amazonaws.com"


def handler(event, context):
    mode = event.get("mode", "start")
    if not ENABLED:
        return skipped("EnableGuardDutyInvestigation is off")

    targets = (event.get("finding") or {}).get("targets") or {}
    if not targets.get("sequence"):
        return skipped("not an attack sequence")

    region = event.get("region")
    detector_id = event.get("detectorId")
    if not region or not detector_id:
        return skipped("no region or detector id")

    if mode == "start":
        return start(event, region, detector_id)
    if mode == "poll":
        return poll(event, region)
    raise ValueError(f"Unknown mode {mode!r}")


def skipped(reason):
    logger.info(f"Investigation skipped: {reason}")
    return {"available": False, "advisory": True, "reason": reason}


def start(event, region, detector_id):
    incident_id = event["incidentId"]
    finding_id = event.get("findingId")
    prompt = (
        f"Investigate finding {finding_id} in account {event.get('accountId')}"
        if finding_id
        else f"Investigate incident {incident_id}"
    )

    status, body = sigv4.signed_request(
        "guardduty",
        region,
        "POST",
        f"{endpoint(region)}/detector/{detector_id}/investigation",
        {"triggerPrompt": prompt, "clientToken": incident_id[:64]},
    )

    if status == 202:
        investigation_id = body.get("investigationId")
        logger.info(f"Started investigation {investigation_id} for {incident_id}")
        return {"available": True, "advisory": True, "investigationId": investigation_id,
                "status": "IN_PROGRESS", "polls": 0}

    return skipped(explain(status, body))


def poll(event, region):
    """One poll per invocation; the state machine's Wait loop paces them."""
    investigation = event.get("investigation") or {}
    investigation_id = investigation.get("investigationId")
    if not investigation_id:
        return skipped("no investigation to poll")

    polls = int(investigation.get("polls", 0)) + 1
    status_code, body = sigv4.signed_request(
        "guardduty", region, "GET",
        f"{endpoint(region)}/investigation/{investigation_id}",
    )

    if status_code != 200:
        return skipped(explain(status_code, body))

    status = (body.get("status") or body.get("investigationStatus") or "IN_PROGRESS").upper()
    done = status in TERMINAL_STATUSES or polls >= MAX_POLLS

    return {
        "available": True,
        "advisory": True,
        "investigationId": investigation_id,
        "status": status,
        "polls": polls,
        "done": done,
        "gaveUp": polls >= MAX_POLLS and status not in TERMINAL_STATUSES,
        # Only the summary is carried forward; the full report can be large and
        # is available in the console.
        "summary": str(body.get("summary") or body.get("investigationSummary") or "")[:4000],
    }


def explain(status, body):
    """Turn a preview-API error into something a responder can act on."""
    message = (body or {}).get("Message") or (body or {}).get("message") or ""
    if status == 403:
        return (
            "GuardDuty Investigation refused the request (403). Only the delegated "
            "administrator account can create investigations, and the AI_ANALYST "
            f"detector feature must be enabled. {message}"
        )
    if status == 400:
        return (
            "GuardDuty Investigation rejected the request (400). This is usually the "
            "preview quota - 10 investigations per account per day, 100 in total - or "
            f"an unsupported Region. {message}"
        )
    if status == 404:
        return f"GuardDuty Investigation is not available in this Region (404). {message}"
    return f"GuardDuty Investigation returned {status}. {message}"
