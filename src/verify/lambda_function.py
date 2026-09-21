"""Re-fetch the finding from GuardDuty and open the incident.

This is the trust boundary. The execution input carries identifiers; every
target that containment will act on is derived here, from what GetFindings
returns. A finding that has gone missing or been archived between emission and
processing stops the run rather than triggering containment on stale grounds.
"""

import json
import logging

from irlib import findings, incidents

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# A DynamoDB item caps at 400 KB. Runtime Monitoring findings carry process and
# file detail that can get large, so the copy kept on the incident record is
# bounded. Phase 2 writes the unabridged finding to the evidence bucket.
MAX_STORED_FINDING_BYTES = 200_000


class FindingMismatch(Exception):
    """What GuardDuty returned is not the finding we were asked about."""


def handler(event, context):
    logger.info(f"Verifying finding: {json.dumps(event)}")

    finding_id = event["findingId"]
    detector_id = event["detectorId"]

    finding = findings.get_finding(detector_id, finding_id)

    if finding.get("id") != finding_id:
        raise FindingMismatch(
            f"Asked for finding {finding_id!r} but GuardDuty returned {finding.get('id')!r}"
        )
    for field in ("accountId", "region"):
        expected, actual = event.get(field), finding.get(field)
        if expected and actual and expected != actual:
            raise FindingMismatch(
                f"Finding {finding_id!r} has {field}={actual!r}, execution input said {expected!r}"
            )

    summary = findings.summarize(finding)
    targets = findings.extract_targets(finding)

    if targets["rejectedInstanceIds"]:
        logger.warning(
            f"Ignoring malformed instance ids on finding {finding_id}: "
            f"{targets['rejectedInstanceIds']}"
        )

    serialized = json.dumps(finding, default=str)
    incidents.open_incident(
        event["incidentId"],
        {
            "FindingId": finding_id,
            "FindingType": summary["type"],
            "AccountId": summary["accountId"] or event.get("accountId"),
            "Region": summary["region"] or event.get("region"),
            "DetectorId": detector_id,
            "summary": summary,
            "targets": targets,
            "finding": finding if len(serialized) <= MAX_STORED_FINDING_BYTES else
                       {"truncated": True, "bytes": len(serialized), "summary": summary},
        },
    )

    logger.info(
        f"Verified {finding_id}: type={summary['type']} severity={summary['severity']} "
        f"instances={targets['instanceIds']}"
    )
    return {"summary": summary, "targets": targets}
