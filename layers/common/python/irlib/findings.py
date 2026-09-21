"""Read GuardDuty findings and pull the target resources out of them.

Nothing downstream of Phase 1 trusts the EventBridge payload. The Router passes
only identifiers; this module re-fetches the finding with GetFindings and every
target is derived from what GuardDuty returns. That closes two gaps: an
EventBridge event body cannot be used to point containment at an arbitrary
instance, and a finding that was archived between emission and processing is
dropped instead of acted on.
"""

import json
import logging
import re

import boto3

logger = logging.getLogger()

# Both the 8- and 17-character forms. Used to validate anything that will be
# passed to a mutating EC2 call, and to tell an instance-role session name
# apart from a human one.
INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8}(?:[0-9a-f]{9})?$")

# Step Functions execution names: 80 characters, and the safe set is narrower
# than what GuardDuty puts in a finding id.
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9_-]")
MAX_EXECUTION_NAME = 80

_FINDING_ARN_DETECTOR = re.compile(r":detector/([^/]+)/finding/")


class FindingNotFound(Exception):
    """GetFindings returned nothing for this id."""


class FindingArchived(Exception):
    """The finding was archived, so it is no longer actionable."""


def _client(client=None):
    return client if client is not None else boto3.client("guardduty")


def execution_name(finding_id):
    """Derive a stable, legal execution name from a finding id.

    GuardDuty re-emits the same finding id as activity recurs, so naming the
    execution after the finding makes duplicate events collide on
    ExecutionAlreadyExists instead of starting a second containment run.
    """
    if not finding_id:
        raise ValueError("finding_id is required")
    return _UNSAFE_NAME_CHARS.sub("-", finding_id)[:MAX_EXECUTION_NAME]


def incident_id(finding_id):
    """The incident id is the sanitised finding id, so the ledger is idempotent too."""
    return execution_name(finding_id)


def detector_id_from_detail(detail):
    """Read the detector id from the event, falling back to the finding ARN.

    service.detectorId is optional in the API model, so do not rely on it alone;
    the finding ARN always embeds the detector id.
    """
    detector_id = (detail.get("service") or {}).get("detectorId")
    if detector_id:
        return detector_id
    match = _FINDING_ARN_DETECTOR.search(detail.get("arn") or "")
    return match.group(1) if match else None


def get_finding(detector_id, finding_id, client=None):
    """Re-fetch the finding. Raises if it is missing or archived."""
    response = _client(client).get_findings(DetectorId=detector_id, FindingIds=[finding_id])
    found = response.get("Findings") or []
    if not found:
        raise FindingNotFound(
            f"GetFindings returned no finding for {finding_id!r} in detector {detector_id!r}"
        )

    finding = json.loads(json.dumps(found[0], default=str))
    if (finding.get("Service") or finding.get("service") or {}).get("Archived") or (
        finding.get("Service") or finding.get("service") or {}
    ).get("archived"):
        raise FindingArchived(f"Finding {finding_id!r} is archived")

    return _normalise(finding)


def _normalise(finding):
    """GetFindings returns PascalCase keys; EventBridge delivers camelCase.

    Normalising to camelCase means fixtures captured from either source, and
    every path documented in the GuardDuty API reference, work unchanged.
    """
    if isinstance(finding, dict):
        return {_lower_first(k): _normalise(v) for k, v in finding.items()}
    if isinstance(finding, list):
        return [_normalise(item) for item in finding]
    return finding


def _lower_first(key):
    return key[:1].lower() + key[1:] if key else key


def summarize(finding):
    """The small, flat view of a finding used for decisions and notifications."""
    service = finding.get("service") or {}
    return {
        "findingId": finding.get("id"),
        "type": finding.get("type"),
        "severity": float(finding.get("severity") or 0.0),
        "title": finding.get("title"),
        "description": finding.get("description"),
        "createdAt": finding.get("createdAt"),
        "updatedAt": finding.get("updatedAt"),
        "accountId": finding.get("accountId"),
        "region": finding.get("region"),
        "count": service.get("count"),
        "resourceType": (finding.get("resource") or {}).get("resourceType"),
        "resourceRole": service.get("resourceRole"),
        "featureName": service.get("featureName"),
    }


def instance_id_from_principal(principal_id):
    """Recover the instance id from an EC2 instance-role session.

    IMDS names the session after the instance, so principalId looks like
    'AROAEXAMPLEID:i-0123456789abcdef0'. The regex guard matters: a human's
    session name lands in the same field, and must not be mistaken for an
    instance to contain.

    # VERIFY: confirmed against the documented principalId shape, not yet
    # against a real InstanceCredentialExfiltration finding in an account.
    """
    if not principal_id or ":" not in principal_id:
        return None
    session_name = principal_id.split(":", 1)[1]
    return session_name if INSTANCE_ID_RE.match(session_name) else None


def extract_targets(finding):
    """Everything containment might act on, derived only from the fetched finding."""
    resource = finding.get("resource") or {}
    service = finding.get("service") or {}
    resource_type = resource.get("resourceType")

    instance_ids = []
    instance_details = resource.get("instanceDetails") or {}
    if instance_details.get("instanceId"):
        instance_ids.append(instance_details["instanceId"])

    access_key = None
    key_details = resource.get("accessKeyDetails") or {}
    if key_details:
        access_key = {
            "accessKeyId": key_details.get("accessKeyId"),
            "principalId": key_details.get("principalId"),
            "userName": key_details.get("userName"),
            "userType": key_details.get("userType"),
        }
        derived = instance_id_from_principal(key_details.get("principalId"))
        if derived and derived not in instance_ids:
            instance_ids.append(derived)
            access_key["derivedInstanceId"] = derived

    sequence = (service.get("detection") or {}).get("sequence")
    sequence_summary = summarize_sequence(sequence) if sequence else None
    if sequence_summary:
        for candidate in sequence_summary["instanceIds"]:
            if candidate not in instance_ids:
                instance_ids.append(candidate)

    return {
        "resourceType": resource_type,
        "instanceIds": [i for i in instance_ids if INSTANCE_ID_RE.match(i or "")],
        "rejectedInstanceIds": [i for i in instance_ids if not INSTANCE_ID_RE.match(i or "")],
        "accessKey": access_key,
        "sequence": sequence_summary,
        "remoteIps": remote_ips(finding),
        "domains": queried_domains(finding),
    }


def summarize_sequence(sequence):
    """Flatten an Extended Threat Detection attack sequence.

    Path and field names come from the GuardDuty API reference: the sequence is
    at service.detection.sequence, its resources are ResourceV2 objects, and its
    indicators are Indicator objects whose key enum includes VULNERABILITY and
    REACHABILITY.
    """
    resources = sequence.get("resources") or []
    indicators = sequence.get("sequenceIndicators") or []

    instance_ids = []
    for item in resources:
        if item.get("resourceType") != "EC2_INSTANCE":
            continue
        # VERIFY: uid is documented as "the unique identifier of the resource";
        # whether it holds a bare instance id or an ARN is not stated, so try
        # both fields and keep whichever looks like an instance id.
        for candidate in (item.get("uid"), item.get("name")):
            if not candidate:
                continue
            tail = candidate.rsplit("/", 1)[-1]
            if INSTANCE_ID_RE.match(tail):
                if tail not in instance_ids:
                    instance_ids.append(tail)
                break

    indicator_keys = sorted({i.get("key") for i in indicators if i.get("key")})
    return {
        "uid": sequence.get("uid"),
        "description": sequence.get("description"),
        "instanceIds": instance_ids,
        "resourceCount": len(resources),
        "signalCount": len(sequence.get("signals") or []),
        "indicatorKeys": indicator_keys,
        "indicators": [
            {"key": i.get("key"), "title": i.get("title"), "values": (i.get("values") or [])[:10]}
            for i in indicators
        ],
        "escalated": "VULNERABILITY" in indicator_keys and "REACHABILITY" in indicator_keys,
    }


def remote_ips(finding):
    """Remote IPv4 addresses named in the finding, for the optional NACL backstop."""
    action = (finding.get("service") or {}).get("action") or {}
    found = []

    for key in ("networkConnectionAction", "awsApiCallAction", "kubernetesApiCallAction"):
        ip = ((action.get(key) or {}).get("remoteIpDetails") or {}).get("ipAddressV4")
        if ip:
            found.append(ip)

    for probe in (action.get("portProbeAction") or {}).get("portProbeDetails") or []:
        ip = (probe.get("remoteIpDetails") or {}).get("ipAddressV4")
        if ip:
            found.append(ip)

    return sorted(set(found))


def queried_domains(finding):
    """Domains the instance looked up, for the DNS Firewall block list."""
    action = (finding.get("service") or {}).get("action") or {}
    domain = (action.get("dnsRequestAction") or {}).get("domain")
    return [domain] if domain else []
