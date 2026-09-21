"""The write-ahead incident ledger.

Every containment action follows the same three steps:

    begin_action()   -> persist what we are about to do and the prior state
    <the AWS call>
    complete_action() -> mark it done, with the result

The record is written *before* the mutating call, never after. If the function
dies mid-action, the ledger still names the resource and holds the state needed
to put it back - which is what makes the Phase 4 release path possible. Writing
it afterwards would lose exactly the cases that matter.

Every action is keyed by a caller-supplied `action_key` that is deterministic
for a given incident and target, so a retried execution recognises work that
already finished instead of repeating it.

Values that are not plain strings are stored as JSON text. DynamoDB has no
float type, and a GuardDuty severity like 8.5 would otherwise force Decimal
handling into every caller.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()

META_RECORD_ID = "META"
ACTION_PREFIX = "ACTION#"

STATUS_PENDING = "PENDING"
STATUS_DONE = "DONE"
STATUS_FAILED = "FAILED"
STATUS_SKIPPED = "SKIPPED"

# What begin_action() tells the caller to do next.
PROCEED = "PROCEED"  # nothing recorded yet, go ahead
SKIP = "SKIP"        # already completed, do not repeat
RETRY = "RETRY"      # started but never finished, safe to run again


def _client(client=None):
    return client if client is not None else boto3.client("dynamodb")


def _table_name(table_name=None):
    name = table_name or os.environ.get("INCIDENTS_TABLE")
    if not name:
        raise RuntimeError("INCIDENTS_TABLE is not set")
    return name


def now():
    return datetime.now(timezone.utc).isoformat()


def _s(value):
    return {"S": str(value)}


def _json(value):
    return {"S": json.dumps(value, default=str, sort_keys=True)}


def _plain(item):
    """Flatten a DynamoDB item into plain Python, decoding the JSON blobs."""
    out = {}
    for key, typed in (item or {}).items():
        value = typed.get("S")
        if key in ("PriorState", "Result", "Attributes") and value is not None:
            try:
                out[key] = json.loads(value)
                continue
            except ValueError:
                pass
        out[key] = value
    return out


def open_incident(incident_id, attributes, table_name=None, client=None):
    """Create the incident's META record. Returns ("CREATED"|"EXISTS", item).

    GuardDuty re-emits the same finding id as activity recurs, and the incident
    id is derived from it, so a repeat event lands on an existing META record
    rather than opening a second incident.
    """
    item = {
        "IncidentId": _s(incident_id),
        "RecordId": _s(META_RECORD_ID),
        "OpenedAt": _s(now()),
        "Status": _s("OPEN"),
        "Attributes": _json(attributes),
    }
    for key in ("FindingId", "FindingType", "AccountId", "Region", "DetectorId", "Environment"):
        if attributes.get(key):
            item[key] = _s(attributes[key])

    try:
        _client(client).put_item(
            TableName=_table_name(table_name),
            Item=item,
            ConditionExpression="attribute_not_exists(IncidentId)",
        )
        return "CREATED", _plain(item)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise
        logger.info(f"Incident {incident_id} already open; treating this event as a recurrence.")
        return "EXISTS", get_meta(incident_id, table_name=table_name, client=client)


def update_incident(incident_id, updates, table_name=None, client=None):
    """Patch top-level fields on the META record."""
    if not updates:
        return
    names, values, sets = {}, {}, []
    for index, (key, value) in enumerate(sorted(updates.items())):
        names[f"#k{index}"] = key
        values[f":v{index}"] = _s(value) if isinstance(value, str) else _json(value)
        sets.append(f"#k{index} = :v{index}")

    _client(client).update_item(
        TableName=_table_name(table_name),
        Key={"IncidentId": _s(incident_id), "RecordId": _s(META_RECORD_ID)},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def get_meta(incident_id, table_name=None, client=None):
    response = _client(client).get_item(
        TableName=_table_name(table_name),
        Key={"IncidentId": _s(incident_id), "RecordId": _s(META_RECORD_ID)},
        ConsistentRead=True,
    )
    return _plain(response.get("Item"))


def begin_action(
    incident_id,
    action_key,
    action,
    target,
    prior_state=None,
    table_name=None,
    client=None,
):
    """Record an action before performing it.

    Returns (PROCEED|SKIP|RETRY, record). The caller must not touch AWS until
    this has returned.
    """
    record_id = ACTION_PREFIX + action_key
    item = {
        "IncidentId": _s(incident_id),
        "RecordId": _s(record_id),
        "Action": _s(action),
        "Target": _s(target),
        "Status": _s(STATUS_PENDING),
        "StartedAt": _s(now()),
        "PriorState": _json(prior_state if prior_state is not None else {}),
    }

    try:
        _client(client).put_item(
            TableName=_table_name(table_name),
            Item=item,
            ConditionExpression="attribute_not_exists(RecordId)",
        )
        return PROCEED, _plain(item)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise

    existing = _plain(
        _client(client)
        .get_item(
            TableName=_table_name(table_name),
            Key={"IncidentId": _s(incident_id), "RecordId": _s(record_id)},
            ConsistentRead=True,
        )
        .get("Item")
    )
    status = existing.get("Status")
    if status in (STATUS_DONE, STATUS_SKIPPED):
        logger.info(f"Action {action_key} already {status} for {incident_id}; skipping.")
        return SKIP, existing

    # PENDING or FAILED: the prior state on the existing record is the one
    # captured before the first attempt, so it stays authoritative for release.
    logger.info(f"Action {action_key} was left {status} for {incident_id}; retrying.")
    return RETRY, existing


def complete_action(incident_id, action_key, result=None, table_name=None, client=None):
    _finish(incident_id, action_key, STATUS_DONE, {"Result": _json(result or {})}, table_name, client)


def skip_action(incident_id, action_key, reason, table_name=None, client=None):
    _finish(incident_id, action_key, STATUS_SKIPPED, {"Result": _json({"reason": reason})}, table_name, client)


def fail_action(incident_id, action_key, error, table_name=None, client=None):
    _finish(incident_id, action_key, STATUS_FAILED, {"Error": _s(str(error)[:1024])}, table_name, client)


def _finish(incident_id, action_key, status, extra, table_name, client):
    names = {"#s": "Status", "#c": "CompletedAt"}
    values = {":s": _s(status), ":c": _s(now())}
    sets = ["#s = :s", "#c = :c"]
    for index, (key, value) in enumerate(sorted(extra.items())):
        names[f"#e{index}"] = key
        values[f":e{index}"] = value
        sets.append(f"#e{index} = :e{index}")

    _client(client).update_item(
        TableName=_table_name(table_name),
        Key={"IncidentId": _s(incident_id), "RecordId": _s(ACTION_PREFIX + action_key)},
        UpdateExpression="SET " + ", ".join(sets),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def list_actions(incident_id, table_name=None, client=None):
    """Every action record for an incident, oldest first.

    The Phase 4 release path walks this list in reverse.
    """
    response = _client(client).query(
        TableName=_table_name(table_name),
        KeyConditionExpression="IncidentId = :i AND begins_with(RecordId, :p)",
        ExpressionAttributeValues={":i": _s(incident_id), ":p": _s(ACTION_PREFIX)},
        ConsistentRead=True,
    )
    records = [_plain(item) for item in response.get("Items", [])]
    return sorted(records, key=lambda r: (r.get("StartedAt") or "", r.get("RecordId") or ""))


def run_action(
    incident_id,
    action_key,
    action,
    target,
    perform,
    prior_state=None,
    best_effort=False,
    table_name=None,
    client=None,
):
    """Record, perform, then mark done - the write-ahead invariant in one place.

    Individual containment steps call this instead of touching the ledger
    themselves, so none of them can forget to record the prior state before
    mutating, and a retried execution skips whatever already completed.

    `best_effort=True` swallows the failure after recording it. Use it only
    where the step is genuinely optional - starting a malware scan, say - never
    for a step that later actions or the release path depend on.

    Returns a summary dict; `status` is DONE, SKIPPED or FAILED.
    """
    state, record = begin_action(
        incident_id,
        action_key,
        action,
        target,
        prior_state=prior_state,
        table_name=table_name,
        client=client,
    )

    if state == SKIP:
        return {
            "action": action,
            "target": target,
            "status": STATUS_SKIPPED,
            "detail": "already completed for this incident",
            "result": record.get("Result") or {},
        }

    try:
        result = perform(record.get("PriorState") or prior_state or {})
    except Exception as exc:  # noqa: BLE001 - recorded, then re-raised unless best effort
        fail_action(incident_id, action_key, exc, table_name=table_name, client=client)
        logger.error(f"Action {action_key} failed for {incident_id}: {exc}")
        if best_effort:
            return {
                "action": action,
                "target": target,
                "status": STATUS_FAILED,
                "detail": f"best effort, continuing: {exc}",
            }
        raise

    complete_action(incident_id, action_key, result, table_name=table_name, client=client)
    return {
        "action": action,
        "target": target,
        "status": STATUS_DONE,
        "result": result or {},
    }
