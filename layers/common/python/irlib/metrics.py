"""Emit timing metrics in CloudWatch embedded metric format.

EMF means writing a specially shaped JSON line to stdout: CloudWatch Logs
extracts the metric values from it. That is worth doing over PutMetricData for
two reasons - no function needs `cloudwatch:PutMetricData`, and there is no
extra API call on the containment path, where latency is the thing being
measured.

Two metrics, both measured from the finding's own `createdAt` rather than from
when this pipeline happened to start:

* `TimeToNotifySeconds` - how long until a human was told.
* `TimeToContainSeconds` - how long until the last containment action finished,
  taken from the ledger rather than from when the notification was sent.

Measuring from `createdAt` includes GuardDuty's own detection and delivery
latency, which is usually the largest part and is not something this pipeline
controls. That is deliberate: it is the number a responder actually cares
about, and quoting the faster internal-only figure would flatter the pipeline.
"""

import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()

NAMESPACE = os.environ.get("METRICS_NAMESPACE", "IRPipeline")

TIME_TO_CONTAIN = "TimeToContainSeconds"
TIME_TO_NOTIFY = "TimeToNotifySeconds"

# Dimensions are deliberately low cardinality. EMF creates one custom metric
# per unique dimension combination, so an instance id here would bill per
# instance and make the dashboard unreadable.
DIMENSION_SETS = [["Environment"], ["Environment", "FindingType"]]


def parse_timestamp(value):
    """Parse a GuardDuty timestamp. Returns None rather than raising."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        # GuardDuty emits e.g. 2026-09-21T12:00:00.000Z
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        logger.warning(f"Could not parse a timestamp: {value!r}")
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def seconds_between(start, end=None):
    """Elapsed seconds, or None if either end is unusable."""
    started = parse_timestamp(start)
    if started is None:
        return None
    finished = parse_timestamp(end) if end is not None else datetime.now(timezone.utc)
    if finished is None:
        return None
    elapsed = (finished - started).total_seconds()
    # A negative elapsed time means clock skew or a bad timestamp. Reporting it
    # would put a nonsense point on the dashboard.
    return round(elapsed, 3) if elapsed >= 0 else None


def emit(values, environment="unknown", finding_type="unknown", extra=None):
    """Write one EMF document. `values` maps metric name to a number.

    Never raises: a metric that cannot be emitted must not fail an incident.
    """
    measured = {name: value for name, value in (values or {}).items() if value is not None}
    if not measured:
        return None

    document = {
        "_aws": {
            "Timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": NAMESPACE,
                    "Dimensions": DIMENSION_SETS,
                    "Metrics": [
                        {"Name": name, "Unit": "Seconds"} for name in sorted(measured)
                    ],
                }
            ],
        },
        "Environment": str(environment or "unknown")[:250],
        "FindingType": str(finding_type or "unknown")[:250],
        **measured,
    }
    if extra:
        # Context for querying the logs; not a dimension, so it does not bill.
        document.update({k: v for k, v in extra.items() if k not in document})

    try:
        print(json.dumps(document, default=str))
    except Exception as exc:  # noqa: BLE001 - never fail an incident over a metric
        logger.warning(f"Could not emit metrics: {exc}")
        return None
    return document


def containment_completed_at(action_records):
    """The latest CompletedAt across completed containment actions.

    The ledger is the authority on when containment actually finished. The
    notification goes out afterwards, so using the notification time would
    overstate it - and on a partial failure there may be no notification
    boundary at all.
    """
    from . import incidents

    completed = [
        record.get("CompletedAt")
        for record in action_records or []
        if record.get("Status") == incidents.STATUS_DONE and record.get("CompletedAt")
        and not str(record.get("Action", "")).startswith("release:")
    ]
    return max(completed) if completed else None
