"""Timing metrics, and the claims the documentation makes about them."""

import json
import pathlib
import re

import pytest

from conftest import load_lambda
from irlib import incidents, metrics

ROOT = pathlib.Path(__file__).resolve().parent.parent
alert = load_lambda("alert")


# --- the embedded metric format ---------------------------------------------


def test_the_document_matches_the_emf_specification(capsys):
    metrics.emit({metrics.TIME_TO_NOTIFY: 12.5}, environment="production",
                 finding_type="Backdoor:EC2/C&CActivity.B")
    document = json.loads(capsys.readouterr().out.strip())

    node = document["_aws"]
    assert isinstance(node["Timestamp"], int), "Timestamp must be epoch milliseconds"
    assert node["Timestamp"] > 1_000_000_000_000

    directive = node["CloudWatchMetrics"][0]
    assert set(directive) == {"Namespace", "Dimensions", "Metrics"}
    assert directive["Namespace"] == "IRPipeline"

    for name in (m["Name"] for m in directive["Metrics"]):
        assert name in document, f"{name} must be a member of the root node"
        assert isinstance(document[name], (int, float))

    for dimension_set in directive["Dimensions"]:
        assert len(dimension_set) <= 30
        for key in dimension_set:
            assert key in document, f"dimension {key} must be a root member"
            assert isinstance(document[key], str)


def test_units_are_valid_cloudwatch_units(capsys):
    metrics.emit({metrics.TIME_TO_CONTAIN: 1.0}, environment="production")
    document = json.loads(capsys.readouterr().out.strip())
    for metric in document["_aws"]["CloudWatchMetrics"][0]["Metrics"]:
        assert metric["Unit"] == "Seconds"


def test_dimensions_stay_low_cardinality():
    """EMF bills one custom metric per unique dimension combination.

    An instance id or incident id here would bill per incident and make the
    dashboard unreadable.
    """
    for dimension_set in metrics.DIMENSION_SETS:
        for key in dimension_set:
            assert key in ("Environment", "FindingType"), (
                f"{key} is too high cardinality to be a dimension"
            )


def test_context_travels_outside_the_dimensions(capsys):
    metrics.emit({metrics.TIME_TO_NOTIFY: 1.0}, extra={"incidentId": "inc-1"})
    document = json.loads(capsys.readouterr().out.strip())
    assert document["incidentId"] == "inc-1"
    dimensions = {k for group in document["_aws"]["CloudWatchMetrics"][0]["Dimensions"]
                  for k in group}
    assert "incidentId" not in dimensions, "that would bill per incident"


# --- measurement ------------------------------------------------------------


def test_elapsed_time_is_measured_from_the_finding():
    assert metrics.seconds_between(
        "2026-09-21T12:00:00.000Z", "2026-09-21T12:00:45.500Z"
    ) == 45.5


@pytest.mark.parametrize("value", ["not-a-date", "", None, "2026-13-45T99:99:99Z"])
def test_an_unparseable_timestamp_yields_nothing(value):
    assert metrics.seconds_between(value) is None


def test_clock_skew_is_dropped_not_reported():
    """A negative elapsed time would put a nonsense point on the dashboard."""
    assert metrics.seconds_between("2026-09-21T12:01:00Z", "2026-09-21T12:00:00Z") is None


def test_nothing_is_emitted_when_there_is_nothing_to_measure(capsys):
    assert metrics.emit({"TimeToContainSeconds": None}) is None
    assert capsys.readouterr().out == ""


def test_containment_time_comes_from_the_ledger_not_the_notification():
    """The notification goes out afterwards, so using its time would overstate it."""
    records = [
        {"Action": "evidence-store", "Status": incidents.STATUS_DONE,
         "CompletedAt": "2026-09-21T12:00:10Z"},
        {"Action": "disable-imds", "Status": incidents.STATUS_DONE,
         "CompletedAt": "2026-09-21T12:00:40Z"},
        {"Action": "nacl-backstop", "Status": incidents.STATUS_FAILED,
         "CompletedAt": "2026-09-21T12:00:55Z"},
    ]
    assert metrics.containment_completed_at(records) == "2026-09-21T12:00:40Z"


def test_release_actions_do_not_count_as_containment():
    """Releasing hours later must not be recorded as a slow containment."""
    records = [
        {"Action": "disable-imds", "Status": incidents.STATUS_DONE,
         "CompletedAt": "2026-09-21T12:00:40Z"},
        {"Action": "release:disable-imds", "Status": incidents.STATUS_DONE,
         "CompletedAt": "2026-09-22T09:00:00Z"},
    ]
    assert metrics.containment_completed_at(records) == "2026-09-21T12:00:40Z"


def test_no_completed_actions_yields_nothing():
    assert metrics.containment_completed_at([]) is None
    assert metrics.containment_completed_at(
        [{"Action": "x", "Status": incidents.STATUS_FAILED}]
    ) is None


# --- the alert emits them ---------------------------------------------------


@pytest.fixture
def notified(monkeypatch):
    sent, updates = {}, []

    class FakeSns:
        def publish(self, **kwargs):
            sent.update(kwargs)
            return {"MessageId": "m-1"}

    monkeypatch.setattr(alert, "sns_client", FakeSns())
    monkeypatch.setattr(incidents, "update_incident",
                        lambda incident_id, values, **_k: updates.append(values))
    return sent, updates


def build_event(kind="NOTIFY"):
    return {
        "notifyKind": kind,
        "incidentId": "inc-1",
        "findingId": "f-1",
        "accountId": "111122223333",
        "region": "us-east-1",
        "finding": {
            "summary": {"type": "Backdoor:EC2/C&CActivity.B", "severity": 8.0,
                        "title": "t", "description": "d",
                        "createdAt": "2026-09-21T12:00:00.000Z"},
            "targets": {"instanceIds": ["i-0123456789abcdef0"]},
        },
        "enrichment": {"environment": "production", "environmentSource": "tag"},
        "decision": {"decision": "NOTIFY", "ruleId": "r", "policyVersion": 1, "actions": []},
    }


def test_a_notification_records_time_to_notify(notified, monkeypatch, capsys):
    monkeypatch.setattr(incidents, "list_actions", lambda *_a, **_k: [])
    result = alert.handler(build_event(), None)
    assert metrics.TIME_TO_NOTIFY in result["timings"]
    assert result["timings"][metrics.TIME_TO_NOTIFY] > 0


def test_a_containment_notification_records_both(notified, monkeypatch):
    monkeypatch.setattr(incidents, "list_actions", lambda *_a, **_k: [
        {"Action": "disable-imds", "Status": incidents.STATUS_DONE,
         "Target": "i-0", "CompletedAt": "2026-09-21T12:00:40Z"},
    ])
    result = alert.handler(build_event(kind="CONTAINED"), None)
    assert result["timings"][metrics.TIME_TO_CONTAIN] == 40.0


def test_the_timings_are_recorded_on_the_incident(notified, monkeypatch):
    _sent, updates = notified
    monkeypatch.setattr(incidents, "list_actions", lambda *_a, **_k: [])
    alert.handler(build_event(), None)
    assert any("Timings" in update for update in updates)


def test_a_metrics_failure_never_costs_a_notification(notified, monkeypatch):
    """The alert has already gone out by the time timings are recorded."""
    sent, _updates = notified
    monkeypatch.setattr(incidents, "list_actions",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("AccessDenied")))
    result = alert.handler(build_event(kind="CONTAINED"), None)
    assert sent, "the notification must still have been published"
    assert result["status"] == "SENT"


def test_no_function_needs_put_metric_data():
    """EMF is chosen partly so nothing needs this permission."""
    template = (ROOT / "template.yaml").read_text()
    assert "cloudwatch:PutMetricData" not in template


# --- the dashboard ----------------------------------------------------------


def test_the_dashboard_body_is_valid_json_after_substitution():
    template = (ROOT / "template.yaml").read_text()
    start = template.index("DashboardBody: !Sub |")
    body = template[start:].split("\n", 1)[1]
    lines = []
    for line in body.splitlines():
        if line.strip() and not line.startswith("          "):
            break
        lines.append(line[10:])
    # Substitutions become plain strings once CloudFormation resolves them.
    rendered = re.sub(r"\$\{[^}]+\}", "resolved", "\n".join(lines))
    dashboard = json.loads(rendered)
    assert dashboard["widgets"], "the dashboard must have widgets"


def test_the_dashboard_charts_both_metrics():
    template = (ROOT / "template.yaml").read_text()
    assert metrics.TIME_TO_CONTAIN in template
    assert metrics.TIME_TO_NOTIFY in template


def test_the_dashboard_states_what_the_numbers_include():
    """A time-to-contain chart without that caveat invites misreading."""
    template = (ROOT / "template.yaml").read_text()
    assert "createdAt" in template
    assert "detection and delivery latency" in template
