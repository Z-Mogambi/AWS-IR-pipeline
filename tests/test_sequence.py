"""Attack sequences: parsing, the containment cap, and escalation.

The sample fixture is deliberately shaped like the API reference describes:
service.detection.sequence, ResourceV2 entries with uid and name, and Indicator
entries with key/title/values.
"""

import json
import pathlib

import pytest

from conftest import load_lambda
from irlib import findings, policy

decide = load_lambda("decide")

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def sequence_finding():
    with (ROOT / "events" / "guardduty-attack-sequence-finding.json").open() as handle:
        return json.load(handle)["detail"]


# --- parsing ----------------------------------------------------------------


def test_instance_ids_are_extracted_from_the_documented_path(sequence_finding):
    """service.detection.sequence.resources, filtered to EC2_INSTANCE."""
    targets = findings.extract_targets(sequence_finding)
    assert targets["sequence"]["instanceIds"] == [
        "i-0111111111aaaaaaa",
        "i-0222222222bbbbbbb",
    ]
    assert targets["instanceIds"] == targets["sequence"]["instanceIds"]


def test_non_instance_resources_are_not_treated_as_targets(sequence_finding):
    """The instance profile and VPC are context, not things to contain."""
    targets = findings.extract_targets(sequence_finding)
    assert "shared-app-profile" not in targets["instanceIds"]
    assert "vpc-0abcdef0123456789" not in targets["instanceIds"]
    assert targets["sequence"]["resourceCount"] == 4


@pytest.mark.parametrize(
    "resource",
    [
        {"resourceType": "EC2_INSTANCE", "uid": "arn:aws:ec2:us-east-1:1:instance/i-0111111111aaaaaaa"},
        {"resourceType": "EC2_INSTANCE", "uid": "i-0111111111aaaaaaa"},
        {"resourceType": "EC2_INSTANCE", "uid": "something-else", "name": "i-0111111111aaaaaaa"},
    ],
)
def test_the_instance_id_is_found_whether_uid_is_an_arn_or_bare(resource):
    """VERIFY-3: the docs do not state which form uid takes, so both work."""
    summary = findings.summarize_sequence({"resources": [resource], "sequenceIndicators": []})
    assert summary["instanceIds"] == ["i-0111111111aaaaaaa"]


def test_a_resource_that_is_not_an_instance_id_is_ignored():
    summary = findings.summarize_sequence(
        {"resources": [{"resourceType": "EC2_INSTANCE", "uid": "not-an-instance"}],
         "sequenceIndicators": []}
    )
    assert summary["instanceIds"] == []


def test_signals_and_description_are_carried_through(sequence_finding):
    summary = findings.extract_targets(sequence_finding)["sequence"]
    assert summary["signalCount"] == 3
    assert "cryptomining" in summary["description"]
    assert summary["uid"] == "sequence-example-0001"


def test_indicator_keys_are_collected(sequence_finding):
    summary = findings.extract_targets(sequence_finding)["sequence"]
    assert set(summary["indicatorKeys"]) == {
        "ATTACK_TACTIC", "CRYPTOMINING_DOMAIN", "VULNERABILITY", "REACHABILITY"
    }


def test_a_finding_with_no_sequence_has_no_sequence_summary(finding_factory):
    targets = findings.extract_targets(findings._normalise(finding_factory()))
    assert targets["sequence"] is None


# --- escalation -------------------------------------------------------------


def test_vulnerability_plus_reachability_escalates(sequence_finding):
    """Known CVEs on a resource that is reachable from the internet."""
    summary = findings.extract_targets(sequence_finding)["sequence"]
    assert summary["escalated"] is True


@pytest.mark.parametrize(
    "keys",
    [["VULNERABILITY"], ["REACHABILITY"], ["MALICIOUS_IP"], []],
)
def test_either_indicator_alone_does_not_escalate(keys):
    summary = findings.summarize_sequence(
        {"resources": [], "sequenceIndicators": [{"key": k} for k in keys]}
    )
    assert summary["escalated"] is False


def test_the_decision_carries_the_escalation_and_its_reason(sequence_finding, monkeypatch):
    from irlib import incidents

    monkeypatch.setattr(incidents, "update_incident", lambda *_a, **_k: None)
    targets = findings.extract_targets(sequence_finding)
    result = decide.handler(
        {
            "incidentId": "inc-1",
            "finding": {"summary": findings.summarize(sequence_finding), "targets": targets},
            "enrichment": {"environment": "production"},
        },
        None,
    )
    assert result["escalated"] is True
    assert "VULNERABILITY and REACHABILITY" in result["escalationReason"]
    assert "VULNERABILITY" in result["sequenceIndicators"]


# --- the containment cap ----------------------------------------------------


def test_a_sequence_within_the_cap_is_contained_automatically(monkeypatch):
    monkeypatch.setattr(decide, "MAX_AUTO_CONTAIN_INSTANCES", 3)
    result = decide._cap_bulk_containment(
        {"decision": "AUTO_CONTAIN", "actions": ["network"], "ruleId": "r"},
        {"instanceIds": ["i-1", "i-2", "i-3"]},
    )
    assert result["decision"] == "AUTO_CONTAIN"


def test_a_sequence_above_the_cap_needs_a_human(monkeypatch):
    """Containing a whole Auto Scaling group because it shares an AMI is an outage."""
    monkeypatch.setattr(decide, "MAX_AUTO_CONTAIN_INSTANCES", 3)
    result = decide._cap_bulk_containment(
        {"decision": "AUTO_CONTAIN", "actions": ["network"], "ruleId": "r"},
        {"instanceIds": [f"i-{n}" for n in range(30)]},
    )
    assert result["decision"] == "APPROVAL_REQUIRED"
    assert result["downgradedFrom"] == "AUTO_CONTAIN"
    assert "30 instances" in result["downgradeReason"]
    assert result["instanceCount"] == 30
    # The planned actions survive, so the approval request says what would happen.
    assert result["actions"] == ["network"]


def test_the_cap_does_not_touch_a_decision_that_was_not_auto_contain(monkeypatch):
    monkeypatch.setattr(decide, "MAX_AUTO_CONTAIN_INSTANCES", 1)
    for decision in ("NOTIFY", "APPROVAL_REQUIRED", "IGNORE"):
        result = decide._cap_bulk_containment(
            {"decision": decision, "actions": [], "ruleId": "r"},
            {"instanceIds": ["i-1", "i-2", "i-3"]},
        )
        assert result["decision"] == decision


def test_attack_sequences_are_on_the_auto_contain_allowlist(sequence_finding):
    """Subject to the cap above, which is the Phase 5 qualification."""
    result = policy.evaluate(
        sequence_finding["type"], sequence_finding["severity"], "production", "Instance", "ACTOR"
    )
    assert result["decision"] == "AUTO_CONTAIN"
    assert result["ruleId"] == "auto-contain-attack-sequence"
    assert result["severityBand"] == "critical"


# --- notification -----------------------------------------------------------


def test_the_notification_includes_the_sequence_and_the_escalation(sequence_finding, monkeypatch):
    from irlib import incidents

    alert = load_lambda("alert")
    sent = {}

    class FakeSns:
        def publish(self, **kwargs):
            sent.update(kwargs)
            return {"MessageId": "m-1"}

    monkeypatch.setattr(alert, "sns_client", FakeSns())
    monkeypatch.setattr(incidents, "list_actions", lambda *_a, **_k: [])

    targets = findings.extract_targets(sequence_finding)
    alert.handler(
        {
            "notifyKind": "APPROVAL_REQUIRED",
            "incidentId": "inc-1",
            "findingId": sequence_finding["id"],
            "accountId": "123456789012",
            "region": "us-east-1",
            "finding": {"summary": findings.summarize(sequence_finding), "targets": targets},
            "enrichment": {"environment": "production", "environmentSource": "tag"},
            "decision": {
                "decision": "APPROVAL_REQUIRED", "ruleId": "auto-contain-attack-sequence",
                "policyVersion": 1, "actions": ["evidence", "network"],
                "escalated": True,
                "escalationReason": "The sequence carries both VULNERABILITY and REACHABILITY "
                                    "indicators: a resource with known CVEs that is reachable "
                                    "from the internet.",
            },
        },
        None,
    )

    message = sent["Message"]
    assert "ATTACK SEQUENCE" in message
    assert "3 signal(s) across 4 resource(s)" in message
    assert "i-0111111111aaaaaaa, i-0222222222bbbbbbb" in message
    assert "[VULNERABILITY]" in message and "[REACHABILITY]" in message
    assert "ESCALATED" in message
    assert "[ESCALATED]" in sent["Subject"]
    assert len(sent["Subject"]) <= 100 and sent["Subject"].isascii()


def test_structured_indicator_values_do_not_break_rendering():
    """SUSPICIOUS_NETWORK is documented with a mapping, not plain strings."""
    alert = load_lambda("alert")
    rendered = alert._render_values([{"AnyCompany": ["TUNNEL_VPN", "IS_ANONYMOUS"]}])
    assert "TUNNEL_VPN" in rendered


def test_the_sample_sequence_matches_the_event_rule_pattern(sequence_finding):
    """The rule keys on the type prefix, since there is no resourceType to match."""
    assert sequence_finding["type"].startswith("AttackSequence:")
