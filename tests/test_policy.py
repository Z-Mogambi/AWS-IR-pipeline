"""The response policy matrix.

These are the cases the policy exists to get right, so they are asserted
against the real response-policy.json rather than a fixture.
"""

import copy

import pytest

from irlib import policy


def decide(finding_type, severity, environment, resource_type="Instance", resource_role="ACTOR"):
    return policy.evaluate(finding_type, severity, environment, resource_type, resource_role)


# --- the cases named in the brief -------------------------------------------


@pytest.mark.parametrize("environment", ["production", "non-production"])
def test_port_probe_never_contains(environment):
    """Anyone on the internet can probe an open port and trigger this finding.

    Containing on it would hand an outsider a remote denial-of-service button.
    """
    result = decide("Recon:EC2/PortProbeUnprotectedPort", 2.0, environment, resource_role="TARGET")
    assert result["decision"] == "NOTIFY"
    assert result["actions"] == []
    assert result["ruleId"] == "notify-inbound-recon"


@pytest.mark.parametrize(
    "finding_type",
    [
        "Backdoor:EC2/C&CActivity.B",
        "Backdoor:EC2/C&CActivity.B!DNS",
        "CryptoCurrency:EC2/BitcoinTool.B",
        "Impact:Runtime/CryptoMinerExecuted",
        "Execution:Runtime/ReverseShell",
        "Trojan:EC2/DNSDataExfiltration",
    ],
)
@pytest.mark.parametrize("environment", ["production", "non-production"])
def test_allowlist_contains_in_every_environment(finding_type, environment):
    result = decide(finding_type, 8.0, environment)
    assert result["decision"] == "AUTO_CONTAIN"
    assert result["ruleId"] == "auto-contain-high-confidence"
    assert set(result["actions"]) == {"evidence", "network", "credentials", "imds"}


def test_non_production_medium_auto_contains():
    result = decide("Behavior:EC2/NetworkPortUnusual", 5.0, "non-production")
    assert result["decision"] == "AUTO_CONTAIN"
    assert result["ruleId"] == "default-non-production-medium-plus"


def test_production_default_requires_approval():
    result = decide("Behavior:EC2/NetworkPortUnusual", 5.0, "production")
    assert result["decision"] == "APPROVAL_REQUIRED"
    assert result["ruleId"] == "default-production"


def test_low_severity_notifies_even_in_non_production():
    result = decide("Behavior:EC2/TrafficVolumeUnusual", 2.0, "non-production")
    assert result["decision"] == "NOTIFY"
    assert result["ruleId"] == "notify-low-severity"


def test_attack_sequence_prefix_matches():
    result = decide("AttackSequence:EC2/CompromisedInstanceGroup", 9.0, "production", None, None)
    assert result["decision"] == "AUTO_CONTAIN"
    assert result["ruleId"] == "auto-contain-attack-sequence"
    assert result["severityBand"] == "critical"


def test_ai_protection_notifies_but_cost_harvesting_needs_approval():
    assert decide("Impact:IAMUser/AnomalousModelInvocation", 5.0, "production", "AccessKey", None)[
        "decision"
    ] == "NOTIFY"
    assert decide("Impact:IAMUser/CostHarvesting", 5.0, "production", "AccessKey", None)[
        "decision"
    ] == "APPROVAL_REQUIRED"


# --- Conflict 1: credential exfiltration cannot reach the Instance rule ------


def test_instance_credential_exfiltration_is_on_the_allowlist():
    result = decide(
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        8.0,
        "production",
        resource_type="AccessKey",
        resource_role=None,
    )
    assert result["decision"] == "AUTO_CONTAIN"
    assert result["ruleId"] == "auto-contain-instance-credential-exfiltration"


def test_credential_exfiltration_reaches_the_pipeline_via_the_access_key_rule():
    """These findings carry resourceType AccessKey, not Instance.

    The rule above was once unreachable: the only EventBridge rule filtered on
    Instance, which these findings never match. The AccessKey rule makes it
    live.
    """
    import pathlib

    template = (pathlib.Path(__file__).resolve().parent.parent / "template.yaml").read_text()
    assert "- Instance" in template
    assert "- AccessKey" in template


# --- strictness -------------------------------------------------------------


def test_unknown_match_key_is_rejected():
    """A typo in the policy file must fail loudly, not silently widen containment."""
    document = copy.deepcopy(policy.load_policy())
    document["rules"][0]["match"]["severtiyMin"] = 7.0
    with pytest.raises(policy.PolicyError, match="unknown match keys"):
        policy.validate_policy(document)


def test_unknown_containment_action_is_rejected():
    document = copy.deepcopy(policy.load_policy())
    document["rules"][0]["actions"] = ["evidence", "nuke"]
    with pytest.raises(policy.PolicyError, match="unknown containment actions"):
        policy.validate_policy(document)


def test_notify_rule_cannot_carry_containment_actions():
    document = copy.deepcopy(policy.load_policy())
    for rule in document["rules"]:
        if rule["decision"] == "NOTIFY":
            rule["actions"] = ["network"]
            break
    with pytest.raises(policy.PolicyError, match="must not carry containment actions"):
        policy.validate_policy(document)


def test_duplicate_rule_ids_are_rejected():
    document = copy.deepcopy(policy.load_policy())
    document["rules"].append(copy.deepcopy(document["rules"][0]))
    with pytest.raises(policy.PolicyError, match="Duplicate rule id"):
        policy.validate_policy(document)


def test_unknown_environment_default_is_production():
    assert policy.load_policy()["unknownEnvironment"] == "production"


def test_severity_bands_match_the_documented_ranges():
    assert policy.severity_band(2.0) == "low"
    assert policy.severity_band(4.0) == "medium"
    assert policy.severity_band(8.9) == "high"
    assert policy.severity_band(9.0) == "critical"


def test_every_rule_is_reachable_in_order():
    """No rule may be fully shadowed by an identical earlier match block."""
    seen = []
    for rule in policy.load_policy()["rules"]:
        assert rule["match"] not in seen, f"Rule {rule['id']} is shadowed by an earlier rule."
        seen.append(rule["match"])
