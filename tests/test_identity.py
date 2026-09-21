"""Identity containment: access key classification and deactivation."""

import pytest

from conftest import load_lambda
from fakes import LedgerFake, ServiceFake, names, params
from irlib import guard, incidents

identity = load_lambda("identity")


def build_event(access_key):
    return {
        "incidentId": "inc-1",
        "finding": {"targets": {"accessKey": access_key}},
    }


@pytest.fixture
def wired(monkeypatch):
    log = []

    def configure(prior_status="Active", completed=None, errors=None):
        iam = ServiceFake(log, "iam", responses={
            "list_access_keys": {
                "AccessKeyMetadata": [{"AccessKeyId": "AKIAEXAMPLE", "Status": prior_status}]
            }
        }, errors=errors)
        monkeypatch.setattr(incidents, "_client", lambda c=None: LedgerFake(log, completed))
        monkeypatch.setattr(identity, "iam_client", iam)
        return log

    return log, configure


# --- classification ---------------------------------------------------------


def test_an_iam_user_key_is_deactivated_here():
    assert identity.classify(
        {"userType": "IAMUser", "userName": "alice", "accessKeyId": "AKIAEXAMPLE"}
    )["method"] == identity.METHOD_DEACTIVATE_KEY


def test_an_ec2_instance_session_goes_to_the_instance_deny():
    """The session name is the instance id, which is how the instance is recovered."""
    plan = identity.classify(
        {"userType": "AssumedRole", "userName": "web-role",
         "principalId": "AROAEXAMPLEID:i-0123456789abcdef0"}
    )
    assert plan["method"] == identity.METHOD_INSTANCE
    assert plan["instanceId"] == "i-0123456789abcdef0"


def test_a_human_role_session_goes_to_the_token_issue_time_deny():
    """A person's session name must not be mistaken for an instance id."""
    plan = identity.classify(
        {"userType": "AssumedRole", "userName": "admin-role",
         "principalId": "AROAEXAMPLEID:alice@example.com"}
    )
    assert plan["method"] == identity.METHOD_SESSIONS
    assert "instanceId" not in plan


def test_an_unknown_user_type_does_nothing():
    assert identity.classify({"userType": "FederatedUser"})["method"] is None


def test_no_access_key_does_nothing():
    assert identity.classify(None)["method"] is None
    assert identity.classify({})["method"] is None


def test_an_iam_user_with_no_name_does_nothing():
    assert identity.classify({"userType": "IAMUser", "accessKeyId": "AKIA1"})["method"] is None


# --- deactivation -----------------------------------------------------------


def test_the_key_is_deactivated_with_an_explicit_user_name(wired):
    """UpdateAccessKey infers the user from the caller if UserName is omitted.

    That would mean the pipeline deactivating one of its own keys, so the name
    is always passed explicitly.
    """
    log, configure = wired
    configure()
    identity.handler(
        build_event({"userType": "IAMUser", "userName": "alice", "accessKeyId": "AKIAEXAMPLE"}),
        None,
    )
    call = params(log, "iam.update_access_key")[0]
    assert call == {"UserName": "alice", "AccessKeyId": "AKIAEXAMPLE", "Status": "Inactive"}


def test_the_prior_status_is_recorded_before_deactivating(wired):
    """A key that was already inactive must not be reactivated on release."""
    import json

    log, configure = wired
    configure(prior_status="Inactive")
    identity.handler(
        build_event({"userType": "IAMUser", "userName": "alice", "accessKeyId": "AKIAEXAMPLE"}),
        None,
    )
    order = names(log)
    assert order.index("iam.list_access_keys") < order.index("iam.update_access_key")
    assert order.index("ledger.put_item") < order.index("iam.update_access_key")

    record = [e for e in log if e[0] == "ledger.put_item"][0][1]
    assert json.loads(record["Item"]["PriorState"]["S"])["status"] == "Inactive"


def test_a_protected_principal_is_refused(wired, monkeypatch):
    """Deactivating the break-glass user's key is the worst possible outcome."""
    log, configure = wired
    configure()
    monkeypatch.setenv("PROTECTED_ROLE_NAMES", "break-glass-user")

    with pytest.raises(guard.ProtectedPrincipalError):
        identity.handler(
            build_event({"userType": "IAMUser", "userName": "break-glass-user",
                         "accessKeyId": "AKIAEXAMPLE"}),
            None,
        )
    assert "iam.update_access_key" not in names(log)


def test_role_sessions_are_left_to_the_credential_function(wired):
    log, configure = wired
    configure()
    result = identity.handler(
        build_event({"userType": "AssumedRole", "userName": "web-role",
                     "principalId": "AROAX:i-0123456789abcdef0"}),
        None,
    )
    assert result["actions"] == []
    assert result["classification"]["method"] == identity.METHOD_INSTANCE
    assert "iam.update_access_key" not in names(log)


def test_a_repeat_run_does_not_deactivate_twice(wired):
    log, configure = wired
    configure(completed={"ACTION#deactivate-access-key#AKIAEXAMPLE": {"status": "Inactive"}})
    identity.handler(
        build_event({"userType": "IAMUser", "userName": "alice", "accessKeyId": "AKIAEXAMPLE"}),
        None,
    )
    assert "iam.update_access_key" not in names(log)


def test_an_unreadable_prior_status_does_not_block_containment(wired):
    log, configure = wired
    configure(errors={"list_access_keys": RuntimeError("AccessDenied")})
    identity.handler(
        build_event({"userType": "IAMUser", "userName": "alice", "accessKeyId": "AKIAEXAMPLE"}),
        None,
    )
    assert "iam.update_access_key" in names(log)


# --- AI Protection findings -------------------------------------------------


def test_ai_protection_findings_are_access_keys_and_classify_normally():
    """All three carry resourceType AccessKey; the policy decides what happens."""
    from irlib import policy

    for finding_type, expected in (
        ("Impact:IAMUser/AnomalousModelInvocation", "NOTIFY"),
        ("Impact:IAMUser/PromptInjection.Direct", "NOTIFY"),
        ("Impact:IAMUser/CostHarvesting", "APPROVAL_REQUIRED"),
    ):
        result = policy.evaluate(finding_type, 5.0, "production", "AccessKey", None)
        assert result["decision"] == expected, finding_type


def test_other_identity_findings_default_to_approval():
    from irlib import policy

    result = policy.evaluate(
        "CredentialAccess:IAMUser/AnomalousBehavior", 5.0, "non-production", "AccessKey", None
    )
    assert result["decision"] == "APPROVAL_REQUIRED"
    assert result["ruleId"] == "approval-identity-default"
