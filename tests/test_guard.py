"""Protected principals: the pipeline must never contain itself or break glass."""

import pytest

from irlib import guard


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.setenv("PROTECTED_ROLE_NAMES", "BreakGlassAdmin, IncidentCommander")
    monkeypatch.setenv("PIPELINE_ROLE_PREFIX", "ir-pipeline-")


@pytest.mark.parametrize(
    "role",
    [
        "BreakGlassAdmin",
        "IncidentCommander",
        "arn:aws:iam::111122223333:role/BreakGlassAdmin",
        "ir-pipeline-IsolateFunctionRole-ABC123",
        "arn:aws:iam::111122223333:role/ir-pipeline-VerifyFunctionRole-XYZ",
        "arn:aws:iam::111122223333:role/aws-service-role/ssm.amazonaws.com/AWSServiceRoleForAmazonSSM",
        "",
        None,
    ],
)
def test_protected_roles_are_refused(role):
    assert guard.is_protected_role(role) is True
    with pytest.raises(guard.ProtectedPrincipalError):
        guard.assert_role_actionable(role, context="test")


@pytest.mark.parametrize(
    "role",
    [
        "AppServerRole",
        "arn:aws:iam::111122223333:role/AppServerRole",
        "ec2-web-tier",
    ],
)
def test_ordinary_workload_roles_are_actionable(role):
    assert guard.is_protected_role(role) is False
    assert guard.assert_role_actionable(role) == role


def test_extra_protected_roles_can_be_supplied_per_call():
    assert guard.is_protected_role("AppServerRole", extra_protected=["AppServerRole"]) is True


def test_an_unidentifiable_principal_is_treated_as_protected():
    """Failing closed: if we cannot name the principal, we do not act on it."""
    assert guard.is_protected_role(None) is True
