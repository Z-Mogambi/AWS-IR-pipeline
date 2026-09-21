"""The function that holds iam:PutRolePolicy.

These tests are mostly about what it refuses to do. It is the most dangerous
code in the stack, so the refusals matter more than the happy path.
"""

import json

import pytest

from conftest import load_lambda
from fakes import LedgerFake, ServiceFake, names, params
from irlib import guard, incidents

credcontain = load_lambda("credcontain")

INSTANCE_ID = "i-0123456789abcdef0"


def build_event(instance_ids=None, access_key=None, account="111122223333", region="us-east-1"):
    return {
        "incidentId": "inc-1",
        "accountId": account,
        "region": region,
        "finding": {
            "targets": {
                "instanceIds": [INSTANCE_ID] if instance_ids is None else instance_ids,
                "accessKey": access_key,
            }
        },
    }


class IamFake(ServiceFake):
    """Adds the exceptions namespace boto3 clients expose."""

    class _NoSuchEntity(Exception):
        pass

    @property
    def exceptions(self):
        outer = self

        class Exceptions:
            NoSuchEntityException = outer._NoSuchEntity

        return Exceptions()


@pytest.fixture
def wired(monkeypatch):
    log = []

    def configure(stored_policy=None, profile_arn="arn:aws:iam::111122223333:instance-profile/web",
                  roles=None, errors=None, completed=None):
        document = stored_policy if stored_policy is not None else {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        iam = IamFake(log, "iam", responses={
            "get_instance_profile": {
                "InstanceProfile": {
                    "Roles": roles if roles is not None else [{"RoleName": "web-role"}]
                }
            },
            "get_role_policy": {"PolicyDocument": document},
        }, errors=errors)
        ec2 = ServiceFake(log, "ec2", responses={
            "describe_instances": {
                "Reservations": [{"Instances": [{
                    "InstanceId": INSTANCE_ID,
                    "IamInstanceProfile": {"Arn": profile_arn} if profile_arn else None,
                }]}]
            }
        })
        monkeypatch.setattr(incidents, "_client", lambda c=None: LedgerFake(log, completed))
        monkeypatch.setattr(credcontain, "iam_client", iam)
        monkeypatch.setattr(credcontain, "ec2_client", ec2)
        monkeypatch.setattr(credcontain, "VERIFY_WRITTEN_POLICIES", True)
        return log

    return log, configure


# --- the EC2 instance path --------------------------------------------------


def test_the_deny_is_pinned_to_one_instance_arn(wired):
    """This is what makes it kill only the compromised instance's credentials.

    ec2:SourceInstanceARN is part of the role session, so it travels with
    credentials wherever they are used - including the attacker's own machine.
    Other instances on the same role have a different ARN and keep working.
    """
    log, configure = wired
    configure()
    credcontain.handler(build_event(), None)

    call = params(log, "iam.put_role_policy")[0]
    document = json.loads(call["PolicyDocument"])
    statement = document["Statement"][0]

    assert statement["Effect"] == "Deny"
    assert statement["Action"] == "*"
    assert statement["Condition"] == {
        "ArnEquals": {
            "ec2:SourceInstanceARN": f"arn:aws:ec2:us-east-1:111122223333:instance/{INSTANCE_ID}"
        }
    }
    assert call["PolicyName"] == f"IR-Quarantine-{INSTANCE_ID}"
    assert call["RoleName"] == "web-role"


def test_token_issue_time_is_never_used_on_the_instance_path(wired):
    """It would break every other instance sharing the role.

    IMDS keeps serving the revoked credentials until they expire, so the
    instances fail and stay failing until the policy is removed.
    """
    log, configure = wired
    configure()
    credcontain.handler(build_event(), None)
    document = params(log, "iam.put_role_policy")[0]["PolicyDocument"]
    assert "TokenIssueTime" not in document


def test_the_role_is_derived_from_aws_not_from_the_event(wired):
    """The event cannot name the role this function writes to."""
    log, configure = wired
    configure(roles=[{"RoleName": "actual-role-from-iam"}])
    event = build_event()
    event["finding"]["targets"]["roleName"] = "attacker-supplied-role"

    credcontain.handler(event, None)
    order = names(log)
    assert order.index("ec2.describe_instances") < order.index("iam.put_role_policy")
    assert order.index("iam.get_instance_profile") < order.index("iam.put_role_policy")
    assert params(log, "iam.put_role_policy")[0]["RoleName"] == "actual-role-from-iam"


def test_an_instance_with_no_profile_writes_nothing(wired):
    log, configure = wired
    configure(profile_arn=None)
    result = credcontain.handler(build_event(), None)
    assert "iam.put_role_policy" not in names(log)
    assert result["skipped"]


def test_a_profile_with_no_role_writes_nothing(wired):
    log, configure = wired
    configure(roles=[])
    result = credcontain.handler(build_event(), None)
    assert "iam.put_role_policy" not in names(log)


# --- refusals ---------------------------------------------------------------


@pytest.mark.parametrize(
    "instance_id",
    ["i-REPLACE_ME", "i-0123", "instance-1", "i-0123456789ABCDEF0", "*", "i-0123456789abcdef0 ",
     "../../etc", ""],
)
def test_malformed_instance_ids_are_refused(wired, instance_id):
    """This value ends up inside an ARN in a policy document."""
    log, configure = wired
    configure()
    with pytest.raises(credcontain.RefusedError, match="malformed instance id"):
        credcontain.contain_instance_credentials(build_event(), "inc-1", instance_id)
    assert "iam.put_role_policy" not in names(log)


def test_a_missing_account_or_region_is_refused(wired):
    log, configure = wired
    configure()
    with pytest.raises(credcontain.RefusedError, match="Account id and region"):
        credcontain.handler(build_event(account=None), None)


def test_a_non_deny_document_is_refused_before_writing(wired):
    log, configure = wired
    configure()
    with pytest.raises(credcontain.RefusedError, match="non-Deny"):
        credcontain.write_policy(
            incident_id="inc-1", role_name="web-role", policy_name="IR-Quarantine-x",
            document={"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            method="x", action_key="x", detail={},
        )
    assert "iam.put_role_policy" not in names(log)


def test_a_document_with_a_smuggled_allow_is_refused(wired):
    """Every statement is checked, not just the first."""
    log, configure = wired
    configure()
    with pytest.raises(credcontain.RefusedError, match="non-Deny"):
        credcontain.assert_deny_only({
            "Statement": [
                {"Effect": "Deny", "Action": "*", "Resource": "*"},
                {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
            ]
        })


def test_an_empty_document_is_refused(wired):
    with pytest.raises(credcontain.RefusedError, match="no statements"):
        credcontain.assert_deny_only({"Statement": []})


def test_protected_roles_are_refused(wired, monkeypatch):
    """Break-glass roles and the pipeline's own roles are exactly the wrong targets."""
    log, configure = wired
    configure(roles=[{"RoleName": "BreakGlassAdmin"}])
    monkeypatch.setenv("PROTECTED_ROLE_NAMES", "BreakGlassAdmin")

    with pytest.raises(guard.ProtectedPrincipalError):
        credcontain.handler(build_event(), None)
    assert "iam.put_role_policy" not in names(log)


def test_the_pipelines_own_roles_are_refused(wired, monkeypatch):
    log, configure = wired
    configure(roles=[{"RoleName": "ir-pipeline-CredContainFunctionRole-ABC"}])
    monkeypatch.setenv("PIPELINE_ROLE_PREFIX", "ir-pipeline-")

    with pytest.raises(guard.ProtectedPrincipalError):
        credcontain.handler(build_event(), None)
    assert "iam.put_role_policy" not in names(log)


def test_a_malformed_role_name_is_refused(wired):
    log, configure = wired
    configure()
    with pytest.raises(credcontain.RefusedError, match="malformed role name"):
        credcontain.write_policy(
            incident_id="inc-1", role_name="bad/role name!", policy_name="IR-Quarantine-x",
            document={"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]},
            method="x", action_key="x", detail={},
        )


# --- read-after-write -------------------------------------------------------


def test_the_written_policy_is_read_back_and_checked(wired):
    log, configure = wired
    configure()
    result = credcontain.handler(build_event(), None)

    order = names(log)
    # There is an earlier GetRolePolicy recording whether the policy already
    # existed, for release. The read-back is the one after the write.
    write = order.index("iam.put_role_policy")
    assert "iam.get_role_policy" in order[write:], "the written policy must be read back"
    verified = result["actions"][0]["result"]["verified"]
    assert verified == {"checked": True, "denyOnly": True, "statements": 1}


def test_an_allow_that_somehow_reached_iam_raises(wired):
    """The alert the brief asks for, at the only moment it can still be acted on."""
    log, configure = wired
    configure(stored_policy={
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    })
    with pytest.raises(credcontain.RefusedError, match="non-Deny"):
        credcontain.handler(build_event(), None)


def test_a_policy_document_returned_as_a_string_is_still_checked(wired):
    log, configure = wired
    configure(stored_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    }))
    result = credcontain.handler(build_event(), None)
    assert result["actions"][0]["result"]["verified"]["denyOnly"] is True


# --- the non-EC2 role session path ------------------------------------------


def test_role_sessions_use_token_issue_time_with_an_ec2_guard(wired):
    """The Null guard stops this template taking effect on an EC2 session."""
    log, configure = wired
    configure()
    credcontain.handler(
        build_event(instance_ids=[], access_key={"userType": "AssumedRole", "userName": "admin-role"}),
        None,
    )

    call = params(log, "iam.put_role_policy")[0]
    condition = json.loads(call["PolicyDocument"])["Statement"][0]["Condition"]
    assert "aws:TokenIssueTime" in condition["DateLessThan"]
    assert condition["Null"] == {"ec2:SourceInstanceARN": "true"}
    assert call["RoleName"] == "admin-role"


def test_an_instance_target_wins_over_an_access_key(wired):
    """A credential-exfiltration finding names both; the instance path is the right one."""
    log, configure = wired
    configure()
    result = credcontain.handler(
        build_event(access_key={"userType": "AssumedRole", "userName": "web-role"}), None
    )
    assert result["method"] == credcontain.METHOD_INSTANCE


def test_nothing_to_contain_is_not_an_error(wired):
    log, configure = wired
    configure()
    result = credcontain.handler(build_event(instance_ids=[], access_key=None), None)
    assert result["actions"] == []
    assert "iam.put_role_policy" not in names(log)


# --- ledger -----------------------------------------------------------------


def test_the_write_is_recorded_before_it_happens(wired):
    log, configure = wired
    configure()
    credcontain.handler(build_event(), None)
    order = names(log)
    assert order.index("ledger.put_item") < order.index("iam.put_role_policy")


def test_a_repeat_run_does_not_rewrite_the_policy(wired):
    log, configure = wired
    configure(completed={f"ACTION#deny-instance-credentials#{INSTANCE_ID}": {"roleName": "web-role"}})
    credcontain.handler(build_event(), None)
    assert "iam.put_role_policy" not in names(log)
