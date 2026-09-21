"""Release: replaying the ledger backwards."""

import json

import pytest

from conftest import load_lambda
from fakes import LedgerFake, ServiceFake, names, params
from irlib import guard, incidents

release = load_lambda("release")


def action(name, target, prior=None, result=None, status=None, started="2026-09-21T12:00:00Z"):
    return {
        "RecordId": f"ACTION#{name}#{target}",
        "Action": name,
        "Target": target,
        "Status": status or incidents.STATUS_DONE,
        "StartedAt": started,
        "PriorState": prior or {},
        "Result": result or {},
    }


FULL_CONTAINMENT = [
    action("evidence-store", "i-0abc", result={"keys": ["k"]}),
    action("protect-termination", "i-0abc", prior={"disableApiTermination": False}),
    action("protect-stop", "i-0abc", prior={"disableApiStop": False}),
    action("shutdown-behavior", "i-0abc", prior={"instanceInitiatedShutdownBehavior": "terminate"}),
    action("preserve-volumes", "i-0abc",
           prior={"blockDeviceMappings": [{"deviceName": "/dev/xvda", "volumeId": "vol-1",
                                           "deleteOnTermination": True}]}),
    action("snapshot", "i-0abc", result={"snapshotIds": ["snap-1"]}),
    action("asg-detach", "i-0abc", prior={"autoScalingGroupName": "web-asg"}),
    action("elb-deregister", "i-0abc", result={"deregistered": [{"targetGroupArn": "arn:tg/web"}]}),
    action("quarantine-sg-create", "vpc-0abc", result={"groupId": "sg-quarantine", "created": True}),
    action("quarantine-sg-open", "sg-quarantine", result={"openedAt": "t0"}),
    action("eni-isolate", "eni-primary", prior={"groups": ["sg-web"]}),
    action("eni-isolate", "eni-second", prior={"groups": ["sg-db", "sg-mgmt"]}),
    action("quarantine-sg-seal", "sg-quarantine", result={"sealedAt": "t1"}),
    action("dns-block", "evil.example",
           result={"domains": ["evil.example"], "domainListId": "rslvr-fdl-1",
                   "associationId": "rslvr-frgassoc-1"}),
    action("nacl-backstop", "subnet-0abc",
           result={"entries": [{"networkAclId": "acl-1", "ruleNumber": 2, "egress": False}]}),
    action("deny-instance-credentials", "web-role",
           prior={"roleName": "web-role", "policyName": "IR-Quarantine-i-0abc",
                  "existedBefore": False}),
    action("disable-imds", "i-0abc",
           prior={"httpEndpoint": "enabled", "httpTokens": "required",
                  "httpPutResponseHopLimit": 2}),
]


class IamFake(ServiceFake):
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

    def configure(records=None, completed=None, errors=None, meta=None):
        ledger = LedgerFake(log, completed)
        ledger.list_actions = lambda *_a, **_k: records
        monkeypatch.setattr(incidents, "_client", lambda c=None: ledger)
        monkeypatch.setattr(
            incidents, "list_actions",
            lambda incident_id, **_k: list(records if records is not None else FULL_CONTAINMENT),
        )
        monkeypatch.setattr(
            incidents, "get_meta",
            lambda incident_id, **_k: meta if meta is not None else {"FindingId": "f-1",
                                                                     "FindingType": "T"},
        )
        monkeypatch.setattr(release, "ec2_client", ServiceFake(log, "ec2", errors=errors))
        monkeypatch.setattr(release, "iam_client", IamFake(log, "iam", errors=errors))
        monkeypatch.setattr(release, "route53resolver_client", ServiceFake(log, "r53", errors=errors))
        return log

    return log, configure


# --- ordering ---------------------------------------------------------------


def test_every_interface_is_restored_before_the_group_is_deleted(wired):
    """A security group still attached to an interface cannot be deleted.

    This is the one hard ordering dependency in release.
    """
    log, configure = wired
    configure()
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)

    order = names(log)
    last_restore = max(
        index for index, entry in enumerate(log)
        if entry[0] == "ec2.modify_network_interface_attribute"
    )
    delete = order.index("ec2.delete_security_group")
    assert last_restore < delete


def test_the_release_order_is_the_containment_order_reversed(wired):
    log, configure = wired
    configure()
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)

    performed = [a["action"].removeprefix("release:") for a in result["actions"]]
    assert performed == [
        "disable-imds",
        "deny-instance-credentials",
        "dns-block",
        "nacl-backstop",
        "eni-isolate",
        "eni-isolate",
        "quarantine-sg-create",
        "preserve-volumes",
        "shutdown-behavior",
        "protect-stop",
        "protect-termination",
    ]


def test_credentials_come_back_before_the_network_does(wired):
    """The reverse of containment: the Deny is lifted before the instance is
    back on the network, never the other way round."""
    log, configure = wired
    configure()
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    performed = [a["action"] for a in result["actions"]]
    assert performed.index("release:deny-instance-credentials") < performed.index(
        "release:eni-isolate"
    )


# --- individual reversals ---------------------------------------------------


def test_each_interface_goes_back_to_its_own_groups(wired):
    log, configure = wired
    configure()
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)

    restored = {
        call["NetworkInterfaceId"]: call["Groups"]
        for call in params(log, "ec2.modify_network_interface_attribute")
    }
    assert restored == {"eni-primary": ["sg-web"], "eni-second": ["sg-db", "sg-mgmt"]}


def test_every_metadata_setting_is_restored_not_just_the_endpoint(wired):
    """Restoring HttpEndpoint alone would leave HttpTokens at the API default,
    silently downgrading an IMDSv2-only instance."""
    log, configure = wired
    configure()
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)

    call = params(log, "ec2.modify_instance_metadata_options")[0]
    assert call["HttpEndpoint"] == "enabled"
    assert call["HttpTokens"] == "required"
    assert call["HttpPutResponseHopLimit"] == 2


def test_the_credential_deny_is_deleted(wired):
    log, configure = wired
    configure()
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    assert params(log, "iam.delete_role_policy")[0] == {
        "RoleName": "web-role", "PolicyName": "IR-Quarantine-i-0abc"
    }


def test_a_policy_that_existed_before_containment_is_left_alone(wired):
    """Deleting it would remove something that was not ours."""
    log, configure = wired
    configure(records=[action("deny-instance-credentials", "web-role",
                              prior={"roleName": "web-role", "policyName": "existing-policy",
                                     "existedBefore": True})])
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    assert "iam.delete_role_policy" not in names(log)
    assert "existed on" in result["actions"][0]["result"]["skipped"]


def test_release_refuses_protected_roles(wired, monkeypatch):
    log, configure = wired
    configure(records=[action("deny-instance-credentials", "BreakGlassAdmin",
                              prior={"roleName": "BreakGlassAdmin", "policyName": "p",
                                     "existedBefore": False})])
    monkeypatch.setenv("PROTECTED_ROLE_NAMES", "BreakGlassAdmin")
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    assert "iam.delete_role_policy" not in names(log)
    assert result["actions"][0]["status"] == incidents.STATUS_FAILED


def test_domains_are_removed_but_the_vpc_association_is_kept(wired):
    """Other incidents may still rely on the association; an empty list is harmless."""
    log, configure = wired
    configure()
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)

    call = params(log, "r53.update_firewall_domains")[0]
    assert call["Operation"] == "REMOVE"
    assert call["Domains"] == ["evil.example"]
    assert "r53.disassociate_firewall_rule_group" not in names(log)


def test_nacl_entries_are_deleted_by_number_and_direction(wired):
    log, configure = wired
    configure()
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    assert params(log, "ec2.delete_network_acl_entry")[0] == {
        "NetworkAclId": "acl-1", "RuleNumber": 2, "Egress": False
    }


def test_volume_lifecycle_is_restored(wired):
    log, configure = wired
    configure()
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    mappings = [
        call["BlockDeviceMappings"]
        for call in params(log, "ec2.modify_instance_attribute")
        if "BlockDeviceMappings" in call
    ][0]
    assert mappings == [{"DeviceName": "/dev/xvda", "Ebs": {"DeleteOnTermination": True}}]


def test_a_key_that_was_already_inactive_is_not_reactivated(wired):
    """Someone disabled it on purpose; release must not undo that."""
    log, configure = wired
    configure(records=[action("deactivate-access-key", "AKIA1",
                              prior={"userName": "alice", "accessKeyId": "AKIA1",
                                     "status": "Inactive"})])
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    assert "iam.update_access_key" not in names(log)
    assert "Inactive" in result["actions"][0]["result"]["skipped"]


def test_a_key_that_was_active_is_reactivated(wired):
    log, configure = wired
    configure(records=[action("deactivate-access-key", "AKIA1",
                              prior={"userName": "alice", "accessKeyId": "AKIA1",
                                     "status": "Active"})])
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    assert params(log, "iam.update_access_key")[0]["Status"] == "Active"


# --- things release does not undo -------------------------------------------


def test_evidence_and_snapshots_are_never_undone(wired):
    log, configure = wired
    configure()
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    performed = [a["action"] for a in result["actions"]]
    for action_name in ("evidence-store", "snapshot", "tag-instance"):
        assert f"release:{action_name}" not in performed
    assert "ec2.delete_snapshot" not in names(log)


def test_asg_and_load_balancer_reattachment_are_reported_as_manual(wired):
    log, configure = wired
    configure()
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    manual = {step["action"] for step in result["manualSteps"]}
    assert manual == {"asg-detach", "elb-deregister"}
    assert "asg.attach_instances" not in names(log)


# --- resilience -------------------------------------------------------------


def test_one_failing_step_does_not_strand_the_rest(wired):
    """A partial release must still get everything else back."""
    log, configure = wired
    configure(errors={"delete_security_group": RuntimeError("DependencyViolation")})
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)

    statuses = {a["action"]: a["status"] for a in result["actions"]}
    assert statuses["release:quarantine-sg-create"] == incidents.STATUS_FAILED
    assert statuses["release:protect-termination"] == incidents.STATUS_DONE


def test_a_group_already_gone_is_not_an_error(wired):
    from botocore.exceptions import ClientError

    log, configure = wired
    configure(errors={"delete_security_group": ClientError(
        {"Error": {"Code": "InvalidGroup.NotFound", "Message": "gone"}}, "DeleteSecurityGroup"
    )})
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    entry = [a for a in result["actions"] if a["action"] == "release:quarantine-sg-create"][0]
    assert entry["result"]["alreadyGone"] is True


def test_a_group_still_in_use_is_reported_not_forced(wired):
    from botocore.exceptions import ClientError

    log, configure = wired
    configure(errors={"delete_security_group": ClientError(
        {"Error": {"Code": "DependencyViolation", "Message": "in use"}}, "DeleteSecurityGroup"
    )})
    result = release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    entry = [a for a in result["actions"] if a["action"] == "release:quarantine-sg-create"][0]
    assert entry["result"]["stillInUse"] is True


def test_a_rerun_skips_what_already_came_back(wired):
    log, configure = wired
    configure(completed={"ACTION#release#eni-isolate#eni-primary": {"groups": ["sg-web"]}})
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    restored = [c["NetworkInterfaceId"] for c in params(log, "ec2.modify_network_interface_attribute")]
    assert restored == ["eni-second"]


def test_only_completed_containment_actions_are_reversed(wired):
    """A step that failed never happened, so there is nothing to undo."""
    log, configure = wired
    configure(records=[
        action("eni-isolate", "eni-primary", prior={"groups": ["sg-web"]}),
        action("eni-isolate", "eni-failed", prior={"groups": ["sg-x"]},
               status=incidents.STATUS_FAILED),
    ])
    release.handler({"mode": "restore", "incidentId": "inc-1"}, None)
    restored = [c["NetworkInterfaceId"] for c in params(log, "ec2.modify_network_interface_attribute")]
    assert restored == ["eni-primary"]


# --- load mode --------------------------------------------------------------


def test_load_describes_the_plan_without_changing_anything(wired):
    log, configure = wired
    configure()
    plan = release.handler({"mode": "load", "incidentId": "inc-1"}, None)

    assert [step["action"] for step in plan["plan"]][0] == "disable-imds"
    assert {step["action"] for step in plan["manualSteps"]} == {"asg-detach", "elb-deregister"}
    mutating = [name for name, _ in log if name.startswith(("ec2.", "iam.", "r53."))]
    assert mutating == [], f"load must not change anything, but called {mutating}"


def test_load_rejects_an_unknown_incident(wired):
    log, configure = wired
    configure(meta={})
    with pytest.raises(ValueError, match="No incident record"):
        release.handler({"mode": "load", "incidentId": "nope"}, None)


def test_an_unknown_mode_is_rejected(wired):
    log, configure = wired
    configure()
    with pytest.raises(ValueError, match="Unknown mode"):
        release.handler({"mode": "delete-everything", "incidentId": "inc-1"}, None)


def test_every_ordered_action_has_a_handler():
    """A step in the order with no handler would silently never be reversed."""
    assert set(release.RELEASE_ORDER) == set(release.HANDLERS)


def test_every_containment_action_is_classified():
    """Nothing a containment function records may fall through unnoticed."""
    recorded = {
        "evidence-store", "protect-termination", "protect-stop", "shutdown-behavior",
        "preserve-volumes", "snapshot", "asg-detach", "elb-deregister", "malware-scan",
        "tag-instance", "memory-capture", "quarantine-sg-create", "quarantine-sg-open",
        "eni-isolate", "quarantine-sg-seal", "nacl-backstop", "dns-block",
        "deny-instance-credentials", "deny-older-sessions", "deactivate-access-key",
        "disable-imds",
    }
    classified = set(release.RELEASE_ORDER) | release.NOTHING_TO_UNDO | set(release.MANUAL)
    assert recorded - classified == set(), f"unclassified: {recorded - classified}"
