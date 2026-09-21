"""Network isolation: untracked flows, every ENI, and safe re-runs."""

import json

import pytest

from conftest import load_lambda
from fakes import LedgerFake, ServiceFake, ledger_writes, names, params
from irlib import incidents

netisolate = load_lambda("netisolate")


def build_event(interfaces=None, domains=None, remote_ips=None, subnet_id="subnet-0abc"):
    return {
        "incidentId": "inc-1",
        "finding": {
            "targets": {
                "instanceIds": ["i-0123456789abcdef0"],
                "domains": domains or [],
                "remoteIps": remote_ips or [],
            }
        },
        "enrichment": {
            "instance": {
                "instanceId": "i-0123456789abcdef0",
                "vpcId": "vpc-0abc",
                "subnetId": subnet_id,
                "networkInterfaces": interfaces
                if interfaces is not None
                else [{"networkInterfaceId": "eni-primary", "groups": ["sg-web"]}],
            }
        },
    }


@pytest.fixture
def wired(monkeypatch):
    """Returns (log, configure) so each test can adjust the canned responses."""
    log = []
    state = {}

    def configure(completed=None, describe_groups=None, acls=None, r53=None, errors=None):
        ledger = LedgerFake(log, completed=completed)
        ec2 = ServiceFake(
            log,
            "ec2",
            responses={
                "create_security_group": {"GroupId": "sg-quarantine"},
                "describe_security_groups": describe_groups
                if describe_groups is not None
                else (lambda kw: {"SecurityGroups": []}
                      if kw.get("Filters")
                      else {"SecurityGroups": [{"GroupId": "sg-quarantine",
                                                "IpPermissions": [{"IpProtocol": "-1"}],
                                                "IpPermissionsEgress": [{"IpProtocol": "-1"}]}]}),
                "describe_network_acls": acls if acls is not None else {"NetworkAcls": []},
            },
            errors=errors,
        )
        resolver = ServiceFake(log, "r53", responses=r53 or {})
        monkeypatch.setattr(incidents, "_client", lambda c=None: ledger)
        monkeypatch.setattr(netisolate, "ec2_client", ec2)
        monkeypatch.setattr(netisolate, "route53resolver_client", resolver)
        state["ec2"] = ec2
        return log

    return log, configure


# --- the untracked-flow technique -------------------------------------------


def test_group_is_opened_before_attachment_and_sealed_after(wired):
    """This ordering is the whole point.

    Opening the group makes existing connections untracked; attaching it moves
    the instance behind it; sealing it drops those untracked flows. Open after
    attach, or seal before attach, and an established reverse shell survives.
    """
    log, configure = wired
    configure()
    netisolate.handler(build_event(), None)
    order = names(log)

    opened = order.index("ec2.authorize_security_group_ingress")
    attached = order.index("ec2.modify_network_interface_attribute")
    sealed = order.index("ec2.revoke_security_group_ingress")
    assert opened < attached < sealed


def test_the_group_is_opened_to_all_traffic_v4_and_v6(wired):
    log, configure = wired
    configure()
    netisolate.handler(build_event(), None)

    for operation in ("ec2.authorize_security_group_ingress", "ec2.authorize_security_group_egress"):
        permission = params(log, operation)[0]["IpPermissions"][0]
        assert permission["IpProtocol"] == "-1"
        assert permission["IpRanges"] == [{"CidrIp": "0.0.0.0/0"}]
        assert permission["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]


def test_both_directions_are_revoked_when_sealing(wired):
    log, configure = wired
    configure()
    netisolate.handler(build_event(), None)
    assert params(log, "ec2.revoke_security_group_ingress")
    assert params(log, "ec2.revoke_security_group_egress")


def test_the_exposure_window_is_reported(wired):
    """The instance really is briefly open, so say so rather than hide it."""
    log, configure = wired
    configure()
    result = netisolate.handler(build_event(), None)
    window = result["exposureWindow"]
    assert window["openedAt"] and window["sealedAt"]
    assert window["seconds"] is not None and window["seconds"] >= 0


def test_a_duplicate_egress_rule_is_not_an_error(wired):
    """A new group already allows all egress to 0.0.0.0/0."""
    from botocore.exceptions import ClientError

    log, configure = wired
    configure(errors={
        "authorize_security_group_egress": ClientError(
            {"Error": {"Code": "InvalidPermission.Duplicate", "Message": "exists"}},
            "AuthorizeSecurityGroupEgress",
        )
    })
    result = netisolate.handler(build_event(), None)
    assert result["quarantineSecurityGroupId"] == "sg-quarantine"


# --- every interface --------------------------------------------------------


def test_multi_eni_instances_move_every_interface(wired):
    """ModifyInstanceAttribute(Groups=...) only moves the primary interface."""
    log, configure = wired
    configure()
    result = netisolate.handler(
        build_event(
            interfaces=[
                {"networkInterfaceId": "eni-primary", "groups": ["sg-web"]},
                {"networkInterfaceId": "eni-second", "groups": ["sg-db", "sg-mgmt"]},
                {"networkInterfaceId": "eni-third", "groups": []},
            ]
        ),
        None,
    )
    moved = [p["NetworkInterfaceId"] for p in params(log, "ec2.modify_network_interface_attribute")]
    assert moved == ["eni-primary", "eni-second", "eni-third"]
    assert result["interfacesIsolated"] == ["eni-primary", "eni-second", "eni-third"]
    assert "ec2.modify_instance_attribute" not in names(log)


def test_each_interfaces_original_groups_are_recorded_before_it_moves(wired):
    """Without the prior groups, a moved interface could never be put back."""
    log, configure = wired
    configure()
    netisolate.handler(
        build_event(
            interfaces=[
                {"networkInterfaceId": "eni-primary", "groups": ["sg-web"]},
                {"networkInterfaceId": "eni-second", "groups": ["sg-db", "sg-mgmt"]},
            ]
        ),
        None,
    )

    recorded = {}
    for index, (operation, payload) in enumerate(log):
        if operation != "ledger.put_item":
            continue
        record_id = payload["Item"]["RecordId"]["S"]
        if not record_id.startswith("ACTION#eni-isolate#"):
            continue
        eni = record_id.rsplit("#", 1)[1]
        recorded[eni] = json.loads(payload["Item"]["PriorState"]["S"])["groups"]

        moved_after = [
            call["NetworkInterfaceId"]
            for op, call in log[index:]
            if op == "ec2.modify_network_interface_attribute"
        ]
        assert eni in moved_after, f"{eni} was moved before its groups were recorded"

    assert recorded == {"eni-primary": ["sg-web"], "eni-second": ["sg-db", "sg-mgmt"]}


# --- per incident, not shared ------------------------------------------------


def test_the_quarantine_group_is_tagged_with_the_incident(wired):
    """A shared group would briefly un-isolate every other quarantined instance."""
    log, configure = wired
    configure()
    netisolate.handler(build_event(), None)
    tags = params(log, "ec2.create_security_group")[0]["TagSpecifications"][0]["Tags"]
    assert {"Key": "IRPipeline:IncidentId", "Value": "inc-1"} in tags


def test_an_existing_group_for_this_incident_is_reused(wired):
    """Re-running must not create a second group."""
    log, configure = wired
    configure(describe_groups=lambda kw: (
        {"SecurityGroups": [{"GroupId": "sg-existing"}]}
        if kw.get("Filters")
        else {"SecurityGroups": [{"GroupId": "sg-existing", "IpPermissions": [],
                                  "IpPermissionsEgress": []}]}
    ))
    result = netisolate.handler(build_event(), None)
    assert "ec2.create_security_group" not in names(log)
    assert result["quarantineSecurityGroupId"] == "sg-existing"


# --- idempotency -------------------------------------------------------------


def test_completed_steps_are_not_repeated_on_a_re_run(wired):
    log, configure = wired
    configure(completed={
        "ACTION#quarantine-sg-create#inc-1": {"groupId": "sg-quarantine", "created": False},
        "ACTION#eni-isolate#eni-primary": {"networkInterfaceId": "eni-primary"},
    })
    netisolate.handler(build_event(), None)

    assert "ec2.create_security_group" not in names(log)
    assert "ec2.modify_network_interface_attribute" not in names(log)
    # Sealing still runs: it is the step that actually drops the flows.
    assert "ec2.revoke_security_group_ingress" in names(log)


def test_write_ahead_precedes_every_mutating_call(wired):
    """No mutation may happen before its own ledger record exists."""
    log, configure = wired
    configure()
    netisolate.handler(build_event(domains=["evil.example"]), None)

    mutating = {
        "ec2.create_security_group",
        "ec2.authorize_security_group_ingress",
        "ec2.modify_network_interface_attribute",
        "ec2.revoke_security_group_ingress",
        "r53.update_firewall_domains",
    }
    seen_writes = 0
    for operation, _ in log:
        if operation == "ledger.put_item":
            seen_writes += 1
        elif operation in mutating:
            assert seen_writes > 0, f"{operation} ran before any ledger write"


# --- optional extras ---------------------------------------------------------


def test_dns_domains_are_normalised_and_the_vpc_is_associated(wired, monkeypatch):
    monkeypatch.setattr(netisolate, "DNS_FIREWALL_DOMAIN_LIST_ID", "rslvr-fdl-1")
    monkeypatch.setattr(netisolate, "DNS_FIREWALL_RULE_GROUP_ID", "rslvr-frg-1")
    log, configure = wired
    configure(r53={
        "list_firewall_rule_group_associations": {"FirewallRuleGroupAssociations": []},
        "associate_firewall_rule_group": {"FirewallRuleGroupAssociation": {"Id": "rslvr-frgassoc-1"}},
    })
    netisolate.handler(build_event(domains=["Evil.Example.", "evil.example"]), None)

    update = params(log, "r53.update_firewall_domains")[0]
    assert update["Operation"] == "ADD"
    assert update["Domains"] == ["evil.example"]
    assert "r53.associate_firewall_rule_group" in names(log)


def test_an_existing_vpc_association_is_not_duplicated(wired, monkeypatch):
    monkeypatch.setattr(netisolate, "DNS_FIREWALL_DOMAIN_LIST_ID", "rslvr-fdl-1")
    monkeypatch.setattr(netisolate, "DNS_FIREWALL_RULE_GROUP_ID", "rslvr-frg-1")
    log, configure = wired
    configure(r53={
        "list_firewall_rule_group_associations": {
            "FirewallRuleGroupAssociations": [{"Id": "rslvr-frgassoc-existing"}]
        }
    })
    netisolate.handler(build_event(domains=["evil.example"]), None)
    assert "r53.associate_firewall_rule_group" not in names(log)


def test_dns_failure_does_not_undo_the_isolation(wired, monkeypatch):
    """The DNS step is best effort; isolation has already happened."""
    monkeypatch.setattr(netisolate, "DNS_FIREWALL_DOMAIN_LIST_ID", "rslvr-fdl-1")
    log, configure = wired
    configure()
    monkeypatch.setattr(
        netisolate,
        "route53resolver_client",
        ServiceFake(log, "r53", errors={"update_firewall_domains": RuntimeError("throttled")}),
    )
    result = netisolate.handler(build_event(domains=["evil.example"]), None)
    assert result["quarantineSecurityGroupId"] == "sg-quarantine"
    failed = [a for a in result["actions"] if a["status"] == incidents.STATUS_FAILED]
    assert failed and failed[0]["action"] == "dns-block"


def test_nacl_backstop_is_off_by_default(wired):
    log, configure = wired
    configure()
    netisolate.handler(build_event(remote_ips=["198.51.100.7"]), None)
    assert "ec2.create_network_acl_entry" not in names(log)


def test_nacl_backstop_uses_the_reserved_range_and_denies_both_directions(wired, monkeypatch):
    monkeypatch.setattr(netisolate, "ENABLE_NACL_BACKSTOP", True)
    log, configure = wired
    configure(acls={"NetworkAcls": [{"NetworkAclId": "acl-1", "Entries": [{"RuleNumber": 1}]}]})
    netisolate.handler(build_event(remote_ips=["198.51.100.7"]), None)

    entries = params(log, "ec2.create_network_acl_entry")
    assert len(entries) == 2
    assert {e["Egress"] for e in entries} == {True, False}
    for entry in entries:
        assert entry["RuleAction"] == "deny"
        assert entry["CidrBlock"] == "198.51.100.7/32"
        assert entry["RuleNumber"] in netisolate.NACL_RULE_RANGE


def test_nacl_backstop_skips_rather_than_overwrite_someone_elses_rule(wired, monkeypatch):
    monkeypatch.setattr(netisolate, "ENABLE_NACL_BACKSTOP", True)
    log, configure = wired
    occupied = [{"RuleNumber": n} for n in netisolate.NACL_RULE_RANGE]
    configure(acls={"NetworkAcls": [{"NetworkAclId": "acl-1", "Entries": occupied}]})
    result = netisolate.handler(build_event(remote_ips=["198.51.100.7"]), None)

    assert "ec2.create_network_acl_entry" not in names(log)
    backstop = [a for a in result["actions"] if a["action"] == "nacl-backstop"][0]
    assert backstop["result"]["skipped"]


# --- refusals ----------------------------------------------------------------


def test_refuses_without_interfaces(wired):
    log, configure = wired
    configure()
    with pytest.raises(ValueError, match="network interfaces"):
        netisolate.handler(build_event(interfaces=[]), None)


def test_refuses_without_a_vpc(wired):
    log, configure = wired
    configure()
    event = build_event()
    event["enrichment"]["instance"]["vpcId"] = None
    with pytest.raises(ValueError, match="No VPC"):
        netisolate.handler(event, None)
