"""Evidence collection: ordering, protections, and best-effort boundaries."""

import json

import pytest

from conftest import load_lambda
from fakes import LedgerFake, ServiceFake, ledger_writes, names, params
from irlib import incidents

evidence = load_lambda("evidence")


def build_event(asg=None, volumes=None):
    instance = {
        "instanceId": "i-0123456789abcdef0",
        "vpcId": "vpc-0abc",
        "subnetId": "subnet-0abc",
        "disableApiTermination": False,
        "disableApiStop": False,
        "instanceInitiatedShutdownBehavior": "terminate",
        "blockDeviceMappings": volumes
        if volumes is not None
        else [
            {"DeviceName": "/dev/xvda", "Ebs": {"VolumeId": "vol-1", "DeleteOnTermination": True}},
            {"DeviceName": "/dev/sdf", "Ebs": {"VolumeId": "vol-2", "DeleteOnTermination": True}},
        ],
        "autoScalingGroupName": asg,
        "autoScalingHealthCheckType": "ELB" if asg else None,
    }
    return {
        "incidentId": "inc-1",
        "accountId": "111122223333",
        "region": "us-east-1",
        "finding": {"summary": {"type": "Backdoor:EC2/C&CActivity.B"}},
        "enrichment": {"instance": instance},
    }


@pytest.fixture
def wired(monkeypatch):
    log = []

    def configure(completed=None, target_groups=None, errors=None):
        monkeypatch.setattr(evidence, "EVIDENCE_BUCKET", "evidence-bucket")
        monkeypatch.setattr(incidents, "_client", lambda c=None: LedgerFake(log, completed))
        monkeypatch.setattr(evidence, "s3_client", ServiceFake(log, "s3", errors=errors))
        monkeypatch.setattr(
            evidence, "ec2_client",
            ServiceFake(log, "ec2", responses={
                "create_snapshots": {"Snapshots": [{"SnapshotId": "snap-1"}, {"SnapshotId": "snap-2"}]},
            }, errors=errors),
        )
        monkeypatch.setattr(evidence, "autoscaling_client", ServiceFake(log, "asg", errors=errors))
        monkeypatch.setattr(
            evidence, "elbv2_client",
            ServiceFake(log, "elb", responses={
                "describe_target_health": {
                    "TargetHealthDescriptions": [
                        {"Target": {"Id": "i-0123456789abcdef0", "Port": 8080}}
                    ]
                },
            }, errors=errors),
        )
        monkeypatch.setattr(evidence, "guardduty_client", ServiceFake(
            log, "gd", responses={"start_malware_scan": {"ScanId": "scan-1"}}, errors=errors))

        # elbv2 pagination is driven through a paginator, so stub that directly.
        class Paginator:
            def paginate(self, **_kwargs):
                return [{"TargetGroups": target_groups if target_groups is not None
                         else [{"TargetGroupArn": "arn:tg/web", "TargetType": "instance"}]}]

        evidence.elbv2_client.get_paginator = lambda _name: Paginator()
        return log

    return log, configure


# --- ordering ---------------------------------------------------------------


def test_evidence_is_stored_before_anything_is_changed(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(), None)
    order = names(log)
    assert order.index("s3.put_object") < order.index("ec2.modify_instance_attribute")


def test_protections_are_applied_before_the_snapshot(wired):
    """Protections are what stop the instance vanishing while snapshots run."""
    log, configure = wired
    configure()
    evidence.handler(build_event(), None)
    keys = ledger_writes(log)
    assert keys.index("protect-termination#i-0123456789abcdef0") < keys.index(
        "snapshot#i-0123456789abcdef0"
    )
    assert keys.index("protect-stop#i-0123456789abcdef0") < keys.index(
        "snapshot#i-0123456789abcdef0"
    )


def test_the_recorded_step_order_matches_the_documented_one(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(asg="web-asg"), None)
    assert [k.split("#")[0] for k in ledger_writes(log)] == [
        "evidence-store",
        "protect-termination",
        "protect-stop",
        "shutdown-behavior",
        "preserve-volumes",
        "snapshot",
        "asg-detach",
        "elb-deregister",
        "malware-scan",
        "tag-instance",
    ]


def test_write_ahead_precedes_every_mutating_call(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(asg="web-asg"), None)

    mutating = {
        "s3.put_object", "ec2.modify_instance_attribute", "ec2.create_snapshots",
        "asg.detach_instances", "elb.deregister_targets", "gd.start_malware_scan",
        "ec2.create_tags",
    }
    writes = 0
    for operation, _ in log:
        if operation == "ledger.put_item":
            writes += 1
        elif operation in mutating:
            assert writes > 0, f"{operation} ran before any ledger write"


# --- the individual protections ---------------------------------------------


def test_each_attribute_is_a_separate_call(wired):
    """ModifyInstanceAttribute accepts exactly one attribute per call."""
    log, configure = wired
    configure()
    evidence.handler(build_event(), None)
    for call in params(log, "ec2.modify_instance_attribute"):
        attributes = set(call) - {"InstanceId"}
        assert len(attributes) == 1, f"more than one attribute in one call: {attributes}"


def test_termination_and_stop_protection_and_shutdown_behaviour(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(), None)
    applied = {}
    for call in params(log, "ec2.modify_instance_attribute"):
        applied.update({k: v for k, v in call.items() if k != "InstanceId"})
    assert applied["DisableApiTermination"] == {"Value": True}
    assert applied["DisableApiStop"] == {"Value": True}
    assert applied["InstanceInitiatedShutdownBehavior"] == {"Value": "stop"}


def test_volumes_are_detached_from_the_instance_lifecycle(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(), None)
    mappings = [
        c["BlockDeviceMappings"]
        for c in params(log, "ec2.modify_instance_attribute")
        if "BlockDeviceMappings" in c
    ][0]
    assert mappings == [
        {"DeviceName": "/dev/xvda", "Ebs": {"DeleteOnTermination": False}},
        {"DeviceName": "/dev/sdf", "Ebs": {"DeleteOnTermination": False}},
    ]


def test_prior_volume_settings_are_recorded_for_release(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(), None)
    record = [
        e[1] for e in log
        if e[0] == "ledger.put_item"
        and e[1]["Item"]["RecordId"]["S"].endswith("preserve-volumes#i-0123456789abcdef0")
    ][0]
    prior = json.loads(record["Item"]["PriorState"]["S"])["blockDeviceMappings"]
    assert prior[0]["deleteOnTermination"] is True
    assert prior[0]["volumeId"] == "vol-1"


def test_snapshots_are_tagged_with_the_incident(wired):
    log, configure = wired
    configure()
    result = evidence.handler(build_event(), None)
    tags = params(log, "ec2.create_snapshots")[0]["TagSpecifications"][0]["Tags"]
    assert {"Key": "IncidentId", "Value": "inc-1"} in tags
    snapshot = [a for a in result["actions"] if a["action"] == "snapshot"][0]
    assert snapshot["result"]["snapshotIds"] == ["snap-1", "snap-2"]


def test_an_instance_with_no_volumes_skips_the_volume_step(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(volumes=[]), None)
    assert "preserve-volumes#i-0123456789abcdef0" not in ledger_writes(log)


# --- Auto Scaling and load balancers ----------------------------------------


def test_asg_detach_keeps_production_capacity(wired):
    """ShouldDecrementDesiredCapacity=False so a replacement launches at once."""
    log, configure = wired
    configure()
    evidence.handler(build_event(asg="web-asg"), None)
    call = params(log, "asg.detach_instances")[0]
    assert call["AutoScalingGroupName"] == "web-asg"
    assert call["ShouldDecrementDesiredCapacity"] is False


def test_detach_happens_before_the_instance_goes_quiet(wired):
    """An ELB health check would otherwise terminate it and destroy the evidence."""
    log, configure = wired
    configure()
    evidence.handler(build_event(asg="web-asg"), None)
    assert "asg-detach#i-0123456789abcdef0" in ledger_writes(log)


def test_an_instance_outside_an_asg_skips_the_detach(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(asg=None), None)
    assert "asg.detach_instances" not in names(log)


def test_registered_targets_are_deregistered(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(), None)
    call = params(log, "elb.deregister_targets")[0]
    assert call["TargetGroupArn"] == "arn:tg/web"
    assert call["Targets"] == [{"Id": "i-0123456789abcdef0", "Port": 8080}]


def test_non_instance_target_groups_are_skipped(wired):
    log, configure = wired
    configure(target_groups=[{"TargetGroupArn": "arn:tg/lambda", "TargetType": "lambda"}])
    evidence.handler(build_event(), None)
    assert "elb.describe_target_health" not in names(log)


def test_the_target_group_scan_is_bounded(wired):
    """A large account must not time the function out."""
    log, configure = wired
    many = [{"TargetGroupArn": f"arn:tg/{i}", "TargetType": "instance"} for i in range(250)]
    configure(target_groups=many)
    result = evidence.handler(build_event(), None)
    deregister = [a for a in result["actions"] if a["action"] == "elb-deregister"][0]
    assert deregister["result"]["targetGroupsScanned"] == evidence.MAX_TARGET_GROUPS_SCANNED
    assert deregister["result"]["truncated"] is True


# --- best effort ------------------------------------------------------------


def test_a_failed_malware_scan_does_not_stop_containment(wired, monkeypatch):
    log, configure = wired
    configure()
    monkeypatch.setattr(
        evidence, "guardduty_client",
        ServiceFake(log, "gd", errors={"start_malware_scan": RuntimeError("BadRequestException")}),
    )
    result = evidence.handler(build_event(), None)
    scan = [a for a in result["actions"] if a["action"] == "malware-scan"][0]
    assert scan["status"] == incidents.STATUS_FAILED
    # The steps after it still ran.
    assert "ec2.create_tags" in names(log)


def test_a_failed_snapshot_does_stop_containment(wired, monkeypatch):
    """Snapshots are not optional; losing the disk is losing the investigation."""
    log, configure = wired
    configure()
    monkeypatch.setattr(
        evidence, "ec2_client",
        ServiceFake(log, "ec2", errors={"create_snapshots": RuntimeError("SnapshotLimitExceeded")}),
    )
    with pytest.raises(RuntimeError, match="SnapshotLimitExceeded"):
        evidence.handler(build_event(), None)


def test_memory_capture_is_off_by_default(wired):
    log, configure = wired
    configure()
    evidence.handler(build_event(), None)
    assert "memory-capture#i-0123456789abcdef0" not in ledger_writes(log)


def test_memory_capture_reports_that_it_is_not_implemented(wired, monkeypatch):
    """Enabling the flag must not silently imply memory was captured."""
    log, configure = wired
    configure()
    monkeypatch.setattr(evidence, "ENABLE_MEMORY_CAPTURE", True)
    result = evidence.handler(build_event(), None)
    capture = [a for a in result["actions"] if a["action"] == "memory-capture"][0]
    assert capture["result"]["implemented"] is False


# --- idempotency and refusals ------------------------------------------------


def test_completed_steps_are_not_repeated(wired):
    log, configure = wired
    configure(completed={
        "ACTION#snapshot#i-0123456789abcdef0": {"snapshotIds": ["snap-1"]},
        "ACTION#tag-instance#i-0123456789abcdef0": {},
    })
    evidence.handler(build_event(), None)
    assert "ec2.create_snapshots" not in names(log)
    assert "ec2.create_tags" not in names(log)


def test_refuses_without_an_instance(wired):
    log, configure = wired
    configure()
    with pytest.raises(ValueError, match="No instance"):
        evidence.handler({"incidentId": "inc-1", "enrichment": {"instance": {}}}, None)


def test_refuses_without_a_bucket(wired, monkeypatch):
    log, configure = wired
    configure()
    monkeypatch.setattr(evidence, "EVIDENCE_BUCKET", "")
    with pytest.raises(RuntimeError, match="EVIDENCE_BUCKET"):
        evidence.handler(build_event(), None)
