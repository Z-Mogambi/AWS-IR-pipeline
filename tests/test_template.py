"""Assertions against the template after the SAM transform.

`sam validate` only checks that the template is well formed. These run the real
SAM transform so the IAM and wiring claims are checked against the
CloudFormation that would actually be deployed - which is where the Phase 1
least-privilege requirements live.

Nothing here contacts AWS: the transform is a pure function and the S3 URIs
`sam package` would fill in are stubbed.
"""

import pathlib

import pytest

samtranslator = pytest.importorskip(
    "samtranslator", reason="aws-sam-translator is a dev dependency; pinned in Phase 7"
)

from samtranslator.translator.transform import transform  # noqa: E402
from samtranslator.yaml_helper import yaml_parse  # noqa: E402
from unittest.mock import MagicMock  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

FUNCTION_LOGICAL_IDS = [
    "RouterFunction",
    "VerifyFunction",
    "EnrichFunction",
    "DecideFunction",
    "EvidenceFunction",
    "NetIsolateFunction",
    "AlertFunction",
]


@pytest.fixture(scope="module")
def transformed():
    template = yaml_parse((ROOT / "template.yaml").read_text())
    for resource in template["Resources"].values():
        properties = resource.get("Properties", {})
        for key in ("CodeUri", "ContentUri", "DefinitionUri"):
            if key in properties:
                properties[key] = "s3://stub-bucket/stub-key"
    loader = MagicMock()
    loader.load.return_value = {}
    return transform(template, {}, loader)


def resources_of(transformed, resource_type):
    return {
        name: body
        for name, body in transformed["Resources"].items()
        if body["Type"] == resource_type
    }


def statements_for(transformed, function_logical_id):
    """Every IAM statement attached to one function's role."""
    functions = resources_of(transformed, "AWS::Lambda::Function")
    role_ref = functions[function_logical_id]["Properties"]["Role"]
    role_name = role_ref["Fn::GetAtt"][0]

    collected = []
    for policy in transformed["Resources"][role_name]["Properties"].get("Policies", []):
        collected.extend(policy["PolicyDocument"]["Statement"])
    return collected


def actions_of(statement):
    action = statement.get("Action", [])
    return action if isinstance(action, list) else [action]


# --- wiring -----------------------------------------------------------------


@pytest.mark.parametrize("logical_id", FUNCTION_LOGICAL_IDS)
def test_every_function_gets_the_shared_layer_and_table(transformed, logical_id):
    properties = resources_of(transformed, "AWS::Lambda::Function")[logical_id]["Properties"]
    assert properties.get("Layers"), f"{logical_id} is missing the irlib layer"
    variables = properties["Environment"]["Variables"]
    for name in ("INCIDENTS_TABLE", "PROTECTED_ROLE_NAMES", "PIPELINE_ROLE_PREFIX"):
        assert name in variables, f"{logical_id} is missing {name}"


def test_function_specific_variables_survive_the_globals_merge(transformed):
    functions = resources_of(transformed, "AWS::Lambda::Function")
    router = functions["RouterFunction"]["Properties"]["Environment"]["Variables"]
    alert = functions["AlertFunction"]["Properties"]["Environment"]["Variables"]
    assert "SFN_STATE_MACHINE_ARN" in router and "INCIDENTS_TABLE" in router
    assert "SNS_TOPIC_ARN" in alert and "INCIDENTS_TABLE" in alert


def test_only_the_expected_functions_exist(transformed):
    assert sorted(resources_of(transformed, "AWS::Lambda::Function")) == sorted(
        FUNCTION_LOGICAL_IDS
    )


# --- least privilege --------------------------------------------------------


def test_only_the_router_may_start_an_execution(transformed):
    """A Phase 1 requirement: nothing else in the stack can start the pipeline."""
    for logical_id in FUNCTION_LOGICAL_IDS:
        has_start = any(
            any(a.startswith("states:StartExecution") for a in actions_of(statement))
            for statement in statements_for(transformed, logical_id)
        )
        assert has_start == (logical_id == "RouterFunction"), (
            f"{logical_id} should {'' if logical_id == 'RouterFunction' else 'not '}"
            "hold states:StartExecution"
        )


@pytest.mark.parametrize("logical_id", FUNCTION_LOGICAL_IDS)
def test_no_wildcard_actions(transformed, logical_id):
    for statement in statements_for(transformed, logical_id):
        for action in actions_of(statement):
            assert action != "*", f"{logical_id} grants Action: *"
            assert not action.endswith(":*"), f"{logical_id} grants {action}"


@pytest.mark.parametrize("logical_id", FUNCTION_LOGICAL_IDS)
def test_wildcard_resources_only_where_the_action_requires_it(transformed, logical_id):
    """EC2 Describe calls cannot be scoped to a resource; everything else must be."""
    allowed_on_star = {
        # EC2 and ELBv2 Describe actions do not support resource-level
        # permissions. Anything else on "*" is a mistake.
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeNetworkAcls",
        "autoscaling:DescribeAutoScalingInstances",
        "autoscaling:DescribeAutoScalingGroups",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
    }
    for statement in statements_for(transformed, logical_id):
        resource = statement.get("Resource")
        resources = resource if isinstance(resource, list) else [resource]
        if "*" not in resources:
            continue
        for action in actions_of(statement):
            assert action in allowed_on_star, (
                f"{logical_id} grants {action} on Resource '*' but that action "
                "supports resource-level permissions"
            )


def test_no_function_holds_managed_policies(transformed):
    """The old EnrichFunction used AmazonEC2ReadOnlyAccess, which is account-wide."""
    for logical_id in FUNCTION_LOGICAL_IDS:
        functions = resources_of(transformed, "AWS::Lambda::Function")
        role_name = functions[logical_id]["Properties"]["Role"]["Fn::GetAtt"][0]
        managed = transformed["Resources"][role_name]["Properties"].get("ManagedPolicyArns", [])
        # SAM always attaches the basic execution role for CloudWatch Logs.
        extra = [
            arn
            for arn in managed
            if "AWSLambdaBasicExecutionRole" not in str(arn)
        ]
        assert not extra, f"{logical_id} carries managed policies: {extra}"


def test_credential_containment_is_not_yet_granted_anywhere(transformed):
    """iam:PutRolePolicy arrives in Phase 3, in one dedicated function only."""
    for logical_id in FUNCTION_LOGICAL_IDS:
        for statement in statements_for(transformed, logical_id):
            assert "iam:PutRolePolicy" not in actions_of(statement)


# --- durable state ----------------------------------------------------------


def test_incidents_table_is_encrypted_recoverable_and_retained(transformed):
    table = transformed["Resources"]["IncidentsTable"]
    properties = table["Properties"]
    assert properties["BillingMode"] == "PAY_PER_REQUEST"
    assert properties["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"] is True
    assert properties["SSESpecification"]["SSEEnabled"] is True
    # Losing the ledger would strand every contained instance.
    assert table.get("DeletionPolicy") == "Retain"
    assert table.get("UpdateReplacePolicy") == "Retain"


def test_the_state_machine_can_invoke_exactly_the_states_it_uses(transformed):
    machines = resources_of(transformed, "AWS::StepFunctions::StateMachine")
    assert len(machines) == 1
    role_name = list(machines.values())[0]["Properties"]["RoleArn"]["Fn::GetAtt"][0]

    invokable = set()
    for policy in transformed["Resources"][role_name]["Properties"]["Policies"]:
        for statement in policy["PolicyDocument"]["Statement"]:
            if "lambda:InvokeFunction" in actions_of(statement):
                invokable.add(str(statement["Resource"]))

    # Router is deliberately absent: the state machine must not be able to
    # re-enter the pipeline.
    assert len(invokable) == 6
    assert not any("RouterFunction" in entry for entry in invokable)


def test_eventbridge_can_only_invoke_the_router_from_this_account(transformed):
    permissions = resources_of(transformed, "AWS::Lambda::Permission")
    assert len(permissions) == 1
    properties = list(permissions.values())[0]["Properties"]
    assert properties["Principal"] == "events.amazonaws.com"
    assert "SourceAccount" in properties, "confused-deputy guard is missing"
    assert "SourceArn" in properties


# --- Phase 2 resources ------------------------------------------------------


def test_evidence_bucket_is_locked_encrypted_private_and_retained(transformed):
    bucket = transformed["Resources"]["EvidenceBucket"]
    properties = bucket["Properties"]
    assert properties["VersioningConfiguration"]["Status"] == "Enabled"
    assert properties["ObjectLockEnabled"] is True
    rule = properties["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]
    assert rule["Mode"] == "GOVERNANCE"
    assert properties["BucketEncryption"]
    for flag in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"):
        assert properties["PublicAccessBlockConfiguration"][flag] is True
    assert bucket.get("DeletionPolicy") == "Retain"
    assert bucket.get("UpdateReplacePolicy") == "Retain"


def test_evidence_bucket_refuses_plaintext_transport(transformed):
    policy = transformed["Resources"]["EvidenceBucketPolicy"]["Properties"]["PolicyDocument"]
    denies = [s for s in policy["Statement"] if s["Effect"] == "Deny"]
    assert any(
        s["Condition"]["Bool"]["aws:SecureTransport"] == "false" for s in denies
    ), "the bucket policy must deny non-TLS access"


def test_nothing_can_bypass_object_lock_governance(transformed):
    """Retention is only meaningful if the pipeline cannot lift it."""
    for logical_id in FUNCTION_LOGICAL_IDS:
        for statement in statements_for(transformed, logical_id):
            assert "s3:BypassGovernanceRetention" not in actions_of(statement)
            assert "s3:DeleteObject" not in actions_of(statement)


def test_only_the_evidence_function_can_write_evidence(transformed):
    for logical_id in FUNCTION_LOGICAL_IDS:
        writes = any(
            "s3:PutObject" in actions_of(statement)
            for statement in statements_for(transformed, logical_id)
        )
        assert writes == (logical_id == "EvidenceFunction")


def test_dns_firewall_rule_group_blocks(transformed):
    rules = transformed["Resources"]["QuarantineDnsRuleGroup"]["Properties"]["FirewallRules"]
    assert len(rules) == 1
    assert rules[0]["Action"] == "BLOCK"
    assert rules[0]["BlockResponse"] == "NXDOMAIN"


def test_the_seed_domain_can_never_resolve(transformed):
    """The resource requires a domain; it must not be one anyone could register."""
    domains = transformed["Resources"]["QuarantineDomainList"]["Properties"]["Domains"]
    assert all(d.endswith(".invalid") for d in domains), domains


def test_snapshot_tagging_is_scoped_to_creation(transformed):
    """ec2:CreateTags is a re-tagging primitive; keep it narrow."""
    for statement in statements_for(transformed, "NetIsolateFunction"):
        if "ec2:CreateTags" in actions_of(statement):
            assert statement["Condition"]["StringEquals"]["ec2:CreateAction"] == "CreateSecurityGroup"
