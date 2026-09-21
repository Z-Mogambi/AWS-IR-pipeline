"""Assertions against the template after the SAM transform.

`sam validate` only checks that the template is well formed. These run the real
SAM transform so the IAM and wiring claims are checked against the
CloudFormation that would actually be deployed - which is where the Phase 1
least-privilege requirements live.

Nothing here contacts AWS: the transform is a pure function and the S3 URIs
`sam package` would fill in are stubbed.
"""

import json
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
    "CredContainFunction",
    "IdentityFunction",
    "ImdsFunction",
    "ReleaseFunction",
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


def test_only_one_function_can_write_an_inline_policy(transformed):
    """iam:PutRolePolicy lives in exactly one small, single-purpose function."""
    holders = [
        logical_id
        for logical_id in FUNCTION_LOGICAL_IDS
        if any(
            statement["Effect"] == "Allow" and "iam:PutRolePolicy" in actions_of(statement)
            for statement in statements_for(transformed, logical_id)
        )
    ]
    assert holders == ["CredContainFunction"]


def test_the_pipeline_cannot_rewrite_its_own_roles(transformed):
    """Defence in depth behind irlib.guard, at the IAM layer.

    If the code-level protected-principal check were ever bypassed, IAM still
    refuses PutRolePolicy against the stack's own roles and service-linked roles.
    """
    denies = [
        statement
        for statement in statements_for(transformed, "CredContainFunction")
        if statement["Effect"] == "Deny" and "iam:PutRolePolicy" in actions_of(statement)
    ]
    assert denies, "the credential function must deny writing to the pipeline's own roles"
    guarded = json.dumps(denies)
    assert "aws-service-role" in guarded
    assert "AWS::StackName" in guarded or "${AWS::StackName}" in guarded


def test_only_the_state_machine_can_invoke_the_credential_function(transformed):
    """No resource policy widens access to it beyond the state machine's role."""
    permissions = resources_of(transformed, "AWS::Lambda::Permission")
    for body in permissions.values():
        target = json.dumps(body["Properties"]["FunctionName"])
        assert "CredContain" not in target, (
            "a resource policy on the credential function would let anything in the "
            "account invoke it"
        )


def test_identity_containment_cannot_touch_roles(transformed):
    """The identity function deactivates user keys; roles are the other function's job."""
    for statement in statements_for(transformed, "IdentityFunction"):
        if statement["Effect"] != "Allow":
            continue
        for action in actions_of(statement):
            assert action not in ("iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy")


def test_identity_function_is_scoped_to_users(transformed):
    for statement in statements_for(transformed, "IdentityFunction"):
        if "iam:UpdateAccessKey" in actions_of(statement):
            assert ":user/" in json.dumps(statement["Resource"])


def test_the_three_finding_rules_cover_the_three_shapes(transformed):
    """Instance findings, AccessKey findings, and attack sequences.

    They are deliberately non-overlapping: credential exfiltration and AI
    Protection carry resourceType AccessKey, and attack sequences carry no
    top-level resourceType at all, so each needs its own pattern.
    """
    rules = resources_of(transformed, "AWS::Events::Rule")
    assert len(rules) == 3

    resource_types, type_prefixes = set(), set()
    for body in rules.values():
        detail = body["Properties"]["EventPattern"]["detail"]
        if "resource" in detail:
            resource_types.update(detail["resource"]["resourceType"])
        for matcher in detail.get("type", []):
            type_prefixes.add(matcher["prefix"])

    assert resource_types == {"Instance", "AccessKey"}
    assert type_prefixes == {"AttackSequence:"}


def test_attack_sequences_are_matched_on_the_type_prefix(transformed):
    rules = resources_of(transformed, "AWS::Events::Rule")
    sequence_rules = [
        body for body in rules.values()
        if "type" in body["Properties"]["EventPattern"]["detail"]
    ]
    assert len(sequence_rules) == 1
    detail = sequence_rules[0]["Properties"]["EventPattern"]["detail"]
    # It must not also filter on a resource type, or it would never match.
    assert "resource" not in detail


def test_every_eventbridge_rule_targets_only_the_router(transformed):
    rules = resources_of(transformed, "AWS::Events::Rule")
    for body in rules.values():
        for target in body["Properties"]["Targets"]:
            assert "RouterFunction" in json.dumps(target["Arn"])


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
    assert len(machines) == 2, "the response machine and the release machine"
    body = [m for name, m in machines.items() if "Release" not in name][0]
    role_name = body["Properties"]["RoleArn"]["Fn::GetAtt"][0]

    invokable = set()
    for policy in transformed["Resources"][role_name]["Properties"]["Policies"]:
        for statement in policy["PolicyDocument"]["Statement"]:
            if "lambda:InvokeFunction" in actions_of(statement):
                invokable.add(str(statement["Resource"]))

    # Router is deliberately absent: the state machine must not be able to
    # re-enter the pipeline.
    assert len(invokable) == 9
    assert not any("RouterFunction" in entry for entry in invokable)


def test_eventbridge_can_only_invoke_the_router_from_this_account(transformed):
    permissions = resources_of(transformed, "AWS::Lambda::Permission")
    rules = resources_of(transformed, "AWS::Events::Rule")
    assert len(permissions) == len(rules), "one permission per EventBridge rule"
    for body in permissions.values():
        properties = body["Properties"]
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


# --- Phase 4: approval and release ------------------------------------------


def test_release_can_remove_a_role_policy_but_never_write_one(transformed):
    """Release undoes the credential Deny; it must not be able to create one."""
    actions = set()
    for statement in statements_for(transformed, "ReleaseFunction"):
        if statement["Effect"] == "Allow":
            actions.update(actions_of(statement))
    assert "iam:DeleteRolePolicy" in actions
    assert "iam:PutRolePolicy" not in actions
    assert "iam:AttachRolePolicy" not in actions


def test_release_also_cannot_touch_the_pipelines_own_roles(transformed):
    denies = [
        statement
        for statement in statements_for(transformed, "ReleaseFunction")
        if statement["Effect"] == "Deny" and "iam:DeleteRolePolicy" in actions_of(statement)
    ]
    assert denies
    guarded = json.dumps(denies)
    assert "aws-service-role" in guarded and "StackName" in guarded


def test_release_cannot_create_security_groups(transformed):
    """It only ever deletes the per-incident group it is handed."""
    for statement in statements_for(transformed, "ReleaseFunction"):
        if statement["Effect"] != "Allow":
            continue
        assert "ec2:CreateSecurityGroup" not in actions_of(statement)
        assert "ec2:AuthorizeSecurityGroupIngress" not in actions_of(statement)


def test_the_release_machine_can_only_invoke_release_and_alert(transformed):
    machines = resources_of(transformed, "AWS::StepFunctions::StateMachine")
    body = [m for name, m in machines.items() if "Release" in name][0]
    role_name = body["Properties"]["RoleArn"]["Fn::GetAtt"][0]

    invokable = set()
    for policy in transformed["Resources"][role_name]["Properties"]["Policies"]:
        for statement in policy["PolicyDocument"]["Statement"]:
            if "lambda:InvokeFunction" in actions_of(statement):
                invokable.add(json.dumps(statement["Resource"]))
    assert len(invokable) == 2
    joined = " ".join(invokable)
    assert "ReleaseFunction" in joined and "AlertFunction" in joined
    # It must not be able to reach containment.
    for forbidden in ("CredContainFunction", "NetIsolateFunction", "EvidenceFunction"):
        assert forbidden not in joined


def test_nothing_in_the_stack_can_approve_its_own_requests(transformed):
    """The approval callback is only meaningful if the pipeline cannot call it."""
    for logical_id in FUNCTION_LOGICAL_IDS:
        for statement in statements_for(transformed, logical_id):
            for action in actions_of(statement):
                assert action not in ("states:SendTaskSuccess", "states:SendTaskFailure"), (
                    f"{logical_id} could approve its own containment requests"
                )


def test_the_timeout_action_cannot_be_set_to_something_unexpected(transformed):
    allowed = transformed["Parameters"]["ApprovalTimeoutAction"]["AllowedValues"]
    assert set(allowed) == {"Escalate", "Contain"}


def test_the_containment_cap_and_concurrency_reach_the_decide_function(transformed):
    variables = resources_of(transformed, "AWS::Lambda::Function")["DecideFunction"][
        "Properties"
    ]["Environment"]["Variables"]
    assert "MAX_AUTO_CONTAIN_INSTANCES" in variables
    assert "CONTAINMENT_CONCURRENCY" in variables
