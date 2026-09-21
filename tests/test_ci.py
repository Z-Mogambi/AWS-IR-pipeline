"""The workflows and the deploy role.

CI configuration is part of the security boundary here: a workflow with the
wrong trigger, or a role whose trust policy uses a wildcard, hands an attacker
the credentials that can deploy this pipeline.
"""

import json
import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml")
from samtranslator.yaml_helper import yaml_parse  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
OIDC_TEMPLATE = ROOT / "infra" / "github-oidc-role.yaml"

SHA_PIN = re.compile(r"^[0-9a-f]{40}$")


def load_workflow(path):
    document = yaml.safe_load(path.read_text())
    # "on" is parsed as the boolean True under YAML 1.1.
    document["on"] = document.get("on") or document.get(True)
    return document


@pytest.fixture(scope="module")
def oidc():
    return yaml_parse(OIDC_TEMPLATE.read_text())


def test_there_are_workflows_to_check():
    assert WORKFLOWS, "no workflows found"


# --- triggers ---------------------------------------------------------------


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_pull_request_target_is_never_used(path):
    """It runs with the base repo's secrets while checking out the fork's code.

    That turns any pull request into arbitrary code execution holding this
    repository's credentials.

    Checks the parsed triggers rather than the raw text, so a comment
    explaining why it is avoided does not trip the assertion.
    """
    assert "pull_request_target" not in load_workflow(path)["on"]


def test_ci_runs_on_pull_requests():
    assert "pull_request" in load_workflow(ROOT / ".github/workflows/ci.yml")["on"]


def test_deploy_only_runs_from_main_or_by_hand():
    triggers = load_workflow(ROOT / ".github/workflows/deploy.yml")["on"]
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"]["branches"] == ["main"]


# --- permissions ------------------------------------------------------------


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_permissions_are_declared_explicitly(path):
    """Without a permissions block the token gets the repository default,
    which in many repositories is write."""
    assert "permissions" in load_workflow(path), f"{path.name} declares no permissions"


def test_ci_is_read_only():
    assert load_workflow(ROOT / ".github/workflows/ci.yml")["permissions"] == {
        "contents": "read"
    }


def test_deploy_requests_only_the_oidc_token():
    permissions = load_workflow(ROOT / ".github/workflows/deploy.yml")["permissions"]
    assert permissions == {"id-token": "write", "contents": "read"}


def test_ci_uses_no_secrets():
    """It needs none, so it should not be able to read any."""
    assert "secrets." not in (ROOT / ".github/workflows/ci.yml").read_text()


def test_deploy_uses_oidc_not_stored_keys():
    text = (ROOT / ".github/workflows/deploy.yml").read_text()
    assert "role-to-assume" in text
    for forbidden in ("aws-access-key-id", "aws-secret-access-key", "AWS_SECRET_ACCESS_KEY"):
        assert forbidden not in text, f"{forbidden} means long-lived credentials"


# --- action pinning ---------------------------------------------------------


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit_sha(path):
    """A tag is mutable; whoever controls the action repository can move it."""
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped.startswith("uses:"):
            continue
        reference = stripped.split("uses:", 1)[1].strip()
        _action, _, version = reference.partition("@")
        assert SHA_PIN.match(version), (
            f"{path.name}: {reference} is not pinned to a 40-character commit SHA"
        )


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_pinned_action_says_which_version_it_is(path):
    """A bare SHA is unreadable; the comment above it names the release."""
    lines = path.read_text().splitlines()
    for index, line in enumerate(lines):
        if not line.strip().startswith("uses:"):
            continue
        previous = lines[index - 1].strip()
        assert previous.startswith("#"), (
            f"{path.name} line {index + 1}: no comment naming the pinned version"
        )


def test_no_placeholder_pins_remain():
    for path in WORKFLOWS:
        assert "TODO: pin to SHA" not in path.read_text()


# --- the deploy role --------------------------------------------------------


def trust_statement(oidc):
    role = oidc["Resources"]["GitHubDeployRole"]["Properties"]
    return role["AssumeRolePolicyDocument"]["Statement"][0]


def test_the_trust_policy_matches_one_exact_subject(oidc):
    """StringLike with a wildcard would let any branch, tag or pull request
    in the repository assume the role."""
    condition = trust_statement(oidc)["Condition"]
    assert "StringLike" not in condition, "a wildcard subject defeats the pinning"
    assert "StringEquals" in condition

    subject = condition["StringEquals"]["token.actions.githubusercontent.com:sub"]
    rendered = json.dumps(subject)
    assert "ref:refs/heads/" in rendered, "the subject must be pinned to a branch ref"
    assert "*" not in rendered


def test_the_audience_is_checked(oidc):
    """Without an aud condition, a token minted for another audience works."""
    condition = trust_statement(oidc)["Condition"]["StringEquals"]
    assert condition["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"


def test_the_org_and_repo_are_parameters(oidc):
    assert "GitHubOrg" in oidc["Parameters"]
    assert "GitHubRepo" in oidc["Parameters"]
    assert oidc["Parameters"]["GitHubBranch"]["Default"] == "main"


def deploy_statements(oidc):
    role = oidc["Resources"]["GitHubDeployRole"]["Properties"]
    return role["Policies"][0]["PolicyDocument"]["Statement"]


def test_the_deploy_role_cannot_delete_the_stack(oidc):
    """Tearing the pipeline down is a deliberate act, not something a push does."""
    for statement in deploy_statements(oidc):
        if statement["Effect"] != "Allow":
            continue
        assert "cloudformation:DeleteStack" not in statement.get("Action", [])


def test_the_deploy_role_cannot_delete_the_evidence_bucket(oidc):
    for statement in deploy_statements(oidc):
        if statement["Effect"] != "Allow":
            continue
        assert "s3:DeleteBucket" not in statement.get("Action", [])


def test_the_deploy_role_cannot_rewrite_itself(oidc):
    """Otherwise it could grant itself anything and the scoping is theatre."""
    denies = [s for s in deploy_statements(oidc) if s["Effect"] == "Deny"]
    assert denies, "the deploy role must deny modifying its own role"
    assert "github-deploy" in json.dumps(denies[0]["Resource"])


def test_iam_permissions_are_scoped_to_the_stacks_own_roles(oidc):
    iam_statements = [
        statement for statement in deploy_statements(oidc)
        if statement["Effect"] == "Allow"
        and any(a.startswith("iam:") for a in statement.get("Action", []))
    ]
    assert iam_statements
    for statement in iam_statements:
        rendered = json.dumps(statement["Resource"])
        assert "PipelineStackName" in rendered, (
            "IAM permissions must be scoped to roles belonging to this stack"
        )


def test_a_permissions_boundary_can_be_required(oidc):
    """A role that can create IAM roles is administrator-equivalent without one."""
    assert "PermissionsBoundaryArn" in oidc["Parameters"]
    rendered = json.dumps(deploy_statements(oidc))
    assert "iam:PermissionsBoundary" in rendered


def test_cloudformation_access_is_scoped_to_one_stack(oidc):
    statement = [
        s for s in deploy_statements(oidc)
        if s.get("Sid") == "ManageOnlyThisStack"
    ][0]
    assert "PipelineStackName" in json.dumps(statement["Resource"])
