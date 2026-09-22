"""Keep the documentation honest.

Documentation rots differently from code: it does not fail, it just quietly
stops being true. These check the specific claims most likely to drift, and the
specific claims this project previously got wrong.
"""

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
TESTING = ROOT / "docs" / "TESTING.md"
MULTI_ACCOUNT = ROOT / "docs" / "multi-account.md"
PROGRESS = ROOT / "docs" / "UPGRADE_PROGRESS.md"
SCP = ROOT / "docs" / "scp-protect-environment-tag.json"


@pytest.fixture(scope="module")
def readme():
    return README.read_text()


@pytest.mark.parametrize("path", [README, TESTING, MULTI_ACCOUNT, PROGRESS, SCP],
                         ids=lambda p: p.name)
def test_the_document_exists_and_is_not_a_stub(path):
    assert path.exists(), f"{path.name} is missing"
    assert len(path.read_text()) > 500, f"{path.name} looks like a stub"


# --- claims this project previously got wrong -------------------------------


def test_the_readme_no_longer_describes_functions_that_do_not_exist(readme):
    """The previous README named a 'Remediation Lambda' and correlation IDs."""
    assert "Remediation Lambda" not in readme
    assert "Correlation ID" not in readme and "correlation ID" not in readme


def test_the_readme_quotes_no_unmeasured_performance_numbers(readme):
    """The previous one claimed 'MTTR 1+ hours -> <45 seconds' and '99%+'.

    Nothing has been measured in a real account, so no figure belongs here yet.
    docs/TESTING.md is the procedure for producing one.
    """
    for claim in ("<45 second", "45 seconds", "98%", "99%", "1+ hours"):
        assert claim not in readme, f"unmeasured performance claim: {claim!r}"
    assert re.search(r"no benchmark numbers", readme, re.I), (
        "the README should say why there are no numbers yet"
    )


def test_every_function_directory_is_listed_in_the_readme(readme):
    for path in sorted((ROOT / "src").iterdir()):
        # Skip build artefacts like .aws-sam, which are not source.
        if path.is_dir() and not path.name.startswith("."):
            assert path.name in readme, f"src/{path.name}/ is not mentioned in the README"


def test_the_readme_does_not_name_a_function_that_was_removed(readme):
    """src/isolate was replaced in Phase 2."""
    assert not re.search(r"\bsrc/isolate\b", readme)


# --- claims that must match the code ----------------------------------------


def test_every_policy_rule_appears_in_the_readme_table(readme):
    policy = json.loads(
        (ROOT / "layers/common/python/irlib/response-policy.json").read_text()
    )
    for rule in policy["rules"]:
        assert rule["id"] in readme, f"rule {rule['id']} is not documented"


def test_the_readme_states_the_containment_order(readme):
    order = readme[readme.index("## Containment order"):]
    positions = [order.index(step) for step in
                 ("**Evidence**", "**Network**", "**Credentials**", "**IMDS**")]
    assert positions == sorted(positions), "the documented order is out of sequence"


def test_the_readme_documents_every_template_parameter(readme):
    template = (ROOT / "template.yaml").read_text()
    section = template[template.index("Parameters:"):template.index("Conditions:")]
    parameters = re.findall(r"^  ([A-Z][A-Za-z0-9]+):$", section, re.MULTILINE)
    assert parameters, "no parameters found; the parse is wrong"

    documented = readme + TESTING.read_text()
    undocumented = [p for p in parameters if p not in documented]
    assert not undocumented, f"parameters mentioned nowhere in the docs: {undocumented}"


# --- the prerequisites the template deliberately does not create ------------


def test_the_template_still_does_not_touch_the_detector():
    """Out of scope by design, and the README promises it."""
    template = (ROOT / "template.yaml").read_text()
    for forbidden in ("AWS::GuardDuty::Detector", "AWS::GuardDuty::Filter",
                      "AWS::Inspector", "AWS::GuardDuty::Master"):
        assert forbidden not in template, f"{forbidden} is out of scope"


def test_the_prerequisites_are_documented(readme):
    for prerequisite in ("Runtime Monitoring", "AI Protection", "AI_ANALYST",
                         "Inspector", "SNS subscription"):
        assert prerequisite in readme, f"{prerequisite} is not listed as a prerequisite"


def test_the_known_limitations_are_documented(readme):
    limitations = readme[readme.index("## Known limitations"):]
    for limitation in ("DNS Firewall is VPC-wide", "NACL", "SSM agent",
                       "exposure window", "Memory capture"):
        assert limitation.lower() in limitations.lower(), (
            f"limitation not documented: {limitation}"
        )


def test_the_threat_model_covers_what_the_brief_asked_for(readme):
    threat_model = readme[readme.index("## Threat model"):readme.index("## Prerequisites")]
    for topic in ("pipeline as a target", "Tag spoofing", "Approval spoofing",
                  "Prompt injection", "own permissions"):
        assert topic.lower() in threat_model.lower(), f"threat model omits: {topic}"


# --- the testing procedure --------------------------------------------------


def test_the_stratus_technique_id_is_the_verified_one():
    """Verified against stratus-red-team.cloud, not guessed."""
    assert "aws.credential-access.ec2-steal-instance-credentials" in TESTING.read_text()


def test_the_guardduty_tester_is_attributed_to_the_right_org():
    """It is awslabs, not aws-samples."""
    text = TESTING.read_text()
    assert "awslabs/amazon-guardduty-tester" in text
    assert "aws-samples/amazon-guardduty-tester" not in text


def test_the_testing_doc_covers_the_three_required_procedures():
    text = TESTING.read_text().lower()
    assert "stratus" in text
    assert "sample" in text and "create-sample-findings" in TESTING.read_text()
    assert "reverse shell" in text


def test_the_reverse_shell_test_explains_what_proves_it_worked():
    """The point is the shell dying on seal, not on attach."""
    text = TESTING.read_text()
    assert "quarantine-sg-seal" in text
    assert "negative control" in text.lower(), (
        "the procedure should include the control that shows the mechanism matters"
    )


def test_the_testing_doc_warns_about_sandbox_and_cost():
    text = TESTING.read_text()
    assert "sandbox" in text.lower()
    assert "## Cost" in text
    assert "Object Lock" in text, "retention prevents deleting the evidence bucket"


# --- multi-account is design only -------------------------------------------


def test_multi_account_is_marked_as_unimplemented():
    text = MULTI_ACCOUNT.read_text()
    assert "Design only" in text or "design only" in text
    assert "not implemented" in text.lower()


def test_multi_account_is_actually_not_implemented():
    """The document must not describe something the template quietly does."""
    template = (ROOT / "template.yaml").read_text()
    assert "IRResponder" not in template
    assert "sts:AssumeRole" not in template
    assert not (ROOT / "layers/common/python/irlib/crossaccount.py").exists()


def test_multi_account_covers_the_design_the_brief_asked_for():
    text = MULTI_ACCOUNT.read_text().lower()
    for topic in ("delegated administrator", "security account", "cross-account"):
        assert topic in text, f"multi-account design omits: {topic}"


# --- internal links ---------------------------------------------------------


def test_relative_links_in_the_readme_resolve(readme):
    for target in re.findall(r"\]\((?!https?:)([^)#]+)\)", readme):
        candidates = [ROOT / target, ROOT / "docs" / target]
        assert any(path.exists() for path in candidates), (
            f"README links to {target}, which does not exist"
        )


def test_relative_links_in_the_docs_resolve():
    for document in (TESTING, MULTI_ACCOUNT):
        for target in re.findall(r"\]\((?!https?:)([^)#]+)\)", document.read_text()):
            candidates = [document.parent / target, ROOT / target]
            assert any(path.exists() for path in candidates), (
                f"{document.name} links to {target}, which does not exist"
            )
