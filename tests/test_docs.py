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


@pytest.fixture(scope="module")
def readme():
    return README.read_text()


def test_the_readme_exists_and_is_not_a_stub():
    assert README.exists()
    assert len(README.read_text()) > 500, "the README looks like a stub"


# --- claims this project previously got wrong -------------------------------


def test_the_readme_no_longer_describes_functions_that_do_not_exist(readme):
    """The previous README named a 'Remediation Lambda' and correlation IDs."""
    assert "Remediation Lambda" not in readme
    assert "Correlation ID" not in readme and "correlation ID" not in readme


def test_the_readme_quotes_no_unmeasured_performance_numbers(readme):
    """The previous one claimed 'MTTR 1+ hours -> <45 seconds' and '99%+'.

    Nothing has been measured in a real account, so no figure belongs here yet.
    Nothing has been measured in a real account, so no figure belongs here.
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

    undocumented = [p for p in parameters if p not in readme]
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
                       "exposure window", "Memory capture", "Single account"):
        assert limitation.lower() in limitations.lower(), (
            f"limitation not documented: {limitation}"
        )


def test_the_threat_model_covers_what_the_brief_asked_for(readme):
    threat_model = readme[readme.index("## Threat model"):readme.index("## Prerequisites")]
    for topic in ("pipeline as a target", "Tag spoofing", "Approval spoofing",
                  "Prompt injection", "own permissions"):
        assert topic.lower() in threat_model.lower(), f"threat model omits: {topic}"


# --- internal links ---------------------------------------------------------


def test_relative_links_in_the_readme_resolve(readme):
    for target in re.findall(r"\]\((?!https?:)([^)#]+)\)", readme):
        candidates = [ROOT / target, ROOT / "docs" / target]
        assert any(path.exists() for path in candidates), (
            f"README links to {target}, which does not exist"
        )


def test_the_readme_never_links_to_something_not_in_the_repository():
    """Nothing under docs/ is committed - it is all local working notes.

    A link to one of them would be dead for anyone who clones the repository,
    so every relative link must resolve against tracked files only.
    """
    import subprocess

    tracked = set(
        subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                       text=True, check=True).stdout.split()
    )
    for target in re.findall(r"\]\((?!https?:)([^)#]+)\)", README.read_text()):
        candidates = {target, f"docs/{target}"}
        assert candidates & tracked, (
            f"the README links to {target}, which is not a tracked file"
        )
