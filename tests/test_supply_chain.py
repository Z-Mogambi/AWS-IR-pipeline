"""The runtime must import nothing that is not already in the Lambda runtime.

Every third-party package in a function bundle is code that runs with that
function's IAM permissions. This pipeline holds iam:PutRolePolicy in one
function and can isolate production instances from another, so the dependency
list is part of the security boundary rather than a packaging detail.

The rule: standard library, plus the boto3 and botocore AWS already ships in
the runtime, plus the shared layer. Nothing else.
"""

import ast
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

RUNTIME_FILES = sorted(
    list((ROOT / "src").rglob("*.py")) + list((ROOT / "layers").rglob("*.py"))
)

# Present in the Lambda Python runtime without being bundled.
PROVIDED_BY_RUNTIME = {"boto3", "botocore"}

# The shared layer, mounted at /opt/python.
PROVIDED_BY_LAYER = {"irlib"}

ALLOWED = set(sys.stdlib_module_names) | PROVIDED_BY_RUNTIME | PROVIDED_BY_LAYER


def top_level_imports(path):
    tree = ast.parse(path.read_text(), filename=str(path))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # a relative import inside the layer
                continue
            if node.module:
                found.add(node.module.split(".")[0])
    return found


def test_there_are_runtime_files_to_check():
    assert RUNTIME_FILES, "no runtime source found; the glob is wrong"


@pytest.mark.parametrize("path", RUNTIME_FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_third_party_imports(path):
    unexpected = top_level_imports(path) - ALLOWED
    assert not unexpected, (
        f"{path.relative_to(ROOT)} imports {sorted(unexpected)}, which is not in the "
        "standard library, the Lambda runtime, or the shared layer"
    )


def test_no_function_ships_a_requirements_file():
    """A per-function requirements.txt makes SAM vendor a second copy of boto3."""
    stray = list((ROOT / "src").rglob("requirements.txt"))
    assert not stray, f"remove these: {[str(p.relative_to(ROOT)) for p in stray]}"


def test_the_layer_ships_no_dependencies_either():
    assert not list((ROOT / "layers").rglob("requirements.txt"))


# --- the dev pins -----------------------------------------------------------


DEV_REQUIREMENTS = ROOT / "requirements-dev.txt"


def dev_entries():
    """Parse requirements-dev.txt into {name: (version, [hashes])}."""
    text = DEV_REQUIREMENTS.read_text().replace("\\\n", " ")
    entries = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        name, _, version = parts[0].partition("==")
        hashes = [p.removeprefix("--hash=") for p in parts[1:] if p.startswith("--hash=")]
        entries[name] = (version, hashes)
    return entries


def test_dev_requirements_exist():
    assert DEV_REQUIREMENTS.exists()


def test_every_dev_dependency_is_pinned_to_an_exact_version():
    for name, (version, _hashes) in dev_entries().items():
        assert version, f"{name} is not pinned to an exact version"


def test_every_dev_dependency_carries_hashes():
    """pip --require-hashes refuses the whole file if one entry lacks them."""
    for name, (_version, hashes) in dev_entries().items():
        assert hashes, f"{name} has no --hash entries"
        for digest in hashes:
            assert digest.startswith("sha256:"), f"{name} has a non-sha256 hash: {digest}"


def test_the_dev_pins_cover_what_the_tests_import():
    entries = dev_entries()
    for required in ("pytest", "aws-sam-translator", "pyyaml", "boto3"):
        assert required in entries, f"{required} is used by the suite but not pinned"


def test_dev_requirements_are_not_installed_into_a_function():
    """They exist for the test runner, never for a bundle."""
    for path in (ROOT / "src").rglob("*"):
        assert path.name != "requirements-dev.txt"
