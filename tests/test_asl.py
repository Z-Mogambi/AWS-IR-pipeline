"""Structural checks on the state machine definitions.

These catch the mistakes that a unit test on a single Lambda cannot: a
transition to a state that does not exist, a substitution the template never
supplies, or - the one that matters most - a path from APPROVAL_REQUIRED
straight into containment.
"""

import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
ASL_DIR = ROOT / "statemachine"
ASL_FILES = sorted(ASL_DIR.glob("*.asl.json"))

CONTAINMENT_STATES = {"ContainInstance"}


def load(path):
    with path.open() as handle:
        return json.load(handle)


def transitions(state):
    targets = []
    for key in ("Next", "Default"):
        if state.get(key):
            targets.append(state[key])
    for choice in state.get("Choices", []):
        targets.append(choice["Next"])
    for catcher in state.get("Catch", []):
        targets.append(catcher["Next"])
    return targets


def reachable_from(states, start):
    seen, queue = set(), [start]
    while queue:
        name = queue.pop()
        if name in seen or name not in states:
            continue
        seen.add(name)
        queue.extend(transitions(states[name]))
    return seen


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_is_valid_json(path):
    assert load(path)["States"]


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_every_transition_target_exists(path):
    states = load(path)["States"]
    for name, state in states.items():
        for target in transitions(state):
            assert target in states, f"{name} transitions to unknown state {target}"


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_every_state_is_reachable(path):
    document = load(path)
    states = document["States"]
    unreachable = set(states) - reachable_from(states, document["StartAt"])
    assert not unreachable, f"unreachable states: {sorted(unreachable)}"


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_every_state_terminates_or_transitions(path):
    for name, state in load(path)["States"].items():
        terminal = state.get("End") or state["Type"] in ("Fail", "Succeed")
        assert terminal or transitions(state), f"{name} neither ends nor transitions"


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_substitutions_are_supplied_by_the_template(path):
    """Every ${Name} in the ASL must appear in DefinitionSubstitutions."""
    raw = path.read_text()
    used = set(re.findall(r"\$\{([A-Za-z0-9_]+)\}", raw))
    template = (ROOT / "template.yaml").read_text()
    supplied = set(re.findall(r"^\s{8}([A-Za-z0-9_]+):\s*!GetAtt", template, re.MULTILINE))
    missing = used - supplied
    assert not missing, f"{path.name} uses substitutions the template does not define: {missing}"


# --- the safety property ----------------------------------------------------


def test_approval_required_never_reaches_containment():
    """An APPROVAL_REQUIRED decision must not be able to contain anything.

    Until Phase 4 adds the callback, that branch only notifies. If a future
    edit wires it into containment without a human in between, this fails.
    """
    document = load(ASL_DIR / "incident-response.asl.json")
    states = document["States"]
    route = states["RouteDecision"]

    approval_branch = [
        choice["Next"]
        for choice in route["Choices"]
        if choice.get("StringEquals") == "APPROVAL_REQUIRED"
    ]
    assert approval_branch, "the decision router must have an APPROVAL_REQUIRED branch"

    for start in approval_branch:
        assert not (reachable_from(states, start) & CONTAINMENT_STATES), (
            f"APPROVAL_REQUIRED reaches containment via {start} with no human in between"
        )


def test_ignore_and_notify_never_reach_containment():
    document = load(ASL_DIR / "incident-response.asl.json")
    states = document["States"]
    route = states["RouteDecision"]

    non_containing = [
        choice["Next"]
        for choice in route["Choices"]
        if choice.get("StringEquals") in ("IGNORE", "NOTIFY")
    ] + [route["Default"]]

    for start in non_containing:
        assert not (reachable_from(states, start) & CONTAINMENT_STATES)


def test_auto_contain_is_the_only_route_into_containment():
    document = load(ASL_DIR / "incident-response.asl.json")
    route = document["States"]["RouteDecision"]
    auto = [c["Next"] for c in route["Choices"] if c.get("StringEquals") == "AUTO_CONTAIN"]
    assert auto == ["ContainInstance"]


def test_containment_failure_notifies_before_failing():
    """A partial containment must never end silently."""
    states = load(ASL_DIR / "incident-response.asl.json")["States"]
    catchers = states["ContainInstance"]["Catch"]
    assert catchers, "containment must catch its own failures"
    for catcher in catchers:
        target = states[catcher["Next"]]
        assert target["Type"] == "Task", "the catch target must send a notification"
        assert target["Parameters"]["notifyKind"] == "CONTAINMENT_FAILED"


def test_verification_failure_notifies_before_failing():
    states = load(ASL_DIR / "incident-response.asl.json")["States"]
    target = states[states["VerifyFinding"]["Catch"][0]["Next"]]
    assert target["Parameters"]["notifyKind"] == "VERIFY_FAILED"


def test_enrichment_failure_still_reaches_a_decision():
    """Enrichment is advisory; its failure must not stop the deterministic decision."""
    states = load(ASL_DIR / "incident-response.asl.json")["States"]
    fallback = states[states["EnrichInstance"]["Catch"][0]["Next"]]
    assert fallback["Type"] == "Pass"
    assert fallback["Result"]["environment"] == "production", "fall back to the stricter side"
    assert fallback["Next"] == "Decide"


def test_every_task_has_a_timeout():
    for path in ASL_FILES:
        for name, state in load(path)["States"].items():
            if state["Type"] == "Task":
                assert state.get("TimeoutSeconds"), f"{path.name}:{name} has no TimeoutSeconds"
