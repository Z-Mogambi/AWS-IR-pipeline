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

# At the top level, all containment happens inside this one Map state.
CONTAINMENT_STATES = {"ContainInstances"}

# The per-instance chain, which lives inside that Map's iterator.
CONTAINMENT_STEPS = ["CollectEvidence", "IsolateNetwork", "ContainCredentials",
                     "ContainIdentity", "DisableImds"]


def load(path):
    with path.open() as handle:
        return json.load(handle)


def machines(document):
    """Every state machine in a definition: the top level, plus each Map iterator.

    A Next inside an iterator refers to that iterator's states, so structural
    checks have to be scoped per machine rather than run over a flattened list.
    """
    found = [("top-level", document["StartAt"], document["States"])]
    queue = list(document["States"].items())
    while queue:
        name, state = queue.pop()
        for key in ("Iterator", "ItemProcessor"):
            nested = state.get(key)
            if not nested:
                continue
            found.append((name, nested["StartAt"], nested["States"]))
            queue.extend(nested["States"].items())
    return found


def iterator_of(document, map_state):
    return document["States"][map_state]["Iterator"]["States"]


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
    for label, _start, states in machines(load(path)):
        for name, state in states.items():
            for target in transitions(state):
                assert target in states, f"{label}:{name} transitions to unknown state {target}"


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_every_state_is_reachable(path):
    for label, start, states in machines(load(path)):
        unreachable = set(states) - reachable_from(states, start)
        assert not unreachable, f"{label}: unreachable states {sorted(unreachable)}"


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_every_state_terminates_or_transitions(path):
    for label, _start, states in machines(load(path)):
        for name, state in states.items():
            terminal = state.get("End") or state["Type"] in ("Fail", "Succeed")
            assert terminal or transitions(state), f"{label}:{name} neither ends nor transitions"


@pytest.mark.parametrize("path", ASL_FILES, ids=lambda p: p.name)
def test_substitutions_are_supplied_by_the_template(path):
    """Every ${Name} in the ASL must appear in DefinitionSubstitutions."""
    raw = path.read_text()
    used = set(re.findall(r"\$\{([A-Za-z0-9_]+)\}", raw))
    template = (ROOT / "template.yaml").read_text()
    # Substitutions are supplied with !GetAtt for ARNs and !Ref for plain values.
    supplied = set(
        re.findall(r"^\s{8}([A-Za-z0-9_]+):\s*!(?:GetAtt|Ref)\b", template, re.MULTILINE)
    )
    missing = used - supplied
    assert not missing, f"{path.name} uses substitutions the template does not define: {missing}"


# --- the safety property ----------------------------------------------------


def test_approval_required_reaches_containment_only_through_a_human():
    """Containment on that branch must be gated by the wait-for-token state."""
    states = load(ASL_DIR / "incident-response.asl.json")["States"]
    route = states["RouteDecision"]

    approval_branch = [
        choice["Next"]
        for choice in route["Choices"]
        if choice.get("StringEquals") == "APPROVAL_REQUIRED"
    ]
    assert approval_branch == ["AwaitApproval"]

    gate = states["AwaitApproval"]
    assert gate["Resource"].endswith(".waitForTaskToken"), (
        "the approval state must actually wait for a callback"
    )
    assert gate["Parameters"]["Payload"]["taskToken.$"] == "$$.Task.Token"

    # Remove the gate and containment must become unreachable from this branch.
    without_gate = {name: body for name, body in states.items() if name != "AwaitApproval"}
    assert not (reachable_from(without_gate, "AwaitApproval") & CONTAINMENT_STATES)


def test_an_unanswered_approval_does_not_contain_by_default():
    """Nobody answering is not consent."""
    states = load(ASL_DIR / "incident-response.asl.json")["States"]
    timeout = [
        catcher for catcher in states["AwaitApproval"]["Catch"]
        if "States.Timeout" in catcher["ErrorEquals"]
    ]
    assert timeout, "the approval state must catch its own timeout"

    branch = states[timeout[0]["Next"]]
    assert branch["Type"] == "Choice"
    # Containment is reachable only when the operator explicitly chose it.
    contain = [c for c in branch["Choices"] if c["Next"] in CONTAINMENT_STATES
               or c["Next"] == "BeginContainment"]
    assert all(c.get("StringEquals") == "Contain" for c in contain)
    assert branch["Default"] not in CONTAINMENT_STATES
    assert branch["Default"] != "BeginContainment"


def test_a_declined_approval_contains_nothing():
    states = load(ASL_DIR / "incident-response.asl.json")["States"]
    declined = [
        catcher for catcher in states["AwaitApproval"]["Catch"]
        if catcher["ErrorEquals"] == ["States.ALL"]
    ][0]
    assert not (reachable_from(states, declined["Next"]) & CONTAINMENT_STATES)


def test_release_requires_an_approval_before_restoring_anything():
    """Putting a compromised instance back on the network is never automatic."""
    document = load(ASL_DIR / "release.asl.json")
    states = document["States"]

    gate = states["AwaitReleaseApproval"]
    assert gate["Resource"].endswith(".waitForTaskToken")
    assert gate["Parameters"]["Payload"]["taskToken.$"] == "$$.Task.Token"

    without_gate = {n: b for n, b in states.items() if n != "AwaitReleaseApproval"}
    assert "RestoreIncident" not in reachable_from(without_gate, document["StartAt"])


def test_release_loads_before_it_restores():
    states = load(ASL_DIR / "release.asl.json")["States"]
    assert states["LoadIncident"]["Parameters"]["mode"] == "load"
    assert states["RestoreIncident"]["Parameters"]["mode"] == "restore"
    assert "RestoreIncident" in reachable_from(states, "LoadIncident")
    assert "LoadIncident" not in reachable_from(states, "RestoreIncident")


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
    assert auto == ["BeginContainment"]


def test_containment_failure_notifies_before_failing():
    """A partial containment must never end silently."""
    states = load(ASL_DIR / "incident-response.asl.json")["States"]
    for name in CONTAINMENT_STATES:
        catchers = states[name]["Catch"]
        assert catchers, f"{name} must catch its own failures"
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


def test_no_task_can_wait_forever():
    """A task with no timeout pins an execution open indefinitely.

    The approval states use TimeoutSecondsPath rather than a literal, because
    the value is a template parameter and ASL cannot interpolate one into a
    numeric field.
    """
    for path in ASL_FILES:
        for label, _start, states in machines(load(path)):
            for name, state in states.items():
                if state["Type"] != "Task":
                    continue
                assert state.get("TimeoutSeconds") or state.get("TimeoutSecondsPath"), (
                    f"{path.name}:{label}:{name} has no timeout"
                )


def test_containment_order_is_evidence_network_credentials_imds():
    """The order the whole design depends on.

    Evidence first: isolation cuts off the SSM agent, and an Auto Scaling group
    replaces an unreachable instance. IMDS last: disabling it also cuts off the
    agent, so nothing can be run on the instance remotely afterwards.
    """
    states = iterator_of(load(ASL_DIR / "incident-response.asl.json"), "ContainInstances")
    order = ["CollectEvidence", "IsolateNetwork", "ContainCredentials", "DisableImds"]
    for earlier, later in zip(order, order[1:]):
        assert later in reachable_from(states, earlier), f"{later} must be able to follow {earlier}"
        assert earlier not in reachable_from(states, later), f"{earlier} must not follow {later}"


def test_disabling_imds_is_the_last_containment_step():
    """It cuts off the SSM agent, so nothing may need the instance after it."""
    states = iterator_of(load(ASL_DIR / "incident-response.asl.json"), "ContainInstances")
    after = reachable_from(states, "DisableImds") - {"DisableImds"}
    assert not (after & set(CONTAINMENT_STEPS)), (
        f"containment continues after IMDS is disabled: {sorted(after & set(CONTAINMENT_STEPS))}"
    )


def test_only_one_state_reaches_the_credential_containment_function():
    """iam:PutRolePolicy is reachable from exactly one place in the machine."""
    document = load(ASL_DIR / "incident-response.asl.json")
    callers = [
        f"{label}:{name}"
        for label, _start, states in machines(document)
        for name, body in states.items()
        if body.get("Resource") == "${CredContainFunctionArn}"
    ]
    assert callers == ["ContainInstances:ContainCredentials"]


def test_containment_steps_are_individually_skippable():
    """Each step is gated on its own flag from the decision."""
    states = iterator_of(load(ASL_DIR / "incident-response.asl.json"), "ContainInstances")
    for gate, action_flag, step in (
        ("ShouldCollectEvidence", "$.decision.doEvidence", "CollectEvidence"),
        ("ShouldIsolateNetwork", "$.decision.doNetwork", "IsolateNetwork"),
        ("ShouldContainCredentials", "$.decision.doCredentials", "ContainCredentials"),
        ("ShouldDisableImds", "$.decision.doImds", "DisableImds"),
    ):
        choice = states[gate]["Choices"][0]
        assert choice["Variable"] == action_flag
        assert choice["BooleanEquals"] is True
        assert choice["Next"] == step


# --- Phase 5: attack sequences ----------------------------------------------


def test_containment_iterates_over_every_enriched_instance():
    """An attack sequence names a group of instances, not one."""
    states = load(ASL_DIR / "incident-response.asl.json")["States"]
    contain = states["ContainInstances"]
    assert contain["Type"] == "Map"
    assert contain["ItemsPath"] == "$.enrichment.instances"


def test_map_concurrency_is_bounded():
    """Unbounded fan-out across an Auto Scaling group would hit EC2 rate limits."""
    contain = load(ASL_DIR / "incident-response.asl.json")["States"]["ContainInstances"]
    assert contain.get("MaxConcurrency") or contain.get("MaxConcurrencyPath"), (
        "the containment Map must bound its concurrency"
    )


def test_each_iteration_sees_only_its_own_instance():
    """Otherwise a step could act on a sibling instance of the same sequence."""
    contain = load(ASL_DIR / "incident-response.asl.json")["States"]["ContainInstances"]
    enrichment = contain["Parameters"]["enrichment"]
    assert enrichment["instance.$"] == "$$.Map.Item.Value"
    assert "instances.$" not in enrichment


def test_a_single_instance_finding_still_works_through_the_map():
    """The Map is the only containment path, so one instance means one iteration."""
    states = load(ASL_DIR / "incident-response.asl.json")["States"]
    assert states["BeginContainment"]["Next"] == "ContainInstances"
    iterator = iterator_of(load(ASL_DIR / "incident-response.asl.json"), "ContainInstances")
    assert iterator["ShouldCollectEvidence"]["Type"] == "Choice"


def test_one_failed_instance_does_not_end_silently():
    """The Map catches so a partial containment still notifies."""
    contain = load(ASL_DIR / "incident-response.asl.json")["States"]["ContainInstances"]
    assert contain["Catch"][0]["Next"] == "NotifyContainmentFailed"
