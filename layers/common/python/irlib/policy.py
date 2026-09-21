"""Evaluation of the versioned response policy.

The policy lives in response-policy.json beside this module. It is data, not
code, so it can be reviewed and diffed on its own; this module only decides
which rule matches first.

Validation is deliberately strict: an unrecognised key inside a rule's `match`
block raises instead of being ignored. A typo like "severtiyMin" would
otherwise silently drop a condition and widen containment.
"""

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger()

DEFAULT_POLICY_PATH = Path(__file__).with_name("response-policy.json")

DECISIONS = ("IGNORE", "NOTIFY", "APPROVAL_REQUIRED", "AUTO_CONTAIN")
ENVIRONMENTS = ("production", "non-production")
MATCH_KEYS = (
    "type",
    "typePrefix",
    "severityMin",
    "severityMax",
    "environment",
    "resourceType",
    "resourceRole",
)

_CACHE = {}


class PolicyError(Exception):
    """The policy file is malformed. Fail loudly rather than guess a decision."""


def load_policy(path=None):
    """Load and validate the policy, caching by resolved path."""
    resolved = Path(path or os.environ.get("RESPONSE_POLICY_PATH") or DEFAULT_POLICY_PATH)
    key = str(resolved)
    if key not in _CACHE:
        try:
            with resolved.open(encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError) as exc:
            raise PolicyError(f"Could not read response policy at {resolved}: {exc}") from exc
        _CACHE[key] = validate_policy(document)
    return _CACHE[key]


def validate_policy(document):
    """Check the structural invariants the evaluator relies on."""
    if not isinstance(document.get("version"), int):
        raise PolicyError("Policy needs an integer 'version'.")

    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PolicyError("Policy needs a non-empty 'rules' list.")

    known_actions = set(document.get("containmentActions", {}))
    seen_ids = set()

    for rule in rules:
        rule_id = rule.get("id")
        if not rule_id:
            raise PolicyError("Every rule needs an 'id'.")
        if rule_id in seen_ids:
            raise PolicyError(f"Duplicate rule id {rule_id!r}.")
        seen_ids.add(rule_id)
        _validate_outcome(rule, known_actions, rule_id)

        match = rule.get("match")
        if not isinstance(match, dict) or not match:
            raise PolicyError(f"Rule {rule_id!r} needs a non-empty 'match' block.")
        unknown = set(match) - set(MATCH_KEYS)
        if unknown:
            raise PolicyError(f"Rule {rule_id!r} has unknown match keys: {sorted(unknown)}")
        for key in ("environment",):
            for value in match.get(key, []):
                if value not in ENVIRONMENTS:
                    raise PolicyError(f"Rule {rule_id!r} matches unknown environment {value!r}.")

    fallback = document.get("fallback")
    if not isinstance(fallback, dict):
        raise PolicyError("Policy needs a 'fallback' outcome.")
    _validate_outcome(fallback, known_actions, "fallback")

    unknown_env = document.get("unknownEnvironment")
    if unknown_env not in ENVIRONMENTS:
        raise PolicyError(f"'unknownEnvironment' must be one of {ENVIRONMENTS}, got {unknown_env!r}.")

    return document


def _validate_outcome(outcome, known_actions, where):
    decision = outcome.get("decision")
    if decision not in DECISIONS:
        raise PolicyError(f"{where}: decision {decision!r} is not one of {DECISIONS}.")

    actions = outcome.get("actions", [])
    if not isinstance(actions, list):
        raise PolicyError(f"{where}: 'actions' must be a list.")
    unknown = set(actions) - known_actions
    if unknown:
        raise PolicyError(f"{where}: unknown containment actions {sorted(unknown)}.")
    if decision != "AUTO_CONTAIN" and decision != "APPROVAL_REQUIRED" and actions:
        raise PolicyError(f"{where}: decision {decision} must not carry containment actions.")


def severity_band(severity, policy=None):
    """Return the band name ('low'...'critical') for a numeric severity."""
    bands = (policy or load_policy())["severityBands"]
    for name, span in bands.items():
        if span["min"] <= severity <= span["max"]:
            return name
    return "unknown"


def evaluate(
    finding_type,
    severity,
    environment,
    resource_type=None,
    resource_role=None,
    policy=None,
):
    """Return the first matching outcome as a plain dict.

    This is pure: no AWS calls, no clock, no randomness. The same finding always
    produces the same decision, which is what makes the AI triage in Phase 6
    safe to bolt on afterwards.
    """
    policy = policy or load_policy()
    context = {
        "type": finding_type,
        "severity": float(severity),
        "environment": environment,
        "resourceType": resource_type,
        "resourceRole": resource_role,
    }

    for rule in policy["rules"]:
        if _matches(rule["match"], context):
            return _outcome(rule, policy, context)

    return _outcome(policy["fallback"], policy, context, rule_id="fallback")


def _matches(match, context):
    if "type" in match and context["type"] not in match["type"]:
        return False
    if "typePrefix" in match:
        finding_type = context["type"] or ""
        if not any(finding_type.startswith(prefix) for prefix in match["typePrefix"]):
            return False
    if "severityMin" in match and context["severity"] < match["severityMin"]:
        return False
    if "severityMax" in match and context["severity"] > match["severityMax"]:
        return False
    if "environment" in match and context["environment"] not in match["environment"]:
        return False
    if "resourceType" in match and context["resourceType"] not in match["resourceType"]:
        return False
    if "resourceRole" in match and context["resourceRole"] not in match["resourceRole"]:
        return False
    return True


def _outcome(rule, policy, context, rule_id=None):
    decision = rule["decision"]
    actions = list(rule.get("actions", [])) if decision in ("AUTO_CONTAIN", "APPROVAL_REQUIRED") else []
    return {
        "decision": decision,
        "actions": actions,
        # Step Functions Choice rules cannot test membership of an array, so the
        # action set is also published as flags the state machine can branch on.
        "doEvidence": "evidence" in actions,
        "doNetwork": "network" in actions,
        "doCredentials": "credentials" in actions,
        "doImds": "imds" in actions,
        "ruleId": rule_id or rule["id"],
        "ruleDescription": rule.get("description", ""),
        "policyVersion": policy["version"],
        "severityBand": severity_band(context["severity"], policy),
        "evaluated": {
            "type": context["type"],
            "severity": context["severity"],
            "environment": context["environment"],
            "resourceType": context["resourceType"],
            "resourceRole": context["resourceRole"],
        },
    }
