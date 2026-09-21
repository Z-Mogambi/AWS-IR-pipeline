"""Validate the model's output, or discard it.

The model is advisory, so the only question here is whether its answer is
well-formed enough to show a responder. Anything that is not - wrong shape,
unknown tactic, confidence outside 0 to 1, prose wrapped around the JSON - is
discarded and the notification falls back to the deterministic view.

Discarding is cheap. The containment decision was made before the model ran, so
losing the triage costs a paragraph in an email and nothing else.
"""

import json
import logging
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REQUIRED_FIELDS = ("summary", "attack_stage", "blast_radius", "recommended_action",
                   "confidence", "rationale")

# The model may only recommend; it may not contain. These are labels a human
# reads, not instructions the pipeline follows.
RECOMMENDED_ACTIONS = ("ignore", "monitor", "contain", "escalate")

# MITRE ATT&CK enterprise tactics, which is also the vocabulary GuardDuty uses
# for its threat purposes.
ATTACK_TACTICS = (
    "reconnaissance", "resource development", "initial access", "execution",
    "persistence", "privilege escalation", "defense evasion", "credential access",
    "discovery", "lateral movement", "collection", "command and control",
    "exfiltration", "impact",
)

MAX_TEXT_FIELD = 2000

_FENCE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def handler(event, context):
    raw = event.get("triageRaw")
    try:
        parsed = parse(raw)
        validated = validate(parsed)
    except ValueError as exc:
        logger.warning(f"Discarding model output: {exc}")
        return unavailable(f"the model's reply was not usable: {exc}")

    logger.info(
        f"Triage accepted: {validated['recommended_action']} "
        f"(confidence {validated['confidence']})"
    )
    return {"available": True, "advisory": True, **validated}


def unavailable(reason):
    """The shape the notification renders when there is no usable triage."""
    return {"available": False, "advisory": True, "reason": reason}


def parse(raw):
    """Pull the JSON object out of a Bedrock InvokeModel response."""
    if raw is None:
        raise ValueError("no model response")

    body = raw
    # The optimised Step Functions integration nests the model body; a direct
    # SDK call does not. Accept either.
    if isinstance(body, dict) and "Body" in body:
        body = body["Body"]
    if isinstance(body, str):
        body = json.loads(body)

    if isinstance(body, dict) and "content" in body:
        blocks = body.get("content") or []
        text = "".join(
            block.get("text", "") for block in blocks if block.get("type", "text") == "text"
        )
    elif isinstance(body, str):
        text = body
    else:
        raise ValueError("unrecognised response shape")

    if not text.strip():
        raise ValueError("the model returned no text")

    # The prompt asks for bare JSON, but a stray code fence should not lose an
    # otherwise good answer.
    cleaned = _FENCE.sub("", text).strip()
    try:
        return json.loads(cleaned)
    except ValueError as exc:
        raise ValueError(f"not valid JSON: {exc}") from exc


def validate(parsed):
    if not isinstance(parsed, dict):
        raise ValueError("the reply was not a JSON object")

    missing = [field for field in REQUIRED_FIELDS if field not in parsed]
    if missing:
        raise ValueError(f"missing fields: {missing}")

    extra = set(parsed) - set(REQUIRED_FIELDS)
    if extra:
        # Not fatal, but the contract is exact - drop anything unexpected
        # rather than render text nobody specified.
        logger.warning(f"Dropping unexpected fields from the model reply: {sorted(extra)}")

    action = str(parsed["recommended_action"]).strip().lower()
    if action not in RECOMMENDED_ACTIONS:
        raise ValueError(f"recommended_action {action!r} is not one of {RECOMMENDED_ACTIONS}")

    tactic = str(parsed["attack_stage"]).strip()
    if tactic.lower() not in ATTACK_TACTICS:
        raise ValueError(f"attack_stage {tactic!r} is not a MITRE ATT&CK tactic")

    try:
        confidence = float(parsed["confidence"])
    except (TypeError, ValueError) as exc:
        raise ValueError(f"confidence is not a number: {parsed['confidence']!r}") from exc
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"confidence {confidence} is outside 0 to 1")

    text_fields = {}
    for field in ("summary", "blast_radius", "rationale"):
        value = parsed[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")
        text_fields[field] = value.strip()[:MAX_TEXT_FIELD]

    return {
        "recommended_action": action,
        "attack_stage": tactic,
        "confidence": round(confidence, 3),
        **text_fields,
    }
