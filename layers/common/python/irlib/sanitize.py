"""Wrap attacker-influenced text before it reaches a model.

Almost everything interesting in a GuardDuty finding is written, directly or
indirectly, by the attacker: the finding title and description quote their
domains and process names, tag values are writable by anyone who can tag a
resource, and user agents, DNS names, command lines and CloudTrail request
parameters are all their input. Any of it can contain instructions aimed at
whatever reads the finding next.

Three defences here, in order of how much they are worth:

1. **A per-request nonce on the delimiters.** The block boundaries carry a
   random token the attacker cannot know, so text inside the block cannot
   forge a closing delimiter and start issuing instructions. Fixed delimiters
   like ``---`` or ``</data>`` can simply be typed by the attacker.
2. **Truncation.** Every field is capped, and the whole block is capped again.
   A very long field is a way to push the real instructions out of the model's
   attention, and it also just costs money.
3. **Control-character stripping.** Keeps the block readable and stops ANSI or
   newline tricks disturbing the structure.

None of this is sufficient on its own, which is why the model's output is
advisory only and the Bedrock guardrail runs over the same block.
"""

import json
import secrets
import unicodedata

DEFAULT_FIELD_CHARS = 2000
DEFAULT_BLOCK_CHARS = 12000
TRUNCATION_MARKER = " ...[truncated]"


def new_nonce():
    """A fresh delimiter token per request. Never reuse one across requests."""
    return secrets.token_hex(8)


def scrub(value, max_chars=DEFAULT_FIELD_CHARS):
    """Flatten one value to a bounded, single-line-safe string."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = json.dumps(value, default=str, sort_keys=True)

    cleaned = "".join(
        character
        for character in value
        # Keep newlines and tabs; drop every other control character.
        if character in "\n\t" or unicodedata.category(character)[0] != "C"
    )
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER
    return cleaned


def block(label, fields, nonce, max_chars=DEFAULT_BLOCK_CHARS, field_chars=DEFAULT_FIELD_CHARS):
    """Render a nonce-delimited untrusted block.

    `fields` is a mapping of name to value. Names are trusted (we choose them);
    values are not.
    """
    lines = []
    for name, value in fields.items():
        rendered = scrub(value, field_chars)
        if not rendered:
            continue
        lines.append(f"{name}: {rendered}")

    body = "\n".join(lines)
    if len(body) > max_chars:
        body = body[: max_chars - len(TRUNCATION_MARKER)] + TRUNCATION_MARKER

    return f"<{label} nonce={nonce}>\n{body}\n</{label} nonce={nonce}>"


def contains_nonce(text, nonce):
    """True if untrusted text tried to forge the delimiter.

    Effectively impossible for a random nonce, but if it ever happens the
    request should be treated as an attack rather than sent to the model.
    """
    return nonce in (text or "")
