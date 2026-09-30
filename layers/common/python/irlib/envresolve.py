"""Decide whether a resource is production.

Two sources, in priority order:

1. ACCOUNT_ENVIRONMENT_MAP - an operator-supplied "account=environment" list.
   Accounts are far harder for an attacker to change than tags, so the map wins.
2. The Environment tag on the instance.

A missing tag, an unreadable tag, or a value nobody recognises resolves to
production. That is the deliberate direction to fail in: treating a production
box as a dev box means skipping containment on the resource that matters most,
whereas the reverse only costs an approval prompt. An SCP denying changes to
the Environment tag key, except by one named role, stops the tag being a way to
influence this decision at all.
"""

import logging
import os

from . import policy as policy_module

logger = logging.getLogger()


def parse_account_map(raw):
    """Parse '111122223333=non-production,444455556666=production' into a dict."""
    mapping = {}
    for entry in (raw or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        account, _, environment = entry.partition("=")
        account = account.strip()
        environment = environment.strip().lower()
        if not account or environment not in policy_module.ENVIRONMENTS:
            logger.warning(f"Ignoring malformed ACCOUNT_ENVIRONMENT_MAP entry: {entry!r}")
            continue
        mapping[account] = environment
    return mapping


def resolve(account_id=None, tags=None, policy=None, account_map_raw=None):
    """Return (environment, source) where source explains which rule applied."""
    policy = policy or policy_module.load_policy()

    raw_map = account_map_raw if account_map_raw is not None else os.environ.get("ACCOUNT_ENVIRONMENT_MAP", "")
    account_map = parse_account_map(raw_map)
    if account_id and account_id in account_map:
        return account_map[account_id], "account-map"

    tag_key = policy.get("environmentTagKey", "Environment")
    value = _tag_value(tags, tag_key)
    if value is None:
        return policy["unknownEnvironment"], "default-missing-tag"

    normalised = value.strip().lower()
    for environment, accepted in policy["environmentTagValues"].items():
        if normalised in accepted:
            return environment, "tag"

    logger.warning(
        f"Unrecognised {tag_key} tag value {value!r}; treating the resource as "
        f"{policy['unknownEnvironment']}."
    )
    return policy["unknownEnvironment"], "default-unknown-tag-value"


def _tag_value(tags, tag_key):
    """Read a tag, matching the key case-insensitively.

    EC2 tag keys are case sensitive, so 'environment' and 'Environment' are two
    different tags. Matching loosely here means a lowercase tag still classifies
    the instance instead of silently falling through to the production default.
    """
    if not tags:
        return None
    wanted = tag_key.lower()
    for tag in tags:
        if (tag.get("Key") or "").lower() == wanted:
            return tag.get("Value")
    return None
