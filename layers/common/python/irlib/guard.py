"""Refuse to act on principals and resources the pipeline must never touch.

Three categories:

* the pipeline's own roles - containing itself would strand every incident;
* operator-configured break-glass and admin roles - the accounts a responder
  uses to undo a bad call;
* service-linked roles - AWS owns these, and denying one breaks the service
  rather than the attacker.

Checks are name-based and deliberately conservative: anything that looks like a
protected principal is protected.
"""

import logging
import os

logger = logging.getLogger()

SERVICE_LINKED_MARKER = ":role/aws-service-role/"


class ProtectedPrincipalError(Exception):
    """Raised instead of mutating a protected principal or resource."""


def protected_role_names():
    configured = os.environ.get("PROTECTED_ROLE_NAMES", "")
    return {name.strip() for name in configured.split(",") if name.strip()}


def pipeline_role_prefix():
    return os.environ.get("PIPELINE_ROLE_PREFIX", "").strip()


def is_protected_role(role, extra_protected=None):
    """True when `role` (a role name or ARN) must not be modified."""
    if not role:
        return True  # An unidentifiable principal is not one to act on.

    if SERVICE_LINKED_MARKER in role:
        return True

    name = role.rsplit("/", 1)[-1] if "/" in role else role

    protected = protected_role_names() | set(extra_protected or [])
    if name in protected or role in protected:
        return True

    prefix = pipeline_role_prefix()
    if prefix and name.startswith(prefix):
        return True

    return False


def assert_role_actionable(role, context="", extra_protected=None):
    """Raise ProtectedPrincipalError if `role` is off limits."""
    if is_protected_role(role, extra_protected=extra_protected):
        raise ProtectedPrincipalError(
            f"Refusing to act on protected principal {role!r}"
            + (f" ({context})" if context else "")
        )
    return role
