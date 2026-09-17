"""Rule dispatch shared by both auth-gateway gate paths.

The gateway checks a request twice: Caddy's ``forward_auth`` call
(``GET /api/authz/forward-auth``) and the wildcard proxy path that carries every
other request. Both must reach the same verdict about the same request, so the
resolution of "which group, which rule" and the action that follows from it live
here rather than inside either caller.

The invariant this module exists to hold: when nothing matches, the request is
refused. Two different situations used to look identical to the caller because
both were reported as ``(None, None)``:

* **no group matched the host** (a Route may still exist for it) and
* **a group matched the host but no rule matched the path**.

The first follows the ``unmatched_action`` setting. The second is a broken
invariant, because every group is meant to end in a ``/*`` catch-all, and it is
refused unconditionally: a setting must not be able to turn a data fault into an
open proxy.
"""

from __future__ import annotations

from typing import Any

from shared.models import Rule, RuleGroup
from shared.security import host_matches, path_matches

UNMATCHED_ACTIONS = ("access_code", "deny", "none")
DEFAULT_UNMATCHED_ACTION = "access_code"
KNOWN_ACTIONS = ("access_code", "custom_password", "deny", "none")

#: Returned when no rule applies and the host matched no group, and when a group
#: matched without a rule. It is deliberately the gating action, not an allow.
REFUSED_ACTION = "access_code"


def normalize_unmatched_action(value: Any) -> str:
    """Return a valid ``unmatched_action``, falling back to the gating default."""
    if value is None:
        return DEFAULT_UNMATCHED_ACTION
    action = str(value).strip().lower()
    if action in UNMATCHED_ACTIONS:
        return action
    return DEFAULT_UNMATCHED_ACTION


def find_group_rule(
    host: str, path: str, groups: list[RuleGroup]
) -> tuple[RuleGroup | None, Rule | None]:
    """First host-matching group, then the first rule in it whose path matches.

    Returns ``(group, None)`` when the group matched the host but nothing matched
    the path. That is the signal the callers need: ``(None, None)`` cannot be
    told apart from "no group matched this host at all".
    """
    for group in sorted(groups, key=lambda g: g.display_order):
        if not host_matches(group.domain, host):
            continue
        for rule in sorted(group.rules, key=lambda r: r.display_order):
            if path_matches(rule.path, path):
                return group, rule
        return group, None
    return None, None


def resolve_rule_action(
    group: RuleGroup | None,
    rule: Rule | None,
    unmatched_action: Any = DEFAULT_UNMATCHED_ACTION,
) -> str:
    """The action that governs a request. Never ``None``, never an unknown value.

    ``unmatched_action`` only applies when the host matched no group at all.
    """
    if rule is not None:
        action = str(getattr(rule, "action", "") or "").strip()
        # An unrecognised action is a data fault. Gating is the safe reading of it.
        return action if action in KNOWN_ACTIONS else REFUSED_ACTION
    if group is not None:
        # Group matched the host, no rule matched the path: refuse, always.
        return REFUSED_ACTION
    return normalize_unmatched_action(unmatched_action)
