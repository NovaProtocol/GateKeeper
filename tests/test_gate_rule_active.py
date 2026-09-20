"""Resolution with `Rule.active`: skipping is fall-through, not deny.

Pure and fast, no HTTP and no database. The flags here are the ones that decide
what a visitor gets, so each case is written as the consequence rather than as a
list comparison:

* a switched-off rule is skipped, so the request falls through to the catch-all;
* a switched-off rule cannot shadow an active one, whatever its position;
* a group whose only path-matching rule is off is still **refused**: the
  fail-closed branch, unchanged by this feature;
* a `Rule` with no `active` attribute at all still governs, which is what keeps
  an un-upgraded API or an old cache from silencing every rule;
* and `resolve_rule_action` returns exactly what it returned before for all four
  actions, so the column cannot have changed what an action means.
"""

from __future__ import annotations

import pytest

from shared.gate import (
    DEFAULT_UNMATCHED_ACTION,
    find_group_rule,
    resolve_rule_action,
)
from shared.models import Rule, RuleGroup


def _group(gid: int, domain: str, order: int = 0) -> RuleGroup:
    group = RuleGroup(name=f"g{gid}", domain=domain, display_order=order, is_default=False)
    group.id = gid
    return group


def _rule(rid: int, path: str, action: str, order: int, active: bool | None = True) -> Rule:
    rule = Rule(group_id=1, path=path, action=action, display_order=order)
    rule.id = rid
    if active is not None:
        rule.active = active
    return rule


def _shape(result: tuple[RuleGroup | None, Rule | None]) -> tuple[str | None, str | None]:
    """A `(group, rule)` pair as comparable text."""
    group, rule = result
    return (group.name if group else None, rule.path if rule else None)


def test_an_inactive_rule_is_skipped_so_the_request_reaches_the_catch_all() -> None:
    group = _group(1, "app.test")
    narrow = _rule(1, "/private/*", "access_code", 0, active=False)
    catch_all = _rule(2, "/*", "none", 1)
    group.rules = [narrow, catch_all]

    matched_group, matched_rule = find_group_rule("app.test", "/private/x", [group])

    assert matched_group is group
    assert matched_rule is catch_all
    assert resolve_rule_action(matched_group, matched_rule) == "none"


def test_an_inactive_rule_does_not_shadow_an_active_one_below_it() -> None:
    """The switch is the way out of a shadowed rule, without deleting it."""
    group = _group(1, "app.test")
    broad_but_off = _rule(1, "/*", "access_code", 0, active=False)
    narrow = _rule(2, "/public/*", "none", 1)
    group.rules = [broad_but_off, narrow]

    _, matched_rule = find_group_rule("app.test", "/public/page", [group])

    assert matched_rule is narrow


def test_a_group_whose_only_matching_rule_is_off_is_still_refused() -> None:
    """The fail-closed branch, unchanged: no active rule matched, so no access.

    This is the case the catch-all guard exists to keep out of reach, and it is
    why the refusal must not depend on a setting.
    """
    group = _group(1, "app.test")
    only = _rule(1, "/private/*", "none", 0, active=False)
    group.rules = [only]

    matched_group, matched_rule = find_group_rule("app.test", "/private/x", [group])

    assert matched_group is group
    assert matched_rule is None
    assert resolve_rule_action(matched_group, matched_rule, "none") == "access_code"


def test_a_rule_with_no_active_attribute_still_governs() -> None:
    """The partially-deployed case, which must never switch gating off.

    The stand-in is a plain object with the fields resolution reads and **no**
    `active` at all, the shape a bare `Rule(...)` has on a stack whose API has
    not shipped the column, and the shape an in-memory cache built before it
    would carry. The mapped `Rule` class always has the attribute (it is a
    declarative column), so a real `Rule` cannot express this case.
    """

    class NoActive:
        id = 1
        path = "/*"
        action = "access_code"
        display_order = 0

    class PlainGroup:
        id = 1
        name = "plain"
        domain = "app.test"
        display_order = 0

    legacy = NoActive()
    assert not hasattr(legacy, "active")
    plain = PlainGroup()
    plain.rules = [legacy]  # type: ignore[attr-defined]

    matched_group, matched_rule = find_group_rule("app.test", "/anything", [plain])

    assert matched_rule is legacy
    assert matched_group is plain
    assert resolve_rule_action(matched_group, matched_rule) == "access_code"


def test_an_inactive_rule_in_a_non_matching_group_is_irrelevant() -> None:
    """Host matching still happens first, so the flag cannot widen a group."""
    off_group = _group(1, "other.test")
    off_group.rules = [_rule(1, "/*", "none", 0, active=False)]
    on_group = _group(2, "app.test", order=1)
    catch_all = _rule(2, "/*", "access_code", 0)
    on_group.rules = [catch_all]

    _, matched_rule = find_group_rule("app.test", "/", [off_group, on_group])

    assert matched_rule is catch_all


def test_the_flag_does_not_change_what_an_action_does() -> None:
    """`resolve_rule_action` is untouched: same four actions, same four answers."""
    group = _group(1, "app.test")
    for action in ("access_code", "none", "custom_password", "deny"):
        rule = _rule(1, "/x", action, 0)
        assert resolve_rule_action(group, rule) == action
        rule.active = False  # ignored: it is the caller that skips, not this
        assert resolve_rule_action(group, rule) == action


def test_unmatched_action_still_only_applies_without_a_group() -> None:
    """The other fail-closed boundary, restated because this feature touches it."""
    group = _group(1, "app.test", order=5)
    for setting in ("none", "deny", "access_code"):
        # No group at all: the setting decides.
        assert resolve_rule_action(None, None, setting) == setting
        # Group matched, nothing matched the path: the setting must not decide.
        assert resolve_rule_action(group, None, setting) == "access_code"


@pytest.mark.parametrize("active", [True, False])
def test_find_group_rule_is_deterministic_for_a_repeated_probe(active: bool) -> None:
    """Two calls with the same data agree, the gateway caches for 5s."""
    group = _group(1, "app.test")
    group.rules = [
        _rule(1, "/a/*", "access_code", 0, active=active),
        _rule(2, "/*", "none", 1),
    ]
    first = find_group_rule("app.test", "/a/b", [group])
    second = find_group_rule("app.test", "/a/b", [group])
    assert _shape(first) == _shape(second)


def test_the_default_unmatched_action_is_still_the_gating_reading() -> None:
    assert DEFAULT_UNMATCHED_ACTION == "access_code"
