"""The per-group ``/*`` catch-all: the reading, the backfill, and the check.

Every group must end in exactly one ``/*`` catch-all, sorted last. That was an
unwritten convention, and the gate depends on it: when a group matches a host
but no rule matches the path, ``shared/gate.py`` refuses the request
unconditionally, on the grounds that the group's catch-all is missing or has
been reordered below a narrower rule. A group without one therefore refuses
every path it does not name explicitly, which is safe but surprising, and a
group whose catch-all is not last has a rule behind it that can never fire.

Nothing in the schema says which rule is the catch-all, so this module holds the
single reading of it (``rules.is_default``) and the two operations the rest of
the code needs: the boot backfill that establishes the invariant, and the report
that proves what it changed. The backfill renumbers ``display_order`` per group,
which is a real change to live data, so it returns a before/after snapshot
rather than a bare count.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models import Rule, RuleGroup

#: The path that makes a rule a group's fallback for everything it does not name.
CATCH_ALL = "/*"

#: What a freshly seeded catch-all does. Gating is the default because a public
#: path has to be a deliberate decision, never the absence of one.
DEFAULT_ACTION = "access_code"

#: Actions a catch-all may carry. Mirrors the create-rule endpoint.
KNOWN_ACTIONS = ("access_code", "none", "custom_password", "deny")

#: What an absent ``rules.active`` reads as. This is the module's single reading of
#: a missing value, shared by the ORM path and the gateway so they cannot drift.
#:
#: It is ``True``, *active*, and that direction is deliberate. An inactive rule
#: is skipped, so reading a missing field as inactive would switch gating off for
#: every rule on a stack whose API has not yet been upgraded to send the field, or
#: whose cache predates the column. The safe reading of "I was told nothing" is
#: "the rule still governs".
DEFAULT_ACTIVE_READING = True


def rule_rows(groups: list[RuleGroup], rules: list[Rule]) -> list[dict[str, Any]]:
    """One row per rule: where it sits, and whether it is the catch-all.

    Ordered by group then position, so two snapshots of the same database taken
    before and after the backfill can be compared line by line.
    """
    by_group: dict[int | None, list[Rule]] = {}
    for rule in rules:
        by_group.setdefault(rule.group_id, []).append(rule)
    rows: list[dict[str, Any]] = []
    for group in sorted(groups, key=lambda g: g.id):
        for rule in sorted(by_group.get(group.id, []), key=lambda r: (r.display_order, r.id or 0)):
            rows.append(
                {
                    "group_id": group.id,
                    "group_name": group.name,
                    "rule_id": rule.id,
                    "path": rule.path,
                    "action": rule.action,
                    "display_order": rule.display_order,
                    "is_default": bool(rule.is_default),
                }
            )
    return rows


def diff_rows(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows whose position or flag actually moved, keyed by rule id.

    A newly inserted rule is reported as a change with no "before" entry, since
    an id alone cannot express "this did not exist".
    """
    old = {row["rule_id"]: row for row in before}
    changed: list[dict[str, Any]] = []
    for row in after:
        previous = old.get(row["rule_id"])
        if previous is None:
            changed.append({"rule_id": row["rule_id"], "before": None, "after": row})
            continue
        if (
            previous["display_order"] != row["display_order"]
            or previous["is_default"] != row["is_default"]
        ):
            changed.append({"rule_id": row["rule_id"], "before": previous, "after": row})
    return changed


def invariant_problems(groups: list[RuleGroup], rules: list[Rule]) -> list[str]:
    """Every way the mandatory-catch-all invariant fails, for a boot-time log.

    Log-only on purpose: refusing to start over a data shape would take the
    admin panel down with the gateway, and the panel is how the shape is fixed.
    """
    problems: list[str] = []
    by_group: dict[int | None, list[Rule]] = {}
    for rule in rules:
        by_group.setdefault(rule.group_id, []).append(rule)
    for group in sorted(groups, key=lambda g: g.id):
        rows = by_group.get(group.id, [])
        catches = [r for r in rows if r.path == CATCH_ALL]
        flagged = [r for r in rows if r.is_default]
        if not rows:
            continue
        if len(flagged) != 1:
            problems.append(f"group {group.id}: {len(flagged)} is_default rules, expected 1")
        if not catches:
            problems.append(f"group {group.id}: no /* catch-all")
        # An inactive catch-all cannot be produced through the API or restored
        # from a validated file, so it means a hand-edited database. The result is
        # the fail-closed branch, every path the group does not name is refused
        #, which is safe but must be visible at boot rather than discovered from
        # a visitor.
        for rule in catches:
            if getattr(rule, "active", DEFAULT_ACTIVE_READING) is False:
                problems.append(f"group {group.id}: the /* catch-all is inactive")
        ordered = sorted(rows, key=lambda r: (r.display_order, r.id or 0))
        if ordered and ordered[-1].path != CATCH_ALL:
            problems.append(f"group {group.id}: catch-all is not last")
    return problems


async def load(session: AsyncSession) -> tuple[list[RuleGroup], list[Rule]]:
    """Every group and rule, so a caller can snapshot or check them."""
    groups = list((await session.execute(select(RuleGroup).order_by(RuleGroup.id))).scalars().all())
    rules = list((await session.execute(select(Rule).order_by(Rule.id))).scalars().all())
    return groups, rules


def add_is_default_column(sync_conn: Any) -> bool:
    """Add `rules.is_default` if the table predates it. Returns whether it ran.

    Guarded the way the other boot migrations are: `PRAGMA table_info` first,
    then `ALTER TABLE ADD COLUMN` inside a `try`. There is no Alembic in this
    stack, and the column is additive with a default, so a live table gains it
    without a rewrite while a fresh one already has it from `create_all`.
    """
    try:
        rows = sync_conn.execute(text("PRAGMA table_info(rules)")).fetchall()
        if "is_default" in {row[1] for row in rows}:
            return False
        sync_conn.execute(text("ALTER TABLE rules ADD COLUMN is_default BOOLEAN DEFAULT 0"))
        return True
    except Exception:
        return False


def add_rule_active_column(sync_conn: Any) -> bool:
    """Add `rules.active` if the table predates it. Returns whether it ran.

    Guarded exactly like :func:`add_is_default_column`: `PRAGMA table_info` first,
    then `ALTER TABLE ADD COLUMN` inside a `try`. There is no Alembic in this
    stack, so the guarded `ALTER` is the migration path, and the column is
    additive with a constant default, so a live table gains it without a rewrite
    while a fresh one already has it from `create_all`.

    **This migration does not renumber anything.** `add_is_default_column`'s
    backfill (`apply_rule_defaults`) compacts each group's `display_order`; an
    operator reading this one should know it is not that kind of migration.
    `SQLite ALTER TABLE ADD COLUMN` with a constant `DEFAULT 1` populates every
    existing row with `1`, so live rules come back **active** without a backfill
    pass, and without a window in which a rule reads as inactive.
    """
    try:
        rows = sync_conn.execute(text("PRAGMA table_info(rules)")).fetchall()
        if "active" in {row[1] for row in rows}:
            return False
        sync_conn.execute(text("ALTER TABLE rules ADD COLUMN active BOOLEAN DEFAULT 1"))
        return True
    except Exception:
        return False


async def apply_rule_defaults(session: AsyncSession) -> dict[str, Any]:
    """Establish the invariant across every group and report the difference.

    Per group, in id order:

    1. no ``/*`` rule → one is inserted at the end, flagged ``is_default``;
    2. otherwise the ``/*`` with the highest ``display_order`` is flagged and any
       other ``/*`` in that group is un-flagged, so a group that somehow grew two
       keeps exactly one;
    3. every group's rules are renumbered ``0..n-1`` in their existing ascending
       order with the catch-all moved to the end. Relative order is otherwise
       preserved, and a catch-all that was already last produces no change.

    The caller must commit. Nothing here deletes a rule.
    """
    groups, rules = await load(session)
    before = rule_rows(groups, rules)

    by_group: dict[int | None, list[Rule]] = {}
    for rule in rules:
        by_group.setdefault(rule.group_id, []).append(rule)

    inserted: list[dict[str, Any]] = []
    for group in sorted(groups, key=lambda g: g.id):
        rows = by_group.setdefault(group.id, [])
        catches = [r for r in rows if r.path == CATCH_ALL]
        if catches:
            # Highest display_order wins, matching how a backup file written
            # before the column existed is read.
            chosen = max(catches, key=lambda r: (r.display_order, r.id or 0))
            for other in catches:
                if other is not chosen and other.is_default:
                    other.is_default = False  # type: ignore[assignment]
        else:
            order = max((r.display_order for r in rows), default=-1) + 1
            chosen = Rule(
                group_id=group.id,
                path=CATCH_ALL,
                action=DEFAULT_ACTION,
                display_order=order,
                is_default=True,
                active=True,
            )
            session.add(chosen)
            rows.append(chosen)
            inserted.append({"group_id": group.id, "group_name": group.name, "path": CATCH_ALL})
        if not chosen.is_default:
            chosen.is_default = True  # type: ignore[assignment]

        # The catch-all goes last; everything else keeps its relative order.
        rest = sorted(
            (r for r in rows if r is not chosen),
            key=lambda r: (r.display_order, r.id or 0),
        )
        for index, rule in enumerate([*rest, chosen]):
            rule.display_order = index  # type: ignore[assignment]

    await session.flush()
    groups, rules = await load(session)
    after = rule_rows(groups, rules)
    return {
        "before": before,
        "after": after,
        "changed": diff_rows(before, after),
        "inserted": inserted,
    }
