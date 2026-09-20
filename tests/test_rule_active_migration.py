"""The `rules.active` migration, against databases built from real shapes.

`active` is one additive column with a constant default, so the migration is
smaller than the `is_default` one and does not renumber anything. What it does
have to prove is the thing that is easy to get wrong and hard to see: an existing
rule must come back **active**. Reading `NULL`, or a missing value, as inactive
would silently take every rule out of the gate's walk and hand every host to
whatever sits below it, which is the opposite of fail-closed.

So these tests do not assert "the column exists". They build throwaway SQLite
files with the pre-`active` schema, run the migration over them, and check the
column, every rule's flag, and that `display_order` was left exactly as it was, the point of difference from the `is_default` migration, which does renumber.

Nothing here touches `/data/gatekeeper.db`: each case gets its own file under
`/tmp`, built with the schema as it stood before the column.
"""

from __future__ import annotations

import asyncio
import sqlite3
import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from shared.models import Rule
from shared.rule_defaults import add_rule_active_column, invariant_problems

#: The `rules` table as it stood *before* this change: no `active`. `is_default`
#: is already present, so this is genuinely the current production shape and not
#: some older one, the migration has to cope with the table the live stack holds
#: today.
LEGACY_SCHEMA = """
CREATE TABLE rule_groups (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    domain VARCHAR(255) NOT NULL,
    display_order INTEGER NOT NULL,
    is_default BOOLEAN,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE rules (
    id INTEGER PRIMARY KEY,
    group_id INTEGER NOT NULL REFERENCES rule_groups (id) ON DELETE CASCADE,
    path VARCHAR(1024) NOT NULL,
    action VARCHAR(32) NOT NULL,
    custom_password_hash TEXT,
    custom_password_salt VARCHAR(64),
    allow_ip TEXT,
    allow_time VARCHAR(255),
    rate_limit VARCHAR(64),
    display_order INTEGER NOT NULL,
    is_default BOOLEAN,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


def _db_path() -> Path:
    return (Path("/tmp") / f"gatekeeper_active_{uuid.uuid4().hex}.db").resolve()


#: Each case is (groups, rules) in the shapes the live database holds. The
#: `display_order` values are deliberately sparse and unordered, so a migration
#: that quietly renumbered would be caught rather than passing by luck.
CASES: dict[str, tuple[list[tuple], list[tuple]]] = {
    # The production shape: the default group plus three project groups.
    "live": (
        [
            (1, "*.*/*", "*.*/*", 9999, 1),
            (3, "projectnova.download", "projectnova.download", 1, 0),
            (5, "portfolio.projectnova.download", "portfolio.projectnova.download", 2, 0),
        ],
        [
            (1, 1, "/*", "access_code", 0, 1),
            (12, 3, "/robots.txt", "none", 0, 0),
            (15, 3, "/*", "none", 1, 1),
            (13, 5, "/robots.txt", "none", 0, 0),
            (14, 5, "/*", "access_code", 1, 1),
        ],
    ),
    # Sparse orders, so a renumbering migration would be visible.
    "sparse_orders": (
        [(2, "sparse.projectnova.download", "sparse.projectnova.download", 4, 0)],
        [
            (7, 2, "/documentation/*", "access_code", 1, 0),
            (8, 2, "/public/*", "none", 9, 0),
            (9, 2, "/*", "access_code", 14, 1),
        ],
    ),
    # No rules at all: nothing to populate, and nothing may be inserted either.
    "empty_group": (
        [(1, "*.*/*", "*.*/*", 9999, 1)],
        [],
    ),
}


def _build(path: Path, groups: list[tuple], rules: list[tuple]) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SCHEMA)
    conn.executemany("INSERT INTO rule_groups VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)", groups)
    conn.executemany(
        "INSERT INTO rules (id, group_id, path, action, display_order, is_default) "
        "VALUES (?,?,?,?,?,?)",
        rules,
    )
    conn.commit()
    conn.close()


def _columns(path: Path) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("PRAGMA table_info(rules)").fetchall()
    finally:
        conn.close()


def _rule_rows(path: Path) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "SELECT id, display_order, is_default, active FROM rules ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


@pytest.mark.parametrize("case", sorted(CASES))
def test_column_is_added_and_every_existing_rule_comes_back_active(case: str) -> None:
    path = _db_path()
    groups, rules = CASES[case]
    _build(path, groups, rules)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as session:
            ran = add_rule_active_column(session.connection())
            session.commit()
        assert ran is True, "the migration must report that it ran"

        names = {row[1] for row in _columns(path)}
        assert "active" in names

        rows = _rule_rows(path)
        assert len(rows) == len(rules)
        # Every pre-existing rule is active. Not one, not most: all of them.
        assert [row[3] for row in rows] == [1] * len(rules), rows
        # And nothing else moved. This is the difference from the `is_default`
        # migration, which renumbers each group's `display_order`.
        assert [(row[0], row[1], row[2]) for row in rows] == [
            (r[0], r[4], r[5]) for r in sorted(rules, key=lambda r: r[0])
        ]
    finally:
        engine.dispose()
        path.unlink(missing_ok=True)


def test_a_second_run_is_a_no_op() -> None:
    """Idempotent, and it says so rather than re-running the ALTER."""
    path = _db_path()
    _build(path, *CASES["live"])
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as session:
            assert add_rule_active_column(session.connection()) is True
            session.commit()
            assert add_rule_active_column(session.connection()) is False
            session.commit()
        # The column is still there, and still populated.
        assert "active" in {row[1] for row in _columns(path)}
        assert all(row[3] == 1 for row in _rule_rows(path))
    finally:
        engine.dispose()
        path.unlink(missing_ok=True)


def test_the_orm_can_read_the_migrated_table() -> None:
    """The column the ORM declares is the column the migration adds.

    A migration that renamed it, or added it with a different spelling, would
    pass the PRAGMA checks above and still fail here.
    """
    path = _db_path()
    _build(path, *CASES["live"])
    engine = create_engine(f"sqlite:///{path}")
    try:
        with Session(engine) as session:
            add_rule_active_column(session.connection())
            session.commit()
        with Session(engine) as session:
            rows = list(session.execute(select(Rule).order_by(Rule.id)).scalars().all())
        assert len(rows) == 5
        assert all(rule.active is not False for rule in rows)
        assert [rule.path for rule in rows] == ["/*", "/robots.txt", "/robots.txt", "/*", "/*"]
        assert [rule.display_order for rule in rows] == [0, 0, 0, 1, 1]
    finally:
        engine.dispose()
        path.unlink(missing_ok=True)


def test_missing_field_reads_as_active() -> None:
    """The reading that makes a partially-deployed stack safe.

    A `Rule` built by a fixture, or carried by a gateway cache that predates the
    column, has no `active` at all. It must keep governing: "I was told nothing"
    cannot mean "the rule is off", or an un-upgraded API could silence every rule
    on the stack at once.
    """
    from shared.gate import _is_active

    assert _is_active(Rule(path="/x", action="none", display_order=0)) is True
    explicit_on = Rule(path="/x", action="none", display_order=0)
    explicit_on.active = True
    assert _is_active(explicit_on) is True
    explicit_off = Rule(path="/x", action="none", display_order=0)
    explicit_off.active = False
    assert _is_active(explicit_off) is False
    # `None` is not `False`, so a NULL row still reads as active, which is why
    # the column is `nullable=False` in the first place.
    nulled = Rule(path="/x", action="none", display_order=0)
    nulled.active = None
    assert _is_active(nulled) is True


def test_invariant_problems_reports_an_inactive_catch_all() -> None:
    """The boot-time, log-only check for a state the panel cannot produce."""
    from shared.models import RuleGroup

    group = RuleGroup(name="g", domain="g.test", display_order=0, is_default=False)
    group.id = 1
    catch_all = Rule(group_id=1, path="/*", action="none", display_order=1, is_default=True)
    catch_all.id = 1
    catch_all.active = False
    group.rules = [catch_all]

    problems = invariant_problems([group], [catch_all])
    assert any("catch-all is inactive" in p for p in problems), problems


def test_migration_is_callable_from_a_sync_connection_like_boot_does() -> None:
    """The lifespan runs it through `conn.run_sync`, so it must tolerate a raw conn.

    Exercised through SQLAlchemy's own `run_sync` rather than by handing the
    function a connection directly, so the boot path is the tested path.
    """
    from shared.db import get_engine

    async def main() -> bool:
        engine = get_engine()
        async with engine.begin() as conn:
            return await conn.run_sync(add_rule_active_column)

    # The app's own database has already been created by conftest, so this is
    # the "column already exists" path: False, and no exception.
    assert asyncio.run(main()) is False
