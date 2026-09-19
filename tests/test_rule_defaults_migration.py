"""The `rules.is_default` migration, against databases built from real shapes.

This is the risky half of the catch-all work. The backfill does not only add a
flag: it renumbers every group's `display_order` to force the catch-all last, and
`display_order` is what the live gate walks. A mistake here is visible to
visitors, not just in a table, which is why the phase that introduced it also
introduced the signed export as the rollback.

So these tests do not assert "the column exists". They build throwaway SQLite
files that reproduce the shapes the production database actually holds (a group
whose catch-all is already last, a project group whose catch-all sits above a
narrower rule, a group with no catch-all at all, a group with two), run the
migration over them, and diff every rule's position and flag before and after.

Nothing here touches `/data/gatekeeper.db`: each case gets its own file under
`/tmp`, built with the pre-`is_default` schema so the `ALTER TABLE` has something
to do.
"""

from __future__ import annotations

import asyncio
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from shared.models import Rule, RuleGroup
from shared.rule_defaults import (
    add_is_default_column,
    add_rule_active_column,
    apply_rule_defaults,
    diff_rows,
    invariant_problems,
    rule_rows,
)

#: The `rules` table as it stood *before* this phase: no `is_default`. It is also
#: the shape from before `active` (a later, additive column), which is why the
#: helper below runs both boot migrations before any ORM query — the mapped
#: `Rule` selects every declared column, so a file missing one cannot be read.
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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


def _db_path() -> Path:
    return (Path("/tmp") / f"gatekeeper_migrate_{uuid.uuid4().hex}.db").resolve()


#: Each case is (groups, rules) in the shapes the live database holds.
#:
#: * `live` — the production shape: the default group plus two project groups,
#:   every catch-all already last. Expected diff: the flag only.
#: * `catch_all_masked` — the documented live trap: a project group whose `/*`
#:   sits above a narrower rule, so the narrower rule can never fire.
#: * `no_catch_all` — a group created before groups were seeded.
#: * `two_catch_alls` — one is dead weight; exactly one must end up flagged.
#: * `empty_group` — no rules at all; the catch-all must be inserted.
#: * `empty_db` — nothing to migrate.
CASES: dict[str, tuple[list[tuple], list[tuple]]] = {
    "live": (
        [
            (1, "*.*/*", "*.*/*", 9999, 1),
            (2, "gatekeeper.projectnova.download", "gatekeeper.projectnova.download", 0, 0),
            (3, "projectnova.download", "projectnova.download", 1, 0),
        ],
        [
            (1, 1, "/*", "access_code", 0),
            (2, 2, "/*", "none", 0),
            (3, 3, "/*", "none", 0),
        ],
    ),
    "catch_all_masked": (
        [
            (1, "*.*/*", "*.*/*", 9999, 1),
            (2, "gatekeeper.projectnova.download", "gatekeeper.projectnova.download", 0, 0),
        ],
        [
            (1, 1, "/*", "access_code", 0),
            (2, 2, "/documentation/*", "access_code", 1),
            (3, 2, "/*", "none", 0),
        ],
    ),
    "no_catch_all": (
        [
            (1, "*.*/*", "*.*/*", 9999, 1),
            (2, "portfolio.projectnova.download", "portfolio.projectnova.download", 0, 0),
        ],
        [
            (1, 1, "/*", "access_code", 0),
            (2, 2, "/only/*", "none", 0),
        ],
    ),
    "two_catch_alls": (
        [
            (1, "*.*/*", "*.*/*", 9999, 1),
            (2, "twins.projectnova.download", "twins.projectnova.download", 0, 0),
        ],
        [
            (1, 1, "/*", "access_code", 0),
            (2, 2, "/*", "none", 0),
            (3, 2, "/*", "deny", 5),
        ],
    ),
    "empty_group": (
        [
            (1, "*.*/*", "*.*/*", 9999, 1),
            (2, "bare.projectnova.download", "bare.projectnova.download", 0, 0),
        ],
        [
            (1, 1, "/*", "access_code", 0),
        ],
    ),
    "empty_db": ([], []),
}


def _build(case: str) -> Path:
    """A throwaway database in the pre-migration schema, filled with the case."""
    path = _db_path()
    path.unlink(missing_ok=True)
    groups, rules = CASES[case]
    conn = sqlite3.connect(path)
    try:
        conn.executescript(LEGACY_SCHEMA)
        conn.executemany("INSERT INTO rule_groups VALUES (?, ?, ?, ?, ?, NULL)", groups)
        conn.executemany(
            "INSERT INTO rules (id, group_id, path, action, display_order) VALUES (?, ?, ?, ?, ?)",
            rules,
        )
        conn.commit()
    finally:
        conn.close()
    return path


def _column_present(path: Path) -> bool:
    conn = sqlite3.connect(path)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(rules)")}
        return "is_default" in cols
    finally:
        conn.close()


def _boot_migrations(conn: Any) -> bool:
    """What the lifespan's `_migrate_rules` does, in the order it does it.

    Both migrations are additive and independent, so a file that predates either
    gains that column without a rewrite. Running both is what boot does, and the
    ORM cannot read a table that is missing one of them.
    """
    ran = add_is_default_column(conn)
    add_rule_active_column(conn)
    return ran


def _migrate(path: Path) -> dict[str, Any]:
    """Run the real migration over a legacy file and report the diff."""
    engine = create_engine(f"sqlite:///{path}")
    try:
        # A sync `Connection` is what these expect: the boot path hands them one
        # from `conn.run_sync`.
        with engine.begin() as conn:
            ran = _boot_migrations(conn)
        assert ran is True, "the column was already present, so the ALTER did not run"
        assert _column_present(path), "the column is missing after the migration"

        return asyncio.run(_run(path))
    finally:
        engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            Path(f"{path}{suffix}").unlink(missing_ok=True)


async def _run(path: Path) -> dict[str, Any]:
    """The backfill, through the async session the lifespan uses."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    try:
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            report = await apply_rule_defaults(session)
            await session.commit()
        return report
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- #
# The column itself
# --------------------------------------------------------------------------- #


def test_the_column_is_added_to_a_table_that_lacks_it() -> None:
    path = _build("live")
    assert not _column_present(path)
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as conn:
            assert add_is_default_column(conn) is True
        assert _column_present(path)
    finally:
        engine.dispose()
        path.unlink(missing_ok=True)


def test_running_it_twice_is_a_no_op() -> None:
    """Boot runs it every start, so it has to be safe on an already-migrated DB."""
    path = _build("live")
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as conn:
            assert add_is_default_column(conn) is True
        with engine.begin() as conn:
            assert add_is_default_column(conn) is False
    finally:
        engine.dispose()
        path.unlink(missing_ok=True)


def test_existing_rows_default_to_not_the_catch_all() -> None:
    """The `ADD COLUMN` default is what the backfill then corrects."""
    path = _build("live")
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as conn:
            _boot_migrations(conn)
        with Session(engine) as session:
            values = [bool(r.is_default) for r in session.execute(select(Rule)).scalars()]
        assert values == [False, False, False]
    finally:
        engine.dispose()
        path.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# The backfill, over the real shapes
# --------------------------------------------------------------------------- #


CASES_TO_PARAMETRIZE = ["live", "catch_all_masked", "no_catch_all", "two_catch_alls", "empty_group"]


@pytest.mark.parametrize("case", CASES_TO_PARAMETRIZE)
def test_backfill_leaves_every_group_with_one_catch_all_last(case: str) -> None:
    report = _migrate(_build(case))

    by_group: dict[int, list[dict[str, Any]]] = {}
    for row in report["after"]:
        by_group.setdefault(row["group_id"], []).append(row)

    assert by_group, "the case should have at least one group with rules"
    for gid, rows in by_group.items():
        flagged = [r for r in rows if r["is_default"]]
        assert len(flagged) == 1, f"{case}: group {gid} has {len(flagged)} default rules"
        assert flagged[0]["path"] == "/*", f"{case}: group {gid} default is {flagged[0]['path']}"
        assert rows[-1]["is_default"] is True, f"{case}: group {gid} catch-all is not last"
        assert [r["display_order"] for r in rows] == list(range(len(rows))), case


def test_the_live_shape_changes_only_the_flag() -> None:
    """The production layout has every catch-all last already: no position moves."""
    report = _migrate(_build("live"))

    positions_before = {r["rule_id"]: r["display_order"] for r in report["before"]}
    positions_after = {r["rule_id"]: r["display_order"] for r in report["after"]}
    assert positions_before == positions_after
    assert report["inserted"] == []

    moved = {c["rule_id"]: c for c in report["changed"]}
    assert set(moved) == {1, 2, 3}, "every rule gains the flag, and nothing else changes"
    for change in moved.values():
        assert change["before"]["is_default"] is False
        assert change["after"]["is_default"] is True
        assert change["before"]["display_order"] == change["after"]["display_order"]


def test_a_masked_catch_all_is_moved_last() -> None:
    """The documented live trap: the narrower rule sits *above* the catch-all."""
    report = _migrate(_build("catch_all_masked"))

    before = {r["rule_id"]: r for r in report["before"]}
    after = {r["rule_id"]: r for r in report["after"]}

    # Rule 3 is the `/*`; it was at 0 with the narrower rule at 1.
    assert (before[3]["path"], before[3]["display_order"]) == ("/*", 0)
    assert (before[2]["path"], before[2]["display_order"]) == ("/documentation/*", 1)
    assert (after[2]["display_order"], after[3]["display_order"]) == (0, 1)
    assert after[3]["is_default"] is True
    assert after[2]["is_default"] is False

    moved = {c["rule_id"]: c for c in report["changed"]}
    # Rule 1 is the default group's catch-all: it gains the flag and does not move.
    assert set(moved) == {1, 2, 3}
    assert moved[1]["before"]["display_order"] == moved[1]["after"]["display_order"] == 0
    assert moved[2]["before"]["display_order"] == 1
    assert moved[2]["after"]["display_order"] == 0
    assert moved[3]["before"]["display_order"] == 0
    assert moved[3]["after"]["display_order"] == 1


def test_a_group_with_no_catch_all_gets_one_inserted() -> None:
    report = _migrate(_build("no_catch_all"))

    assert report["inserted"] == [
        {"group_id": 2, "group_name": "portfolio.projectnova.download", "path": "/*"}
    ]
    inserted = [r for r in report["after"] if r["path"] == "/*" and r["group_id"] == 2]
    assert len(inserted) == 1
    assert inserted[0]["action"] == "access_code", "a new catch-all gates by default"
    assert inserted[0]["is_default"] is True
    assert inserted[0]["display_order"] == 1, "inserted after the group's existing rule"

    # The group's original rule keeps position 0 and is not the catch-all.
    existing = next(r for r in report["after"] if r["rule_id"] == 2)
    assert existing["display_order"] == 0
    assert existing["is_default"] is False


def test_two_catch_alls_leave_exactly_one_flagged_and_last() -> None:
    """The higher-ordered `/*` wins, matching how an old backup file is read."""
    report = _migrate(_build("two_catch_alls"))

    after = {r["rule_id"]: r for r in report["after"] if r["group_id"] == 2}
    flagged = [r for r in after.values() if r["is_default"]]
    assert len(flagged) == 1
    assert flagged[0]["rule_id"] == 3, "the highest display_order catch-all wins"
    assert flagged[0]["action"] == "deny", "the winning rule keeps its own action"
    assert after[2]["is_default"] is False

    ordered = sorted(after.values(), key=lambda r: r["display_order"])
    assert ordered[-1]["rule_id"] == 3
    assert [r["display_order"] for r in ordered] == [0, 1]


def test_an_empty_group_gains_a_catch_all() -> None:
    report = _migrate(_build("empty_group"))
    rows = [r for r in report["after"] if r["group_id"] == 2]
    assert len(rows) == 1
    assert (rows[0]["path"], rows[0]["display_order"], rows[0]["is_default"]) == ("/*", 0, True)


def test_an_empty_database_is_untouched() -> None:
    report = _migrate(_build("empty_db"))
    assert report["before"] == []
    assert report["after"] == []
    assert report["changed"] == []
    assert report["inserted"] == []


def test_no_rule_is_ever_removed() -> None:
    """A migration that deleted a rule would be a silent policy change."""
    for case in ("live", "catch_all_masked", "two_catch_alls"):
        report = _migrate(_build(case))
        before_ids = {r["rule_id"] for r in report["before"]}
        after_ids = {r["rule_id"] for r in report["after"]}
        assert before_ids <= after_ids, case
        assert report["inserted"] == [] or case != "live"


def test_running_the_backfill_twice_changes_nothing() -> None:
    """It runs on every boot, so a second run has to be a no-op."""
    path = _build("catch_all_masked")
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as conn:
            _boot_migrations(conn)
        first = asyncio.run(_run(path))
        assert first["changed"], "the first run should have work to do"

        second = asyncio.run(_run(path))
        assert second["changed"] == []
        assert second["inserted"] == []
        assert second["after"] == first["after"]
    finally:
        engine.dispose()
        for suffix in ("", "-wal", "-shm"):
            Path(f"{path}{suffix}").unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# The boot-time check and the snapshot helpers
# --------------------------------------------------------------------------- #


def _rows_to_models(rows: list[dict[str, Any]]) -> tuple[list[RuleGroup], list[Rule]]:
    groups: dict[int, RuleGroup] = {}
    rules: list[Rule] = []
    for row in rows:
        gid = row["group_id"]
        if gid not in groups:
            groups[gid] = RuleGroup(
                id=gid, name=row["group_name"], domain="x.test", display_order=0
            )
        rules.append(
            Rule(
                id=row["rule_id"],
                group_id=gid,
                path=row["path"],
                action=row["action"],
                display_order=row["display_order"],
                is_default=row["is_default"],
            )
        )
    return list(groups.values()), rules


def test_the_boot_check_is_quiet_on_a_migrated_database() -> None:
    report = _migrate(_build("catch_all_masked"))
    groups, rules = _rows_to_models(report["after"])
    assert invariant_problems(groups, rules) == []


def test_the_boot_check_reports_a_group_with_no_catch_all() -> None:
    rows = [
        {
            "group_id": 1,
            "group_name": "a",
            "rule_id": 1,
            "path": "/named/*",
            "action": "none",
            "display_order": 0,
            "is_default": False,
        }
    ]
    groups, rules = _rows_to_models(rows)
    problems = invariant_problems(groups, rules)
    assert any("no /* catch-all" in p for p in problems)
    assert any("0 is_default rules" in p for p in problems)
    assert any("catch-all is not last" in p for p in problems)


def test_the_boot_check_reports_two_flagged_rules() -> None:
    rows = [
        {
            "group_id": 1,
            "group_name": "a",
            "rule_id": 1,
            "path": "/*",
            "action": "none",
            "display_order": 0,
            "is_default": True,
        },
        {
            "group_id": 1,
            "group_name": "a",
            "rule_id": 2,
            "path": "/*",
            "action": "deny",
            "display_order": 1,
            "is_default": True,
        },
    ]
    groups, rules = _rows_to_models(rows)
    assert any("2 is_default rules" in p for p in invariant_problems(groups, rules))


def test_the_check_skips_a_group_with_no_rules() -> None:
    """A rule-less group is reported by the missing-catch-all check, not by both."""
    groups, rules = _rows_to_models([])
    assert invariant_problems(groups, rules) == []


def test_snapshots_are_comparable_line_by_line() -> None:
    """`before` and `after` come from the same function, so a diff is a diff."""
    report = _migrate(_build("live"))
    assert report["before"] == rule_rows(*_rows_to_models(report["before"]))
    assert diff_rows(report["before"], report["before"]) == []
