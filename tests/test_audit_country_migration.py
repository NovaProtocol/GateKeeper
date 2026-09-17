"""The `audit_logs.country` migration, against a database shaped like production.

The live table had 8162 rows and no `country` column when this was written, so
the test builds a throwaway SQLite file with the same 18 columns and the same
row count, runs the real `api.app._migrate_audit` over it, and diffs the columns,
the indexes and the row census before and after.

Two claims are load-bearing:

* **exactly one column is added and nothing else moves.** The migration is
  guarded `ALTER TABLE ... ADD COLUMN`, run at every boot against a live table, so
  the failure mode to guard against is an unguarded statement that works on a
  fresh volume and breaks on the second start;
* **the new index exists after the first run, not after the second.** The
  `country` index is created in the same pass as the column, which is easy to get
  wrong by checking a column set read before the `ALTER`: the index would then
  quietly appear only on the next restart, and the aggregation would table-scan
  in the meantime.

Nothing here touches `/data/gatekeeper.db`. Each case gets its own file under
`/tmp`, built with the pre-`country` schema.
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

from sqlalchemy import create_engine

from api.app import _migrate_audit

#: The production `audit_logs` columns at the time of writing, in table order.
#: `api_key_id` is legacy and deliberately kept: this test reproduces the live
#: shape rather than the model's, because the migration runs against the table.
PROD_COLUMNS: list[tuple[str, str]] = [
    ("id", "INTEGER PRIMARY KEY"),
    ("ts", "DATETIME DEFAULT CURRENT_TIMESTAMP"),
    ("ip", "VARCHAR(64)"),
    ("host", "VARCHAR(255)"),
    ("path", "VARCHAR(1024)"),
    ("action", "VARCHAR(32)"),
    ("code_id", "INTEGER"),
    ("api_key_id", "INTEGER"),
    ("rule_group_id", "INTEGER"),
    ("rule_id", "INTEGER"),
    ("matched_action", "VARCHAR(32)"),
    ("latency_ms", "INTEGER"),
    ("user_agent", "VARCHAR(512)"),
    ("request_id", "VARCHAR(64)"),
    ("referer", "VARCHAR(1024)"),
    ("method", "VARCHAR(10)"),
    ("status_code", "INTEGER"),
    ("attempted_code", "VARCHAR(64)"),
]

#: The row count the live table held. Reproduced so the census below is a real
#: measurement rather than three rows pretending to be a log.
PROD_ROWS = 8162


def _path() -> Path:
    return (Path("/tmp") / f"gatekeeper_country_{uuid.uuid4().hex}.db").resolve()


def _build(path: Path, rows: int = PROD_ROWS) -> Path:
    conn = sqlite3.connect(path)
    try:
        cols = ",\n    ".join(f"{name} {type_}" for name, type_ in PROD_COLUMNS)
        conn.execute(f"CREATE TABLE audit_logs (\n    {cols}\n)")
        conn.executemany(
            "INSERT INTO audit_logs (ts, ip, host, path, action) VALUES (?, ?, ?, ?, ?)",
            [
                (
                    f"2026-09-{(i % 17) + 1:02d} 10:00:00",
                    "172.22.0.4" if i % 5 else "203.0.113.7",
                    "app.projectnova.download",
                    "/",
                    "no_cookie_redirect",
                )
                for i in range(rows)
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return path


def _columns(path: Path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return [row[1] for row in conn.execute("PRAGMA table_info(audit_logs)")]
    finally:
        conn.close()


def _indexes(path: Path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return sorted(row[1] for row in conn.execute("PRAGMA index_list(audit_logs)"))
    finally:
        conn.close()


def _census(path: Path) -> tuple[int, int, int]:
    """(rows, NULL countries, non-NULL countries)."""
    conn = sqlite3.connect(path)
    try:
        return (
            conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM audit_logs WHERE country IS NULL").fetchone()[0],
            conn.execute("SELECT COUNT(*) FROM audit_logs WHERE country IS NOT NULL").fetchone()[0],
        )
    finally:
        conn.close()


def _migrate(path: Path) -> None:
    """Run the real migration the way the lifespan does: a sync connection."""
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as conn:
            _migrate_audit(conn)
    finally:
        engine.dispose()


def _cleanup(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Pre-flight: the shape the migration is aimed at
# --------------------------------------------------------------------------- #


def test_the_fixture_reproduces_the_live_shape() -> None:
    path = _build(_path(), rows=10)
    try:
        assert _columns(path) == [name for name, _ in PROD_COLUMNS]
        assert "country" not in _columns(path)
        conn = sqlite3.connect(path)
        try:
            assert conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] == 10
        finally:
            conn.close()
    finally:
        _cleanup(path)


# --------------------------------------------------------------------------- #
# The migration
# --------------------------------------------------------------------------- #


def test_the_country_column_is_added_and_nothing_else_changes() -> None:
    path = _build(_path())
    before = _columns(path)
    try:
        _migrate(path)

        after = _columns(path)
        assert [c for c in after if c not in before] == ["country"]
        assert [c for c in before if c not in after] == []
        assert after[: len(before)] == before, "the new column is appended, not inserted"
    finally:
        _cleanup(path)


def test_existing_rows_read_null_and_none_are_lost() -> None:
    """No backfill: a row recorded before this column existed is honestly empty."""
    path = _build(_path())
    try:
        _migrate(path)

        total, nulls, filled = _census(path)
        assert total == PROD_ROWS
        assert nulls == PROD_ROWS
        assert filled == 0
    finally:
        _cleanup(path)


def test_the_index_exists_after_the_first_run() -> None:
    """The trap: checking a column set read before the ALTER defers the index."""
    path = _build(_path(), rows=10)
    try:
        _migrate(path)

        assert "ix_audit_logs_country" in _indexes(path)
    finally:
        _cleanup(path)


def test_running_it_twice_is_a_no_op() -> None:
    """Every boot runs it, so a second pass must add nothing and drop nothing."""
    path = _build(_path(), rows=10)
    try:
        _migrate(path)
        first_columns, first_indexes, first_census = (
            _columns(path),
            _indexes(path),
            _census(path),
        )

        _migrate(path)

        assert _columns(path) == first_columns
        assert _indexes(path) == first_indexes
        assert _census(path) == first_census
        assert _columns(path).count("country") == 1
    finally:
        _cleanup(path)


def test_it_survives_a_table_that_is_missing_entirely() -> None:
    """A brand new volume has no `audit_logs` when this runs, and that is fine."""
    path = _path()
    conn = sqlite3.connect(path)
    conn.close()
    try:
        _migrate(path)
    finally:
        _cleanup(path)


def test_it_survives_a_table_that_already_has_every_column() -> None:
    """A database migrated by a newer build must not be altered backwards."""
    path = _path()
    conn = sqlite3.connect(path)
    try:
        cols = [*PROD_COLUMNS, ("country", "VARCHAR(2)")]
        conn.execute(
            f"CREATE TABLE audit_logs ({', '.join(f'{n} {t}' for n, t in cols)})"
        )
        conn.execute(
            "INSERT INTO audit_logs (host, country) VALUES ('already.test', 'PH')"
        )
        conn.commit()
    finally:
        conn.close()
    try:
        _migrate(path)

        assert _columns(path).count("country") == 1
        assert _census(path) == (1, 0, 1), "the existing value was left alone"
        assert "ix_audit_logs_country" in _indexes(path)
    finally:
        _cleanup(path)


# --------------------------------------------------------------------------- #
# The model agrees with the table
# --------------------------------------------------------------------------- #


def test_the_model_declares_the_column_the_migration_creates() -> None:
    from shared.models import AuditLog

    assert "country" in AuditLog.__table__.columns
    column = AuditLog.__table__.columns["country"]
    assert column.nullable is True
    assert column.type.length == 2, "a country code is two characters"
