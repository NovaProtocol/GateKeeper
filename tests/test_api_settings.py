"""Settings validation and log pruning, at the HTTP surface.

Two things are load-bearing here and both are checked from the outside rather
than by calling the helpers:

* **an invalid value cannot be persisted.** The panel is not the only writer any
  more, so the rule is asserted at `PUT /api/settings/{key}` for every key the
  panel owns, including the two whose direction matters most: a bad
  `unmatched_action` must not become `none`, and a bad `session_lifetime_hours`
  must not become a lifetime the cookie code would then act on;
* **a prune deletes by age and by nothing else.** Fixtures carry explicit
  timestamps on both sides of the boundary, so an off-by-one that takes the
  boundary row fails here.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import Any

import pytest
from sqlalchemy import select, text

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}

#: Every key the manage panel writes, with a value that must be refused.
INVALID_VALUES = [
    ("unmatched_action", "allow", "access_code, deny, none"),
    ("unmatched_action", "access-code", "access_code, deny, none"),
    ("unmatched_action", "", "access_code, deny, none"),
    ("rate_limit_access_code_per_min", "0", "1..1000"),
    ("rate_limit_access_code_per_min", "1001", "1..1000"),
    ("rate_limit_access_code_per_min", "five", "whole number"),
    ("session_lifetime_hours", "0", "1..720"),
    ("session_lifetime_hours", "721", "1..720"),
    ("session_lifetime_hours", "-1", "1..720"),
    ("session_lifetime_hours", "12.5", "whole number"),
    ("maintenance_mode", "maybe", "true or false"),
    ("log_retention_days", "6", "7..3650"),
    ("log_retention_days", "3651", "7..3650"),
]

VALID_VALUES = [
    ("unmatched_action", "deny", "deny"),
    ("unmatched_action", "  NONE  ", "none"),
    ("rate_limit_access_code_per_min", "120", "120"),
    ("rate_limit_access_code_per_min", " 7 ", "7"),
    ("session_lifetime_hours", "1", "1"),
    ("session_lifetime_hours", "720", "720"),
    ("maintenance_mode", "TRUE", "true"),
    ("maintenance_mode", "1", "true"),
    ("maintenance_mode", "off", "false"),
    ("log_retention_days", "7", "7"),
    ("log_retention_days", "3650", "3650"),
]


def _put(client: Any, key: str, value: Any) -> Any:
    return client.put(f"/api/settings/{key}", json={"value": value}, headers=INTERNAL_KEY_HEADERS)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def test_settings_page_requires_the_internal_key(client: Any) -> None:
    r = client.put("/api/settings/unmatched_action", json={"value": "deny"})
    assert r.status_code == 401


@pytest.mark.parametrize(("key", "value", "message"), INVALID_VALUES)
def test_an_invalid_value_is_refused(client: Any, key: str, value: str, message: str) -> None:
    r = _put(client, key, value)

    assert r.status_code == 400
    assert message in r.json()["detail"]


def test_a_refused_value_is_not_stored(client: Any) -> None:
    """The refusal has to be a refusal, not a rejection followed by a write."""
    _put(client, "unmatched_action", "access_code")
    before = client.get("/api/settings/unmatched_action").json()["value"]

    refused = _put(client, "unmatched_action", "allow")

    after = client.get("/api/settings/unmatched_action").json()["value"]
    assert refused.status_code == 400
    assert after == before == "access_code"


@pytest.mark.parametrize(("key", "value", "stored"), VALID_VALUES)
def test_a_valid_value_is_stored_normalized(client: Any, key: str, value: str, stored: str) -> None:
    r = _put(client, key, value)

    assert r.status_code == 200
    assert r.json()["value"] == stored
    assert client.get(f"/api/settings/{key}").json()["value"] == stored


def test_an_unknown_key_is_still_stored_unvalidated(client: Any) -> None:
    """Unchanged behaviour: the endpoint accepts keys this panel does not own."""
    r = _put(client, "some_future_key", "anything at all")

    assert r.status_code == 200
    assert client.get("/api/settings/some_future_key").json()["value"] == "anything at all"


def test_a_missing_value_is_refused(client: Any) -> None:
    r = client.put("/api/settings/session_lifetime_hours", json={}, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 400


def test_every_manage_key_has_a_row_after_the_lifespan(client: Any) -> None:
    """A fresh volume shows the value it runs with, not a blank."""
    from shared.settings_spec import MANAGE_FIELDS

    rows = {s["key"]: s["value"] for s in client.get("/api/settings").json()}

    assert set(MANAGE_FIELDS) <= set(rows)


# --------------------------------------------------------------------------- #
# Pruning
# --------------------------------------------------------------------------- #


def _insert_log(ts: dt.datetime, host: str) -> None:
    """Write one audit row with an explicit timestamp, through the async engine.

    The API's engine is an async one, so a synchronous `sync_engine` call from
    inside a request's event loop would trip the greenlet check. Going through
    the async session keeps the fixture and the service on the same engine.
    """
    from shared.db import get_sessionmaker
    from shared.models import AuditLog

    async def _write() -> None:
        async with get_sessionmaker()() as s:
            s.add(AuditLog(ts=ts, host=host, path="/", action="auth_success"))
            await s.commit()

    asyncio.run(_write())


def _count_logs() -> int:
    from shared.db import get_engine

    async def _count() -> int:
        engine = get_engine()
        async with engine.connect() as conn:
            return int((await conn.execute(text("SELECT COUNT(*) FROM audit_logs"))).scalar_one())

    return asyncio.run(_count())


def _hosts_left() -> list[str]:
    from shared.db import get_engine

    async def _hosts() -> list[str]:
        engine = get_engine()
        async with engine.connect() as conn:
            rows = await conn.execute(text("SELECT host FROM audit_logs ORDER BY host"))
            return [str(r[0]) for r in rows]

    return asyncio.run(_hosts())


async def _snapshot_settings() -> dict[str, str]:
    from shared.db import get_sessionmaker
    from shared.models import Setting

    async with get_sessionmaker()() as s:
        rows = (await s.execute(select(Setting))).scalars().all()
        return {row.key: row.value for row in rows}


async def _restore_settings(snapshot: dict[str, str]) -> None:
    from shared.db import get_sessionmaker
    from shared.models import Setting

    async with get_sessionmaker()() as s:
        for row in (await s.execute(select(Setting))).scalars().all():
            await s.delete(row)
        for key, value in snapshot.items():
            s.add(Setting(key=key, value=value))
        await s.commit()


@pytest.fixture(autouse=True)
def restore_settings():
    """Put the settings table back after every test in this module.

    The database is shared by the whole run and other modules assert on the
    seeded value of `unmatched_action`, so a test that changes it would otherwise
    fail a suite it never touched. Restoring the rows is cheaper than giving this
    module its own database and keeps the assertions above honest about what they
    changed.
    """
    before = asyncio.run(_snapshot_settings())
    yield
    asyncio.run(_restore_settings(before))


def _clear_logs() -> None:
    from shared.db import get_sessionmaker

    async def _clear() -> None:
        async with get_sessionmaker()() as s:
            await s.execute(text("DELETE FROM audit_logs"))
            await s.commit()

    asyncio.run(_clear())


@pytest.fixture()
def log_window():
    """A clean log table with rows on both sides of a seven-day boundary."""
    _clear_logs()
    now = dt.datetime.utcnow()  # noqa: DTZ003 - matches the column's naive UTC
    _insert_log(now - dt.timedelta(days=30), "old-30.test")
    _insert_log(now - dt.timedelta(days=8), "old-8.test")
    _insert_log(now - dt.timedelta(days=6), "recent-6.test")
    _insert_log(now - dt.timedelta(hours=1), "recent-1h.test")
    yield
    _clear_logs()


def test_prune_requires_the_internal_key(client: Any) -> None:
    r = client.post("/api/logs/prune")
    assert r.status_code == 401


def test_prune_deletes_only_rows_past_the_window(client: Any, log_window: None) -> None:
    r = client.post("/api/logs/prune?days=7", headers=INTERNAL_KEY_HEADERS)

    assert r.status_code == 200
    assert r.json()["deleted"] == 2
    assert r.json()["remaining"] == 2


def test_prune_keeps_a_row_that_is_inside_the_window(client: Any, log_window: None) -> None:
    """Rows inside the window survive; only the two older ones go."""
    r = client.post("/api/logs/prune?days=7", headers=INTERNAL_KEY_HEADERS)

    assert r.json()["deleted"] == 2
    assert sorted(_hosts_left()) == ["recent-1h.test", "recent-6.test"]


def test_prune_boundary_is_about_the_row_and_not_a_rounding(client: Any) -> None:
    """A minute on either side of the cutoff decides it, not the hour or the day.

    Both fixtures are placed seconds away from the cutoff rather than exactly on
    it: the endpoint computes its own ``utcnow()``, so a row placed at exactly
    seven days would be judged by a clock a few milliseconds later and the test
    would depend on that drift. A minute of margin is unambiguous and still fails
    if the comparison ever becomes `<=` on a whole day.
    """
    _clear_logs()
    now = dt.datetime.utcnow()  # noqa: DTZ003 - matches the column's naive UTC
    _insert_log(now - dt.timedelta(days=7, minutes=1), "just-outside.test")
    _insert_log(now - dt.timedelta(days=7) + dt.timedelta(minutes=1), "just-inside.test")

    r = client.post("/api/logs/prune?days=7", headers=INTERNAL_KEY_HEADERS)

    assert r.json()["deleted"] == 1
    assert _hosts_left() == ["just-inside.test"]
    _clear_logs()


def test_prune_defaults_to_the_stored_setting(client: Any, log_window: None) -> None:
    _put(client, "log_retention_days", "7")

    r = client.post("/api/logs/prune", headers=INTERNAL_KEY_HEADERS)

    assert r.json()["deleted"] == 2
    assert r.json()["remaining"] == 2


def test_prune_falls_back_to_the_default_when_the_row_is_unusable(
    client: Any, log_window: None
) -> None:
    """A hand-edited row must not prune everything or nothing."""
    from shared.db import get_sessionmaker
    from shared.models import Setting

    async def _force(value: str) -> None:
        async with get_sessionmaker()() as s:
            row = await s.get(Setting, "log_retention_days")
            if row is None:
                s.add(Setting(key="log_retention_days", value=value))
            else:
                row.value = value  # type: ignore[assignment]
            await s.commit()

    asyncio.run(_force("not-a-number"))

    r = client.post("/api/logs/prune", headers=INTERNAL_KEY_HEADERS)

    # The built-in window is 30 days, so only the 30-day-old row goes.
    assert r.json()["deleted"] == 1
    assert _count_logs() == 3


def test_prune_rejects_days_outside_the_range(client: Any) -> None:
    assert client.post("/api/logs/prune?days=1", headers=INTERNAL_KEY_HEADERS).status_code == 422
    assert (
        client.post("/api/logs/prune?days=99999", headers=INTERNAL_KEY_HEADERS).status_code == 422
    )


def test_prune_on_an_empty_table_is_a_no_op(client: Any) -> None:
    _clear_logs()

    r = client.post("/api/logs/prune?days=7", headers=INTERNAL_KEY_HEADERS)

    assert r.status_code == 200
    assert r.json() == {"ok": True, "deleted": 0, "remaining": 0}
