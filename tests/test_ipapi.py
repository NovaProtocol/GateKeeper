"""Unit tests for :mod:`shared.ipapi`.

Three claims carry this feature, and each is testable without a network, an app
or a clock:

* **the queue is the table.** An address enters as a NULL ``fetched_at`` and
  costs nothing; draining it is a separate, deliberate act. If a lookup could
  happen on the request path, "adding is free" would only be true until the
  first visitor.
* **the policy is the timings.** Never a second lookup for a queued row's worth
  of work, never a refresh inside the floor, queue always ahead of refresh.
* **the rate limiter is the whole reason this can be free.** Exceeding the
  published window is what gets the caller blocked, so both windows are tested,
  not just the headline one.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import time
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shared import ipapi
from shared.db import Base
from shared.models import IpGeo


async def _make_db(path: Path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


def _run(coro):
    return asyncio.run(coro)


SAMPLE = {
    "ipVersion": 4,
    "ipAddress": "34.116.28.166",
    "latitude": 37.4225,
    "longitude": -122.085,
    "countryName": "United States",
    "countryCode": "US",
    "capital": "Washington D.C.",
    "phoneCodes": [1],
    "timeZones": ["America/Los_Angeles"],
    "zipCode": None,
    "cityName": "Mountain View",
    "regionName": "California",
    "regionCode": "CA",
    "continent": "Americas",
    "continentCode": "AM",
    "currencies": ["USD"],
    "languages": ["en"],
    "asn": "396982",
    "asnOrganization": "Google LLC",
    "isProxy": False,
}


# --------------------------------------------------------------------------- #
# The rate limiter
# --------------------------------------------------------------------------- #


def test_a_fresh_limiter_allows_a_call_immediately() -> None:
    assert ipapi.RateLimiter().retry_after(1000.0) == 0.0


def test_the_ten_second_window_bites_before_the_minute_one() -> None:
    """Ten in ten seconds is the limit a burst actually trips."""
    limiter = ipapi.RateLimiter()
    for i in range(ipapi.RATE_PER_10S):
        limiter.record(1000.0 + i * 0.1)
    wait = limiter.retry_after(1000.9)
    assert wait > 0.0, "the eleventh call inside ten seconds must wait"


def test_the_minute_window_is_enforced_too() -> None:
    """The headline limit, isolated from the burst one.

    With one call a second the two windows tie, so this lowers the minute cap to
    make it the one that bites.
    """
    limiter = ipapi.RateLimiter(per_minute=3, per_10s=100)
    for i in range(3):
        limiter.record(1000.0 + i)
    assert limiter.retry_after(1001.0) > 0.0, "a fourth call inside the minute must wait"
    assert limiter.retry_after(1060.5) == 0.0, "...and it frees up once the window passes"


def test_old_calls_stop_counting() -> None:
    limiter = ipapi.RateLimiter()
    for i in range(ipapi.RATE_PER_MINUTE):
        limiter.record(1000.0 + i)
    assert limiter.retry_after(2000.0) == 0.0


# --------------------------------------------------------------------------- #
# The record, the country, the verdict
# --------------------------------------------------------------------------- #


def test_the_country_is_read_from_the_response() -> None:
    assert ipapi.country_of(SAMPLE) == "US"
    assert ipapi.country_of({"countryCode": "ph"}) == "PH"
    assert ipapi.country_of({"countryCode": "USA"}) is None
    assert ipapi.country_of({}) is None
    assert ipapi.country_of(None) is None


def test_the_lookup_wins_when_the_two_disagree() -> None:
    verdict = ipapi.decide_country("PH", "US")
    assert verdict["truth"] == "US"
    assert verdict["source"] == "lookup"
    assert verdict["mismatch"] is True
    assert verdict["cf"] == "PH"
    assert verdict["lookup"] == "US"


def test_cloudflare_is_the_fallback_when_there_is_no_lookup() -> None:
    verdict = ipapi.decide_country("PH", None)
    assert verdict["truth"] == "PH"
    assert verdict["source"] == "cloudflare"
    assert verdict["mismatch"] is False


def test_no_answers_means_no_claim() -> None:
    verdict = ipapi.decide_country(None, None)
    assert verdict["truth"] is None
    assert verdict["source"] is None
    assert verdict["mismatch"] is False


def test_agreement_is_not_a_mismatch() -> None:
    assert ipapi.decide_country("us", "US")["mismatch"] is False


# --------------------------------------------------------------------------- #
# The queue
# --------------------------------------------------------------------------- #


def test_a_new_address_is_queued_without_any_lookup(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "q.db")
        async with sm() as session:
            added = await ipapi.ensure_queued(session, "1.2.3.4")
            assert added is True
            row = await session.get(IpGeo, "1.2.3.4")
            assert row is not None
            assert row.fetched_at is None, "a queued row has no data and no answer"
            assert row.data is None
        await engine.dispose()

    _run(scenario())


def test_queueing_the_same_address_twice_adds_one_row(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "q2.db")
        async with sm() as session:
            assert await ipapi.ensure_queued(session, "1.2.3.4") is True
            assert await ipapi.ensure_queued(session, "1.2.3.4") is False
            rows = (await session.execute(select(IpGeo))).scalars().all()
            assert len(rows) == 1
        await engine.dispose()

    _run(scenario())


def test_an_empty_address_is_not_queued(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "q3.db")
        async with sm() as session:
            assert await ipapi.ensure_queued(session, "") is False
            assert await ipapi.ensure_queued(session, None) is False
        await engine.dispose()

    _run(scenario())


# --------------------------------------------------------------------------- #
# What is due
# --------------------------------------------------------------------------- #


def test_a_queued_row_is_due_immediately(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "d1.db")
        async with sm() as session:
            await ipapi.ensure_queued(session, "1.2.3.4")
            row = (await session.execute(ipapi.next_due())).scalars().first()
            assert row is not None and row.ip == "1.2.3.4"
        await engine.dispose()

    _run(scenario())


def test_data_inside_the_floor_is_not_due(tmp_path: Path) -> None:
    """The hard cap: nothing younger than a day is refreshed, even when idle."""
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "d2.db")
        async with sm() as session:
            session.add(
                IpGeo(
                    ip="1.2.3.4",
                    data=json.dumps(SAMPLE),
                    country_code="US",
                    fetched_at=ipapi.utcnow() - dt.timedelta(hours=12),
                )
            )
            await session.commit()
            assert (await session.execute(ipapi.next_due())).scalars().first() is None
        await engine.dispose()

    _run(scenario())


def test_data_past_the_floor_is_due_when_idle(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "d3.db")
        async with sm() as session:
            session.add(
                IpGeo(
                    ip="1.2.3.4",
                    data=json.dumps(SAMPLE),
                    country_code="US",
                    fetched_at=ipapi.utcnow() - dt.timedelta(hours=30),
                )
            )
            await session.commit()
            row = (await session.execute(ipapi.next_due())).scalars().first()
            assert row is not None and row.ip == "1.2.3.4"
        await engine.dispose()

    _run(scenario())


def test_the_oldest_due_row_is_chosen_first(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "d4.db")
        async with sm() as session:
            for ip, hours in (("new", 26), ("old", 100)):
                session.add(
                    IpGeo(
                        ip=ip,
                        data=json.dumps(SAMPLE),
                        country_code="US",
                        fetched_at=ipapi.utcnow() - dt.timedelta(hours=hours),
                    )
                )
            await session.commit()
            row = (await session.execute(ipapi.next_due())).scalars().first()
            assert row is not None and row.ip == "old"
        await engine.dispose()

    _run(scenario())


def test_a_queued_row_comes_before_a_refresh(tmp_path: Path) -> None:
    """A row with no answer at all is a better use of a request than a refetch."""
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "d5.db")
        async with sm() as session:
            session.add(
                IpGeo(
                    ip="stale",
                    data=json.dumps(SAMPLE),
                    country_code="US",
                    fetched_at=ipapi.utcnow() - dt.timedelta(days=9),
                )
            )
            await session.commit()
            await ipapi.ensure_queued(session, "fresh")
            row = (await session.execute(ipapi.next_due())).scalars().first()
            assert row is not None and row.ip == "fresh"
        await engine.dispose()

    _run(scenario())


# --------------------------------------------------------------------------- #
# The step: success, failure, throttling
# --------------------------------------------------------------------------- #


def test_a_step_stores_the_whole_response(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "s1.db")
        async with sm() as session:
            await ipapi.ensure_queued(session, "1.2.3.4")

        async def fake(ip: str) -> dict:
            assert ip == "1.2.3.4"
            return SAMPLE

        assert await ipapi.worker_step(sm, fetcher=fake) is True
        async with sm() as session:
            row = await session.get(IpGeo, "1.2.3.4")
            assert row is not None
            assert row.fetched_at is not None
            assert row.country_code == "US"
            # "store all data the api returns" - every key, not a chosen few.
            assert json.loads(row.data) == SAMPLE
            assert row.attempts == 0 and row.last_error is None
        await engine.dispose()

    _run(scenario())


def test_a_step_with_nothing_due_does_nothing(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "s2.db")
        called = []

        async def fake(ip: str) -> dict:
            called.append(ip)
            return SAMPLE

        assert await ipapi.worker_step(sm, fetcher=fake) is False
        assert called == []
        await engine.dispose()

    _run(scenario())


def test_a_failed_lookup_is_recorded_and_pushed_back(tmp_path: Path) -> None:
    """One broken address must not be retried in a hot loop."""
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "s3.db")
        async with sm() as session:
            await ipapi.ensure_queued(session, "1.2.3.4")

        async def failing(ip: str) -> dict:
            raise RuntimeError("upstream said no")

        assert await ipapi.worker_step(sm, fetcher=failing) is True
        async with sm() as session:
            row = await session.get(IpGeo, "1.2.3.4")
            assert row is not None
            assert row.fetched_at is None
            assert row.attempts == 1
            assert "upstream said no" in (row.last_error or "")
            assert row.queued_at > ipapi.utcnow(), "the next attempt is pushed out"
            # ...so it is not due again straight away.
            assert (await session.execute(ipapi.next_due())).scalars().first() is None
        await engine.dispose()

    _run(scenario())


def test_the_limiter_stops_a_step_from_spending_a_request(tmp_path: Path) -> None:
    async def scenario() -> None:
        engine, sm = await _make_db(tmp_path / "s4.db")
        async with sm() as session:
            await ipapi.ensure_queued(session, "1.2.3.4")

        limiter = ipapi.RateLimiter(per_minute=1, per_10s=1)
        limiter.record(time.monotonic())
        called = []

        async def fake(ip: str) -> dict:
            called.append(ip)
            return SAMPLE

        assert await ipapi.worker_step(sm, limiter=limiter, fetcher=fake) is False
        assert called == [], "the row is due, but the window says not yet"
        await engine.dispose()

    _run(scenario())
