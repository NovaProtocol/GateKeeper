"""`GET /api/logs/geo`: the four aggregations, over a fixture with known numbers.

The endpoint is the only place the country column is turned into something an
operator reads, and it is checked from the outside for the same reason the rest
of the API is: the shapes it returns are what the page plots, so a wrong total
here is a wrong map there.

The fixture is deliberately small and fully specified: three countries and one
row with no country, with a duplicate address inside one country so `visitors`
has something to de-duplicate, and with exactly one blocked action and one
gated row, so each mode has a number it could only get by counting the right
thing.

Two things are load-bearing and both are asserted:

* **the unknown bucket appears only when there are unknown rows**, because the
  alternative is a permanent "Unknown" entry that makes a healthy capture look
  broken;
* **missing `country` on ingest is a NULL, not a rejection.** A gateway container
  that has not been rebuilt yet sends no such key, and logging must survive that.
"""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import Any

import pytest
from sqlalchemy import select, text

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}

#: `(country, ip, action, code_id, port)`, one row each, plus a second row that
#: shares the PH address so `visitors` has something to collapse.
ROWS: list[tuple[str | None, str, str, int | None]] = [
    ("PH", "203.0.113.10", "auth_success", 1),
    ("PH", "203.0.113.10", "no_cookie_redirect", None),
    ("US", "203.0.113.20", "auth_success", 1),
    ("DE", "203.0.113.30", "deny", None),
    (None, "203.0.113.40", "access_code_fail", None),
]

#: What each mode must return, as `{country: count}` before the Unknown bucket is
#: appended. `views` counts rows, `visitors` distinct addresses, `gated` rows with
#: a code, `blocked` rows whose action is one of the three refusals.
EXPECTED = {
    "views": {"PH": 2, "US": 1, "DE": 1},
    "visitors": {"PH": 1, "US": 1, "DE": 1},
    "gated": {"PH": 1, "US": 1},
    "blocked": {"DE": 1},
}

#: The fixture's one row with no country, which every mode that matches it
#: reports in the unknown bucket rather than dropping from the total.
UNKNOWN_ROW = {"views": 1, "visitors": 1, "gated": 0, "blocked": 1}


async def _clear() -> None:
    from shared.db import get_sessionmaker

    async with get_sessionmaker()() as s:
        await s.execute(text("DELETE FROM audit_logs"))
        await s.commit()


async def _seed(rows: list[tuple[str | None, str, str, int | None]]) -> None:
    from shared.db import get_sessionmaker
    from shared.models import AuditLog, Code

    async with get_sessionmaker()() as s:
        res = await s.execute(select(Code).where(Code.id == 1))
        if res.scalars().first() is None:
            placeholder = Code(id=1, code="geo-fixture-code", label="fixture")
            s.add(placeholder)
            await s.commit()
        now = dt.datetime.utcnow()  # the column stores naive UTC
        for index, (country, ip, action, code_id) in enumerate(rows):
            s.add(
                AuditLog(
                    ts=now - dt.timedelta(seconds=index),
                    ip=ip,
                    host="geo.test",
                    path="/",
                    action=action,
                    country=country,
                    code_id=code_id,
                )
            )
        await s.commit()


def _geo(client: Any, mode: str = "views", **params: str) -> list[dict[str, Any]]:
    r = client.get("/api/logs/geo", params={"mode": mode, **params})
    assert r.status_code == 200, r.text
    return r.json()


def _by_code(points: list[dict[str, Any]]) -> dict[str | None, int]:
    return {p["cc"]: p["count"] for p in points}


@pytest.fixture()
def geo_rows() -> Any:
    """A clean audit table with the fixture rows, restored afterwards.

    The database is shared by the whole run, so the table is cleared before and
    after rather than left populated: another module asserting on an empty or
    specific log table would otherwise fail for a reason it never caused.
    """
    asyncio.run(_clear())
    asyncio.run(_seed(ROWS))
    yield
    asyncio.run(_clear())


# --------------------------------------------------------------------------- #
# The four modes
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("mode", sorted(EXPECTED))
def test_each_mode_counts_exactly_what_it_says(client: Any, geo_rows: None, mode: str) -> None:
    got = _by_code(_geo(client, mode))
    for cc, count in EXPECTED[mode].items():
        assert got.get(cc) == count, (mode, cc, got)
    assert got.get(None, 0) == UNKNOWN_ROW[mode], (mode, got)


def test_views_counts_requests_not_visitors(client: Any, geo_rows: None) -> None:
    """The same address visiting twice is two views: that is the difference."""
    points = _geo(client, "views")
    ph = next(p for p in points if p["cc"] == "PH")
    assert ph["count"] == 2
    # 2 of 5 rows, because the row with no country counts in the total too: a
    # share that ignored it would make the percentages add up to more than 100.
    assert ph["share"] == 0.4


def test_visitors_de_duplicates_the_address(client: Any, geo_rows: None) -> None:
    points = _geo(client, "visitors")
    ph = next(p for p in points if p["cc"] == "PH")
    assert ph["count"] == 1


def test_gated_counts_only_the_rows_that_presented_a_code(client: Any, geo_rows: None) -> None:
    """Two rows carry a code, and both of them have a country."""
    got = _by_code(_geo(client, "gated"))
    assert got == {"PH": 1, "US": 1}


def test_blocked_counts_only_the_refusals(client: Any, geo_rows: None) -> None:
    """The fixture has two refusals: a `deny` from DE and a failed code with no country.

    So one lands under a code and one lands in the unknown bucket, which is the
    honest outcome and precisely why the bucket exists.
    """
    got = _by_code(_geo(client, "blocked"))
    assert got == {"DE": 1, None: 1}


def test_blocked_does_not_count_a_success_or_a_plain_redirect(
    client: Any, geo_rows: None
) -> None:
    """`auth_success` and `no_cookie_redirect` are not refusals."""
    assert sum(_by_code(_geo(client, "blocked")).values()) == 2


def test_the_default_mode_is_views(client: Any, geo_rows: None) -> None:
    r = client.get("/api/logs/geo")
    assert r.status_code == 200
    assert _by_code(r.json()) == _by_code(_geo(client, "views"))


def test_an_unknown_mode_is_refused_with_the_accepted_list(client: Any, geo_rows: None) -> None:
    r = client.get("/api/logs/geo", params={"mode": "heatmap"})
    assert r.status_code == 400
    for mode in ("views", "visitors", "gated", "blocked"):
        assert mode in r.json()["detail"]


def test_a_mode_is_case_insensitive_through_the_page_but_not_the_api(
    client: Any, geo_rows: None
) -> None:
    """The API is explicit; the page normalizes before calling it."""
    assert client.get("/api/logs/geo", params={"mode": "VIEWS"}).status_code == 400


# --------------------------------------------------------------------------- #
# The unknown bucket
# --------------------------------------------------------------------------- #


def test_the_unknown_bucket_appears_when_rows_lack_a_country(
    client: Any, geo_rows: None
) -> None:
    points = _geo(client, "views")
    unknown = [p for p in points if p["cc"] is None]
    assert len(unknown) == 1
    assert unknown[0]["name"] == "Unknown"
    assert unknown[0]["count"] == 1


def test_the_unknown_bucket_is_last_so_it_never_leads_the_list(
    client: Any, geo_rows: None
) -> None:
    points = _geo(client, "views")
    assert points[-1]["cc"] is None


def test_the_unknown_bucket_is_absent_when_every_matched_row_has_a_country(
    client: Any, geo_rows: None
) -> None:
    """`gated` matches only rows that carried a code, all of which have a country.

    `blocked` is the counter-example in the same fixture: its one matching row
    has no country, so the bucket appears. The bucket follows the rows, not the
    mode.
    """
    assert all(p["cc"] is not None for p in _geo(client, "gated"))
    assert any(p["cc"] is None for p in _geo(client, "blocked"))


def test_the_unknown_bucket_is_not_plotted(client: Any, geo_rows: None) -> None:
    """It counts, and it has nowhere to go: no coordinates, so no marker."""
    unknown = next(p for p in _geo(client, "views") if p["cc"] is None)
    assert unknown["lat"] is None
    assert unknown["lon"] is None
    assert unknown["radius"] == 0.0


# --------------------------------------------------------------------------- #
# The shape of a point
# --------------------------------------------------------------------------- #


def test_every_known_point_carries_a_centroid_a_name_and_a_radius(
    client: Any, geo_rows: None
) -> None:
    for point in _geo(client, "views"):
        if point["cc"] is None:
            continue
        assert isinstance(point["lat"], float) and -90 <= point["lat"] <= 90
        assert isinstance(point["lon"], float) and -180 <= point["lon"] <= 180
        assert point["name"] and point["name"] != point["cc"]
        assert point["radius"] > 0


def test_points_are_ordered_largest_first(client: Any, geo_rows: None) -> None:
    counts = [p["count"] for p in _geo(client, "views") if p["cc"] is not None]
    assert counts == sorted(counts, reverse=True)


def test_the_largest_country_has_the_largest_radius(client: Any, geo_rows: None) -> None:
    plotted = [p for p in _geo(client, "views") if p["lat"] is not None]
    biggest = max(plotted, key=lambda p: p["count"])
    assert biggest["radius"] == max(p["radius"] for p in plotted)


def test_an_empty_table_returns_an_empty_list_not_an_error(client: Any) -> None:
    """The state the page is in before any traffic, and after a clear."""
    asyncio.run(_clear())
    try:
        assert _geo(client, "views") == []
    finally:
        asyncio.run(_clear())


# --------------------------------------------------------------------------- #
# Filters
# --------------------------------------------------------------------------- #


def test_the_host_filter_narrows_the_totals(client: Any, geo_rows: None) -> None:
    assert _geo(client, "views", host="geo.test") != []
    assert _geo(client, "views", host="elsewhere.test") == []


def test_a_time_window_excludes_the_rows_outside_it(client: Any, geo_rows: None) -> None:
    future = (dt.datetime.utcnow() + dt.timedelta(days=1)).strftime("%Y-%m-%d")
    assert _geo(client, "views", **{"from": future}) == []


# --------------------------------------------------------------------------- #
# Ingest: the column, and the absent key
# --------------------------------------------------------------------------- #


def _ingest(client: Any, payload: dict[str, Any]) -> Any:
    return client.post("/api/logs", json=payload, headers=INTERNAL_KEY_HEADERS)


def _stored_country(host: str) -> str | None:
    from shared.db import get_sessionmaker
    from shared.models import AuditLog

    async def _read() -> str | None:
        async with get_sessionmaker()() as s:
            res = await s.execute(select(AuditLog).where(AuditLog.host == host))
            row = res.scalars().first()
            return row.country if row else None

    return asyncio.run(_read())


@pytest.fixture()
def clean_logs() -> Any:
    asyncio.run(_clear())
    yield
    asyncio.run(_clear())


def test_a_request_carrying_a_country_stores_it(client: Any, clean_logs: None) -> None:
    """The whole feature in one assertion: header in, country on the row out."""
    r = _ingest(client, {"host": "country.test", "path": "/", "ip": "203.0.113.1", "country": "PH"})
    assert r.status_code == 200
    assert _stored_country("country.test") == "PH"


def test_a_missing_country_key_is_stored_as_null_and_does_not_fail(
    client: Any, clean_logs: None
) -> None:
    """A gateway container that predates this column sends no key at all."""
    r = _ingest(client, {"host": "nogkey.test", "path": "/", "ip": "203.0.113.2"})
    assert r.status_code == 200, r.text
    assert _stored_country("nogkey.test") is None


def test_an_explicit_null_is_stored_as_null(client: Any, clean_logs: None) -> None:
    r = _ingest(client, {"host": "explicitnull.test", "path": "/", "country": None})
    assert r.status_code == 200
    assert _stored_country("explicitnull.test") is None


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("XX", id="cloudflare-unknown"),
        pytest.param("T1", id="tor"),
        pytest.param("ph", id="lowercase"),
        pytest.param("PHL", id="alpha-3"),
        pytest.param("Philippines", id="the-name"),
        pytest.param("1.2.3.4", id="an-address"),
        pytest.param("", id="empty"),
    ],
)
def test_anything_that_is_not_a_country_is_stored_as_null(
    client: Any, clean_logs: None, value: str
) -> None:
    """Ingest is the last gate: a bad code becomes a NULL, never a stored claim."""
    r = _ingest(client, {"host": "refused.test", "path": "/", "country": value})
    assert r.status_code == 200
    assert _stored_country("refused.test") is None


def test_a_long_country_value_cannot_exceed_the_column(client: Any, clean_logs: None) -> None:
    """Truncation is not what saves this: the value is rejected, not cut down."""
    r = _ingest(client, {"host": "long.test", "path": "/", "country": "P" * 200})
    assert r.status_code == 200
    assert _stored_country("long.test") is None


def test_an_ingested_country_then_appears_in_the_aggregation(
    client: Any, clean_logs: None
) -> None:
    """Capture and aggregation are two halves of one claim; check them joined."""
    _ingest(client, {"host": "joined.test", "path": "/", "ip": "203.0.113.9", "country": "PH"})
    assert _ingest(
        client, {"host": "joined.test", "path": "/", "ip": "203.0.113.8", "country": "US"}
    ).status_code == 200

    got = _by_code(_geo(client, "views", host="joined.test"))
    assert got == {"PH": 1, "US": 1}


# --------------------------------------------------------------------------- #
# The listing is additive
# --------------------------------------------------------------------------- #


def test_the_log_listing_carries_the_country(client: Any, clean_logs: None) -> None:
    _ingest(client, {"host": "listed.test", "path": "/", "country": "DE"})
    r = client.get("/api/logs", params={"host": "listed.test"})
    assert r.status_code == 200
    assert r.json()[0]["country"] == "DE"


def test_the_log_listing_reports_null_for_a_row_without_one(
    client: Any, clean_logs: None
) -> None:
    _ingest(client, {"host": "listed-null.test", "path": "/"})
    r = client.get("/api/logs", params={"host": "listed-null.test"})
    assert r.json()[0]["country"] is None
