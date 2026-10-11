"""`GET /api/logs/geo`: the four aggregations, plotted at the lookup's coordinates.

The endpoint is the only place the audit is turned into something an operator
reads, and it is checked from the outside for the same reason the rest of the API
is: the shapes it returns are what the page plots, so a wrong total here is a
wrong map there.

The fixture is small and fully specified. Three addresses resolve to coordinates
(two of them to the *same* point, so the grouping has something to merge), and a
fourth is left without a lookup row at all, which is the state every address is
in until the worker reaches it.

Two things are load-bearing and both are asserted:

* **an address with no coordinates is counted, not guessed.** It lands in the
  unplotted bucket and the totals still add up to the mode's own count, because a
  map that quietly shrinks is worse than one that admits what it cannot place;
* **missing `country` on ingest is a NULL, not a rejection.** A gateway container
  that has not been rebuilt yet sends no such key, and logging must survive that.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
from typing import Any

import pytest
from sqlalchemy import select, text

from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}

#: `(country, ip, action, code_id, status)`, one row each. The first address
#: appears twice so `visitors` has something to collapse, and the statuses are
#: what "valid requests only" reads: two served requests, a login redirect and
#: two refusals.
ROWS: list[tuple[str | None, str, str, int | None, int]] = [
    ("PH", "203.0.113.10", "auth_success", 1, 200),
    ("PH", "203.0.113.10", "no_cookie_redirect", None, 302),
    ("US", "203.0.113.20", "auth_success", 1, 200),
    ("DE", "203.0.113.30", "deny", None, 403),
    (None, "203.0.113.40", "access_code_fail", None, 403),
]

#: What the lookup resolved for each address: `(country, latitude, longitude)`,
#: or `None` for an address the worker has not reached. `.40` shares `.10`'s
#: point on purpose - two addresses a city's single point puts in one place.
GEO_ROWS: dict[str, tuple[str, float, float] | None] = {
    "203.0.113.10": ("PH", 14.5995, 120.9842),
    "203.0.113.20": ("US", 37.4225, -122.085),
    "203.0.113.30": None,
    "203.0.113.40": ("PH", 14.5995, 120.9842),
}

#: What each mode must total, as `{country: count}` over the *plotted* points.
EXPECTED = {
    "views": {"PH": 3, "US": 1},
    "visitors": {"PH": 2, "US": 1},
    "gated": {"PH": 1, "US": 1},
    "blocked": {"PH": 1},
}

#: Mode-matched rows whose address has no coordinates yet - every mode that
#: matches `.30`, which is the one the fixture leaves unqueued.
UNPLOTTED = {"views": 1, "visitors": 1, "gated": 0, "blocked": 1}

#: The mode's own count, which is plotted rows plus the unplotted bucket.
TOTALS = {"views": 5, "visitors": 4, "gated": 2, "blocked": 2}


async def _clear() -> None:
    from shared.db import get_sessionmaker

    async with get_sessionmaker()() as s:
        await s.execute(text("DELETE FROM audit_logs"))
        await s.execute(text("DELETE FROM ip_geo"))
        await s.commit()


async def _seed(rows: list[tuple[str | None, str, str, int | None, int]]) -> None:
    from shared.db import get_sessionmaker
    from shared.models import AuditLog, Code, IpGeo

    async with get_sessionmaker()() as s:
        res = await s.execute(select(Code).where(Code.id == 1))
        if res.scalars().first() is None:
            s.add(Code(id=1, code="geo-fixture-code", label="fixture"))
            await s.commit()
        now = dt.datetime.utcnow()  # the column stores naive UTC
        for index, (country, ip, action, code_id, status) in enumerate(rows):
            s.add(
                AuditLog(
                    ts=now - dt.timedelta(seconds=index),
                    ip=ip,
                    host="geo.test",
                    path="/",
                    action=action,
                    country=country,
                    code_id=code_id,
                    status_code=status,
                )
            )
        for ip, resolved in GEO_ROWS.items():
            if resolved is None:
                continue  # no row at all: the queued state
            code, lat, lon = resolved
            s.add(
                IpGeo(
                    ip=ip,
                    data=json.dumps({"countryCode": code, "latitude": lat, "longitude": lon}),
                    country_code=code,
                    latitude=lat,
                    longitude=lon,
                    fetched_at=now,
                )
            )
        await s.commit()


def _geo(client: Any, mode: str = "views", **params: str) -> dict[str, Any]:
    r = client.get("/api/logs/geo", params={"mode": mode, **params})
    assert r.status_code == 200, r.text
    return r.json()


def _by_code(countries: list[dict[str, Any]]) -> dict[str | None, int]:
    return {c["cc"]: c["count"] for c in countries}


@pytest.fixture()
def geo_rows() -> Any:
    """A clean audit and lookup table with the fixture rows, restored afterwards.

    The database is shared by the whole run, so both tables are cleared before
    and after rather than left populated: another module asserting on an empty
    log or queue would otherwise fail for a reason it never caused.
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
    body = _geo(client, mode)
    got = _by_code(body["countries"])
    for cc, count in EXPECTED[mode].items():
        assert got.get(cc) == count, (mode, cc, got)
    assert body["unlocated"] == UNPLOTTED[mode], (mode, body)
    assert body["total"] == TOTALS[mode], (mode, body)


def test_views_counts_requests_not_visitors(client: Any, geo_rows: None) -> None:
    """The same address visiting twice is two views: that is the difference."""
    body = _geo(client, "views")
    assert _by_code(body["countries"])["PH"] == 3
    # 3 of 5 in the total: the unplotted row counts too, and a share that ignored
    # it would make the percentages add up to more than 100.
    ph = next(c for c in body["countries"] if c["cc"] == "PH")
    assert ph["share"] == 0.6


def test_visitors_de_duplicates_the_address(client: Any, geo_rows: None) -> None:
    """Two addresses, one point: distinct counting happens per point, not per row."""
    body = _geo(client, "visitors")
    assert _by_code(body["countries"])["PH"] == 2


def test_gated_counts_only_the_rows_that_presented_a_code(client: Any, geo_rows: None) -> None:
    assert _by_code(_geo(client, "gated")["countries"]) == {"PH": 1, "US": 1}


def test_blocked_counts_only_the_refusals(client: Any, geo_rows: None) -> None:
    """`deny` from the unqueued address and a failed code from `.40`, which is plotted."""
    assert _by_code(_geo(client, "blocked")["countries"]) == {"PH": 1, None: 1}


def test_the_default_mode_is_views(client: Any, geo_rows: None) -> None:
    r = client.get("/api/logs/geo")
    assert r.status_code == 200
    assert r.json()["total"] == _geo(client, "views")["total"]


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
# The unplotted bucket
# --------------------------------------------------------------------------- #


def test_an_address_with_no_coordinates_is_counted_not_guessed(client: Any, geo_rows: None) -> None:
    body = _geo(client, "views")
    bucket = [c for c in body["countries"] if c["cc"] is None]
    assert len(bucket) == 1
    assert bucket[0]["name"] == "Not yet located"
    assert bucket[0]["count"] == 1
    assert body["unlocated"] == 1


def test_the_unplotted_bucket_is_absent_when_every_row_is_placed(
    client: Any, geo_rows: None
) -> None:
    """`gated` matches only the two placed addresses, so nothing is left over."""
    body = _geo(client, "gated")
    assert body["unlocated"] == 0
    assert all(c["cc"] is not None for c in body["countries"])


def test_the_totals_add_up_to_the_modes_own_count(client: Any, geo_rows: None) -> None:
    """Plotted plus unplotted is the mode's count: nothing is silently lost."""
    for mode in sorted(EXPECTED):
        body = _geo(client, mode)
        plotted = sum(p["count"] for p in body["points"])
        assert plotted + body["unlocated"] == body["total"], mode


def test_the_unplotted_bucket_is_never_a_marker(client: Any, geo_rows: None) -> None:
    """Everything mapped has both ordinates; what cannot be drawn is counted instead."""
    body = _geo(client, "views")
    assert body["points"], "the fixture plots something"
    assert all(p["lat"] is not None and p["lon"] is not None for p in body["points"])
    assert body["unlocated"] == 1


# --------------------------------------------------------------------------- #
# The shape of a point
# --------------------------------------------------------------------------- #


def test_every_point_carries_lookup_coordinates_a_name_and_a_radius(
    client: Any, geo_rows: None
) -> None:
    for point in _geo(client, "views")["points"]:
        assert isinstance(point["lat"], float) and -90 <= point["lat"] <= 90
        assert isinstance(point["lon"], float) and -180 <= point["lon"] <= 180
        assert point["name"] and point["name"] != point["cc"]
        assert point["radius"] > 0


def test_the_same_point_is_one_marker(client: Any, geo_rows: None) -> None:
    """`.10` and `.40` resolve to one place, so they share a marker, not stack.

    The coordinates arrive rounded to two decimals by SQL, which is the grouping
    key - so this asserts on 14.6, not on the fixture's 14.5995.
    """
    points = _geo(client, "views")["points"]
    assert len([p for p in points if p["lat"] == 14.6]) == 1
    merged = next(p for p in points if p["lat"] == 14.6)
    assert merged["count"] == 3  # .10 twice and .40 once


def test_a_marker_carries_the_addresses_that_are_in_it(client: Any, geo_rows: None) -> None:
    """What a cluster shows when it is clicked: who, and how many calls each."""
    points = _geo(client, "views")["points"]
    merged = next(p for p in points if p["lat"] == 14.6)
    assert {e["ip"] for e in merged["ips"]} == {"203.0.113.10", "203.0.113.40"}
    assert merged["ips_total"] == 2
    assert sum(e["count"] for e in merged["ips"]) == merged["count"]


def test_points_are_ordered_largest_first(client: Any, geo_rows: None) -> None:
    counts = [p["count"] for p in _geo(client, "views")["points"]]
    assert counts == sorted(counts, reverse=True)


def test_the_largest_point_has_the_largest_radius(client: Any, geo_rows: None) -> None:
    plotted = _geo(client, "views")["points"]
    biggest = max(plotted, key=lambda p: p["count"])
    assert biggest["radius"] == max(p["radius"] for p in plotted)


def test_an_empty_table_returns_empty_shapes_not_an_error(client: Any) -> None:
    """The state the page is in before any traffic, and after a clear."""
    asyncio.run(_clear())
    try:
        body = _geo(client, "views")
        assert body["points"] == []
        assert body["countries"] == []
        assert body["total"] == 0
        assert body["unlocated"] == 0
    finally:
        asyncio.run(_clear())


# --------------------------------------------------------------------------- #
# Filters
# --------------------------------------------------------------------------- #


def test_only_valid_keeps_the_responses_the_origin_served(
    client: Any, geo_rows: None
) -> None:
    """Not a refusal, not a redirect: a request that actually got a response.

    The criterion is the status, so this drops `no_cookie_redirect` (302) and the
    two refusals (403) while keeping the two served requests (200).
    """
    body = _geo(client, "views", only_valid="true")
    assert body["total"] == 2
    assert _by_code(body["countries"]) == {"PH": 1, "US": 1}
    assert body["unlocated"] == 0


def test_only_valid_judges_by_status_not_action(client: Any, clean_logs: None) -> None:
    """The same action, two outcomes - which is exactly why this reads the status.

    A proxied request that found its upstream is a served request; one that 404'd
    is not. No list of actions could tell those apart.
    """
    for ip, status in (("203.0.113.61", 200), ("203.0.113.62", 404)):
        assert (
            _ingest(
                client,
                {
                    "host": "proxy.test",
                    "path": "/",
                    "ip": ip,
                    "action": "proxy",
                    "status_code": status,
                },
            ).status_code
            == 200
        )
    body = _geo(client, "views", host="proxy.test", only_valid="true")
    assert body["total"] == 1, "the 200 was served, the 404 was not"


def test_only_valid_drops_a_failing_status_even_with_no_action(
    client: Any, clean_logs: None
) -> None:
    """The status signal stands on its own: a 500 is not a served request."""
    _ingest(
        client,
        {"host": "statusonly.test", "path": "/", "ip": "203.0.113.63", "status_code": 500},
    )
    assert _geo(client, "views", host="statusonly.test", only_valid="true")["total"] == 0


def test_only_valid_keeps_a_row_it_cannot_classify(client: Any, clean_logs: None) -> None:
    """No action and no status is not evidence of failure."""
    payload = {"host": "unknown.test", "path": "/", "ip": "203.0.113.64"}
    assert _ingest(client, payload).status_code == 200
    assert _geo(client, "views", host="unknown.test", only_valid="true")["total"] == 1


def test_a_bounce_is_excluded_by_its_action_whatever_its_status(
    client: Any, clean_logs: None
) -> None:
    """`no_cookie_redirect` is never content, so the action decides - not a status."""
    _ingest(
        client,
        {
            "host": "bounce.test",
            "path": "/",
            "ip": "203.0.113.65",
            "action": "no_cookie_redirect",
            "status_code": 200,
        },
    )
    assert _geo(client, "views", host="bounce.test", only_valid="true")["total"] == 0


def test_a_served_action_with_no_status_is_kept(client: Any, clean_logs: None) -> None:
    """An accepted code logs `auth_success` and no status at all: real traffic.

    This is the case that rules out judging by status alone.
    """
    _ingest(
        client,
        {"host": "served.test", "path": "/", "ip": "203.0.113.66", "action": "auth_success"},
    )
    assert _geo(client, "views", host="served.test", only_valid="true")["total"] == 1


def test_a_bare_end_date_includes_the_whole_day(client: Any, geo_rows: None) -> None:
    """`to=YYYY-MM-DD` is a day, not midnight.

    A filter that says "up to today" has to include today; end-of-day resolution
    happens in `_parse_dt`, and without it this returns nothing at all.
    """
    today = dt.datetime.utcnow().strftime("%Y-%m-%d")
    assert _geo(client, "views", **{"to": today})["total"] == 5


def test_a_bare_start_date_begins_the_day(client: Any, geo_rows: None) -> None:
    tomorrow = (dt.datetime.utcnow() + dt.timedelta(days=1)).strftime("%Y-%m-%d")
    assert _geo(client, "views", **{"from": tomorrow})["total"] == 0


def test_the_host_filter_narrows_the_totals(client: Any, geo_rows: None) -> None:
    assert _geo(client, "views", host="geo.test")["total"] > 0
    assert _geo(client, "views", host="elsewhere.test")["total"] == 0


def test_a_time_window_excludes_the_rows_outside_it(client: Any, geo_rows: None) -> None:
    future = (dt.datetime.utcnow() + dt.timedelta(days=1)).strftime("%Y-%m-%d")
    assert _geo(client, "views", **{"from": future})["points"] == []


# --------------------------------------------------------------------------- #
# Ingest: the column, the queue, and the absent key
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


def _queued(ip: str) -> Any:
    from shared.db import get_sessionmaker
    from shared.models import IpGeo

    async def _read() -> Any:
        async with get_sessionmaker()() as s:
            row = await s.get(IpGeo, ip)
            return None if row is None else (row.fetched_at is None)

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


def test_ingest_queues_the_address_without_looking_it_up(client: Any, clean_logs: None) -> None:
    """Seen once, queued, no request spent - the promise the whole design rests on."""
    _ingest(client, {"host": "queued.test", "path": "/", "ip": "203.0.113.77"})
    assert _queued("203.0.113.77") is True


def _read_row(host: str) -> dict[str, Any]:
    """The five request-detail columns for one stored row."""
    from shared.db import get_sessionmaker
    from shared.models import AuditLog

    async def _read() -> dict[str, Any]:
        async with get_sessionmaker()() as s:
            res = await s.execute(select(AuditLog).where(AuditLog.host == host))
            row = res.scalars().first()
            if row is None:
                return {}
            return {
                "accept_language": row.accept_language,
                "sec_ch_ua": row.sec_ch_ua,
                "sec_ch_ua_platform": row.sec_ch_ua_platform,
                "cf_ray": row.cf_ray,
                "query": row.query,
            }

    return asyncio.run(_read())


def test_the_rest_of_the_request_is_stored(client: Any, clean_logs: None) -> None:
    """Language, client hints, Cloudflare's ray, and what was being asked for."""
    r = _ingest(
        client,
        {
            "host": "detail.test",
            "path": "/search",
            "ip": "203.0.113.99",
            "accept_language": "en-US,en;q=0.9",
            "sec_ch_ua": '"Chromium";v="124", "Not:A-Brand";v="24"',
            "sec_ch_ua_platform": '"Linux"',
            "cf_ray": "8a1b2c3d4e5f6789",
            "query": "page=2&q=test",
        },
    )
    assert r.status_code == 200, r.text
    row = _read_row("detail.test")
    assert row["accept_language"] == "en-US,en;q=0.9"
    assert row["sec_ch_ua"].startswith('"Chromium"')
    assert row["sec_ch_ua_platform"] == '"Linux"'
    assert row["cf_ray"] == "8a1b2c3d4e5f6789"
    assert row["query"] == "page=2&q=test"


def test_a_payload_without_them_is_stored_as_nulls(client: Any, clean_logs: None) -> None:
    """A gateway that predates the columns sends nothing, and that is a NULL."""
    assert _ingest(client, {"host": "nodetail.test", "path": "/"}).status_code == 200
    assert all(v is None for v in _read_row("nodetail.test").values())


def test_a_missing_country_key_is_stored_as_null_and_does_not_fail(
    client: Any, clean_logs: None
) -> None:
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


def test_an_ingested_address_without_a_lookup_is_counted_as_unplotted(
    client: Any, clean_logs: None
) -> None:
    """Capture and aggregation are two halves of one claim; check them joined.

    Nothing has looked these two up yet, so the honest answer is that they are
    counted and not placed - not that they are somewhere.
    """
    _ingest(client, {"host": "joined.test", "path": "/", "ip": "203.0.113.9", "country": "PH"})
    assert _ingest(
        client, {"host": "joined.test", "path": "/", "ip": "203.0.113.8", "country": "US"}
    ).status_code == 200

    body = _geo(client, "views", host="joined.test")
    assert body["points"] == []
    assert body["unlocated"] == 2
    assert body["total"] == 2


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
