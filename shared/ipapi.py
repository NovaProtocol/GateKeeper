"""freeipapi lookups, cached in ``ip_geo`` and fed by a queue.

The audit only ever needs to know *who an address is*, once, and the answer to
that does not change between two page views. So this is built around two
promises:

**Adding an address never costs a request.** Every address the audit sees gets a
row immediately; the lookup itself is queued. That is what ``ip_geo``'s NULL
``fetched_at`` means, and it is why a busy day cannot run the free tier dry - the
queue is a backlog, not a burst.

**A lookup happens once, then not again for a long time.** A row is only
re-fetched once its data is older than :data:`RECHECK_AFTER_S`. When the queue is
empty the worker keeps going on the oldest rows, but never touches anything
younger than :data:`MIN_REFRESH_AGE_S`: a hard floor, so "keep it fresh" cannot
turn into "keep asking".

Between those two, the worker is paced at the free tier's own published limits -
60 requests per minute *and* 10 per 10 seconds - rather than at whatever the loop
manages to issue, because exceeding them is how an IP gets blocked and the whole
feature stops.

Nothing here writes to ``audit_logs``. Cloudflare's country stays what it was;
the lookup is a second opinion kept beside it, and it is the one that wins -
see :func:`decide_country`.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import time
from collections import deque
from typing import Any, Awaitable, Callable

import httpx
import structlog
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shared.models import IpGeo

log = structlog.get_logger("gatekeeper.ipapi")

#: One address, JSON in, JSON out. The free tier needs no key.
API_BASE = "https://free.freeipapi.com/api/v1/json"

#: The published free-tier limits. Both are enforced: 60 in a minute is the
#: headline, 10 in 10 seconds is the one a burst actually trips.
RATE_PER_MINUTE = 60
RATE_PER_10S = 10

#: How old data has to be before it is worth looking up again, and the floor the
#: idle path will not cross. The floor is the more aggressive of the two - the
#: point of it is to use spare budget - so it is what actually bounds an idle
#: worker; the recheck figure is what marks a row as *stale* in the UI.
RECHECK_AFTER_S = 3 * 24 * 60 * 60
MIN_REFRESH_AGE_S = 24 * 60 * 60

#: A failed attempt pushes the row out by doubling from here, capped. Without it
#: one address that always fails would be retried forever, one request a second.
BACKOFF_BASE_S = 60
BACKOFF_MAX_S = 6 * 60 * 60

#: How long the loop waits when there is nothing due at all.
IDLE_SLEEP_S = 60.0

#: The request timeout. The API answers in well under a second.
TIMEOUT_S = 10.0


def utcnow() -> dt.datetime:
    """Naive UTC, matching how the rest of the schema stores timestamps."""
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class RateLimiter:
    """A sliding window over the calls actually made.

    Both published limits in one object, because a caller that respects one and
    not the other still gets blocked. ``retry_after`` answers "how long until a
    call is allowed", which lets the worker sleep exactly that long instead of
    polling.
    """

    def __init__(self, *, per_minute: int = RATE_PER_MINUTE, per_10s: int = RATE_PER_10S) -> None:
        self.per_minute = per_minute
        self.per_10s = per_10s
        self._calls: deque[float] = deque()

    def retry_after(self, now: float) -> float:
        """Seconds to wait before the next call may be made."""
        while self._calls and now - self._calls[0] > 60.0:
            self._calls.popleft()
        wait = 0.0
        if len(self._calls) >= self.per_10s:
            wait = max(wait, self._calls[-self.per_10s] + 10.0 - now)
        if len(self._calls) >= self.per_minute:
            wait = max(wait, self._calls[-self.per_minute] + 60.0 - now)
        return max(0.0, wait)

    def record(self, now: float) -> None:
        self._calls.append(now)


async def fetch(ip: str, *, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
    """One address from freeipapi. Raises on anything that is not a JSON body.

    Raises rather than returning an empty dict so a failed lookup is stored as a
    failure with its reason, instead of being cached as "this address is nowhere".
    """
    url = f"{API_BASE}/{ip}"
    if client is not None:
        response = await client.get(url)
    else:
        async with httpx.AsyncClient(timeout=TIMEOUT_S, follow_redirects=True) as own:
            response = await own.get(url)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict) or not data:
        raise ValueError("freeipapi returned no object")
    return data


def country_of(data: dict[str, Any] | None) -> str | None:
    """The two-letter country the API reported, if it reported a usable one."""
    if not isinstance(data, dict):
        return None
    code = data.get("countryCode")
    if not isinstance(code, str):
        return None
    code = code.strip().upper()
    return code if len(code) == 2 and code.isalpha() else None


def decide_country(cf_country: str | None, lookup_country: str | None) -> dict[str, Any]:
    """Which country the audit should act on, given two answers.

    The lookup wins. Cloudflare's ``CF-IPCountry`` is resolved at the edge and is
    the *tunnel's* opinion; freeipapi resolves the address itself, which is what
    the audit is actually asking about. That ranking is returned explicitly
    rather than left to the reader, and a disagreement is reported as a
    disagreement - never silently resolved into one value.
    """
    cf = (cf_country or "").strip().upper() or None
    looked = (lookup_country or "").strip().upper() or None
    if looked:
        truth = looked
    elif cf:
        truth = cf
    else:
        truth = None
    return {
        "truth": truth,
        "source": "lookup" if looked else ("cloudflare" if cf else None),
        "cf": cf,
        "lookup": looked,
        "mismatch": bool(cf and looked and cf != looked),
    }


def parse(row: IpGeo) -> dict[str, Any] | None:
    """The stored JSON as a dict, or ``None`` when there is nothing usable."""
    if not row.data:
        return None
    try:
        data = json.loads(row.data)
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


async def ensure_queued(session: AsyncSession, ip: str | None) -> bool:
    """Make sure ``ip`` has a row. Returns whether one was added.

    This is the only way an address enters the table, and it never makes a
    request - that is the whole design. Idempotent, so the audit ingest can call
    it for every row it writes.
    """
    address = (ip or "").strip()[:64]
    if not address:
        return False
    existing = await session.get(IpGeo, address)
    if existing is not None:
        return False
    session.add(IpGeo(ip=address, queued_at=utcnow()))
    try:
        await session.commit()
    except IntegrityError:
        # Another writer got there first; the row exists either way.
        await session.rollback()
        return False
    return True


def next_due(now: dt.datetime | None = None):
    """A SELECT for the next address worth looking up, queue first.

    Two populations, in priority order: rows that have never been looked up
    (``fetched_at`` NULL), oldest first, and rows whose data has passed the
    floor, oldest first. A queued row is always the better use of a request -
    it has no answer at all - so the idle path only runs when there is nothing
    queued.
    """
    moment = now or utcnow()
    floor = moment - dt.timedelta(seconds=MIN_REFRESH_AGE_S)
    queued = IpGeo.fetched_at.is_(None)
    return (
        select(IpGeo)
        .where(
            or_(
                and_(queued, IpGeo.queued_at <= moment),
                and_(IpGeo.fetched_at.is_not(None), IpGeo.fetched_at <= floor),
            )
        )
        .order_by(case((queued, 0), else_=1), func.coalesce(IpGeo.fetched_at, IpGeo.queued_at))
        .limit(1)
    )


async def worker_step(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    limiter: RateLimiter | None = None,
    fetcher: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
    now: dt.datetime | None = None,
) -> bool:
    """Look up at most one due address. Returns whether it did any work.

    Split out from the loop so the policy - what is due, what a failure does,
    what the rate limiter refuses - is testable without an app, a network or a
    clock. The clock is a parameter for the same reason.
    """
    limiter = limiter or RateLimiter()
    fetch_one = fetcher or fetch
    if limiter.retry_after(time.monotonic()) > 0:
        return False

    moment = now or utcnow()
    async with sessionmaker() as session:
        row = (await session.execute(next_due(moment))).scalars().first()
        if row is None:
            return False
        address = row.ip

    limiter.record(time.monotonic())
    try:
        data = await fetch_one(address)
    except Exception as exc:  # noqa: BLE001 - a failed lookup is stored as a failure
        async with sessionmaker() as session:
            row = await session.get(IpGeo, address)
            if row is not None:
                row.attempts = int(row.attempts or 0) + 1
                row.last_error = str(exc)[:255]
                # Push the next attempt out, doubling. `queued_at` is the row's
                # earliest retry time, so this is also what stops a permanently
                # broken address from eating the whole budget.
                backoff = min(BACKOFF_BASE_S * (2 ** (row.attempts - 1)), BACKOFF_MAX_S)
                row.queued_at = utcnow() + dt.timedelta(seconds=backoff)
                await session.commit()
        log.warning("ipapi_lookup_failed", ip=address, error=str(exc)[:200])
        return True

    async with sessionmaker() as session:
        row = await session.get(IpGeo, address)
        if row is None:
            return True
        row.data = json.dumps(data, separators=(",", ":"))
        row.country_code = country_of(data)
        row.fetched_at = utcnow()
        row.attempts = 0
        row.last_error = None
        await session.commit()
    log.info("ipapi_lookup_stored", ip=address, country=country_of(data))
    return True


async def worker_loop(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    limiter: RateLimiter | None = None,
    fetcher: Callable[[str], Awaitable[dict[str, Any]]] | None = None,
) -> None:
    """Drain the queue, then keep the oldest rows fresh. Runs until cancelled.

    The sleep is computed from the limiter rather than fixed: when the tier is
    close to its window the loop waits exactly the remaining time, and when
    there is simply nothing due it waits :data:`IDLE_SLEEP_S` and looks again.
    """
    limiter = limiter or RateLimiter()
    while True:
        try:
            worked = await worker_step(sessionmaker, limiter=limiter, fetcher=fetcher)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - the loop must outlive any one failure
            log.warning("ipapi_worker_error", error=str(exc)[:200])
            worked = False
        wait = limiter.retry_after(time.monotonic())
        await asyncio.sleep(wait if wait > 0 else (0.0 if worked else IDLE_SLEEP_S))


def start_worker(sessionmaker: async_sessionmaker[AsyncSession]) -> asyncio.Task[None]:
    """Start the loop as a background task. The caller owns cancelling it."""
    return asyncio.create_task(worker_loop(sessionmaker), name="ipapi-worker")
