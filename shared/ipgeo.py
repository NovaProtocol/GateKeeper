"""On-the-spot IP intelligence for the audit view, from the ip66.dev MMDB.

Two decisions shape this module, and both are about what it does NOT do.

**Fetched, not baked.** The database is ~18 MB and rebuilt daily. Downloading it
into ``DB_DIR`` at startup, and only when the local copy is older than a day,
keeps that artifact out of the image and off every layer, while still giving the
audit a real lookup. This is the one place the stance in :mod:`shared.geo` moves:
that module avoids a GeoIP database for a licence, an update cadence and a large
artifact in the image. ip66 is CC BY 4.0 with no key, so the licence is answered;
downloading at runtime answers the size; and the privacy objection there was
about a lookup *service* that would send visitor addresses to a third party,
which a database download does not.

**Looked up, never stored.** A manager viewing an address asks this module at
that moment and reads the answer. Nothing here writes to the audit tables, so
``audit_logs.country`` stays exactly what Cloudflare's header said, no schema
moves and no old row is backfilled. The two sources are allowed to disagree, and
:func:`mismatch` is how the page shows that they do.

Failure is always a ``None``, never an exception: a missing database, an
unreadable one, an address the database does not carry and a refused download all
leave the audit working with the header country it already has.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Callable

import httpx
import maxminddb
import structlog

from shared.config import get_config

log = structlog.get_logger("gatekeeper.ipgeo")

#: The database and how often it is worth re-fetching. The upstream rebuilds
#: daily, so a day is the natural window; the value is a constant rather than an
#: env var because there is nothing deployment-specific about it.
DB_URL = "https://downloads.ip66.dev/db/ip66.mmdb"
DB_FILENAME = "ip66.mmdb"
DB_MAX_AGE_S = 24 * 60 * 60

#: The anonymity flags the database carries per record, as ``record key -> the
#: label the page shows``. Ordered by how much they matter to an operator reading
#: an audit row: a Tor exit is a stronger statement than a hosting provider.
ANON_FLAGS: tuple[tuple[str, str], ...] = (
    ("is_tor_exit_node", "Tor exit node"),
    ("is_public_proxy", "Public proxy"),
    ("is_anonymous_vpn", "Anonymous VPN"),
    ("is_hosting_provider", "Hosting provider"),
)

#: Cached reader, reopened when the file on disk changes (a restart with a fresh
#: download, or a re-fetch while running).
_reader: maxminddb.Reader | None = None
_reader_mtime: float | None = None


def database_path() -> Path:
    """Where the database lives: the same volume the SQLite file uses."""
    return Path(get_config().DB_DIR) / DB_FILENAME


def is_fresh(path: Path | None = None, *, now: float | None = None) -> bool:
    """Is there a copy younger than :data:`DB_MAX_AGE_S`?"""
    target = path if path is not None else database_path()
    try:
        age = (now if now is not None else time.time()) - target.stat().st_mtime
    except OSError:
        return False
    return age < DB_MAX_AGE_S


def _download(dest: Path, *, url: str = DB_URL, timeout: float = 60.0) -> None:
    """Fetch the database to ``dest`` through a temporary file.

    Written beside the target and moved into place with ``os.replace`` so a
    reader never sees a half-written file: the swap is atomic within a
    filesystem, and both paths are in ``DB_DIR``.
    """
    tmp = dest.with_name(dest.name + ".part")
    with httpx.stream("GET", url, timeout=timeout, follow_redirects=True) as response:
        response.raise_for_status()
        with tmp.open("wb") as handle:
            for chunk in response.iter_bytes():
                handle.write(chunk)
    os.replace(tmp, dest)


def ensure_database(
    *,
    path: Path | None = None,
    now: float | None = None,
    fetcher: Callable[[Path], None] | None = None,
) -> bool:
    """Make sure a usable database exists. Returns whether one does.

    Called once at startup. A copy younger than a day is left untouched, which is
    the whole caching rule: the fetch happens on the next startup after it goes
    stale, not on a timer.

    Never raises. A failed download leaves whatever was already there in place -
    a stale database still answers - and a failure with nothing to fall back on
    is reported by returning ``False``, which leaves the audit on its header
    country. ``fetcher`` exists so tests can drive the failure path without a
    network.
    """
    target = path if path is not None else database_path()
    if is_fresh(target, now=now):
        return True
    fetch = fetcher or _download
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fetch(target)
        log.info("ipgeo_database_fetched", path=str(target))
        return True
    except Exception as exc:  # noqa: BLE001 - any failure degrades, never aborts startup
        log.warning("ipgeo_database_fetch_failed", error=str(exc))
        return target.exists()


def _open(path: Path | None = None) -> maxminddb.Reader | None:
    """The cached reader, reopened if the file changed on disk."""
    global _reader, _reader_mtime
    target = path if path is not None else database_path()
    try:
        mtime = target.stat().st_mtime
    except OSError:
        return None
    if _reader is not None and _reader_mtime == mtime:
        return _reader
    if _reader is not None:
        try:
            _reader.close()
        except Exception:  # noqa: BLE001
            pass
        _reader = None
    try:
        _reader = maxminddb.open_database(str(target))
        _reader_mtime = mtime
    except Exception as exc:  # noqa: BLE001 - a corrupt database is a None, not a 500
        log.warning("ipgeo_database_unreadable", error=str(exc))
        return None
    return _reader


def reset() -> None:
    """Drop the cached reader. For tests, and for a caller that just replaced the file."""
    global _reader, _reader_mtime
    if _reader is not None:
        try:
            _reader.close()
        except Exception:  # noqa: BLE001
            pass
    _reader = None
    _reader_mtime = None


def _name(node: Any) -> str | None:
    """The English display name from an MMDB ``names`` map, or ``None``."""
    if not isinstance(node, dict):
        return None
    names = node.get("names")
    if not isinstance(names, dict):
        return None
    value = names.get("en") or next((v for v in names.values() if v), None)
    return str(value) if value else None


def lookup(ip: str) -> dict[str, Any] | None:
    """Everything the database knows about ``ip``, or ``None``.

    The shape is flattened for the page rather than handed over as the raw
    record: the country and continent as code + name, the autonomous system as
    number + organisation, and the anonymity flags as a list of labels, so the
    client has nothing to dig through and no key names to know.
    """
    record = _open()
    if record is None:
        return None
    try:
        data = record.get(ip)
    except Exception:  # noqa: BLE001 - a malformed address is not an error worth a 500
        return None
    if not isinstance(data, dict) or not data:
        return None

    country = data.get("country") if isinstance(data.get("country"), dict) else {}
    continent = data.get("continent") if isinstance(data.get("continent"), dict) else {}
    anon = data.get("anonymous_ip") if isinstance(data.get("anonymous_ip"), dict) else {}

    flags = [label for key, label in ANON_FLAGS if anon.get(key) is True]

    return {
        "ip": ip,
        "country": {
            "code": (country.get("iso_code") or None),
            "name": _name(country),
        },
        "continent": {
            "code": (continent.get("code") or None),
            "name": _name(continent),
        },
        "asn": {
            "number": data.get("autonomous_system_number"),
            "organization": data.get("autonomous_system_organization"),
        },
        "flags": flags,
        "anonymous": anon.get("is_anonymous") is True,
    }


def mismatch(header_country: str | None, looked_up: dict[str, Any] | None) -> bool:
    """Do the tunnel's country and the database's disagree for this address?

    A boolean, not a stored fact: the page uses it to mark a row, and it is
    recomputed on every look rather than written down. ``False`` whenever either
    side is missing - a disagreement needs two answers.
    """
    if not header_country or not looked_up:
        return False
    code = (looked_up.get("country") or {}).get("code")
    if not code:
        return False
    return str(header_country).strip().upper() != str(code).strip().upper()
