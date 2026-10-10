"""Unit tests for :mod:`shared.ipgeo`.

The module has one job that matters and two that are easy to get wrong:

* the caching rule is a file mtime - a copy younger than a day must not be
  re-fetched, an older one must be - and a failed fetch must keep whatever was
  already there instead of taking the audit down with it;
* the record mapping has to survive a database that answers differently from the
  sample, so the tests drive a fake reader rather than the real file.

Nothing here touches the network: the download is a parameter, and the reader is
monkeypatched.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from shared import ipgeo


class FakeReader:
    """The one method the module uses, returning a canned record per address."""

    def __init__(self, records: dict[str, object]) -> None:
        self.records = records
        self.closed = False

    def get(self, ip: str):  # noqa: ANN201 - mirrors maxminddb.Reader.get
        return self.records.get(ip)

    def close(self) -> None:
        self.closed = True


GOOGLE = {
    "country": {"iso_code": "US", "names": {"en": "United States"}},
    "continent": {"code": "NA", "names": {"en": "North America"}},
    "autonomous_system_number": 15169,
    "autonomous_system_organization": "Google LLC",
    "anonymous_ip": {"is_tor_exit_node": False, "is_hosting_provider": True, "is_anonymous": True},
}


@pytest.fixture(autouse=True)
def _clean_reader():
    """Each test starts and ends with no cached reader."""
    ipgeo.reset()
    yield
    ipgeo.reset()


# --------------------------------------------------------------------------- #
# The caching rule
# --------------------------------------------------------------------------- #


def test_a_fresh_copy_is_kept(tmp_path: Path) -> None:
    target = tmp_path / "ip66.mmdb"
    target.write_bytes(b"x")
    assert ipgeo.is_fresh(target, now=target.stat().st_mtime + 60) is True


def test_a_copy_older_than_a_day_is_stale(tmp_path: Path) -> None:
    target = tmp_path / "ip66.mmdb"
    target.write_bytes(b"x")
    assert ipgeo.is_fresh(target, now=target.stat().st_mtime + ipgeo.DB_MAX_AGE_S + 1) is False


def test_a_missing_copy_is_not_fresh(tmp_path: Path) -> None:
    assert ipgeo.is_fresh(tmp_path / "nope.mmdb") is False


def test_a_fresh_copy_is_not_re_fetched(tmp_path: Path) -> None:
    target = tmp_path / "ip66.mmdb"
    target.write_bytes(b"x")
    calls = []

    def fetcher(dest: Path) -> None:
        calls.append(dest)

    assert ipgeo.ensure_database(path=target, now=target.stat().st_mtime + 60, fetcher=fetcher) is True
    assert calls == [], "a copy younger than a day must be left alone"


def test_a_stale_copy_is_re_fetched(tmp_path: Path) -> None:
    target = tmp_path / "ip66.mmdb"
    target.write_bytes(b"old")
    calls = []

    def fetcher(dest: Path) -> None:
        calls.append(dest)
        dest.write_bytes(b"new")

    assert ipgeo.ensure_database(path=target, now=target.stat().st_mtime + ipgeo.DB_MAX_AGE_S + 1, fetcher=fetcher) is True
    assert calls == [target]
    assert target.read_bytes() == b"new"


def test_a_failed_fetch_keeps_the_previous_file(tmp_path: Path) -> None:
    """A stale database still answers, so a failed refresh must not delete it."""
    target = tmp_path / "ip66.mmdb"
    target.write_bytes(b"old")

    def fetcher(dest: Path) -> None:
        raise RuntimeError("offline")

    assert ipgeo.ensure_database(path=target, now=time.time() + ipgeo.DB_MAX_AGE_S + 1, fetcher=fetcher) is True
    assert target.read_bytes() == b"old"


def test_a_failed_fetch_with_nothing_to_fall_back_on_is_false(tmp_path: Path) -> None:
    """Nothing to answer with: the audit stays on the header country."""

    def fetcher(dest: Path) -> None:
        raise RuntimeError("offline")

    assert ipgeo.ensure_database(path=tmp_path / "none.mmdb", fetcher=fetcher) is False


# --------------------------------------------------------------------------- #
# The record mapping
# --------------------------------------------------------------------------- #


def test_a_known_address_maps_to_the_page_shape(monkeypatch) -> None:
    monkeypatch.setattr(ipgeo, "_open", lambda path=None: FakeReader({"1.2.3.4": GOOGLE}))
    info = ipgeo.lookup("1.2.3.4")
    assert info is not None
    assert info["country"] == {"code": "US", "name": "United States"}
    assert info["continent"] == {"code": "NA", "name": "North America"}
    assert info["asn"] == {"number": 15169, "organization": "Google LLC"}
    assert "Hosting provider" in info["flags"]
    assert "Tor exit node" not in info["flags"]
    assert info["anonymous"] is True


def test_an_unknown_address_is_none(monkeypatch) -> None:
    monkeypatch.setattr(ipgeo, "_open", lambda path=None: FakeReader({}))
    assert ipgeo.lookup("9.9.9.9") is None


def test_a_missing_database_is_none(monkeypatch) -> None:
    monkeypatch.setattr(ipgeo, "_open", lambda path=None: None)
    assert ipgeo.lookup("1.2.3.4") is None


def test_a_reader_that_raises_is_none(monkeypatch) -> None:
    class Boom:
        def get(self, ip):
            raise ValueError("bad address")

    monkeypatch.setattr(ipgeo, "_open", lambda path=None: Boom())
    assert ipgeo.lookup("not-an-ip") is None


def test_an_empty_record_is_none(monkeypatch) -> None:
    monkeypatch.setattr(ipgeo, "_open", lambda path=None: FakeReader({"1.2.3.4": {}}))
    assert ipgeo.lookup("1.2.3.4") is None


def test_a_record_without_a_country_still_maps(monkeypatch) -> None:
    """The fields are independent; a missing country must not lose the ASN."""
    monkeypatch.setattr(ipgeo, "_open", lambda path=None: FakeReader({"1.2.3.4": {"autonomous_system_number": 64500}}))
    info = ipgeo.lookup("1.2.3.4")
    assert info is not None
    assert info["country"] == {"code": None, "name": None}
    assert info["asn"]["number"] == 64500
    assert info["flags"] == []


def test_a_non_english_only_record_still_gets_a_name(monkeypatch) -> None:
    monkeypatch.setattr(
        ipgeo,
        "_open",
        lambda path=None: FakeReader({"1.2.3.4": {"country": {"iso_code": "FR", "names": {"fr": "France"}}}}),
    )
    info = ipgeo.lookup("1.2.3.4")
    assert info is not None
    assert info["country"]["name"] == "France"


# --------------------------------------------------------------------------- #
# The mismatch flag
# --------------------------------------------------------------------------- #


def test_no_mismatch_without_both_sides() -> None:
    assert ipgeo.mismatch(None, {"country": {"code": "US"}}) is False
    assert ipgeo.mismatch("US", None) is False
    assert ipgeo.mismatch("US", {"country": {}}) is False


def test_matching_countries_are_not_a_mismatch() -> None:
    assert ipgeo.mismatch("US", {"country": {"code": "US"}}) is False


def test_different_countries_are_a_mismatch() -> None:
    assert ipgeo.mismatch("US", {"country": {"code": "AU"}}) is True


def test_the_comparison_ignores_case_and_space() -> None:
    assert ipgeo.mismatch(" us ", {"country": {"code": "US"}}) is False
