"""Unit tests for :mod:`shared.geo`.

Pure module, no app and no database: ``shared.geo`` decides what lands in
``audit_logs.country`` and what the audit map draws, and both of those are
answers that have to be right for a request whose header may never arrive.

Three groups of claims:

* **the header is read conservatively.** Only two uppercase letters are accepted,
  Cloudflare's "not a country" sentinels are rejected, and anything unusable is
  ``None`` rather than a stored claim. The failure mode of this whole feature is
  a null, so the null path is the one worth testing hardest.
* **the table is usable as data.** Every entry is a real point with a name, so a
  marker cannot be created with a missing or nonsensical coordinate.
* **the map maths is area-honest.** Radius scales with the square root of the
  count, so a circle's *area* is proportional to the number it represents.
"""

from __future__ import annotations

import math
import re

import pytest

from shared.geo import (
    BLOCKED_ACTIONS,
    COUNTRY_HEADERS,
    COUNTRY_INFO,
    DEFAULT_GEO_MODE,
    GEO_MODES,
    MAX_RADIUS,
    MIN_RADIUS,
    UNKNOWN_CC,
    build_points,
    centroid,
    country_name,
    get_country,
    marker_radius,
    normalize_country,
    plot_points,
    summarize,
    totals,
)

CODE_RE = re.compile(r"^[A-Z]{2}$")


# --------------------------------------------------------------------------- #
# The header
# --------------------------------------------------------------------------- #


def test_the_header_precedence_list_is_not_empty() -> None:
    """A module that reads nothing would silently report Unknown forever."""
    assert COUNTRY_HEADERS
    assert all(isinstance(name, str) and name for name in COUNTRY_HEADERS)


def test_a_country_header_is_read_and_used(request_factory) -> None:
    request = request_factory({"CF-IPCountry": "PH"})
    assert get_country(request) == "PH"


def test_surrounding_whitespace_is_stripped(request_factory) -> None:
    request = request_factory({"CF-IPCountry": "  PH  "})
    assert get_country(request) == "PH"


def test_a_missing_header_is_none_and_not_an_error(request_factory) -> None:
    """The documented fallback: no header, no country, nothing raises."""
    request = request_factory({})
    assert get_country(request) is None


def test_an_empty_header_is_none(request_factory) -> None:
    request = request_factory({"CF-IPCountry": "   "})
    assert get_country(request) is None


@pytest.mark.parametrize("value", ["XX", "T1"])
def test_cloudflares_sentinels_are_not_countries(request_factory, value: str) -> None:
    """`XX` means unknown and `T1` means Tor; storing either would be a lie."""
    request = request_factory({"CF-IPCountry": value})
    assert get_country(request) is None


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("ph", id="lowercase"),
        pytest.param("Ph", id="mixed-case"),
        pytest.param("PHL", id="alpha-3"),
        pytest.param("P", id="one-letter"),
        pytest.param("P1", id="digit"),
        pytest.param("P-", id="punctuation"),
        pytest.param("1.2.3.4", id="an-address"),
        pytest.param("<script>", id="markup"),
        pytest.param("\u00d7\u00d7", id="non-ascii"),
        pytest.param("", id="empty"),
    ],
)
def test_anything_but_two_uppercase_letters_is_refused(value: str) -> None:
    assert normalize_country(value) is None


def test_none_is_refused() -> None:
    assert normalize_country(None) is None


def test_a_valid_code_survives_the_normalizer() -> None:
    assert normalize_country("PH") == "PH"


def test_a_lowercase_code_is_rejected_rather_than_upper_cased() -> None:
    """Cloudflare never sends lowercase, so a lowercase value came from elsewhere."""
    assert normalize_country("ph") is None


def test_the_rejection_only_applies_to_the_sentinels_themselves() -> None:
    """`XX` is rejected; `XE` and `TX` are ordinary reserved codes and are kept."""
    assert normalize_country("XX") is None
    assert normalize_country("XXL") is None
    assert normalize_country("XE") == "XE"


# --------------------------------------------------------------------------- #
# The centroid table
# --------------------------------------------------------------------------- #


def test_the_table_covers_the_world_not_a_handful_of_countries() -> None:
    assert len(COUNTRY_INFO) >= 240, len(COUNTRY_INFO)


@pytest.mark.parametrize("cc", sorted(COUNTRY_INFO))
def test_every_entry_is_a_well_formed_point(cc: str) -> None:
    assert CODE_RE.match(cc), f"{cc} is not an ISO 3166-1 alpha-2 code"
    entry = COUNTRY_INFO[cc]
    assert len(entry) == 3, entry
    lat, lon, name = entry
    assert -90.0 <= lat <= 90.0, f"{cc} latitude {lat} is off the globe"
    assert -180.0 <= lon <= 180.0, f"{cc} longitude {lon} is off the globe"
    assert isinstance(name, str) and name.strip(), f"{cc} has no display name"


def test_no_entry_is_merely_a_placeholder_at_the_null_island() -> None:
    """A missing coordinate silently routed through (0, 0) would be a bug marker."""
    at_zero = [cc for cc, (lat, lon, _) in COUNTRY_INFO.items() if lat == 0 and lon == 0]
    assert at_zero == [], at_zero


def test_the_obvious_countries_are_present() -> None:
    for cc in ("PH", "US", "GB", "DE", "IN", "AU", "ZA", "BR", "JP", "SG"):
        assert cc in COUNTRY_INFO, cc


def test_centroid_returns_the_point_for_a_known_code() -> None:
    lat, lon = centroid("PH")
    assert lat == COUNTRY_INFO["PH"][0]
    assert lon == COUNTRY_INFO["PH"][1]


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("ZZ", id="unassigned"),
        pytest.param("", id="empty"),
        pytest.param(None, id="none"),
    ],
)
def test_centroid_is_none_for_a_code_the_table_does_not_carry(value: str | None) -> None:
    assert centroid(value) is None


def test_centroid_upper_cases_before_looking_up() -> None:
    """Lookup is not the same question as capture: a stored `PH` is `PH`."""
    assert centroid("ph") == centroid("PH")


def test_country_name_uses_the_display_name() -> None:
    assert country_name("PH") == COUNTRY_INFO["PH"][2]
    assert country_name("PH") != "PH"


def test_an_unknown_code_keeps_its_code_rather_than_becoming_unknown() -> None:
    """A real code this table happens not to carry is still a real country."""
    assert country_name("XE") == "XE"


def test_a_missing_code_is_unknown() -> None:
    assert country_name(None) == UNKNOWN_CC
    assert country_name("") == UNKNOWN_CC


# --------------------------------------------------------------------------- #
# Radius and share
# --------------------------------------------------------------------------- #


def test_radius_is_zero_when_there_is_nothing_to_show() -> None:
    assert marker_radius(0, 10) == 0.0
    assert marker_radius(5, 0) == 0.0


def test_the_biggest_country_gets_the_maximum_and_no_radius_escapes_the_bounds() -> None:
    assert marker_radius(100, 100) == MAX_RADIUS
    for count in range(1, 101):
        radius = marker_radius(count, 100)
        assert MIN_RADIUS <= radius <= MAX_RADIUS, (count, radius)


def test_radius_scales_with_the_square_root_so_area_tracks_the_count() -> None:
    """Four times the count is four times the area, not four times the radius."""
    biggest = marker_radius(100, 100)
    quarter = marker_radius(25, 100)
    share = (quarter - MIN_RADIUS) / (biggest - MIN_RADIUS)
    assert math.isclose(share, math.sqrt(25 / 100), rel_tol=1e-6)
    assert quarter < biggest


def test_radius_never_exceeds_the_maximum() -> None:
    assert marker_radius(1000, 100) == MAX_RADIUS


# --------------------------------------------------------------------------- #
# Building the points
# --------------------------------------------------------------------------- #


def test_points_are_sorted_by_count_then_name() -> None:
    points = build_points([("US", 5), ("PH", 9), ("DE", 5)])
    assert [(p["cc"], p["count"]) for p in points] == [("PH", 9), ("DE", 5), ("US", 5)]


def test_every_point_carries_its_centroid_and_name() -> None:
    points = build_points([("PH", 3)])
    assert points[0]["lat"] == COUNTRY_INFO["PH"][0]
    assert points[0]["lon"] == COUNTRY_INFO["PH"][1]
    assert points[0]["name"] == COUNTRY_INFO["PH"][2]


def test_shares_add_up_across_every_bucket() -> None:
    points = build_points([("PH", 3), ("US", 1)])
    assert points[0]["share"] == 0.75
    assert points[1]["share"] == 0.25
    assert math.isclose(sum(p["share"] for p in points), 1.0, rel_tol=1e-9)


def test_the_unknown_bucket_is_appended_last_and_only_when_rows_lacked_a_country() -> None:
    with_unknown = build_points([("PH", 3), (None, 2)])
    assert with_unknown[-1]["name"] == UNKNOWN_CC
    assert with_unknown[-1]["cc"] is None
    assert with_unknown[-1]["count"] == 2
    assert with_unknown[-1]["share"] == 0.4

    without = build_points([("PH", 3)])
    assert [p["name"] for p in without] == [COUNTRY_INFO["PH"][2]]


def test_the_unknown_bucket_has_no_point_to_plot() -> None:
    points = build_points([(None, 4), ("PH", 1)])
    assert [p["name"] for p in plot_points(points)] == [COUNTRY_INFO["PH"][2]]


def test_a_country_with_no_centroid_still_counts_in_the_total() -> None:
    """It is data; it just has nowhere to be drawn."""
    points = build_points([("XE", 2), ("PH", 6)])
    assert totals(points) == 8
    assert [p["cc"] for p in plot_points(points)] == ["PH"]
    assert points[0]["cc"] == "PH"


def test_zero_and_negative_counts_are_dropped() -> None:
    assert build_points([("PH", 0), ("US", -3)]) == []


def test_an_empty_input_produces_an_empty_list() -> None:
    assert build_points([]) == []
    assert totals([]) == 0


def test_a_null_country_alone_produces_only_the_unknown_bucket() -> None:
    """The state the page is in if `CF-IPCountry` never arrives at all."""
    points = build_points([(None, 8162)])
    assert len(points) == 1
    assert points[0]["name"] == UNKNOWN_CC
    assert points[0]["lat"] is None and points[0]["lon"] is None
    assert plot_points(points) == []
    assert totals(points) == 8162


def test_shares_are_rounded_so_the_page_does_not_render_a_dozen_digits() -> None:
    points = build_points([("PH", 1), ("US", 2)])
    assert all(len(str(p["share"]).split(".")[-1]) <= 4 for p in points)


# --------------------------------------------------------------------------- #
# The text summary
# --------------------------------------------------------------------------- #


def test_the_summary_names_the_largest_countries_with_their_counts() -> None:
    points = build_points([("PH", 9), ("US", 4)])
    text = summarize(points)
    assert COUNTRY_INFO["PH"][2] in text
    assert "9" in text
    assert COUNTRY_INFO["US"][2] in text


def test_the_summary_counts_the_remainder_rather_than_listing_everything() -> None:
    points = build_points([("PH", 9), ("US", 4), ("DE", 2), ("FR", 1)])
    text = summarize(points, limit=2)
    assert "and 2 more" in text


def test_the_summary_says_so_when_a_single_country_is_all_there_is() -> None:
    text = summarize(build_points([("PH", 1)]))
    assert text.endswith(".")
    assert "more" not in text


def test_the_summary_handles_no_data() -> None:
    assert summarize([]) == "No country data recorded yet."


def test_the_summary_includes_the_unknown_bucket() -> None:
    """Otherwise the one number that explains the missing map would be hidden."""
    text = summarize(build_points([(None, 7), ("PH", 2)]))
    assert UNKNOWN_CC in text


# --------------------------------------------------------------------------- #
# The vocabulary
# --------------------------------------------------------------------------- #


def test_the_modes_are_the_four_the_page_offers() -> None:
    assert GEO_MODES == ("views", "visitors", "gated", "blocked")
    assert DEFAULT_GEO_MODE in GEO_MODES


def test_every_blocked_action_is_a_real_gate_action() -> None:
    """The list is a claim about what the gate writes; a typo would count nothing."""
    for action in BLOCKED_ACTIONS:
        assert action == action.strip()
        assert action == action.lower()
    assert "access_code_fail" in BLOCKED_ACTIONS
    assert "deny" in BLOCKED_ACTIONS
