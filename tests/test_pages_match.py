"""The precedence and glob rules a custom page is read by.

Data only: no HTTP, no database, no request. Every claim the manage panel and
`documentation/docs/custom-pages.md` make about ordering and matching is pinned
here, so a change to :mod:`shared.pages` that quietly alters what the gate serves
fails in one place rather than in production.

The vocabulary is deliberately not the rules' vocabulary: `*` crosses `/`, so a
page pattern names a URL shape rather than a prefix. The two no-match cases at
the end exist because that is exactly the difference — `/robots.txt` must not
cover `/robots.txt.bak`, and `/a/*` must not cover `/ab`.
"""

from __future__ import annotations

import pytest

from shared.models import CustomPage
from shared.pages import (
    glob_match,
    host_glob_matches,
    pattern_matches,
    sample_from_pattern,
    split_pattern,
)


def page(
    pattern: str, body: str = "x", order: int = 0, active: bool = True, pid: int = 1
) -> CustomPage:
    """A `CustomPage` as the gateway builds one from the API's JSON."""
    p = CustomPage(pattern=pattern, body=body, active=active, display_order=order)
    p.id = pid
    return p


def pick(host: str, path: str, pages: list[CustomPage]) -> CustomPage | None:
    """The gate's own selection, re-derived here rather than called.

    Imported from the gateway module would drag in an app; the rule being pinned
    is `(display_order, id)` ascending, first match wins, inactive skipped.
    """
    for candidate in sorted(pages, key=lambda p: (p.display_order, p.id)):
        if candidate.active is False:
            continue
        if pattern_matches(candidate.pattern, host, path):
            return candidate
    return None


# --------------------------------------------------------------------------- #
# Splitting
# --------------------------------------------------------------------------- #


def test_pattern_splits_at_the_first_slash() -> None:
    assert split_pattern("*.example.com/robots.txt") == ("*.example.com", "/robots.txt")
    assert split_pattern("a.test/x/y") == ("a.test", "/x/y")


@pytest.mark.parametrize(
    "pattern",
    ["robots.txt", "/robots.txt", "example.com", "example.com/", ""],
)
def test_a_pattern_that_is_not_a_url_is_rejected(pattern: str) -> None:
    with pytest.raises(ValueError):
        split_pattern(pattern)


# --------------------------------------------------------------------------- #
# Globbing
# --------------------------------------------------------------------------- #


def test_star_crosses_a_slash() -> None:
    """The whole reason a page glob is not `path_matches`."""
    assert glob_match("/a/*", "/a/b/c")
    assert glob_match("*.example.com", "a.b.example.com")


def test_question_mark_is_exactly_one_character() -> None:
    assert glob_match("/v?", "/v1")
    assert not glob_match("/v?", "/v12")


def test_everything_else_is_literal() -> None:
    """A dot is a dot: the regex metacharacter must not leak through."""
    assert glob_match("/a.b", "/a.b")
    assert not glob_match("/a.b", "/axb")


def test_matching_is_anchored_at_both_ends() -> None:
    assert glob_match("/a", "/a")
    assert not glob_match("/a", "/ab")
    assert not glob_match("/a", "/ba")


# --------------------------------------------------------------------------- #
# Host halves
# --------------------------------------------------------------------------- #


def test_host_comparison_ignores_case() -> None:
    assert host_glob_matches("Example.COM", "example.com")
    assert pattern_matches("Example.COM/robots.txt", "eXaMpLe.cOm", "/robots.txt")


def test_path_comparison_is_case_sensitive() -> None:
    assert pattern_matches("a.test/Robots.txt", "a.test", "/Robots.txt")
    assert not pattern_matches("a.test/robots.txt", "a.test", "/Robots.txt")


def test_a_wildcard_host_also_matches_the_bare_apex() -> None:
    """`*.apex` covers the apex, mirroring `shared.security.host_matches`."""
    assert host_glob_matches("*.example.com", "example.com")
    assert host_glob_matches("*.example.com", "a.example.com")
    assert not host_glob_matches("*.example.com", "example.com.evil.test")


def test_a_lone_star_matches_any_host() -> None:
    assert host_glob_matches("*", "anything.test")


def test_a_port_in_the_host_is_ignored() -> None:
    assert host_glob_matches("a.test", "a.test:443")


def test_an_unreadable_pattern_matches_nothing() -> None:
    """A malformed row must never be the reason a body is served."""
    assert not pattern_matches("not-a-url", "not", "/url")


# --------------------------------------------------------------------------- #
# Precedence
# --------------------------------------------------------------------------- #


def test_the_lowest_display_order_wins() -> None:
    specific = page("a.test/robots.txt", body="specific", order=0, pid=2)
    broad = page("a.test/*", body="broad", order=1, pid=1)
    assert pick("a.test", "/robots.txt", [broad, specific]) is specific


def test_equal_display_order_breaks_on_the_lowest_id() -> None:
    first = page("a.test/robots.txt", body="first", order=0, pid=1)
    second = page("a.test/*", body="second", order=0, pid=2)
    assert pick("a.test", "/robots.txt", [second, first]) is first


def test_an_inactive_page_is_skipped_even_when_it_comes_first() -> None:
    off = page("a.test/*", body="off", order=0, active=False, pid=1)
    on = page("a.test/*", body="on", order=1, active=True, pid=2)
    assert pick("a.test", "/robots.txt", [off, on]) is on


def test_nothing_matches_when_every_page_is_inactive() -> None:
    off = page("a.test/*", body="off", order=0, active=False, pid=1)
    assert pick("a.test", "/robots.txt", [off]) is None


def test_the_first_match_is_the_only_match() -> None:
    """Nothing merges or cascades: a page body is one row's body."""
    first = page("a.test/*", body="first", order=0, pid=1)
    second = page("a.test/*", body="second", order=1, pid=2)
    assert pick("a.test", "/robots.txt", [first, second]).body == "first"


# --------------------------------------------------------------------------- #
# What must not match
# --------------------------------------------------------------------------- #


def test_a_page_for_a_path_does_not_cover_its_neighbour() -> None:
    assert pattern_matches("a.test/robots.txt", "a.test", "/robots.txt")
    assert not pattern_matches("a.test/robots.txt", "a.test", "/robots.txt.bak")


def test_a_prefix_pattern_does_not_cover_a_longer_segment() -> None:
    assert pattern_matches("a.test/a/*", "a.test", "/a/b")
    assert not pattern_matches("a.test/a/*", "a.test", "/ab")


def test_a_page_on_one_host_does_not_match_another() -> None:
    assert pattern_matches("a.test/robots.txt", "a.test", "/robots.txt")
    assert not pattern_matches("a.test/robots.txt", "b.test", "/robots.txt")


# --------------------------------------------------------------------------- #
# The representative URL
# --------------------------------------------------------------------------- #


def test_the_sample_replaces_wildcards_with_a_placeholder() -> None:
    assert sample_from_pattern("*.example.com/robots.txt") == ("x.example.com", "/robots.txt")


def test_the_sample_of_a_literal_pattern_is_itself() -> None:
    assert sample_from_pattern("gatekeeper.example.com/login") == (
        "gatekeeper.example.com",
        "/login",
    )


def test_the_sample_of_a_matched_pattern_actually_matches() -> None:
    """A sample the pattern does not cover would make the banner lie."""
    for pattern in ("*.example.com/*", "a.test/v?", "*/*"):
        host, path = sample_from_pattern(pattern)
        assert pattern_matches(pattern, host, path), pattern
