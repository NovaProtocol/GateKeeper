"""Unit tests for :mod:`shared.client_ip`.

Pure module — no app, no client fixture. ``shared.client_ip`` is what decides
what lands in ``audit_logs.ip`` and what keys the per-IP rate limiter, so the
precedence order is the whole contract.
"""

from __future__ import annotations

from shared.client_ip import get_client_ip


def test_cf_connecting_ip_wins_over_every_other_header(request_factory) -> None:
    request = request_factory(
        {
            "CF-Connecting-IP": "203.0.113.1",
            "True-Client-IP": "203.0.113.2",
            "X-Real-IP": "203.0.113.3",
            "X-Forwarded-For": "203.0.113.4, 172.18.0.5",
        }
    )
    assert get_client_ip(request) == "203.0.113.1"


def test_true_client_ip_wins_when_cf_header_absent(request_factory) -> None:
    request = request_factory(
        {
            "True-Client-IP": "203.0.113.2",
            "X-Real-IP": "203.0.113.3",
            "X-Forwarded-For": "203.0.113.4, 172.18.0.5",
        }
    )
    assert get_client_ip(request) == "203.0.113.2"


def test_x_real_ip_wins_when_the_first_two_are_absent(request_factory) -> None:
    request = request_factory(
        {
            "X-Real-IP": "203.0.113.3",
            "X-Forwarded-For": "203.0.113.4, 172.18.0.5",
        }
    )
    assert get_client_ip(request) == "203.0.113.3"


def test_x_forwarded_for_is_the_last_header_resort(request_factory) -> None:
    request = request_factory({"X-Forwarded-For": "203.0.113.4, 172.18.0.5"})
    assert get_client_ip(request) == "203.0.113.4"


def test_x_forwarded_for_takes_the_left_most_entry(request_factory) -> None:
    request = request_factory({"X-Forwarded-For": "203.0.113.4,172.18.0.5,10.0.0.1"})
    assert get_client_ip(request) == "203.0.113.4"


def test_blank_highest_priority_header_falls_through(request_factory) -> None:
    request = request_factory(
        {
            "CF-Connecting-IP": "   ",
            "True-Client-IP": "203.0.113.2",
        }
    )
    assert get_client_ip(request) == "203.0.113.2"


def test_empty_highest_priority_header_falls_through(request_factory) -> None:
    request = request_factory(
        {
            "CF-Connecting-IP": "",
            "X-Real-IP": "203.0.113.3",
        }
    )
    assert get_client_ip(request) == "203.0.113.3"


def test_peer_address_is_used_when_no_headers_are_present(request_factory) -> None:
    request = request_factory({}, client=("198.51.100.7", 44444))
    assert get_client_ip(request) == "198.51.100.7"


def test_sentinel_returned_when_client_is_missing(request_factory) -> None:
    request = request_factory({}, client=None)
    assert get_client_ip(request) == "0.0.0.0"


def test_header_value_is_truncated_to_64_chars(request_factory) -> None:
    request = request_factory({"CF-Connecting-IP": "1" * 100})
    assert get_client_ip(request) == "1" * 64


def test_peer_value_is_truncated_to_64_chars(request_factory) -> None:
    request = request_factory({}, client=("9" * 100, 1234))
    assert get_client_ip(request) == "9" * 64


def test_surrounding_whitespace_is_stripped(request_factory) -> None:
    request = request_factory({"CF-Connecting-IP": "  203.0.113.1  "})
    assert get_client_ip(request) == "203.0.113.1"


def test_packet_ipv6_value_is_returned_untouched(request_factory) -> None:
    request = request_factory({"CF-Connecting-IP": "2001:db8::1"})
    assert get_client_ip(request) == "2001:db8::1"
