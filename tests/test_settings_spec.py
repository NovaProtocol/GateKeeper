"""`shared.settings_spec`: one table, one reader, one direction of failure.

The module exists so a settings key cannot be validated in one place and
interpreted in another. These tests hold the two properties that make it worth
having:

* **the vocabulary is not duplicated.** `unmatched_action` accepts exactly what
  `shared.gate` accepts, so a value the resolver would refuse can never be
  stored, and a value the resolver would accept can never be rejected here;
* **an unreadable value fails in the gating direction.** A row edited by hand,
  or restored from a file written by older code, is normalized before anything
  acts on it, and the fallback for the security-relevant key refuses rather than
  permits. That is Phase 1's invariant seen from the reader's side: a setting
  must not be able to re-open the fail-closed path.
"""

from __future__ import annotations

import pytest

from shared.gate import (
    DEFAULT_UNMATCHED_ACTION,
    UNMATCHED_ACTIONS,
    resolve_rule_action,
)
from shared.settings_spec import (
    LOG_RETENTION_DAYS,
    MAINTENANCE_MESSAGE,
    MAINTENANCE_MESSAGE_MAX,
    MAINTENANCE_MODE,
    MANAGE_FIELDS,
    RATE_LIMIT,
    RETENTION_DEFAULT_DAYS,
    SESSION_LIFETIME_HOURS,
    SETTING_SPECS,
    as_bool,
    as_int,
    default_value,
    read_value,
    validate_value,
)


# --------------------------------------------------------------------------- #
# The vocabulary is shared, not repeated
# --------------------------------------------------------------------------- #


def test_unmatched_action_accepts_exactly_what_the_resolver_accepts() -> None:
    """The two lists are one list. A drift here is a stored value the gate refuses."""
    for action in UNMATCHED_ACTIONS:
        assert validate_value("unmatched_action", action) == action

    for rejected in ("allow", "open", "gate", "custom_password", "", "  ", "none!"):
        with pytest.raises(ValueError):
            validate_value("unmatched_action", rejected)


def test_a_spelled_differently_action_is_normalized_not_refused() -> None:
    """Case and padding are presentation, so they are trimmed rather than rejected."""
    assert validate_value("unmatched_action", "  Access_Code  ") == "access_code"
    assert validate_value("unmatched_action", "DENY") == "deny"


def test_the_manage_fields_are_all_described() -> None:
    assert set(MANAGE_FIELDS) <= set(SETTING_SPECS)


def test_the_gating_action_is_the_default_the_resolver_uses() -> None:
    assert default_value("unmatched_action") == DEFAULT_UNMATCHED_ACTION


# --------------------------------------------------------------------------- #
# The security-critical direction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "stored",
    [None, "", "   ", "allow", "yes", "true", "none_gate", "NONE!", "\x00", "Access Code"],
)
def test_an_unusable_unmatched_action_reads_as_the_gating_default(stored: str | None) -> None:
    """Whatever is in the row, what comes out is the value that refuses."""
    assert read_value("unmatched_action", stored) == DEFAULT_UNMATCHED_ACTION


@pytest.mark.parametrize(
    "stored",
    [None, "", "allow", "yes", "\x00"],
)
def test_an_unusable_setting_cannot_open_the_gate(stored: str | None) -> None:
    """Read through the reader, then resolved: still a refusal.

    This is the whole reason the reader normalizes rather than passing the value
    on. `resolve_rule_action` is asked with the normalized value the gateway
    would use, for a request that matched no group at all, which is the only case
    the setting governs.
    """
    normalized = read_value("unmatched_action", stored)

    assert resolve_rule_action(None, None, normalized) == "access_code"


def test_a_deliberate_permissive_value_still_reads_through() -> None:
    """Normalizing must not defeat the setting: `none` is stored and honoured."""
    assert read_value("unmatched_action", "none") == "none"
    assert resolve_rule_action(None, None, read_value("unmatched_action", "none")) == "none"


def test_a_group_that_matched_without_a_rule_is_refused_whatever_the_setting_says() -> None:
    """Phase 1's invariant, restated where the setting is read."""
    from shared.models import RuleGroup

    group = RuleGroup(name="g", domain="example.test", display_order=0)

    for stored in (None, "none", "deny", "access_code", "nonsense"):
        assert (
            resolve_rule_action(group, None, read_value("unmatched_action", stored))
            == "access_code"
        )


# --------------------------------------------------------------------------- #
# Bounds and fallbacks per key
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("value", "ok"), [(1, True), (720, True), (0, False), (721, False)])
def test_session_lifetime_bounds(value: int, ok: bool) -> None:
    if ok:
        assert validate_value(SESSION_LIFETIME_HOURS, str(value)) == str(value)
    else:
        with pytest.raises(ValueError):
            validate_value(SESSION_LIFETIME_HOURS, str(value))


@pytest.mark.parametrize(("value", "ok"), [(7, True), (3650, True), (6, False), (3651, False)])
def test_retention_bounds(value: int, ok: bool) -> None:
    if ok:
        assert validate_value(LOG_RETENTION_DAYS, str(value)) == str(value)
    else:
        with pytest.raises(ValueError):
            validate_value(LOG_RETENTION_DAYS, str(value))


@pytest.mark.parametrize(
    ("stored", "expected"),
    [("12", 12), (None, 12), ("0", 12), ("-3", 12), ("seven", 12), ("999999", 12)],
)
def test_an_unusable_lifetime_reads_as_the_default(stored: str | None, expected: int) -> None:
    assert as_int(SESSION_LIFETIME_HOURS, stored) == expected


@pytest.mark.parametrize(
    ("stored", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        ("1", True),
        ("false", False),
        ("0", False),
        ("off", False),
        (None, False),
        ("mostly", False),
        ("", False),
    ],
)
def test_an_unusable_maintenance_row_reads_as_off(stored: str | None, expected: bool) -> None:
    """The safe direction for this key is the site staying up, not going dark."""
    assert as_bool(MAINTENANCE_MODE, stored) is expected


def test_the_maintenance_message_is_capped() -> None:
    assert validate_value(MAINTENANCE_MESSAGE, "x" * MAINTENANCE_MESSAGE_MAX)
    with pytest.raises(ValueError):
        validate_value(MAINTENANCE_MESSAGE, "x" * (MAINTENANCE_MESSAGE_MAX + 1))


def test_the_maintenance_message_is_accepted_blank() -> None:
    """Blank is the documented way to say nothing extra."""
    assert validate_value(MAINTENANCE_MESSAGE, "") == ""
    assert validate_value(MAINTENANCE_MESSAGE, "   ") == ""


@pytest.mark.parametrize("raw", ["1", "true", "yes", "on", "TRUE", " 1 "])
def test_every_true_spelling_a_checkbox_or_shell_can_send(raw: str) -> None:
    assert validate_value(MAINTENANCE_MODE, raw) == "true"


def test_a_blank_rate_limit_is_refused_rather_than_defaulted() -> None:
    """The write path refuses; only the read path falls back."""
    with pytest.raises(ValueError):
        validate_value(RATE_LIMIT, "")
    assert read_value(RATE_LIMIT, "") == "5"


def test_an_unknown_key_is_passed_through_unvalidated() -> None:
    assert validate_value("some_future_key", "  spaced  ") == "spaced"
    assert read_value("some_future_key", "anything") == "anything"


def test_the_retention_default_is_a_number_in_range() -> None:
    """A default outside its own bounds would seed a row the panel refuses."""
    stored = validate_value(LOG_RETENTION_DAYS, str(RETENTION_DEFAULT_DAYS))

    assert stored == str(RETENTION_DEFAULT_DAYS)


def test_retention_prefers_the_environment_when_it_is_usable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fresh volume keeps matching the compose file."""
    _reload_config(monkeypatch, LOG_RETENTION_DAYS=45)

    assert default_value(LOG_RETENTION_DAYS) == "45"


def test_retention_ignores_an_environment_value_the_panel_would_refuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An out-of-range env var must not seed a row the panel cannot then edit."""
    _reload_config(monkeypatch, LOG_RETENTION_DAYS=1)

    assert default_value(LOG_RETENTION_DAYS) == str(RETENTION_DEFAULT_DAYS)


def test_retention_falls_back_when_the_environment_value_is_unparseable() -> None:
    """The env var can hold anything a shell can, so the fallback has to hold too."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("shared.settings_spec.get_config", lambda: _Exploding())
        assert default_value(LOG_RETENTION_DAYS) == str(RETENTION_DEFAULT_DAYS)


class _Exploding:
    """A config object whose retention field cannot be coerced to an int."""

    LOG_RETENTION_DAYS = "not-a-number"


def _reload_config(monkeypatch: pytest.MonkeyPatch, **overrides: object) -> None:
    """Swap the cached Settings for one with the fields under test replaced.

    The keyword names are the real field names on ``Settings``, because
    ``model_copy`` matches them exactly: a lower-case spelling would be accepted
    silently and change nothing, which is precisely how a test comes to assert
    the default while believing it set an override.
    """
    from shared import config as config_module

    current = config_module.get_config()
    replacement = current.model_copy(update=overrides)
    monkeypatch.setattr(config_module, "get_config", lambda: replacement)
    monkeypatch.setattr("shared.settings_spec.get_config", lambda: replacement)
