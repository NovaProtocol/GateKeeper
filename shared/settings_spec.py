"""The gateway's settings: what each key accepts, and what it falls back to.

Every settings key that changes behaviour is described here exactly once. Three
callers read this table and none of them re-implements a rule from it:

* ``api`` validates a ``PUT /api/settings/{key}`` against it, so an invalid value
  is refused at the only write path;
* ``auth-gateway`` and ``management`` read a stored value through
  :func:`read_value`, so a row edited outside the panel cannot change behaviour to
  something the panel would refuse;
* the manage settings page builds its form from :data:`MANAGE_FIELDS`, so a key
  cannot exist in the database and be unreachable in the UI.

The fallback direction is deliberately the *safe* reading of each key, not the
convenient one. ``unmatched_action`` falls back to ``access_code``, which refuses
a request it cannot classify, and ``maintenance_mode`` falls back to ``false``,
because defaulting a gateway into an outage on a settings blip would take the
site down rather than protect it. A key whose value cannot be read is therefore
never more permissive than the documented default.

The vocabulary for ``unmatched_action`` is owned by :mod:`shared.gate`; this
module imports it rather than repeating it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from shared.config import get_config
from shared.gate import (
    DEFAULT_UNMATCHED_ACTION,
    UNMATCHED_ACTIONS,
)

#: Keys an operator may set from the manage panel, in the order the page shows
#: them. Everything outside this tuple is still accepted by the API (unchanged
#: behaviour) but has no control and no validation.
MANAGE_FIELDS = (
    "unmatched_action",
    "rate_limit_access_code_per_min",
    "session_lifetime_hours",
    "maintenance_mode",
    "maintenance_message",
    "log_retention_days",
    "geo_lookup_enabled",
)

UNMATCHED_ACTION = "unmatched_action"
RATE_LIMIT = "rate_limit_access_code_per_min"
SESSION_LIFETIME_HOURS = "session_lifetime_hours"
MAINTENANCE_MODE = "maintenance_mode"
MAINTENANCE_MESSAGE = "maintenance_message"
LOG_RETENTION_DAYS = "log_retention_days"
GEO_LOOKUP_ENABLED = "geo_lookup_enabled"

#: The longest maintenance notice the page will render.
MAINTENANCE_MESSAGE_MAX = 200

SESSION_LIFETIME_MIN = 1
SESSION_LIFETIME_MAX = 720

RETENTION_MIN = 7
RETENTION_MAX = 3650

#: Hard fallback for the log retention window, used when `LOG_RETENTION_DAYS` is
#: absent or outside the range the panel accepts.
RETENTION_DEFAULT_DAYS = 30

RATE_LIMIT_MIN = 1
RATE_LIMIT_MAX = 1000

_TRUE_WORDS = ("true", "1", "yes", "on")
_FALSE_WORDS = ("false", "0", "no", "off")


@dataclass(frozen=True)
class SettingSpec:
    """One settings key: its default, its accepted values, and its note."""

    key: str
    default: str
    validate: Callable[[str], str]
    #: Field on :class:`shared.config.Settings` this default is seeded from, when
    #: the key has an environment variable of its own.
    env_var: str | None = None


def _as_int(raw: Any) -> int:
    text = str(raw).strip()
    try:
        return int(text)
    except (TypeError, ValueError):
        raise ValueError("must be a whole number") from None


def _validate_unmatched_action(raw: Any) -> str:
    value = str(raw).strip().lower()
    if value not in UNMATCHED_ACTIONS:
        raise ValueError("must be one of " + ", ".join(UNMATCHED_ACTIONS))
    return value


def _validate_rate_limit(raw: Any) -> str:
    value = _as_int(raw)
    if not (RATE_LIMIT_MIN <= value <= RATE_LIMIT_MAX):
        raise ValueError(f"must be {RATE_LIMIT_MIN}..{RATE_LIMIT_MAX}")
    return str(value)


def _validate_session_lifetime(raw: Any) -> str:
    value = _as_int(raw)
    if not (SESSION_LIFETIME_MIN <= value <= SESSION_LIFETIME_MAX):
        raise ValueError(f"must be {SESSION_LIFETIME_MIN}..{SESSION_LIFETIME_MAX}")
    return str(value)


def _validate_retention(raw: Any) -> str:
    value = _as_int(raw)
    if not (RETENTION_MIN <= value <= RETENTION_MAX):
        raise ValueError(f"must be {RETENTION_MIN}..{RETENTION_MAX}")
    return str(value)


def normalize_bool(raw: Any) -> str | None:
    """``"true"``/``"false"`` for any spelling a checkbox or shell can produce."""
    text = str(raw).strip().lower()
    if text in _TRUE_WORDS:
        return "true"
    if text in _FALSE_WORDS:
        return "false"
    return None


def _validate_bool(raw: Any) -> str:
    value = normalize_bool(raw)
    if value is None:
        raise ValueError("must be true or false")
    return value


def _validate_message(raw: Any) -> str:
    value = str(raw).strip()
    if len(value) > MAINTENANCE_MESSAGE_MAX:
        raise ValueError(f"must be at most {MAINTENANCE_MESSAGE_MAX} characters")
    return value


SETTING_SPECS: dict[str, SettingSpec] = {
    UNMATCHED_ACTION: SettingSpec(
        UNMATCHED_ACTION, DEFAULT_UNMATCHED_ACTION, _validate_unmatched_action
    ),
    RATE_LIMIT: SettingSpec(RATE_LIMIT, "5", _validate_rate_limit),
    SESSION_LIFETIME_HOURS: SettingSpec(SESSION_LIFETIME_HOURS, "12", _validate_session_lifetime),
    MAINTENANCE_MODE: SettingSpec(MAINTENANCE_MODE, "false", _validate_bool),
    MAINTENANCE_MESSAGE: SettingSpec(MAINTENANCE_MESSAGE, "", _validate_message),
    LOG_RETENTION_DAYS: SettingSpec(
        LOG_RETENTION_DAYS,
        str(RETENTION_DEFAULT_DAYS),
        _validate_retention,
        env_var="LOG_RETENTION_DAYS",
    ),
    GEO_LOOKUP_ENABLED: SettingSpec(GEO_LOOKUP_ENABLED, "true", _validate_bool),
}


def default_value(key: str) -> str:
    """The value a missing row behaves as.

    A key with an environment variable of its own prefers that variable, so a
    fresh volume keeps matching the compose file, but only when the environment
    value would itself be accepted by the panel. An out-of-range
    `LOG_RETENTION_DAYS` falls back to the built-in window rather than seeding a
    row the panel would refuse to edit.
    """
    spec = SETTING_SPECS[key]
    if spec.env_var:
        try:
            return spec.validate(getattr(get_config(), spec.env_var))
        except (ValueError, TypeError, AttributeError):
            pass
    return spec.default


def validate_value(key: str, raw: Any) -> str:
    """The stored form of ``raw`` for ``key``, or ``ValueError`` with the reason.

    ``None`` is refused outright rather than stringified. A settings row whose
    value is NULL would otherwise become the literal ``"none"``, which is a valid
    ``unmatched_action`` and the permissive one: an absent value would silently
    become the setting that stops gating. Anything that arrives here is a stored
    value and has to be real.
    """
    if raw is None:
        raise ValueError("must not be empty")
    spec = SETTING_SPECS.get(key)
    if spec is None:
        return str(raw).strip()
    return spec.validate(raw)


def read_value(key: str, raw: Any | None) -> str:
    """A stored value as the app should use it, falling back to the default.

    This is the reader-side guard. The API refuses to store a bad value, but the
    database can still be edited by hand or restored from an older file, and no
    reader may act on a value the writer would have rejected. A NULL row is one
    of those cases and takes the same fallback as any other unusable value.
    """
    try:
        return validate_value(key, raw)
    except ValueError:
        return default_value(key)


def as_bool(key: str, raw: Any | None) -> bool:
    return read_value(key, raw) == "true"


def as_int(key: str, raw: Any | None) -> int:
    return int(read_value(key, raw))


def default_int(key: str) -> int:
    return int(default_value(key))


def is_manage_field(key: str) -> bool:
    return key in MANAGE_FIELDS
