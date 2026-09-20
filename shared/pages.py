"""The single reading of a custom-page pattern.

A custom page is a body the gateway serves itself, matched by a pattern that
describes the whole URL: ``*.projectnova.download/robots.txt``. The pattern is a
glob on **both** halves, which is why it is not read through
:func:`shared.security.host_matches` / :func:`shared.security.path_matches`:

* those implement the *rules* vocabulary, where a path is exact unless it ends
  in ``/*``, a rule for ``/robots.txt`` deliberately does not cover
  ``/robots.txt.bak``, and a rule for ``/a/*`` deliberately does not cover
  ``/ab``. A page is a different object: it names a URL shape to swallow, so
  ``*`` crossing ``/`` and ``?`` standing for a character is the useful
  reading, and the operator sees one row per shape rather than a pair of
  independent host and path patterns that can be recombined.

* a host+path pair in two columns would let a row claim a host match with an
  empty path, which is not a URL. One column cannot.

The comparison follows the rules' conventions otherwise: hosts are compared
case-insensitively, paths are compared case-sensitively, and ``*.apex`` matches
the bare apex as well as any subdomain of it.

This module is pure: no database, no request, no settings. Everything here is
either a decision the gate and the manage panel must agree on or a
representative value derived from a pattern, so both can import one definition
instead of keeping two.
"""

from __future__ import annotations

import re

#: The response type a page carries unless it says otherwise. Plain text with an
#: explicit charset, because ``X-Content-Type-Options: nosniff`` makes this value
#: the only thing a browser has to go on.
DEFAULT_PAGE_CONTENT_TYPE = "text/plain; charset=utf-8"

#: The longest pattern accepted, matching the column width.
PAGE_PATTERN_MAX = 1024

#: The largest body a page may carry, in characters. Deliberate rather than
#: incidental: every page is held whole in the gateway's in-memory cache and
#: re-fetched on each refresh, and there is no streaming path, so this is the
#: bound on ``256 KiB x pages``.
PAGE_BODY_MAX = 256 * 1024

#: A directive value, and never a header injection. A response type becomes a
#: response header, so a CR or LF in it is response splitting rather than a
#: formatting mistake.
_CONTENT_TYPE_RE = re.compile(
    r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+(\s*;\s*charset=[A-Za-z0-9._-]+)?"
)


def validate_pattern(pattern: str) -> str:
    """Return a normalized pattern, or raise :class:`ValueError` naming the fault.

    One definition, used by the API (which turns it into a refusal) and by the
    backup validator (which turns it into a problem line), so a file the API
    could not have produced cannot restore into a row it would reject.
    """
    if not pattern:
        raise ValueError("pattern required")
    if len(pattern) > PAGE_PATTERN_MAX:
        raise ValueError(f"pattern must be {PAGE_PATTERN_MAX} characters or fewer")
    if any(ch.isspace() for ch in pattern):
        raise ValueError("pattern must not contain whitespace")
    if ".." in pattern:
        raise ValueError("pattern must not contain ..")
    split_pattern(pattern)
    return pattern


def validate_content_type(content_type: str) -> str:
    """Return an accepted response type, or raise :class:`ValueError`."""
    if "\r" in content_type or "\n" in content_type:
        raise ValueError("content_type must not contain a line break")
    if not _CONTENT_TYPE_RE.fullmatch(content_type.strip()):
        raise ValueError("content_type must look like type/subtype")
    return content_type.strip()


def split_pattern(pattern: str) -> tuple[str, str]:
    """``(host_glob, path_glob)`` for a pattern, splitting at the first ``/``.

    A pattern that cannot describe a URL, no separator, an empty host half, or
    a path half that does not start with ``/``, raises :class:`ValueError`. The
    API turns that into a refusal and the backup validator into a problem line,
    so the two agree about what a pattern is.
    """
    raw = str(pattern or "").strip()
    if "/" not in raw:
        raise ValueError("pattern must contain /")
    host_glob, _, remainder = raw.partition("/")
    host_glob = host_glob.strip()
    if not host_glob:
        raise ValueError("pattern must name a host before the /")
    if not remainder:
        raise ValueError("pattern must name a path after the /")
    return host_glob, "/" + remainder


def _compile(glob: str) -> re.Pattern[str]:
    """A glob as an anchored regular expression.

    ``*`` matches any sequence including ``/``, ``?`` matches exactly one
    character, and every other character is literal. Anchored at both ends, so a
    pattern cannot match a prefix of a longer value by accident.
    """
    out = []
    for char in glob:
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
    return re.compile("".join(out) + r"\Z")


def glob_match(pattern: str, value: str) -> bool:
    """Whether ``value`` matches ``pattern``, as one glob, anchored.

    Used for both halves of a page pattern. The caller compares the host half
    case-insensitively (lowercasing both) and the path half case-sensitively,
    which is the split :func:`shared.security.host_matches` makes for rules.
    """
    return bool(_compile(str(pattern)).match(str(value)))


def host_glob_matches(host_glob: str, host: str) -> bool:
    """Host half of a pattern against a hostname, case-insensitively.

    ``*.example.com`` also matches the bare ``example.com``, mirroring
    :func:`shared.security.host_matches`, so a page and a rule that both name
    ``*.example.com`` cover the same set of hosts. ``*`` alone matches any host.
    """
    pattern = str(host_glob or "").strip().lower()
    candidate = str(host or "").strip().split(":")[0].split(",")[0].strip().lower()
    if pattern.startswith("*.") and glob_match(pattern[2:], candidate):
        return True
    return glob_match(pattern, candidate)


def pattern_matches(pattern: str, host: str, path: str) -> bool:
    """Whether a request matches a page pattern. Never raises.

    A stored pattern that cannot be split is a data fault, and the safe reading
    of an unreadable pattern is "matches nothing": a page must never be served
    because its own row was malformed.
    """
    try:
        host_glob, path_glob = split_pattern(pattern)
    except ValueError:
        return False
    if not path.startswith("/"):
        path = "/" + path
    return host_glob_matches(host_glob, host) and glob_match(path_glob, path)


def sample_from_pattern(pattern: str) -> tuple[str, str]:
    """A representative ``(host, path)`` for a pattern.

    Used by the manage panel's governing-rule banner and by the tests, so both
    ask the gate about a URL the pattern is meant to cover instead of about the
    pattern itself. It is a **representative**, not a promise: a wildcard can
    span hosts governed by different rule groups, and this can only ever report
    one of them. The panel says so on the row.
    """
    host_glob, path_glob = split_pattern(pattern)
    return _fill(host_glob), _fill(path_glob)


def _fill(glob: str) -> str:
    """Replace the wildcards with a placeholder and collapse the repeats."""
    filled = glob.replace("*", "x").replace("?", "x")
    filled = re.sub(r"x{2,}", "x", filled)
    return filled
