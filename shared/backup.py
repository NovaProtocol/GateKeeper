"""Signed plain-JSON export and restore of the gateway's configuration.

Rules, rule groups, routes, codes and settings live only in the database volume.
None of them are in git and there is no migration to roll back, so a wrong click
has no undo. This module is the export that makes one possible.

The file is plain, human-readable JSON with a signature field. It is not a JWT:

    {"version": 1, "created_at": "...", "config": {...}, "sig": "<hex>"}

``sig`` is HMAC-SHA256 over the **canonicalised config only**, keyed by
``SECRET_KEY``. Signing the config rather than the whole envelope means the
envelope can carry extra metadata (``created_at``, and anything a later version
adds) without invalidating the file, while every byte that is restored stays
covered. Canonicalisation is ``json.dumps(..., sort_keys=True,
separators=(",", ":"))`` plus a stable row order, so the same configuration
always produces the same signature.

What it does not do: confidentiality. Every access code is in the file in
cleartext. ``sig`` proves the file was produced by this deployment and has not
been altered; it says nothing about who can read it.

Row ids are preserved across a restore so ``audit_logs.code_id``,
``rule_id`` and ``rule_group_id`` keep pointing at the same objects. Where the
restored configuration no longer contains a referenced row, the reference is
nulled rather than deleted: the audit row survives, it just stops claiming a
target that is gone.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from shared.config import get_config
from shared.models import AuditLog, Code, CustomPage, Route, Rule, RuleGroup, Setting
from shared.pages import (
    DEFAULT_PAGE_CONTENT_TYPE,
    PAGE_BODY_MAX,
    validate_content_type,
    validate_pattern,
)
from shared.rule_defaults import DEFAULT_ACTIVE_READING
from shared.security import is_valid_host

#: Bump when the config shape changes in a way old files cannot satisfy.
VERSION = 1

#: The config sections, also the restore order (FK-safe: groups before rules).
SECTIONS = ("routes", "groups", "rules", "codes", "settings")

#: Sections a file may carry **in addition** to `SECTIONS`. These are optional:
#: absent means empty, and they are not part of the unknown-key check.
#:
#: `pages` is here rather than in `SECTIONS` for a reason that is load-bearing.
#: `validate()` refuses a file with a missing required section, so promoting
#: `pages` would make every backup taken before this feature unusable, and
#: bumping `VERSION` would refuse those files too. Either would destroy the
#: owner's only rollback point at exactly the moment it is needed. Optional and
#: absent is the only shape that keeps an old file restorable.
OPTIONAL_SECTIONS = ("pages",)

ACTIONS = ("access_code", "none", "custom_password", "deny")
ROUTE_TYPES = ("proxy", "redirect")
REDIRECT_CODES = (301, 302, 307, 308)

#: Audit columns that point at a restored row, and the section each mirrors.
AUDIT_REFERENCES = {
    "code_id": "codes",
    "rule_id": "rules",
    "rule_group_id": "groups",
}

#: `rules.is_default` arrives with the mandatory-catch-all work. Present only so
#: a configuration written before that column existed still restores after it.
RULES_HAVE_IS_DEFAULT = hasattr(Rule, "is_default")

#: The reading of an absent ``rules[].active``: **active**. The same reading the
#: gateway, the ORM and the gate use, imported rather than restated so a file, a
#: cache and a database cannot disagree about what silence means.
#:
#: Keeping the field optional is what keeps old files restorable. A required
#: ``active`` would refuse every backup taken before the column existed, which
#: would destroy the owner's only rollback point at exactly the moment a schema
#: change makes it worth having. That is also why ``VERSION`` stays 1: this is a
#: field inside the existing ``rules`` section, not a new section, so old and new
#: files both validate.
RULES_ACTIVE_DEFAULT = DEFAULT_ACTIVE_READING

#: Settings the panel writes about itself rather than configuration the gateway
#: runs on. Left out of the file: `backup_exported_at` changes on every export,
#: so including it would give an unchanged gateway a different signature each
#: time and break the one property the signature is supposed to have.
BOOKKEEPING_SETTINGS = ("backup_exported_at",)


def canonical(obj: Any) -> str:
    """Deterministic text for a value: sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign(config: dict[str, Any], secret: str | None = None) -> str:
    """HMAC-SHA256 (hex) over the canonicalised config."""
    key = secret or get_config().SECRET_KEY
    digest = hmac.new(key.encode("utf-8"), canonical(config).encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def verify(blob: Any, secret: str | None = None) -> tuple[bool, str]:
    """Check a decoded backup file. Returns ``(ok, reason)``.

    Reasons: ``ok``, ``bad-json``, ``bad-version``, ``missing-sig``,
    ``bad-sig``, ``bad-config``. The version is checked before the signature so
    a file from a future version is refused as such rather than as corrupt.
    """
    if not isinstance(blob, dict):
        return False, "bad-json"
    version = blob.get("version")
    # `True == 1` in Python, so a boolean has to be excluded explicitly or a
    # `"version": true` file would pass as version 1.
    if isinstance(version, bool) or not isinstance(version, int) or version != VERSION:
        return False, "bad-version"
    config = blob.get("config")
    if not isinstance(config, dict):
        return False, "bad-config"
    claimed = blob.get("sig")
    if not isinstance(claimed, str) or not claimed.strip():
        return False, "missing-sig"
    if not hmac.compare_digest(claimed.strip().lower(), sign(config, secret)):
        return False, "bad-sig"
    return True, "ok"


def _int(value: Any) -> int | None:
    """Return an int, or None when the value is not one."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except Exception:
            return None
    return None


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _check_ids(rows: list[Any], section: str, problems: list[str]) -> set[int]:
    """Collect ids, reporting anything missing or duplicated."""
    seen: set[int] = set()
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            problems.append(f"{section}[{idx}]: not an object")
            continue
        rid = _int(row.get("id"))
        if rid is None:
            problems.append(f"{section}[{idx}]: id must be an integer")
            continue
        if rid in seen:
            problems.append(f"{section}[{idx}]: duplicate id {rid}")
        seen.add(rid)
    return seen


def _validate_routes(rows: list[dict[str, Any]], problems: list[str]) -> None:
    seen_pairs: set[tuple[str, str]] = set()
    for idx, row in enumerate(rows):
        where = f"routes[{idx}]"
        host = _text(row.get("host")).lower()
        path = _text(row.get("path")) or "/"
        if not host:
            problems.append(f"{where}: host required")
        if not path.startswith("/"):
            problems.append(f"{where}: path must start with /")
        route_type = _text(row.get("route_type")) or "proxy"
        if route_type not in ROUTE_TYPES:
            problems.append(f"{where}: route_type must be one of {', '.join(ROUTE_TYPES)}")
        elif route_type == "proxy":
            if not _text(row.get("upstream")):
                problems.append(f"{where}: upstream required for a proxy route")
            port = _int(row.get("port"))
            if port is None or not (1 <= port <= 65535):
                problems.append(f"{where}: port must be 1-65535")
        elif not _text(row.get("redirect_target")):
            problems.append(f"{where}: redirect_target required for a redirect route")
        # Checked regardless of type: the column carries a server default, so a
        # proxy row normally has one too and a bad value is bad either way.
        code = _int(row.get("redirect_code"))
        if code is not None and code not in REDIRECT_CODES:
            allowed = ", ".join(str(c) for c in REDIRECT_CODES)
            problems.append(f"{where}: redirect_code must be one of {allowed}")
        pair = (host, path)
        if host and pair in seen_pairs:
            problems.append(f"{where}: duplicate route {host}{path}")
        seen_pairs.add(pair)


def _validate_groups(rows: list[dict[str, Any]], problems: list[str]) -> set[int]:
    gids = _check_ids(rows, "groups", problems)
    seen_names: set[str] = set()
    default_count = 0
    for idx, row in enumerate(rows):
        where = f"groups[{idx}]"
        name = _text(row.get("name"))
        if not name:
            problems.append(f"{where}: name required")
        elif name in seen_names:
            problems.append(f"{where}: duplicate group name {name}")
        seen_names.add(name)
        # The domain is checked for shape in `config_warnings` instead: the
        # database enforces `name` uniqueness but not the domain, so a refusal
        # here could reject a file this deployment produced itself.
        if not _text(row.get("domain")):
            problems.append(f"{where}: domain required")
        if _int(row.get("display_order")) is None:
            problems.append(f"{where}: display_order must be an integer")
        if row.get("is_default") is True:
            default_count += 1
    if rows and default_count != 1:
        problems.append(f"groups: exactly one group must be is_default, found {default_count}")
    return gids


def _has_password(row: dict[str, Any]) -> bool:
    """Whether a rule row carries both halves of a custom password."""
    return bool(_text(row.get("custom_password_hash")) and _text(row.get("custom_password_salt")))


def _validate_rules(rows: list[dict[str, Any]], gids: set[int], problems: list[str]) -> None:
    _check_ids(rows, "rules", problems)
    catches: dict[int, int] = {gid: 0 for gid in gids}
    for idx, row in enumerate(rows):
        where = f"rules[{idx}]"
        gid = _int(row.get("group_id"))
        if gid is None:
            problems.append(f"{where}: group_id must be an integer")
        elif gid not in gids:
            problems.append(f"{where}: group_id {gid} is not in the file's groups")
        path = _text(row.get("path"))
        if not path.startswith("/"):
            problems.append(f"{where}: path must start with /")
        if path == "/*" and gid in catches:
            catches[gid] += 1
        action = _text(row.get("action"))
        if action not in ACTIONS:
            problems.append(f"{where}: action must be one of {', '.join(ACTIONS)}")
        elif action == "custom_password" and not _has_password(row):
            # A rule that gates on a password but carries no hash would restore
            # into a rule nobody can satisfy. Refuse it instead.
            problems.append(f"{where}: custom_password rule needs custom_password_hash and salt")
        if _int(row.get("display_order")) is None:
            problems.append(f"{where}: display_order must be an integer")
        if "active" in row and not isinstance(row.get("active"), bool):
            # Absent means active, and that is accepted, it is what makes a file
            # written before the column restorable. Present-but-wrong is not.
            problems.append(f"{where}: active must be true or false")
    # A group with no catch-all refuses every path it does not name, and since
    # `/*` became a reserved path there is no way to add one afterwards through
    # the panel: the group would have to be deleted and recreated. Refused here,
    # where the operator can still fix the file, rather than applied into a host
    # that answers nothing.
    for gid in sorted(catches):
        if catches[gid] == 0:
            problems.append(
                f"group {gid}: no /* catch-all, so every request for its host would be refused"
            )
    _refuse_inactive_catch_all(rows, problems)


def _refuse_inactive_catch_all(rows: list[dict[str, Any]], problems: list[str]) -> None:
    """Refuse a file whose effective catch-all is switched off, however spelled.

    Checked as a second pass rather than per row, because the catch-all a restore
    will actually rely on is not always the flagged one: `derive_rule_defaults`
    marks the highest-``display_order`` ``/*`` of a group when the file predates
    the flag. Keying only on ``is_default`` would let a hand-edited file declare
    its catch-all by position and switch it off past the check.
    """
    by_group: dict[int, list[tuple[int, dict[str, Any]]]] = {}
    for idx, row in enumerate(rows):
        gid = _int(row.get("group_id"))
        if gid is None or _text(row.get("path")) != "/*":
            continue
        by_group.setdefault(gid, []).append((idx, row))
    for gid in sorted(by_group):
        rows_of_group = by_group[gid]
        flagged = [(i, r) for i, r in rows_of_group if r.get("is_default") is True]
        if flagged:
            effective = max(flagged, key=lambda pair: _int(pair[1].get("display_order")) or 0)
        else:
            effective = max(rows_of_group, key=lambda pair: _int(pair[1].get("display_order")) or 0)
        if effective[1].get("active") is False:
            problems.append(
                f"rules[{effective[0]}]: the /* catch-all cannot be deactivated, "
                "because its group would then have no fallback"
            )


def config_warnings(config: dict[str, Any]) -> list[str]:
    """Shape problems the gate tolerates but the operator should still see.

    A group whose domain `is_valid_host` rejects, or a group carrying more than
    one ``/*`` catch-all: both can be produced through the API, so refusing them
    would mean an export the panel cannot put back. The gate never matches a
    malformed host, and only the first catch-all of a group can ever match, so
    each is fail-closed rather than dangerous. Reported, not used to reject.

    A group with **no** catch-all is a different case and is a fatal problem in
    `validate()`: since ``/*`` became a reserved path, such a group cannot be
    repaired through the panel, only deleted and recreated.
    """
    notes: list[str] = []
    per_group: dict[int, list[str]] = {}
    for row in config.get("rules", []):
        if not isinstance(row, dict):
            continue
        gid = _int(row.get("group_id"))
        if gid is not None:
            per_group.setdefault(gid, []).append(_text(row.get("path")))
    for row in config.get("groups", []):
        if not isinstance(row, dict):
            continue
        gid = _int(row.get("id"))
        if gid is None:
            continue
        domain = _text(row.get("domain"))
        if domain and not is_valid_host(domain):
            notes.append(f"group {gid}: domain '{domain}' matches no host, so its rules never run")
        catches = per_group.get(gid, []).count("/*")
        if catches > 1:
            notes.append(f"group {gid}: {catches} /* catch-alls, only the first can ever match")
    return notes


def _validate_pages(rows: list[dict[str, Any]], problems: list[str]) -> None:
    """Mirror the API's field rules, so a file it could not have produced is refused.

    A duplicate pattern is a problem line rather than last-one-wins: the column
    is unique, so a file carrying two would restore one of them silently.
    """
    _check_ids(rows, "pages", problems)
    seen: set[str] = set()
    for idx, row in enumerate(rows):
        where = f"pages[{idx}]"
        pattern = _text(row.get("pattern"))
        if not pattern:
            problems.append(f"{where}: pattern required")
        else:
            try:
                validate_pattern(pattern)
            except ValueError as e:
                problems.append(f"{where}: {e}")
            if pattern in seen:
                problems.append(f"{where}: duplicate pattern {pattern}")
            seen.add(pattern)
        content_type = _text(row.get("content_type")) or DEFAULT_PAGE_CONTENT_TYPE
        try:
            validate_content_type(content_type)
        except ValueError as e:
            problems.append(f"{where}: {e}")
        body = row.get("body")
        if not isinstance(body, str):
            problems.append(f"{where}: body must be a string")
        elif len(body) > PAGE_BODY_MAX:
            problems.append(
                f"{where}: body must be {PAGE_BODY_MAX // 1024} KiB or fewer "
                f"({PAGE_BODY_MAX} characters)"
            )
        if _int(row.get("display_order")) is None:
            problems.append(f"{where}: display_order must be an integer")
        if "active" in row and not isinstance(row["active"], bool):
            problems.append(f"{where}: active must be true or false")


def _validate_codes(rows: list[dict[str, Any]], problems: list[str]) -> None:
    _check_ids(rows, "codes", problems)
    seen: set[str] = set()
    for idx, row in enumerate(rows):
        where = f"codes[{idx}]"
        code = _text(row.get("code"))
        if not code:
            problems.append(f"{where}: code required")
        elif code in seen:
            problems.append(f"{where}: duplicate code")
        seen.add(code)
        if "active" in row and not isinstance(row["active"], bool):
            problems.append(f"{where}: active must be true or false")


def _validate_settings(rows: list[dict[str, Any]], problems: list[str]) -> None:
    seen: set[str] = set()
    for idx, row in enumerate(rows):
        where = f"settings[{idx}]"
        key = _text(row.get("key"))
        if not key:
            problems.append(f"{where}: key required")
        elif key in seen:
            problems.append(f"{where}: duplicate key {key}")
        seen.add(key)
        if not isinstance(row.get("value"), str):
            problems.append(f"{where}: value must be a string")


def validate(config: Any) -> list[str]:
    """Every reason this config cannot be applied, not just the first.

    Mirrors the field rules the create endpoints enforce, so anything the UI
    could not have produced is refused here rather than written and discovered
    later by the gate.
    """
    if not isinstance(config, dict):
        return ["config must be an object"]
    problems: list[str] = []
    for section in SECTIONS:
        if section not in config:
            problems.append(f"missing config section '{section}'")
        elif not isinstance(config[section], list):
            problems.append(f"config section '{section}' must be a list")
    for section in OPTIONAL_SECTIONS:
        # Optional means absent is fine. Present-but-wrong is not: a `pages` key
        # holding an object is a malformed file, not an empty section.
        if section in config and not isinstance(config[section], list):
            problems.append(f"config section '{section}' must be a list")
    for key in config:
        if key not in SECTIONS and key not in OPTIONAL_SECTIONS:
            problems.append(f"unknown config section '{key}'")
    if problems:
        return problems
    _validate_routes(config["routes"], problems)
    gids = _validate_groups(config["groups"], problems)
    _validate_rules(config["rules"], gids, problems)
    _validate_codes(config["codes"], problems)
    _validate_settings(config["settings"], problems)
    _validate_pages(config.get("pages", []), problems)
    return problems


def derive_rule_defaults(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Copy of ``rules`` with each group's catch-all marked ``is_default``.

    Only used when the model has the column and a file predates it: the
    catch-all is the highest ``display_order`` ``/*`` rule of its group, the
    same reading the migration backfill uses.
    """
    best: dict[int, int] = {}
    for idx, row in enumerate(rules):
        if _text(row.get("path")) != "/*":
            continue
        gid = _int(row.get("group_id"))
        if gid is None:
            continue
        order = _int(row.get("display_order")) or 0
        current = best.get(gid)
        if current is None or order >= (_int(rules[current].get("display_order")) or 0):
            best[gid] = idx
    out: list[dict[str, Any]] = []
    for idx, row in enumerate(rules):
        marked = dict(row)
        if RULES_HAVE_IS_DEFAULT:
            gid = _int(row.get("group_id"))
            marked["is_default"] = idx == best.get(gid) if gid is not None else False
        out.append(marked)
    return out


def _route_row(route: Route) -> dict[str, Any]:
    """One route, in the shape the file stores it."""
    return {
        "id": route.id,
        "host": route.host,
        "path": route.path or "/",
        "route_type": route.route_type or "proxy",
        "upstream": route.upstream,
        "port": route.port,
        "redirect_target": route.redirect_target,
        "redirect_code": route.redirect_code,
    }


def _group_row(group: RuleGroup) -> dict[str, Any]:
    """One rule group, in the shape the file stores it."""
    return {
        "id": group.id,
        "name": group.name,
        "domain": group.domain,
        "display_order": group.display_order,
        "is_default": bool(group.is_default),
    }


def _rule_row(rule: Rule) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": rule.id,
        "group_id": rule.group_id,
        "path": rule.path,
        "action": rule.action,
        "custom_password_hash": rule.custom_password_hash,
        "custom_password_salt": rule.custom_password_salt,
        "allow_ip": rule.allow_ip,
        "allow_time": rule.allow_time,
        "rate_limit": rule.rate_limit,
        "display_order": rule.display_order,
        "active": bool(rule.active),
    }
    if RULES_HAVE_IS_DEFAULT:
        row["is_default"] = bool(rule.is_default)
    return row


def _code_row(code: Code) -> dict[str, Any]:
    """One access code, in the shape the file stores it."""
    return {
        "id": code.id,
        "code": code.code,
        "label": code.label,
        "display_name": code.display_name,
        "active": bool(code.active),
    }


def _setting_row(setting: Setting) -> dict[str, Any]:
    """One setting, in the shape the file stores it."""
    return {"key": setting.key, "value": setting.value}


def _page_row(page: CustomPage) -> dict[str, Any]:
    """One custom page, in the shape the file stores it."""
    return {
        "id": page.id,
        "pattern": page.pattern,
        "body": page.body,
        "content_type": page.content_type or DEFAULT_PAGE_CONTENT_TYPE,
        "active": bool(page.active),
        "display_order": page.display_order,
    }


async def build_backup(db: AsyncSession, secret: str | None = None) -> dict[str, Any]:
    """Read the whole configuration and sign it. Ordered by id, so it repeats."""
    routes = (await db.execute(select(Route).order_by(Route.id))).scalars().all()
    groups = (await db.execute(select(RuleGroup).order_by(RuleGroup.id))).scalars().all()
    rules = (await db.execute(select(Rule).order_by(Rule.id))).scalars().all()
    codes = (await db.execute(select(Code).order_by(Code.id))).scalars().all()
    settings = (await db.execute(select(Setting).order_by(Setting.key))).scalars().all()
    settings = [s for s in settings if s.key not in BOOKKEEPING_SETTINGS]
    pages = (await db.execute(select(CustomPage).order_by(CustomPage.id))).scalars().all()
    config: dict[str, Any] = {
        "routes": [_route_row(r) for r in routes],
        "groups": [_group_row(g) for g in groups],
        "rules": [_rule_row(r) for r in rules],
        "codes": [_code_row(c) for c in codes],
        "settings": [_setting_row(s) for s in settings],
        "pages": [_page_row(p) for p in pages],
    }
    created_at = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    signature = sign(config, secret)
    return {"version": VERSION, "created_at": created_at, "config": config, "sig": signature}


def _ordered_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Renumber each group's rules so its catch-all sorts last.

    The same shape the migration backfill establishes, applied to a restored
    file: order within a group is otherwise preserved, and relative order is
    what `display_order` means, so a file whose catch-all sits in the middle
    would otherwise restore the very state the invariant forbids.
    """
    out: list[dict[str, Any]] = []
    by_group: dict[int | None, list[dict[str, Any]]] = {}
    for row in rules:
        by_group.setdefault(_int(row.get("group_id")), []).append(row)
    for gid, rows in by_group.items():
        if gid is None:
            out.extend(rows)
            continue
        catches = [r for r in rows if _text(r.get("path")) == "/*"]
        rest = [r for r in rows if _text(r.get("path")) != "/*"]
        ordered = sorted(rest, key=lambda r: _int(r.get("display_order")) or 0)
        if catches:
            ordered.append(max(catches, key=lambda r: _int(r.get("display_order")) or 0))
        for index, row in enumerate(ordered):
            renumbered = dict(row)
            renumbered["display_order"] = index
            out.append(renumbered)
    return out


def _insert_all(db: AsyncSession, config: dict[str, Any]) -> None:
    """Stage every restored row. Groups first: rules carry a group_id."""
    for row in config["groups"]:
        db.add(
            RuleGroup(
                id=_int(row.get("id")),
                name=row.get("name"),
                domain=row.get("domain"),
                display_order=_int(row.get("display_order")) or 0,
                is_default=bool(row.get("is_default")),
            )
        )
    rules = config["rules"]
    if RULES_HAVE_IS_DEFAULT:
        rules = derive_rule_defaults(rules)
    rules = _ordered_rules(rules)
    for row in rules:
        rule = Rule(
            id=_int(row.get("id")),
            group_id=_int(row.get("group_id")),
            path=row.get("path"),
            action=row.get("action"),
            custom_password_hash=row.get("custom_password_hash"),
            custom_password_salt=row.get("custom_password_salt"),
            allow_ip=row.get("allow_ip"),
            allow_time=row.get("allow_time"),
            rate_limit=row.get("rate_limit"),
            display_order=_int(row.get("display_order")) or 0,
            active=bool(row.get("active", RULES_ACTIVE_DEFAULT)),
        )
        if RULES_HAVE_IS_DEFAULT:
            # A file that predates the column says nothing about which rule is
            # the catch-all, so it is derived rather than defaulted to False.
            rule.is_default = bool(row.get("is_default", True))
        db.add(rule)
    for row in config["routes"]:
        db.add(
            Route(
                id=_int(row.get("id")),
                host=row.get("host"),
                path=row.get("path") or "/",
                route_type=row.get("route_type") or "proxy",
                upstream=row.get("upstream"),
                port=_int(row.get("port")),
                redirect_target=row.get("redirect_target"),
                redirect_code=_int(row.get("redirect_code")),
            )
        )
    for row in config["codes"]:
        db.add(
            Code(
                id=_int(row.get("id")),
                code=row.get("code"),
                label=row.get("label"),
                display_name=row.get("display_name"),
                active=bool(row.get("active", True)),
            )
        )
    for row in config["settings"]:
        db.add(Setting(key=row.get("key"), value=row.get("value")))
    for row in config.get("pages", []):
        db.add(
            CustomPage(
                id=_int(row.get("id")),
                pattern=row.get("pattern"),
                body=row.get("body") or "",
                content_type=row.get("content_type") or DEFAULT_PAGE_CONTENT_TYPE,
                active=bool(row.get("active", True)),
                display_order=_int(row.get("display_order")) or 0,
            )
        )


async def _detach_audit_refs(db: AsyncSession) -> dict[str, int]:
    """Null every audit reference the restored configuration cannot resolve."""
    detached: dict[str, int] = {}
    for column, section in AUDIT_REFERENCES.items():
        model = {"codes": Code, "rules": Rule, "groups": RuleGroup}[section]
        target = getattr(AuditLog, column)
        present = select(model.id)
        stmt = update(AuditLog).where(target.is_not(None), target.not_in(present))
        res = await db.execute(stmt.values({column: None}))
        detached[column] = res.rowcount or 0
    return detached


async def apply_backup(db: AsyncSession, config: dict[str, Any]) -> dict[str, Any]:
    """Replace the configuration with ``config`` in one transaction.

    Idempotent: applying the same file twice ends in the same state. Any
    failure rolls the whole thing back, so a rejected restore cannot leave a
    half-replaced configuration behind.

    Settings the file does not carry, `backup_exported_at` included, are removed
    with the rest: the file is the whole configuration, so the panel reports no
    export taken until the next download rather than claiming the previous one.
    """
    counts = {section: len(config[section]) for section in SECTIONS}
    counts.update({section: len(config.get(section, [])) for section in OPTIONAL_SECTIONS})
    try:
        for model in (Rule, RuleGroup, Route, Code, Setting, CustomPage):
            await db.execute(delete(model))
        _insert_all(db, config)
        # The detach runs after the flush so the subqueries see the new rows.
        await db.flush()
        detached = await _detach_audit_refs(db)
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    return {"counts": counts, "detached_logs": detached}
