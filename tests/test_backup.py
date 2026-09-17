"""Signed configuration export and restore.

The export is the only rollback point that exists for rules and codes: they live
in the database volume, are not in git, and have no migration to undo. So these
tests are less about the JSON shape than about the two properties that make the
file worth trusting:

1. The signature covers the configuration and nothing else, so an altered
   ``config`` is refused while incidental envelope metadata is not.
2. A refused restore writes nothing. A half-applied configuration would be worse
   than no backup at all.

Every test that replaces the configuration puts it back afterwards, because a
restore swaps all five sections at once and the modules that follow assert on
the lifespan seeds.
"""

from __future__ import annotations

import asyncio
import copy
import json
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select

from shared.backup import (
    VERSION,
    apply_backup,
    canonical,
    config_warnings,
    derive_rule_defaults,
    sign,
    validate,
    verify,
)
from shared.db import get_sessionmaker
from shared.models import AuditLog, Code, Route, Rule, RuleGroup, Setting
from tests.conftest import TEST_INTERNAL_API_KEY

INTERNAL_KEY_HEADERS = {"X-Internal-Api-Key": TEST_INTERNAL_API_KEY}
OTHER_SECRET = "a-completely-different-key-of-32-characters"
CONFIG_SECTIONS = ("routes", "groups", "rules", "codes", "settings")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _export(client) -> dict[str, Any]:
    r = client.get("/api/backup", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    return json.loads(r.text)


def _restore(client, blob: Any, **params: Any):
    return client.post(
        "/api/backup/restore", json=blob, headers=INTERNAL_KEY_HEADERS, params=params or None
    )


def _resign(config: dict[str, Any], secret: str | None = None) -> dict[str, Any]:
    """Re-sign an edited config so the file is internally consistent again."""
    return {
        "version": VERSION,
        "created_at": "2026-01-01T00:00:00Z",
        "config": config,
        "sig": sign(config, secret),
    }


def _current_config(client) -> dict[str, Any]:
    blob = _export(client)
    assert verify(blob)[0] is True
    return blob["config"]


def _unique_code() -> str:
    return f"code-{uuid.uuid4().hex[:12]}"


def _count(model) -> int:
    async def _run() -> int:
        session = get_sessionmaker()()
        try:
            return (await session.execute(select(func.count()).select_from(model))).scalar_one()
        finally:
            await session.close()

    return asyncio.run(_run())


@pytest.fixture(autouse=True)
def _restore_config(client):
    """Give every test one route to work with, then put everything back.

    A restore replaces all five sections at once, so a test that applies one
    must not leave the next module without the lifespan seeds. The route is
    added before the snapshot so the restore it re-applies keeps it.
    """
    if not _current_config(client)["routes"]:
        r = client.post(
            "/api/routes",
            json={"host": "seed.backup-test", "path": "/", "upstream": "seed", "port": 8080},
            headers=INTERNAL_KEY_HEADERS,
        )
        assert r.status_code == 200, r.text
    snapshot = _export(client)
    yield
    assert _restore(client, snapshot).status_code == 200


# --------------------------------------------------------------------------- #
# The file itself
# --------------------------------------------------------------------------- #


def test_export_requires_the_internal_key(client) -> None:
    assert client.get("/api/backup").status_code == 401


def test_export_is_a_download_with_the_documented_shape(client) -> None:
    r = client.get("/api/backup", headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert "attachment" in r.headers["content-disposition"]
    assert "gatekeeper-config-" in r.headers["content-disposition"]

    blob = json.loads(r.text)
    assert blob["version"] == VERSION
    assert blob["created_at"].endswith("Z")
    assert len(blob["sig"]) == 64
    assert sorted(blob.keys()) == ["config", "created_at", "sig", "version"]
    assert sorted(blob["config"].keys()) == sorted(CONFIG_SECTIONS)


def test_export_is_readable_json_not_an_encoded_token(client) -> None:
    """The owner asked for a signature over plain text, not a JWT."""
    raw = client.get("/api/backup", headers=INTERNAL_KEY_HEADERS).text
    assert raw.lstrip().startswith("{")
    assert "\n" in raw  # indented, so an operator can read it
    assert "eyJ" not in raw.split("\n")[0]
    assert set(json.loads(raw)) == {"version", "created_at", "config", "sig"}


def test_export_excludes_audit_logs(client) -> None:
    blob = _export(client)
    assert "audit_logs" not in blob["config"]
    assert "logs" not in blob["config"]
    assert "audit" not in canonical(blob["config"])


def test_export_repeats_itself_when_nothing_changed(client) -> None:
    """Sorted keys and a stable row order, so the same state signs identically.

    The panel records `backup_exported_at` on every export. If that landed in
    the signed config, the second call here would sign differently from the
    first and a restore would rewrite configuration that had not changed.
    """
    first = _export(client)
    second = _export(client)

    assert second["config"] == first["config"]
    assert second["sig"] == first["sig"]
    assert "backup_exported_at" not in {s["key"] for s in second["config"]["settings"]}
    assert second["created_at"] != first["created_at"] or second["sig"] == first["sig"]


def test_canonical_is_order_independent() -> None:
    assert canonical({"b": 1, "a": [3, 2]}) == canonical({"a": [3, 2], "b": 1})
    assert canonical({"a": 1}) == '{"a":1}'


def test_signature_covers_only_the_config(client) -> None:
    """Changing envelope metadata keeps the file valid: `sig` is over `config`."""
    blob = _export(client)
    blob["created_at"] = "1999-12-31T23:59:59Z"
    assert verify(blob) == (True, "ok")

    r = _restore(client, blob, dry_run=1)
    assert r.status_code == 200
    assert r.json()["ok"] is True


# --------------------------------------------------------------------------- #
# Signature proofs
# --------------------------------------------------------------------------- #


def test_valid_signature_is_accepted(client) -> None:
    r = _restore(client, _export(client), dry_run=1)
    assert r.status_code == 200
    body = r.json()
    assert body["sig"] is True
    assert body["ok"] is True
    assert body["reason"] == "ok"
    assert body["problems"] == []


def test_single_byte_change_in_config_is_rejected(client) -> None:
    """One character in one code value, signature left alone -> 409."""
    blob = _export(client)
    assert blob["config"]["codes"], "the fixture database must carry at least one code"
    original = blob["config"]["codes"][0]["code"]
    blob["config"]["codes"][0]["code"] = original[:-1] + ("x" if original.endswith("y") else "y")

    assert verify(blob) == (False, "bad-sig")

    r = _restore(client, blob, dry_run=1)
    assert r.status_code == 409
    assert r.json() == {
        "ok": False,
        "sig": False,
        "reason": "bad-sig",
        "problems": [],
        "counts": {},
        "warnings": [],
    }


def test_wrong_secret_key_is_rejected(client) -> None:
    """Signed by a different deployment: the HMAC cannot match."""
    blob = _export(client)
    blob["sig"] = sign(blob["config"], OTHER_SECRET)
    assert blob["sig"] != sign(blob["config"])

    assert verify(blob) == (False, "bad-sig")
    assert _restore(client, blob, dry_run=1).status_code == 409


def test_wrong_secret_key_is_rejected_when_the_service_key_rotates(client, monkeypatch) -> None:
    """Same file, same service, key rotated underneath it."""
    import shared.backup as backup

    blob = _export(client)
    assert verify(blob) == (True, "ok")

    class _Rotated:
        SECRET_KEY = OTHER_SECRET

    monkeypatch.setattr(backup, "get_config", lambda: _Rotated())
    assert verify(blob) == (False, "bad-sig")


@pytest.mark.parametrize(
    ("blob", "reason"),
    [
        ({"version": VERSION, "config": {"a": []}}, "missing-sig"),
        ({"version": VERSION, "config": {"a": []}, "sig": ""}, "missing-sig"),
        ({"version": VERSION, "config": {"a": []}, "sig": "   "}, "missing-sig"),
        ({"version": VERSION, "config": {"a": []}, "sig": None}, "missing-sig"),
        ({"version": VERSION, "config": {"a": []}, "sig": 12345}, "missing-sig"),
        ({"version": VERSION, "sig": "ab"}, "bad-config"),
        ({"version": VERSION, "config": "not-an-object", "sig": "ab"}, "bad-config"),
        ("a bare string", "bad-json"),
        ([], "bad-json"),
        (None, "bad-json"),
    ],
)
def test_malformed_files_are_rejected_with_a_reason(blob, reason: str) -> None:
    assert verify(blob) == (False, reason)


@pytest.mark.parametrize("version", [0, 2, 99, "1", None, True])
def test_unknown_version_is_rejected(version) -> None:
    """A future file is refused as a version problem, not misreported as corrupt."""
    config = {"routes": [], "groups": [], "rules": [], "codes": [], "settings": []}
    assert verify({"version": version, "config": config, "sig": sign(config)}) == (
        False,
        "bad-version",
    )


def test_version_is_checked_before_the_signature(client) -> None:
    """A future version carrying a valid signature is still refused, as a version."""
    config = _current_config(client)
    blob = {"version": VERSION + 1, "config": config, "sig": sign(config)}
    assert verify(blob) == (False, "bad-version")

    r = _restore(client, blob)
    assert r.status_code == 400
    assert r.json()["reason"] == "bad-version"


def test_missing_signature_over_the_endpoint_is_400(client) -> None:
    blob = _export(client)
    del blob["sig"]

    r = _restore(client, blob)
    assert r.status_code == 400
    assert r.json()["reason"] == "missing-sig"


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def _broken(client, section: str, mutate) -> list[str]:
    config = copy.deepcopy(_current_config(client))
    mutate(config[section])
    return validate(config)


def test_validation_problems_are_reported_all_at_once(client) -> None:
    config = copy.deepcopy(_current_config(client))
    config["groups"][0]["name"] = ""
    config["rules"][0]["action"] = "allow"

    problems = validate(config)
    assert any("groups[0]: name required" in p for p in problems)
    assert any("rules[0]: action must be one of" in p for p in problems)
    assert len(problems) >= 2


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda cfg: cfg[0].update(name=""), "name required"),
        (lambda cfg: cfg[0].update(domain=""), "domain required"),
        (lambda cfg: cfg[0].update(display_order="later"), "display_order must be an integer"),
        (lambda cfg: cfg[1].update(name=cfg[0]["name"]), "duplicate group name"),
        (lambda cfg: cfg[1].update(is_default=True), "exactly one group must be is_default"),
    ],
)
def test_group_validation(client, mutate, expected: str) -> None:
    assert any(expected in p for p in _broken(client, "groups", mutate))


def test_a_bad_domain_is_a_warning_not_a_refusal(client) -> None:
    """`POST /api/groups` does not check the domain, so a saved typo must still
    restore. The gate never matches such a host, which is fail-closed."""
    before = _current_config(client)
    config = copy.deepcopy(before)
    config["groups"][0]["domain"] = "not a domain!!"

    assert not any("invalid domain" in p for p in validate(config))
    assert any("matches no host" in n for n in config_warnings(config))

    r = _restore(client, _resign(config))
    assert r.status_code == 200, r.text
    assert any("matches no host" in n for n in r.json()["warnings"])


def test_a_group_without_a_catch_all_is_refused(client) -> None:
    """Since `/*` became a reserved path, a group without a catch-all cannot be
    repaired through the panel — only deleted and recreated. So a file carrying
    one is refused, with the reason, rather than applied into a host that
    answers nothing."""
    gid = client.post(
        "/api/groups",
        json={
            "name": f"nocatch-{uuid.uuid4().hex[:8]}",
            "domain": f"{uuid.uuid4().hex[:8]}.nocatch.test",
        },
        headers=INTERNAL_KEY_HEADERS,
    ).json()["id"]

    config = _current_config(client)
    assert [r for r in config["rules"] if r["group_id"] == gid], "the group seeds a catch-all"

    stripped = copy.deepcopy(config)
    stripped["rules"] = [r for r in stripped["rules"] if r["group_id"] != gid]

    problems = validate(stripped)
    assert any(f"group {gid}: no /* catch-all" in p for p in problems)

    r = _restore(client, _resign(stripped))
    assert r.status_code == 400, r.text
    assert any("no /* catch-all" in p for p in r.json()["problems"])


def test_a_loaded_group_with_no_catch_all_is_still_refused(client) -> None:
    """The check reads the file, not the database, so it holds for any file."""
    config = {
        "routes": [],
        "groups": [
            {"id": 1, "name": "a", "domain": "a.test", "display_order": 0, "is_default": False},
            {"id": 2, "name": "b", "domain": "b.test", "display_order": 1, "is_default": True},
        ],
        "rules": [
            {"id": 1, "group_id": 1, "path": "/named/*", "action": "none", "display_order": 0},
            {"id": 2, "group_id": 2, "path": "/*", "action": "access_code", "display_order": 0},
        ],
        "codes": [],
        "settings": [],
    }
    problems = validate(config)
    assert any("group 1: no /* catch-all" in p for p in problems)
    assert not any("group 2" in p for p in problems)


def test_two_catch_alls_are_restorable_and_reported(client) -> None:
    """Only the first catch-all can ever match, so the second is dead weight.

    Reported rather than refused: the API cannot create a second `/*` any more,
    but the gate tolerates one (the first wins), so a file carrying one is not
    dangerous and refusing it would strand an operator with no way to load it.
    A restore renumbers the group so the catch-all sorts last.
    """
    config = copy.deepcopy(_current_config(client))
    gid = config["groups"][0]["id"]
    clone = copy.deepcopy(
        next(r for r in config["rules"] if r["group_id"] == gid and r["path"] == "/*")
    )
    clone["id"] = max(r["id"] for r in config["rules"]) + 1
    clone["display_order"] = clone["display_order"] + 1
    config["rules"].append(clone)

    assert validate(config) == []
    assert any(f"group {gid}: 2 /* catch-alls" in n for n in config_warnings(config))
    assert _restore(client, _resign(config)).status_code == 200

    restored = _current_config(client)
    ordered = sorted(
        (r for r in restored["rules"] if r["group_id"] == gid),
        key=lambda r: r["display_order"],
    )
    assert ordered[-1]["path"] == "/*", "the catch-all still sorts last after a restore"


def test_a_restore_puts_the_catch_all_last(client) -> None:
    """A file whose catch-all sits above a narrower rule restores renumbered.

    `display_order` is what the gate walks, so restoring the order verbatim
    would reinstate the exact shape the invariant forbids: the narrower rule
    behind the catch-all could never fire.
    """
    config = copy.deepcopy(_current_config(client))
    gid = config["groups"][0]["id"]
    catch_all = next(r for r in config["rules"] if r["group_id"] == gid and r["path"] == "/*")
    catch_all["display_order"] = 0
    other = {
        "id": max(r["id"] for r in config["rules"]) + 1,
        "group_id": gid,
        "path": "/named/*",
        "action": "deny",
        "display_order": 1,
    }
    config["rules"].append(other)

    assert validate(config) == []
    assert _restore(client, _resign(config)).status_code == 200

    # `/api/backup` lists rules by id, so the order has to be read off
    # `display_order`, which is what the gate actually walks.
    restored = [r for r in _current_config(client)["rules"] if r["group_id"] == gid]
    ordered = sorted(restored, key=lambda r: r["display_order"])
    assert [r["path"] for r in ordered] == ["/named/*", "/*"]
    assert [r["display_order"] for r in ordered] == [0, 1]


def test_a_clean_config_has_no_warnings() -> None:
    """Built directly, because the shared test database accumulates groups that
    other modules create without a catch-all."""
    config = {
        "routes": [],
        "groups": [
            {"id": 1, "name": "*.*/*", "domain": "*.*/*", "display_order": 9999, "is_default": True}
        ],
        "rules": [
            {"id": 1, "group_id": 1, "path": "/*", "action": "access_code", "display_order": 0}
        ],
        "codes": [],
        "settings": [],
    }
    assert config_warnings(config) == []


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda cfg: cfg[0].update(path="no-slash"), "path must start with /"),
        (lambda cfg: cfg[0].update(action="allow"), "action must be one of"),
        (lambda cfg: cfg[0].update(group_id=999999), "is not in the file's groups"),
        (lambda cfg: cfg[0].update(display_order="first"), "display_order must be an integer"),
    ],
)
def test_rule_validation(client, mutate, expected: str) -> None:
    assert any(expected in p for p in _broken(client, "rules", mutate))


def test_rule_validation_refuses_a_password_rule_with_no_hash(client) -> None:
    def mutate(rules):
        rules[0]["action"] = "custom_password"
        rules[0]["custom_password_hash"] = None
        rules[0]["custom_password_salt"] = None

    assert any("custom_password_hash" in p for p in _broken(client, "rules", mutate))


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda cfg: cfg[0].update(port=0), "port must be 1-65535"),
        (lambda cfg: cfg[0].update(port=70000), "port must be 1-65535"),
        (lambda cfg: cfg[0].update(route_type="tunnel"), "route_type must be one of"),
        (lambda cfg: cfg[0].update(upstream=""), "upstream required"),
        (lambda cfg: cfg[0].update(host=""), "host required"),
        (lambda cfg: cfg[0].update(redirect_code=200), "redirect_code must be one of"),
    ],
)
def test_route_validation(client, mutate, expected: str) -> None:
    assert any(expected in p for p in _broken(client, "routes", mutate))


def test_route_validation_accepts_a_redirect(client) -> None:
    def mutate(routes):
        routes[0].update(
            route_type="redirect", redirect_target="https://example.test", redirect_code=308
        )

    assert _broken(client, "routes", mutate) == []


def test_code_and_setting_validation(client) -> None:
    assert any(
        "code required" in p for p in _broken(client, "codes", lambda cfg: cfg[0].update(code=""))
    )

    def duplicate(codes):
        clone = copy.deepcopy(codes[0])
        clone["id"] = max(c["id"] for c in codes) + 1
        codes.append(clone)

    assert any("duplicate code" in p for p in _broken(client, "codes", duplicate))
    assert any(
        "value must be a string" in p
        for p in _broken(client, "settings", lambda cfg: cfg[0].update(value=5))
    )


def test_validation_refuses_a_missing_or_unknown_section(client) -> None:
    config = copy.deepcopy(_current_config(client))
    del config["codes"]
    config["api_keys"] = []

    problems = validate(config)
    assert "missing config section 'codes'" in problems
    assert "unknown config section 'api_keys'" in problems


def test_validation_rejects_a_non_object() -> None:
    assert validate(["not", "an", "object"]) == ["config must be an object"]


def test_invalid_config_over_the_endpoint_is_400_and_writes_nothing(client) -> None:
    before = _current_config(client)
    config = copy.deepcopy(before)
    config["routes"][0]["port"] = 0

    r = _restore(client, _resign(config))
    assert r.status_code == 400
    body = r.json()
    assert body["sig"] is True
    assert body["reason"] == "invalid-config"
    assert any("port must be 1-65535" in p for p in body["problems"])
    assert _current_config(client) == before


# --------------------------------------------------------------------------- #
# Restore behaviour
# --------------------------------------------------------------------------- #


def test_round_trip_restores_the_exported_state(client) -> None:
    """Export, mutate the database, restore, and get the export back."""
    blob = _export(client)
    exported = blob["config"]

    created = client.post(
        "/api/routes",
        json={"host": "roundtrip.test", "path": "/", "upstream": "x", "port": 8080},
        headers=INTERNAL_KEY_HEADERS,
    )
    assert created.status_code == 200, created.text
    mutated = _current_config(client)
    assert any(row["host"] == "roundtrip.test" for row in mutated["routes"])
    assert mutated != exported

    # The bytes the download produced are the bytes applied: no re-signing.
    r = _restore(client, blob)
    assert r.status_code == 200, r.text
    assert r.json()["counts"] == {section: len(exported[section]) for section in CONFIG_SECTIONS}

    restored = _current_config(client)
    assert restored == exported
    assert not any(row["host"] == "roundtrip.test" for row in restored["routes"])


def test_restore_preserves_row_ids(client) -> None:
    """Ids are what `audit_logs` points at, so a restore must not renumber."""
    blob = _export(client)
    ids = {
        section: sorted(row["id"] for row in blob["config"][section])
        for section in ("routes", "groups", "rules", "codes")
    }

    assert _restore(client, blob).status_code == 200
    after = _current_config(client)
    for section, expected in ids.items():
        assert sorted(row["id"] for row in after[section]) == expected


def test_restore_is_idempotent(client) -> None:
    blob = _export(client)

    assert _restore(client, blob).status_code == 200
    first = _current_config(client)
    assert _restore(client, blob).status_code == 200
    assert _current_config(client) == first


def test_dry_run_writes_nothing(client) -> None:
    blob = _export(client)
    client.post(
        "/api/routes",
        json={"host": "dryrun.test", "path": "/", "upstream": "x", "port": 8080},
        headers=INTERNAL_KEY_HEADERS,
    )
    mutated = _current_config(client)

    r = _restore(client, blob, dry_run=1)
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert _current_config(client) == mutated, "a preview must not touch the database"


def test_dry_run_reports_counts_without_detached_logs(client) -> None:
    body = _restore(client, _export(client), dry_run=1).json()
    assert body["detached_logs"] == {}
    assert body["counts"]["groups"] >= 1
    assert body["counts"]["rules"] >= 1


def test_a_bad_signature_leaves_the_database_untouched(client) -> None:
    before = _current_config(client)
    blob = _export(client)
    blob["config"]["groups"][0]["name"] = "renamed-behind-the-signature"
    assert blob["config"] != before

    assert _restore(client, blob).status_code == 409
    assert _current_config(client) == before


def test_a_rejected_config_leaves_the_database_untouched(client) -> None:
    before = _current_config(client)
    config = copy.deepcopy(before)
    config["groups"][0]["name"] = ""

    assert _restore(client, _resign(config)).status_code == 400
    assert _current_config(client) == before


def test_a_rejected_restore_mid_file_leaves_the_database_untouched(client) -> None:
    """A refused restore is refused whole: no section is partly replaced."""
    before = _current_config(client)
    config = copy.deepcopy(before)
    config["routes"] = []
    config["groups"] = []
    config["rules"][0]["action"] = "allow"  # the only problem, at the end of validation

    r = _restore(client, _resign(config))
    assert r.status_code == 400
    assert r.json()["reason"] == "invalid-config"
    assert _current_config(client) == before


def test_a_failed_apply_rolls_back_completely(client) -> None:
    """A mid-apply failure must leave the previous configuration in place.

    Two codes sharing one id pass validation of every other kind and fail at
    insert time, which is the "looked fine then blew up" case the single
    transaction exists for.
    """
    before = _current_config(client)
    config = copy.deepcopy(before)
    config["codes"].append(copy.deepcopy(config["codes"][0]))

    async def _apply() -> Exception | None:
        session = get_sessionmaker()()
        try:
            await apply_backup(session, config)
            return None
        except Exception as e:  # the failure itself is the assertion
            return e
        finally:
            await session.close()

    error = asyncio.run(_apply())
    assert error is not None, "the duplicate id must have failed the insert"
    assert _current_config(client) == before, "the failed restore must have written nothing"


def test_restore_can_empty_a_section(client) -> None:
    config = copy.deepcopy(_current_config(client))
    config["routes"] = []

    assert _restore(client, _resign(config)).status_code == 200
    assert _current_config(client)["routes"] == []


# --------------------------------------------------------------------------- #
# audit_logs references
# --------------------------------------------------------------------------- #


def _insert_log(client, **extra: Any) -> int:
    payload: dict[str, Any] = {
        "ip": "203.0.113.9",
        "host": "logs.test",
        "path": "/",
        "action": "auth_success",
    }
    payload.update(extra)
    r = client.post("/api/logs", json=payload, headers=INTERNAL_KEY_HEADERS)
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _log(client, log_id: int) -> dict[str, Any]:
    rows = client.get("/api/logs", params={"per_page": 100}).json()
    match = next((row for row in rows if row["id"] == log_id), None)
    assert match is not None, f"audit row {log_id} disappeared"
    return match


def test_restore_nulls_a_dangling_code_id_and_keeps_the_row(client) -> None:
    """History is preserved; only the reference to a code that is gone is dropped."""
    code = client.post(
        "/api/codes",
        json={"code": _unique_code(), "label": "audited"},
        headers=INTERNAL_KEY_HEADERS,
    ).json()
    log_id = _insert_log(client, code_id=code["id"])
    assert _log(client, log_id)["code_id"] == code["id"]

    blob = _export(client)
    blob["config"]["codes"] = [row for row in blob["config"]["codes"] if row["id"] != code["id"]]

    r = _restore(client, _resign(blob["config"]))
    assert r.status_code == 200, r.text
    assert r.json()["detached_logs"]["code_id"] >= 1

    row = _log(client, log_id)
    assert row["code_id"] is None
    assert row["host"] == "logs.test"
    assert row["action"] == "auth_success"


def test_restore_leaves_resolvable_code_references_alone(client) -> None:
    code = client.post(
        "/api/codes", json={"code": _unique_code(), "label": "kept"}, headers=INTERNAL_KEY_HEADERS
    ).json()
    log_id = _insert_log(client, code_id=code["id"])

    assert _restore(client, _export(client)).status_code == 200
    assert _log(client, log_id)["code_id"] == code["id"]


def test_restore_nulls_dangling_rule_and_group_references(client) -> None:
    """The same policy as `code_id`, for the other two foreign keys.

    The reference has to point at a rule the restored file no longer contains,
    so the file is stripped of the whole group (and, with it, that group's
    catch-all, which the validator would otherwise refuse).
    """
    gid = client.post(
        "/api/groups",
        json={"name": f"ref-{uuid.uuid4().hex[:8]}", "domain": f"{uuid.uuid4().hex[:8]}.ref.test"},
        headers=INTERNAL_KEY_HEADERS,
    ).json()["id"]
    rid = client.post(
        f"/api/groups/{gid}/rules",
        json={"path": "/audited/*", "action": "none"},
        headers=INTERNAL_KEY_HEADERS,
    ).json()["id"]
    log_id = _insert_log(
        client,
        ip="203.0.113.10",
        host="refs.test",
        action="none_gate",
        rule_id=rid,
        rule_group_id=gid,
    )

    blob = _export(client)
    blob["config"]["rules"] = [row for row in blob["config"]["rules"] if row["group_id"] != gid]
    blob["config"]["groups"] = [row for row in blob["config"]["groups"] if row["id"] != gid]

    body = _restore(client, _resign(blob["config"])).json()
    assert body["detached_logs"]["rule_id"] >= 1
    assert body["detached_logs"]["rule_group_id"] >= 1

    row = _log(client, log_id)
    assert row["rule_id"] is None
    assert row["rule_group_id"] is None
    assert row["host"] == "refs.test"


def test_restore_never_deletes_audit_rows(client) -> None:
    before = _count(AuditLog)
    _insert_log(client)
    after_insert = _count(AuditLog)
    assert after_insert == before + 1

    config = copy.deepcopy(_current_config(client))
    config["codes"] = []
    assert _restore(client, _resign(config)).status_code == 200
    assert _count(AuditLog) == after_insert


def test_audit_logs_are_not_in_the_restore_surface() -> None:
    """The five replaced tables are exactly the configuration tables."""
    assert set(CONFIG_SECTIONS) == {"routes", "groups", "rules", "codes", "settings"}
    for model in (Route, RuleGroup, Rule, Code, Setting):
        assert model.__tablename__ != "audit_logs"
    assert AuditLog.__tablename__ == "audit_logs"


# --------------------------------------------------------------------------- #
# Forward compatibility
# --------------------------------------------------------------------------- #


def test_derive_rule_defaults_picks_the_highest_ordered_catch_all() -> None:
    """A file written before `is_default` existed still restores sensibly."""
    rules = [
        {"id": 1, "group_id": 7, "path": "/*", "action": "none", "display_order": 0},
        {"id": 2, "group_id": 7, "path": "/a/*", "action": "none", "display_order": 1},
        {"id": 3, "group_id": 7, "path": "/*", "action": "access_code", "display_order": 2},
    ]
    derived = derive_rule_defaults(rules)

    assert [row["id"] for row in derived] == [1, 2, 3]
    if "is_default" in derived[0]:
        assert [row["is_default"] for row in derived] == [False, False, True]


def test_a_file_without_is_default_restores(client) -> None:
    """Deleting the field produces the shape a Phase-2-era export has."""
    config = copy.deepcopy(_current_config(client))
    for row in config["rules"]:
        row.pop("is_default", None)

    r = _restore(client, _resign(config))
    assert r.status_code == 200, r.text
    assert _current_config(client)["rules"]
