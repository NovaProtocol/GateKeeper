"""Phase 5 verification: the four security-relevant claims, end to end.

Each item is driven through the real ASGI apps over a throwaway database, with
the management panel pointed at the API's own ASGI transport so every hop, header
and status code is real and only the socket is missing.

Run with::

    uv run --no-project --with-requirements requirements.txt \
        --with-requirements requirements-dev.txt python tests/ui/check_settings.py

It prints one line per expectation and exits non-zero if any of them fails, so the
output can be pasted into a verification log as it stands.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import importlib.util
import os
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

BASE = Path(__file__).resolve().parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

DB_PATH = (Path("/tmp") / f"gatekeeper_settings_check_{uuid.uuid4().hex}.db").resolve()
os.environ["SECRET_KEY"] = "test-secret-key-at-least-32-characters"
os.environ["MANAGE_PASSWORD"] = "test-manage-password"
os.environ["BACKUP_CODE"] = "test-backup-code"
os.environ["INTERNAL_API_KEY"] = "test-internal-api-key"
os.environ["DEPLOYMENT_TYPE"] = "debug"
os.environ["DB_DIR"] = str(DB_PATH.parent)
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{DB_PATH}"
os.environ["API_HTTP_ADDR"] = "http://api.invalid:8002"
os.environ["LOG_RETENTION_DAYS"] = "30"

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select, text  # noqa: E402

import management.app as management_app  # noqa: E402
from api.app import app as api_app  # noqa: E402
from shared.db import get_sessionmaker  # noqa: E402
from shared.gate import resolve_rule_action  # noqa: E402
from shared.jwt import create_manage_token, decode_without_verify  # noqa: E402
from shared.models import AuditLog, Code, Route, Rule, RuleGroup, Setting  # noqa: E402
from shared.settings_spec import (  # noqa: E402
    LOG_RETENTION_DAYS,
    MAINTENANCE_MODE,
    SESSION_LIFETIME_HOURS,
    read_value,
)

INTERNAL = {"X-Internal-Api-Key": "test-internal-api-key"}
API = "http://api:8002"
CSRF = "check-csrf"
ORIGIN = "http://testserver"
HOST = "portfolio.projectnova.download"
GK_HOST = "gatekeeper.projectnova.download"

failures: list[str] = []


def check(label: str, actual: Any, expected: Any) -> Any:
    ok = actual == expected
    note = "" if ok else f"   <- expected {expected!r}"
    print(f"{'ok  ' if ok else 'FAIL'}  {label}: {actual!r}{note}")
    if not ok:
        failures.append(label)
    return actual


# --------------------------------------------------------------------------- #
# Small async helpers over the throwaway database
# --------------------------------------------------------------------------- #


def _row(key: str) -> str | None:
    async def _read() -> str | None:
        async with get_sessionmaker()() as s:
            row = await s.get(Setting, key)
            return None if row is None else str(row.value)

    return asyncio.run(_read())


def _set_row(key: str, value: str) -> None:
    """Write a settings row the way a hand edit or an old restore would."""

    async def _write() -> None:
        async with get_sessionmaker()() as s:
            row = await s.get(Setting, key)
            if row is None:
                s.add(Setting(key=key, value=value))
            else:
                row.value = value
            await s.commit()

    asyncio.run(_write())


def _insert_log(ts: dt.datetime, host: str) -> None:
    async def _write() -> None:
        async with get_sessionmaker()() as s:
            s.add(AuditLog(ts=ts, host=host, path="/", action="auth_success"))
            await s.commit()

    asyncio.run(_write())


def _hosts() -> list[str]:
    async def _read() -> list[str]:
        async with get_sessionmaker()() as s:
            rows = await s.execute(select(AuditLog).order_by(AuditLog.host))
            return [str(r.host) for r in rows.scalars().all()]

    return asyncio.run(_read())


def _clear_logs() -> None:
    async def _do() -> None:
        async with get_sessionmaker()() as s:
            await s.execute(text("DELETE FROM audit_logs"))
            await s.commit()

    asyncio.run(_do())


def _api_request(method: str, path: str, **kwargs: Any) -> httpx.Response:
    """Call the API's own ASGI app, so the real route and its gates run."""

    async def _send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api_app), base_url=API, timeout=10.0
        ) as client:
            return await client.request(method, path, headers=INTERNAL, **kwargs)

    return asyncio.run(_send())


def _api_post(path: str) -> httpx.Response:
    return _api_request("POST", path)


# --------------------------------------------------------------------------- #
# Gateway helpers
# --------------------------------------------------------------------------- #


def _load_gateway() -> Any:
    spec = importlib.util.spec_from_file_location(
        "auth_gateway.app", BASE / "auth-gateway" / "app.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["auth_gateway.app"] = module
    spec.loader.exec_module(module)
    return module


def _group(gid: int, name: str, domain: str, rules: list[tuple[str, str]]) -> RuleGroup:
    group = RuleGroup(name=name, domain=domain, display_order=gid, is_default=False)
    group.id = gid
    for index, (path, action) in enumerate(rules):
        rule = Rule(group_id=gid, path=path, action=action, display_order=index)
        rule.id = gid * 100 + index
        group.rules.append(rule)
    return group


def _install_settings(module: Any, **values: str) -> None:
    now = time.monotonic()
    for key, value in values.items():
        module._SettingCache[key] = (now, value)


def _install(
    module: Any,
    groups: list[RuleGroup],
    routes: list[Route] | None = None,
    **settings: str,
) -> None:
    """Seed both module-scoped caches, which is the only way to load them here."""
    module._CacheGroups = groups
    module._CacheRoutes = routes or []
    module._CacheTs = time.monotonic()
    module._SettingCache.clear()
    _install_settings(module, **settings)


def _cookies(response: Any, name: str) -> list[str]:
    return [h for h in response.headers.get_list("set-cookie") if h.startswith(f"{name}=")]


def _max_age(response: Any, name: str) -> int:
    match = re.search(r"Max-Age=(\d+)", _cookies(response, name)[0])
    assert match
    return int(match.group(1))


def _minted_token(response: Any) -> str:
    return _cookies(response, "gatekeeper_token")[0].split(";", 1)[0].split("=", 1)[1]


_ip_counter = [0]


def _ip() -> str:
    _ip_counter[0] += 1
    return f"10.9.{_ip_counter[0] // 250}.{_ip_counter[0] % 250 + 1}"


def _login(module: Any, gateway: TestClient) -> Any:
    granted = Code(code="a-good-code", label="tester", display_name="tester")
    granted.id = 3

    async def _verify(value: str) -> Any:
        return granted if value == "a-good-code" else None

    async def _rate(_ip: str) -> tuple[bool, int, int]:
        return False, 0, 60

    with (
        patch.object(module, "_verify_code_value", _verify),
        patch.object(module, "_check_access_code_rate_limited", _rate),
    ):
        return gateway.get(
            "/?access_code=a-good-code",
            headers={"X-Forwarded-Host": HOST, "CF-Connecting-IP": _ip()},
            follow_redirects=False,
        )


def _gateway_client(module: Any) -> TestClient:
    """A gateway TestClient with a live httpx client behind it.

    The gateway's lifespan closes its shared ``httpx.AsyncClient`` on the way out
    and leaves the closed object in the module global, so a second run in the
    same process would proxy through a dead handle and answer 502 for reasons
    that have nothing to do with what is being checked here.
    """
    module._httpx_client = None
    return TestClient(module.app)


class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    hits: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - the stdlib name
        type(self).hits.append(self.path)
        body = b"upstream-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


# --------------------------------------------------------------------------- #
# 2. unmatched_action: the panel, the API, and the resolver
# --------------------------------------------------------------------------- #


def item_2(manage: TestClient) -> None:
    print()
    print("--- 2. unmatched_action: panel -> stored row -> shared/gate.py ---")

    auth = {"manage_session": create_manage_token(), "csrf_token": CSRF}

    for action in ("deny", "none", "access_code"):
        response = manage.post(
            "/manage/settings",
            data={"csrf_token": CSRF, "unmatched_action": action},
            cookies=auth,
            headers={"Origin": ORIGIN},
            follow_redirects=False,
        )
        check(f"panel accepts {action!r}", response.status_code, 302)
        stored = check(f"  stored row for {action!r}", _row("unmatched_action"), action)
        check(
            "  resolve_rule_action(read_value(row))",
            resolve_rule_action(None, None, read_value("unmatched_action", stored)),
            action,
        )

    panel = manage.post(
        "/manage/settings",
        data={"csrf_token": CSRF, "unmatched_action": "allow"},
        cookies=auth,
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    check("panel refuses 'allow'", panel.status_code, 400)
    check("  row untouched", _row("unmatched_action"), "access_code")

    api = _api_request("PUT", "/api/settings/unmatched_action", json={"value": "allow"})
    check("the API refuses 'allow' directly", api.status_code, 400)
    check("  row still untouched", _row("unmatched_action"), "access_code")

    check(
        "an empty stored row still gates",
        resolve_rule_action(None, None, read_value("unmatched_action", "")),
        "access_code",
    )
    check(
        "a NULL stored row still gates",
        resolve_rule_action(None, None, read_value("unmatched_action", None)),
        "access_code",
    )


# --------------------------------------------------------------------------- #
# 3. Session lifetime: the visitor moves, the admin cookie does not
# --------------------------------------------------------------------------- #


def item_3(manage: TestClient, module: Any) -> None:
    print()
    print("--- 3. session lifetime: visitor moves, manage_session does not ---")

    auth = {"manage_session": create_manage_token(), "csrf_token": CSRF}
    gateway = _gateway_client(module)

    with gateway:
        for hours in (48, 1):
            response = manage.post(
                "/manage/settings",
                data={"csrf_token": CSRF, SESSION_LIFETIME_HOURS: str(hours)},
                cookies=auth,
                headers={"Origin": ORIGIN},
                follow_redirects=False,
            )
            check(f"panel accepts {hours}h", response.status_code, 302)
            check("  stored", _row(SESSION_LIFETIME_HOURS), str(hours))

            _install(module, [_group(1, "open", HOST, [("/*", "access_code")])])
            _install_settings(module, **{SESSION_LIFETIME_HOURS: str(hours)})
            minted = _login(module, gateway)
            check(
                f"  cookie Max-Age at {hours}h",
                _max_age(minted, "gatekeeper_token"),
                hours * 3600,
            )
            claims = decode_without_verify(_minted_token(minted))
            assert claims is not None
            check("  JWT exp - iat", claims["exp"] - claims["iat"], hours * 3600)

    admin = manage.post(
        "/manage/login",
        data={"manage_password": "test-manage-password", "csrf_token": CSRF},
        cookies={"csrf_token": CSRF},
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    check("manage_session Max-Age stays 8h", _max_age(admin, "manage_session"), 8 * 3600)

    _set_row(SESSION_LIFETIME_HOURS, "9999")
    _install(module, [_group(1, "open", HOST, [("/*", "access_code")])])
    with gateway:
        minted = _login(module, gateway)
    check("an out-of-range row reads as 12h", _max_age(minted, "gatekeeper_token"), 12 * 3600)


# --------------------------------------------------------------------------- #
# 4. Maintenance mode
# --------------------------------------------------------------------------- #


def item_4(module: Any, upstream: tuple[str, int]) -> None:
    print()
    print("--- 4. maintenance mode: covers the site, never the way back in ---")

    route = Route(host=HOST, path="/", route_type="proxy", upstream=upstream[0], port=upstream[1])
    route.id = 1
    gateway = _gateway_client(module)
    _Upstream.hits.clear()

    with gateway:
        _install(
            module,
            [_group(1, "open", HOST, [("/*", "none")])],
            [route],
            **{MAINTENANCE_MODE: "false"},
        )
        normal = gateway.get(
            "/anything",
            headers={"X-Forwarded-Host": HOST, "CF-Connecting-IP": _ip()},
            follow_redirects=False,
        )
        check("off: the site is served", normal.status_code, 200)
        check("  the upstream was dialled", _Upstream.hits, ["/anything"])

        _Upstream.hits.clear()
        _install_settings(
            module, **{MAINTENANCE_MODE: "true", "maintenance_message": "Back at six"}
        )
        html = gateway.get(
            "/anything",
            headers={"X-Forwarded-Host": HOST, "Accept": "text/html", "CF-Connecting-IP": _ip()},
            follow_redirects=False,
        )
        check("on: a normal host gets 503", html.status_code, 503)
        check("  the themed page is served", "Down for maintenance" in html.text, True)
        check("  the notice is rendered", "Back at six" in html.text, True)
        check("  Retry-After is set", html.headers.get("retry-after"), "300")
        check("  the upstream was NOT dialled", _Upstream.hits, [])

        forward = gateway.get(
            "/api/authz/forward-auth",
            headers={
                "X-Forwarded-Host": HOST,
                "X-Forwarded-Uri": "/anything",
                "CF-Connecting-IP": _ip(),
            },
            follow_redirects=False,
        )
        check("on: forward_auth agrees", forward.status_code, 503)

        _install(
            module,
            [_group(1, "gk", GK_HOST, [("/*", "none")])],
            **{MAINTENANCE_MODE: "true"},
        )
        exempt = gateway.get(
            "/manage/settings",
            headers={"X-Forwarded-Host": GK_HOST, "CF-Connecting-IP": _ip()},
            follow_redirects=False,
        )
        check("on: /manage is NOT 503", exempt.status_code != 503, True)
        # It went past the gate to the proxy stage instead, which is the normal
        # path. The 502 is this harness's own: `gatekeeper_management` is not
        # running here, so nothing is listening on the upstream address.
        check("  it took the normal proxy path, not the gate", exempt.status_code, 502)

        rest = gateway.get(
            "/documentation/index.html",
            headers={"X-Forwarded-Host": GK_HOST, "CF-Connecting-IP": _ip()},
            follow_redirects=False,
        )
        check("on: the rest of that host still is 503", rest.status_code, 503)

        _Upstream.hits.clear()
        _install(
            module,
            [_group(1, "open", HOST, [("/*", "none")])],
            [route],
            **{MAINTENANCE_MODE: "false"},
        )
        back = gateway.get(
            "/anything",
            headers={"X-Forwarded-Host": HOST, "CF-Connecting-IP": _ip()},
            follow_redirects=False,
        )
        check("off again: served", back.status_code, 200)
        check("  the upstream is dialled again", _Upstream.hits, ["/anything"])


# --------------------------------------------------------------------------- #
# 5. Retention: boot sweep, endpoint and panel button
# --------------------------------------------------------------------------- #


def item_5(manage: TestClient) -> None:
    print()
    print("--- 5. retention: boot sweep, POST /api/logs/prune and the button ---")

    now = dt.datetime.utcnow()  # noqa: DTZ003 - the column stores naive UTC

    _clear_logs()
    _insert_log(now - dt.timedelta(days=40), "old-40.test")
    _insert_log(now - dt.timedelta(days=20), "old-20.test")
    _insert_log(now - dt.timedelta(days=1), "new-1.test")
    response = _api_post(f"{API}/api/logs/prune?days=30")
    check("prune?days=30 deleted exactly the 40-day row", response.json()["deleted"], 1)
    check("  survivors", sorted(_hosts()), ["new-1.test", "old-20.test"])

    _clear_logs()
    _insert_log(now - dt.timedelta(days=40), "old-40.test")
    _insert_log(now - dt.timedelta(days=20), "old-20.test")
    _set_row(LOG_RETENTION_DAYS, "30")
    with TestClient(api_app):
        pass
    check("boot sweep removed the 40-day row", sorted(_hosts()), ["old-20.test"])

    _clear_logs()
    _insert_log(now - dt.timedelta(days=25), "old-25.test")
    _insert_log(now - dt.timedelta(days=15), "old-15.test")
    _set_row(LOG_RETENTION_DAYS, "20")
    with TestClient(api_app):
        pass
    check("boot sweep honoured the stored 20 days", sorted(_hosts()), ["old-15.test"])

    # A fresh pair for the button, because the boot sweep above already thinned
    # the table and the point here is what the button itself removes.
    _clear_logs()
    _insert_log(now - dt.timedelta(days=25), "old-25.test")
    _insert_log(now - dt.timedelta(days=15), "old-15.test")

    auth = {"manage_session": create_manage_token(), "csrf_token": CSRF}
    refused = manage.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": "nope"},
        cookies=auth,
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    check("the button refuses an unconfirmed post", refused.status_code, 403)
    check("  nothing was deleted", len(_hosts()), 2)

    pressed = manage.post(
        "/manage/logs/prune",
        data={"csrf_token": CSRF, "confirm": "PRUNE"},
        cookies=auth,
        headers={"Origin": ORIGIN},
        follow_redirects=False,
    )
    check("the button reports its count", "Deleted 1 audit row" in pressed.text, True)
    check("  pruned by the stored window", sorted(_hosts()), ["old-15.test"])

    _clear_logs()


def main() -> int:
    print("=" * 78)
    print("PHASE 5 VERIFICATION  (throwaway db: %s)" % DB_PATH.name)
    print("=" * 78)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    upstream = ("127.0.0.1", server.server_address[1])

    api_client = TestClient(api_app)
    with api_client:
        asgi = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=api_app), base_url=API, timeout=10.0
        )
        with patch.object(management_app, "_get_httpx", lambda: asgi):
            manage = TestClient(management_app.create_app())
            with manage:
                module = _load_gateway()
                item_2(manage)
                item_3(manage, module)
                item_4(module, upstream)
                item_5(manage)

    server.shutdown()
    server.server_close()
    DB_PATH.unlink(missing_ok=True)

    print()
    if failures:
        print(f"FAILED: {len(failures)} check(s)")
        for name in failures:
            print(f"  - {name}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
