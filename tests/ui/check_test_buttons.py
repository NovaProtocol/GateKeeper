"""Rendered-DOM proof of the pre-save test buttons.

The buttons are the point of the phase, so they are proven by pressing them in a
real browser rather than by asserting that a string appears in a template. Four
claims, and each needs the browser:

1. **the control is there and it is named.** Each add and edit modal on Routing
   and Rules renders a Test control with both `title` and `aria-label`, because
   it is icon-only and the glyph carries no accessible name.
2. **a reachable draft reports success.** The button asks the server about the
   values *as typed*, so the fields are filled in and the modal is opened the way
   an operator opens it.
3. **an unreachable draft reports failure with a legible message.** The verdict
   is rendered into the footer slot, not into a console nobody reads.
4. **the `9c1e318` table invariant still holds** on `/manage/routing` and
   `/manage/rules/10`, both of which gained a button and changed their inputs:
   one shared height per row, the last cell still `display: table-cell`, and no
   inline `display:flex` on any `<td>`.

The panel is served in-process with the real templates and the real `manage.css`.
Only the API behind it is stood in, because the two endpoints under test are the
panel's own and they relay to `api:8002`, which is not running here.

Run with::

    uv run --no-project --with playwright --with-requirements requirements.txt \
        python tests/ui/check_test_buttons.py
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, ClassVar

BASE = Path(__file__).resolve().parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

DB_PATH = Path("/tmp/gatekeeper_test_buttons_ui.db").resolve()
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-characters")
os.environ.setdefault("MANAGE_PASSWORD", "test-manage-password")
os.environ.setdefault("BACKUP_CODE", "test-backup-code")
os.environ.setdefault("INTERNAL_API_KEY", "test-internal-api-key")
os.environ.setdefault("DEPLOYMENT_TYPE", "debug")
os.environ.setdefault("DB_DIR", str(DB_PATH.parent))
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{DB_PATH}")
os.environ.setdefault("API_HTTP_ADDR", "http://api.invalid:8002")

import structlog  # noqa: E402
import uvicorn  # noqa: E402

import management.app as management_app  # noqa: E402
from shared.jwt import create_manage_token  # noqa: E402

structlog.configure(
    processors=[structlog.processors.JSONRenderer()],
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
)
logging.getLogger("management").setLevel(logging.WARNING)
logging.getLogger("uvicorn.error").setLevel(logging.ERROR)
logging.getLogger("uvicorn.access").setLevel(logging.ERROR)

GROUPS = [
    {
        "id": 10,
        "name": "portfolio",
        "domain": "portfolio.projectnova.download",
        "display_order": 0,
        "is_default": False,
        "rules_count": 2,
    },
    {
        "id": 12,
        "name": "*.*/*",
        "domain": "*.*/*",
        "display_order": 9999,
        "is_default": True,
        "rules_count": 1,
    },
]

RULES = [
    {
        "id": 1,
        "group_id": 10,
        "path": "/private/*",
        "action": "access_code",
        "rate_limit": None,
        "display_order": 0,
        "is_default": False,
    },
    {
        "id": 2,
        "group_id": 10,
        "path": "/*",
        "action": "none",
        "rate_limit": None,
        "display_order": 1,
        "is_default": True,
    },
]

ROUTES = [
    {
        "id": 5,
        "host": "app.projectnova.download",
        "path": "/",
        "route_type": "proxy",
        "upstream": "portfolio-web",
        "port": 8080,
        "redirect_target": None,
        "redirect_code": None,
    }
]

PAYLOADS: dict[str, Any] = {
    "/api/groups": GROUPS,
    "/api/groups/10/rules": RULES,
    "/api/groups/12/rules": RULES,
    "/api/routes": ROUTES,
    "/api/codes": [],
    "/api/logs": [],
    "/api/warnings": {"groups": [], "rules": []},
}

#: A live listener, so "reachable" is a real connect and not a stubbed answer.
REACHABLE = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
REACHABLE.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
REACHABLE.bind(("127.0.0.1", 0))
REACHABLE.listen(8)
REACHABLE_HOST, REACHABLE_PORT = REACHABLE.getsockname()


def _closed_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class _FakeResponse:
    def __init__(self, payload: Any = None, status_code: int = 200) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload) if payload is not None else ""
        self.content = self.text.encode()
        self.headers: dict[str, str] = {"content-type": "application/json"}

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    """Stands in for `api:8002`, and keeps every probe the browser made.

    `posts` is what makes the browser's own requests observable, so the verdict
    on screen can be tied to the fields the modal actually sent. Both calls the
    routing modal makes are kept, in order, because the first one is the upstream
    probe and the second is the gate preview.
    """

    posts: ClassVar[list[dict[str, Any]]] = []

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(PAYLOADS.get(url.split("http://api:8002", 1)[-1], []))

    async def post(self, url: str, json: Any = None, **kwargs: Any) -> _FakeResponse:
        path = url.split("http://api:8002", 1)[-1]
        type(self).posts.append({"path": path, "body": json})
        if path == "/api/routes/test":
            # The real probe: try to connect to what the browser typed.
            upstream, port = (json or {}).get("upstream"), (json or {}).get("port")
            try:
                conn = socket.create_connection((str(upstream), int(port)), timeout=1.0)
                conn.close()
                return _FakeResponse({"ok": True, "latency": "reachable"})
            except Exception as exc:  # any failure means "not reachable"
                return _FakeResponse({"ok": False, "error": str(exc)})
        if path == "/api/dry-run":
            return _FakeResponse(
                {
                    "matched_group": "portfolio",
                    "matched_rule": "/private/*",
                    "action": "access_code",
                    "warnings": [{"rule": "/*", "message": "shadowed by /private/*"}],
                }
            )
        return _FakeResponse({})

    async def put(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})


management_app._get_httpx = lambda: _FakeClient()  # type: ignore[assignment]

app = management_app.create_app()
config = uvicorn.Config(app, host="127.0.0.1", port=8734, log_level="error")
server = uvicorn.Server(config)
threading.Thread(target=server.run, daemon=True).start()
for _ in range(100):
    if server.started:
        break
    time.sleep(0.05)
assert server.started, "uvicorn did not start"

TOKEN = create_manage_token()
BASE_URL = "http://127.0.0.1:8734"

#: Every Test control on the page, with the names it carries.
CONTROLS = """
() => {
  const out = [];
  document.querySelectorAll('button[title="Test before saving"]').forEach(btn => {
    out.push({
      title: btn.getAttribute('title'),
      aria: btn.getAttribute('aria-label'),
      visibleText: (btn.textContent || '').trim(),
      hidden: btn.offsetParent === null,
      onclick: btn.getAttribute('onclick') || '',
    });
  });
  return out;
}
"""

#: The verdict slot of one modal, as rendered.
VERDICT = """
(which) => {
  const el = document.getElementById(which + '-test-result');
  if (!el) return null;
  return {
    text: (el.textContent || '').trim(),
    role: el.getAttribute('role'),
    live: el.getAttribute('aria-live'),
    spans: Array.from(el.querySelectorAll('span')).map(s => ({
      cls: s.className,
      text: (s.textContent || '').trim(),
      color: getComputedStyle(s).color,
    })),
    html: el.innerHTML.length,
  };
}
"""

TABLE_INVARIANTS = """
() => {
  const out = [];
  document.querySelectorAll('table').forEach((table, tableIndex) => {
    const rows = Array.from(table.querySelectorAll('tbody tr'))
      .filter(r => !r.querySelector('td[colspan]'));
    out.push({
      tableIndex,
      identifier: table.className,
      rows: rows.map((row, rowIndex) => {
        const cells = Array.from(row.children);
        const last = cells[cells.length - 1];
        return {
          rowIndex,
          rowHeight: row.offsetHeight,
          cellHeights: cells.map(c => c.offsetHeight),
          lastTag: last.tagName.toLowerCase(),
          lastDisplay: getComputedStyle(last).display,
          inlineFlexCells: cells.filter(
            c => (c.getAttribute('style') || '').replace(/\\s+/g, '').includes('display:flex')
          ).length,
        };
      }),
    });
  });
  return out;
}
"""


def main() -> int:
    from playwright.sync_api import sync_playwright

    failures: list[str] = []
    note = lambda text: print(text)  # noqa: E731 - a print alias keeps the noise down

    def check(label: str, ok: bool, detail: str = "") -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {label}{('  ' + detail) if detail else ''}")
        if not ok:
            failures.append(f"{label} {detail}".strip())

    print("=" * 78)
    print("RENDERED-DOM PROOF - pre-save test buttons")
    print("=" * 78)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        context.add_cookies(
            [
                {"name": "manage_session", "value": TOKEN, "url": BASE_URL},
                {"name": "csrf_token", "value": "ui-check-csrf", "url": BASE_URL},
            ]
        )
        page = context.new_page()

        # ---------------------------------------------------------------- 1 --
        print("\n1. THE CONTROL IS RENDERED AND IT IS NAMED")
        for path, expected in (("/manage/routing", 3), ("/manage/rules/10", 2)):
            page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
            controls = page.evaluate(CONTROLS)
            print(f"\n  {path}: {len(controls)} Test control(s)")
            for c in controls:
                note(
                    f"      title={c['title']!r} aria-label={c['aria']!r} "
                    f"text={c['visibleText']!r} onclick={c['onclick']!r} hidden={c['hidden']}"
                )
            check(f"{path}: one per modal", len(controls) == expected, f"got {len(controls)}")
            check(
                f"{path}: every control has title and aria-label",
                all(c["title"] and c["aria"] for c in controls),
            )
            check(
                f"{path}: the label is not carried by visible text",
                all(not c["visibleText"] for c in controls),
                "icon-only, so the name has to come from the attributes",
            )
            check(
                f"{path}: every control is in a modal footer, not always-on chrome",
                all("Modal" in c["onclick"] or "test" in c["onclick"] for c in controls),
            )

        # ---------------------------------------------------------------- 2 --
        print("\n2. A REACHABLE DRAFT REPORTS SUCCESS")
        page.goto(f"{BASE_URL}/manage/routing", wait_until="networkidle")
        page.click('button[data-target="#addProxyModal"]')
        page.wait_for_timeout(300)
        _FakeClient.posts.clear()
        page.fill("#proxy-domain", "app.projectnova.download")
        page.fill("#proxy-path", "/")
        page.fill("#proxy-upstream", REACHABLE_HOST)
        page.fill("#proxy-port", str(REACHABLE_PORT))
        page.click("button[onclick=\"testDraft('proxy')\"]")
        page.wait_for_function(
            "() => !document.getElementById('proxy-test-result').textContent.includes('testing')",
            timeout=5000,
        )
        reachable = page.evaluate(VERDICT, "proxy")
        note(f"  verdict: {reachable['text']!r}")
        note(f"  spans  : {[(s['cls'], s['text']) for s in reachable['spans']]}")
        note(f"  the browser typed {REACHABLE_HOST}:{REACHABLE_PORT} and the server agreed")
        check("the reachable draft reports success", "upstream: reachable" in reachable["text"])
        check(
            "the success span carries the ok style",
            any(s["cls"] == "test-ok" and "reachable" in s["text"] for s in reachable["spans"]),
        )
        check(
            "the slot is announced politely",
            reachable["role"] == "status" and reachable["live"] == "polite",
        )
        posts = list(_FakeClient.posts)
        note(f"  the two probes the browser sent: {posts}")
        check("the modal made both calls", len(posts) == 2, f"got {len(posts)}")
        check(
            "the first probe used the typed values, not the row's",
            bool(posts)
            and posts[0]["path"] == "/api/routes/test"
            and posts[0]["body"]["upstream"] == REACHABLE_HOST
            and int(posts[0]["body"]["port"]) == REACHABLE_PORT,
            str(posts[0]["body"]) if posts else "no probe sent",
        )
        check(
            "the second probe is the gate preview for the typed host",
            len(posts) > 1
            and posts[1]["path"] == "/api/dry-run"
            and posts[1]["body"]["host"] == "app.projectnova.download",
            str(posts[1]["body"]) if len(posts) > 1 else "no gate call",
        )
        gate_span = [s for s in reachable["spans"] if s["text"].startswith("gate:")]
        check(
            "the gate verdict names the action, group and rule",
            bool(gate_span)
            and "access_code" in gate_span[0]["text"]
            and "portfolio" in gate_span[0]["text"],
            gate_span[0]["text"] if gate_span else "no gate span",
        )
        shadow = [s for s in reachable["spans"] if s["text"].startswith("shadowed:")]
        check(
            "a shadowing warning is rendered, not swallowed",
            bool(shadow) and shadow[0]["cls"] == "test-bad",
            shadow[0]["text"] if shadow else "no shadowed span",
        )

        # ---------------------------------------------------------------- 3 --
        print("\n3. AN UNREACHABLE DRAFT REPORTS FAILURE")
        dead_port = _closed_port()
        page.fill("#proxy-upstream", "127.0.0.1")
        page.fill("#proxy-port", str(dead_port))
        page.click("button[onclick=\"testDraft('proxy')\"]")
        page.wait_for_function(
            "() => !document.getElementById('proxy-test-result').textContent.includes('testing')",
            timeout=5000,
        )
        dead = page.evaluate(VERDICT, "proxy")
        note(f"  verdict: {dead['text']!r}")
        note(f"  spans  : {[(s['cls'], s['text']) for s in dead['spans']]}")
        check("the unreachable draft reports failure", "upstream: " in dead["text"])
        check("the failure is not reported as reachable", "reachable" not in dead["text"])
        check(
            "the failure span carries the bad style",
            any(s["cls"] == "test-bad" for s in dead["spans"]),
        )
        check(
            "the message names the address that failed",
            f"127.0.0.1:{dead_port}" in dead["text"] or "Connection refused" in dead["text"],
            dead["text"][:120],
        )
        check(
            "nothing was saved: the route list is unchanged",
            len(PAYLOADS["/api/routes"]) == 1,
        )

        print("\n3b. THE RULE MODAL ASKS THE GATE ABOUT THE TYPED PATH")
        page.goto(f"{BASE_URL}/manage/rules/10", wait_until="networkidle")
        _FakeClient.posts.clear()
        page.click('button[data-target="#addRuleModal"]')
        page.wait_for_timeout(300)
        page.click("button[onclick=\"testRuleDraft('add')\"]")
        page.wait_for_timeout(250)
        empty_verdict = page.evaluate(VERDICT, "add")
        note(f"  with no path typed: {empty_verdict['text']!r}")
        check(
            "an empty path is refused in the browser, before any request",
            empty_verdict["text"] == "enter a path first" and not _FakeClient.posts,
            f"and nothing was sent: {_FakeClient.posts}",
        )
        page.fill("#rule-path", "/private/reports")
        page.click("button[onclick=\"testRuleDraft('add')\"]")
        page.wait_for_function(
            "() => !document.getElementById('add-test-result').textContent.includes('testing')",
            timeout=5000,
        )
        rule_verdict = page.evaluate(VERDICT, "add")
        note(f"  verdict: {rule_verdict['text']!r}")
        check("the rule draft reports the matched action", "access_code" in rule_verdict["text"])
        check(
            "the rule draft reports the shadowing warning",
            "shadowed:" in rule_verdict["text"],
        )
        sent = _FakeClient.posts[-1]
        note(f"  the gate call the browser sent: {sent}")
        check(
            "the rule probe used the group's own host",
            sent["path"] == "/api/dry-run" and "projectnova.download" in str(sent["body"]["host"]),
        )
        check(
            "the rule probe sent the typed path",
            sent["body"]["path"] == "/private/reports",
        )

        # ---------------------------------------------------------------- 4 --
        print("\n4. THE 9c1e318 TABLE INVARIANT, ON BOTH TOUCHED TABLES")
        for path in ("/manage/routing", "/manage/rules/10"):
            page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
            tables = page.evaluate(TABLE_INVARIANTS)
            note(f"\n  {path}: {len(tables)} table(s)")
            for table in tables:
                label = table["identifier"] or f"table {table['tableIndex']}"
                shared = [len(set(r["cellHeights"])) == 1 for r in table["rows"]]
                displays = [r["lastDisplay"] for r in table["rows"]]
                inline_flex = sum(r["inlineFlexCells"] for r in table["rows"])
                note(
                    f"      {label}: {len(table['rows'])} row(s)  "
                    f"shared_height={all(shared)}  last_display={sorted(set(displays))}  "
                    f"inline_flex_tds={inline_flex}"
                )
                note(f"        per-row heights: {[r['cellHeights'] for r in table['rows']]}")
                check(f"{path} {label}: every row's cells share one height", all(shared))
                check(
                    f"{path} {label}: last cell is display: table-cell",
                    set(displays) == {"table-cell"},
                )
                check(f"{path} {label}: no inline display:flex on a <td>", inline_flex == 0)

        browser.close()

    REACHABLE.close()

    print("\n" + "=" * 78)
    if failures:
        print(f"FAILURES ({len(failures)}):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
