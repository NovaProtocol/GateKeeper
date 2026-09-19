"""Rendered-DOM proof of the manage-table fix.

The reported bug was a layout bug, so it is proven by the measurement that
found it rather than by asserting on markup: the last cell of each row used to
render ~20px shorter than its own row because an inline `display:flex` took it
out of the table layout algorithm.

Run with::

    uv run --no-project --with playwright python tests/ui/check_tables.py

The script serves the real management app in-process (real templates, real
`manage.css`, real Bootstrap 4.6) and drives Chromium against it. It measures
every page twice: once as shipped, and once with the pre-fix shape re-applied
onto the live DOM (`display:flex` back on the last `<td>`, scroll wrapper
removed) so the before/after numbers come from the same content and the same
browser.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

DB_PATH = Path("/tmp/gatekeeper_ui_check.db").resolve()
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-characters")
os.environ.setdefault("MANAGE_PASSWORD", "test-manage-password")
os.environ.setdefault("BACKUP_CODE", "test-backup-code")
os.environ.setdefault("INTERNAL_API_KEY", "test-internal-api-key")
os.environ.setdefault("DEPLOYMENT_TYPE", "debug")
os.environ.setdefault("DB_DIR", str(DB_PATH.parent))
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{DB_PATH}")
os.environ.setdefault("API_HTTP_ADDR", "http://api.invalid:8002")

import uvicorn  # noqa: E402

import management.app as management_app  # noqa: E402
from shared.jwt import create_manage_token  # noqa: E402

GROUPS = [
    {
        "id": 10,
        "name": "gatekeeper.projectnova.download",
        "domain": "gatekeeper.projectnova.download",
        "display_order": 0,
        "is_default": False,
        "rules_count": 6,
    },
    {
        "id": 11,
        "name": "projectnova.download",
        "domain": "projectnova.download",
        "display_order": 1,
        "is_default": False,
        "rules_count": 3,
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
        "path": "/*",
        "action": "none",
        "rate_limit": None,
        "display_order": 0,
    },
    {
        "id": 2,
        "group_id": 10,
        "path": "/documentation/*",
        "action": "access_code",
        "rate_limit": None,
        "display_order": 1,
    },
    {
        "id": 3,
        "group_id": 10,
        "path": "/api/*",
        "action": "deny",
        "rate_limit": None,
        "display_order": 2,
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
    },
    {
        "id": 6,
        "host": "old.projectnova.download",
        "path": "/docs",
        "route_type": "redirect",
        "upstream": None,
        "port": None,
        "redirect_target": "https://documentation.projectnova.download/docs",
        "redirect_code": 302,
    },
    {
        "id": 7,
        "host": "api.projectnova.download",
        "path": "/v1/*",
        "route_type": "proxy",
        "upstream": "docs-site",
        "port": 8100,
        "redirect_target": None,
        "redirect_code": None,
    },
]

CODES = [
    {
        "id": 3,
        "code": "abcd1234efgh",
        "label": "Alice",
        "display_name": "Alice",
        "active": True,
        "created_at": "2026-01-01 10:00:00",
        "last_accessed": "2026-09-01 12:00:00",
    },
    {
        "id": 4,
        "code": "zzzz9999yyyy",
        "label": "Bob",
        "display_name": "Bob",
        "active": False,
        "created_at": "2026-02-02 11:00:00",
        "last_accessed": None,
    },
]

PAGE_ROWS: list[dict[str, Any]] = [
    {
        "id": 7,
        "pattern": "*.projectnova.download/robots.txt",
        "body": "User-agent: *\nDisallow: /\n",
        "content_type": "text/plain; charset=utf-8",
        "active": True,
        "display_order": 0,
    }
]

PAYLOADS = {
    "/api/groups": GROUPS,
    "/api/groups/10/rules": RULES,
    "/api/routes": ROUTES,
    "/api/pages": PAGE_ROWS,
    "/api/codes": CODES,
}

PAGES = [
    ("/manage/rules", "Rule Groups"),
    ("/manage/rules/10", "Rules"),
    ("/manage/codes", "Access Codes"),
    ("/manage/routing", "Routing"),
    ("/manage/pages", "Custom Pages"),
]

WIDTHS = [1440, 1280, 1024, 820, 600, 420]


class _FakeResponse:
    def __init__(self, payload: Any = None) -> None:
        self.status_code = 200
        self._payload = payload
        self.text = ""

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        path = url.split("http://api:8002", 1)[-1]
        return _FakeResponse(PAYLOADS.get(path, []))

    async def put(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})

    async def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        path = url.split("http://api:8002", 1)[-1]
        # `POST /api/dry-run` resolves each page row's governing rule.
        return _FakeResponse(PAYLOADS.get(path, {}))

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})


management_app._get_httpx = lambda: _FakeClient()  # type: ignore[assignment]

app = management_app.create_app()
config = uvicorn.Config(app, host="127.0.0.1", port=8731, log_level="error")
server = uvicorn.Server(config)
thread = threading.Thread(target=server.run, daemon=True)
thread.start()
for _ in range(100):
    if server.started:
        break
    time.sleep(0.05)
assert server.started, "uvicorn did not start"

TOKEN = create_manage_token()
BASE_URL = "http://127.0.0.1:8731"

MEASURE = """
() => {
  const table = document.querySelector('table.codes-table');
  const wrapper = table.closest('.table-scroll');
  const card = document.querySelector('.card');
  const rows = Array.from(table.querySelectorAll('tbody tr'))
    .filter(r => !r.querySelector('td[colspan]'));
  const data = rows.map((row, i) => {
    const cells = Array.from(row.children);
    const last = cells[cells.length - 1];
    return {
      index: i,
      rowHeight: row.offsetHeight,
      cellHeights: cells.map(c => c.offsetHeight),
      lastDisplay: getComputedStyle(last).display,
      lastClass: last.className,
    };
  });
  const inner = table.querySelector('td.actions-cell > div');
  return {
    rows: data,
    tableWidth: table.getBoundingClientRect().width,
    wrapperWidth: wrapper ? wrapper.getBoundingClientRect().width : null,
    wrapperClientWidth: wrapper ? wrapper.clientWidth : null,
    wrapperScrollWidth: wrapper ? wrapper.scrollWidth : null,
    wrapperTabIndex: wrapper ? wrapper.getAttribute('tabindex') : null,
    wrapperRole: wrapper ? wrapper.getAttribute('role') : null,
    wrapperLabel: wrapper ? wrapper.getAttribute('aria-label') : null,
    cardWidth: card.getBoundingClientRect().width,
    pageScrollOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    actionsDisplay: inner ? getComputedStyle(inner).display : null,
  };
}
"""

APPLY_LEGACY = """
() => {
  const table = document.querySelector('table.codes-table');
  const wrapper = table.closest('.table-scroll');
  if (wrapper) {
    wrapper.parentNode.insertBefore(table, wrapper);
    wrapper.remove();
  }
  table.querySelectorAll('td.actions-cell').forEach(td => {
    td.removeAttribute('class');
    td.style.display = 'flex';
    td.style.gap = '.4rem';
    td.style.justifyContent = 'flex-end';
    td.style.alignItems = 'center';
  });
}
"""

REACHABLE = """
() => {
  const table = document.querySelector('table.codes-table');
  const wrapper = table.closest('.table-scroll');
  const scroller = wrapper || document.documentElement;
  scroller.scrollLeft = 999999;
  const sRect = scroller.getBoundingClientRect();
  const right = wrapper ? sRect.right : document.documentElement.clientWidth;
  const cells = Array.from(table.querySelectorAll('tbody tr td'));
  const clipped = cells
    .map(c => ({
      text: (c.textContent || '').trim().slice(0, 24),
      right: c.getBoundingClientRect().right,
    }))
    .filter(c => c.right > right + 0.5);
  const reachableByScroll = wrapper
    ? wrapper.scrollWidth > wrapper.clientWidth
    : document.documentElement.scrollWidth > document.documentElement.clientWidth;
  return {
    clippedCount: clipped.length,
    clipped: clipped.slice(0, 4),
    scrollerClientWidth: wrapper ? wrapper.clientWidth : document.documentElement.clientWidth,
    scrollerScrollWidth: wrapper ? wrapper.scrollWidth : document.documentElement.scrollWidth,
    reachableByScroll,
    tableWidth: table.getBoundingClientRect().width,
  };
}
"""

ARIA = """
() => {
  const out = [];
  document.querySelectorAll('table.codes-table tbody tr').forEach(row => {
    const cell = row.querySelector('td.actions-cell');
    if (!cell) return;
    cell.querySelectorAll('a, button').forEach(el => {
      out.push({
        aria: el.getAttribute('aria-label'),
        title: el.getAttribute('title'),
        visibleText: (el.textContent || '').trim(),
      });
    });
  });
  return out;
}
"""


def main() -> int:
    from playwright.sync_api import sync_playwright

    failures: list[str] = []
    print("=" * 78)
    print("RENDERED-DOM PROOF — manage table layout")
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

        for path, label in PAGES:
            page.goto(f"{BASE_URL}{path}", wait_until="networkidle")

            after = page.evaluate(MEASURE)
            print(f"\n--- {path}  ({label}) ---")
            print("AFTER (as shipped):")
            for row in after["rows"]:
                heights = sorted(set(row["cellHeights"]))
                side = "BAD" if len(heights) != 1 else "OK "
                print(
                    f"  {side} row {row['index']}: row_height={row['rowHeight']} "
                    f"cell_heights={row['cellHeights']} last_display={row['lastDisplay']}"
                )
                if len(heights) != 1:
                    detail = row["cellHeights"]
                    failures.append(f"{path} row {row['index']}: heights differ {detail}")
                if row["lastDisplay"] != "table-cell":
                    shown = row["lastDisplay"]
                    failures.append(f"{path} row {row['index']}: display={shown}")
                if "actions-cell" not in (row["lastClass"] or ""):
                    failures.append(f"{path} row {row['index']}: last cell lost .actions-cell")

            print(f"  inner .actions display = {after['actionsDisplay']}")
            if after["actionsDisplay"] != "flex":
                failures.append(f"{path}: inner .actions is not flex ({after['actionsDisplay']})")

            tabindex = after["wrapperTabIndex"]
            role = after["wrapperRole"]
            print(
                f"  scroll wrapper: tabindex={tabindex} role={role} "
                f"aria-label={after['wrapperLabel']!r}"
            )
            if tabindex != "0" or role != "region" or not after["wrapperLabel"]:
                failures.append(f"{path}: scroll wrapper is not focusable/named")

            aria = page.evaluate(ARIA)
            missing = [a for a in aria if not a["aria"] or not a["title"]]
            print(f"  row controls={len(aria)}  missing aria-label/title={len(missing)}")
            if missing:
                failures.append(f"{path}: controls without accessible name: {missing}")
            if not aria:
                failures.append(f"{path}: no row controls found")

            # Now re-apply the pre-fix shape on the live DOM and measure again.
            page.evaluate(APPLY_LEGACY)
            before = page.evaluate(MEASURE)
            print("BEFORE (pre-fix shape re-applied to the same DOM):")
            for row in before["rows"]:
                delta = row["rowHeight"] - row["cellHeights"][-1]
                print(
                    f"     row {row['index']}: row_height={row['rowHeight']} "
                    f"last_cell_height={row['cellHeights'][-1]} "
                    f"last_display={row['lastDisplay']}  <== {delta}px shorter than its row"
                )

        # Narrow-width proof on the rules page.
        page.goto(f"{BASE_URL}/manage/rules", wait_until="networkidle")
        print("\n--- narrow-width reachability (/manage/rules) ---")
        print(
            f"{'width':>6} {'card':>7} {'table':>7} {'box_client':>11} "
            f"{'box_scroll':>11} {'clipped':>8} {'reachable':>10} {'page_overflow':>14}"
        )
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.wait_for_timeout(120)
            m = page.evaluate(MEASURE)
            r = page.evaluate(REACHABLE)
            print(
                f"{width:>6} {m['cardWidth']:>7.0f} {r['tableWidth']:>7.0f} "
                f"{r['scrollerClientWidth']:>11.0f} {r['scrollerScrollWidth']:>11.0f} "
                f"{r['clippedCount']:>8} {r['reachableByScroll']!s:>10} "
                f"{m['pageScrollOverflow']:>14.0f}"
            )
            if r["clippedCount"]:
                clipped = r["clipped"]
                failures.append(
                    f"{width}px: {r['clippedCount']} clipped past the scroller: {clipped}"
                )
            if m["pageScrollOverflow"] > 0:
                overflow = m["pageScrollOverflow"]
                failures.append(f"{width}px: page scrolls horizontally by {overflow}px")

        # Pre-fix comparison at the widths where the card used to clip outright.
        page.goto(f"{BASE_URL}/manage/rules", wait_until="networkidle")
        print("\n--- narrow-width reachability, PRE-FIX shape (card clip, no scroll box) ---")
        print(f"{'width':>6} {'table':>7} {'clipped':>8} {'reachable':>10} {'page_overflow':>14}")
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.wait_for_timeout(120)
            page.evaluate(APPLY_LEGACY)
            m = page.evaluate(MEASURE)
            r = page.evaluate(REACHABLE)
            print(
                f"{width:>6} {r['tableWidth']:>7.0f} {r['clippedCount']:>8} "
                f"{r['reachableByScroll']!s:>10} {m['pageScrollOverflow']:>14.0f}"
            )
            page.goto(f"{BASE_URL}/manage/rules", wait_until="networkidle")

        browser.close()

    print("\n" + "=" * 78)
    if failures:
        print(f"FAILURES: {len(failures)}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("ALL RENDERED-DOM CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
