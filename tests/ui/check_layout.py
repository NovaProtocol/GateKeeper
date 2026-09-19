"""Rendered-DOM proof of the manage layout pass.

Three claims were made in review and each is only true if a browser agrees:

1. **The stat strip is compact.** The complaint was that three numbers occupied
   a card each. The measurement is the strip's rendered height against the same
   three numbers in the old card markup, injected into the same page, in the
   same browser, so the comparison is of the change and nothing else.
2. **The layout is genuinely wider.** `/manage` used to cap at 1100px whatever
   the window was. The measurement is the container width at 1440, 1280 and
   1024 against that 1100px ceiling, plus a check that no page scrolls sideways
   at any of the six widths the plan lists.
3. **The table fix from `9c1e318` still holds.** Every table on every page it
   appears on: one shared height per row, the last cell still `display:
   table-cell`, and no inline `display:flex` on any `<td>`.

It also walks the sidebar to prove no link is dead after the rename and the
deletion.

Run with::

    uv run --no-project --with playwright python tests/ui/check_layout.py
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

BASE = Path(__file__).resolve().parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

DB_PATH = Path("/tmp/gatekeeper_layout_check.db").resolve()
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-characters")
os.environ.setdefault("MANAGE_PASSWORD", "test-manage-password")
os.environ.setdefault("BACKUP_CODE", "test-backup-code")
os.environ.setdefault("INTERNAL_API_KEY", "test-internal-api-key")
os.environ.setdefault("DEPLOYMENT_TYPE", "debug")
os.environ.setdefault("DB_DIR", str(DB_PATH.parent))
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{DB_PATH}")
os.environ.setdefault("API_HTTP_ADDR", "http://api.invalid:8002")

# The app logs one JSON line per request to stdout, which would bury the
# measurements below. `structlog.get_logger()` is lazy, so reconfiguring here
# takes effect for the already-imported module.
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
        "path": "/documentation/*",
        "action": "access_code",
        "rate_limit": None,
        "display_order": 0,
        "is_default": False,
    },
    {
        "id": 2,
        "group_id": 10,
        "path": "/api/*",
        "action": "deny",
        "rate_limit": None,
        "display_order": 1,
        "is_default": False,
    },
    {
        "id": 3,
        "group_id": 10,
        "path": "/*",
        "action": "none",
        "rate_limit": None,
        "display_order": 2,
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
    {
        "id": 5,
        "code": "cccc4444dddd",
        "label": "Carol",
        "display_name": "Carol",
        "active": True,
        "created_at": "2026-03-03 09:00:00",
        "last_accessed": None,
    },
]

LOGS = [
    {
        "id": i,
        "ts": f"2026-09-17 10:0{i}:00",
        "ip": "203.0.113.5",
        "host": "app.projectnova.download",
        "path": f"/reports/{i}",
        "action": "auth_success" if i % 2 else "no_cookie_redirect",
    }
    for i in range(10)
]

TOP = [
    {"host": "app.projectnova.download", "path": "/reports", "calls": 40},
    {"host": "app.projectnova.download", "path": "/", "calls": 22},
    {"host": "documentation.projectnova.download", "path": "/docs/intro", "calls": 11},
    {"host": "api.projectnova.download", "path": "/v1/orders", "calls": 6},
    {"host": "app.projectnova.download", "path": "/settings", "calls": 2},
]

BY_IP = [
    {
        "ip": "203.0.113.5",
        "calls": 40,
        "recent": [
            {
                "ts": "2026-09-17 10:00:00",
                "host": "app.projectnova.download",
                "path": "/reports",
                "action": "auth_success",
                "code_label": "Alice",
                "attempted_code": None,
            },
            {
                "ts": "2026-09-17 09:59:00",
                "host": "app.projectnova.download",
                "path": "/",
                "action": "none_gate",
                "code_label": None,
                "attempted_code": "wrong-code",
            },
        ],
        "codes": ["Alice"],
    },
    {
        "ip": "198.51.100.7",
        "calls": 3,
        "recent": [
            {
                "ts": "2026-09-17 09:40:00",
                "host": "documentation.projectnova.download",
                "path": "/docs/intro",
                "action": "auth_success",
                "code_label": "Carol",
                "attempted_code": None,
            }
        ],
        "codes": ["Carol"],
    },
]

SETTINGS = [{"key": "rate_limit_access_code_per_min", "value": "5", "updated_at": None}]

PAYLOADS: dict[str, Any] = {
    "/api/groups": GROUPS,
    "/api/groups/10/rules": RULES,
    "/api/groups/11/rules": [RULES[2]],
    "/api/groups/12/rules": [RULES[2]],
    "/api/routes": ROUTES,
    "/api/codes": CODES,
    "/api/logs": LOGS,
    "/api/logs/top": TOP,
    "/api/logs/by-ip": BY_IP,
    "/api/settings": SETTINGS,
    "/api/warnings": {"groups": [], "rules": []},
}

# Pages that render one of the action tables with an `.actions-cell` column.
TABLE_PAGES = [
    ("/manage/rules", "action-cell table"),
    ("/manage/rules/10", "action-cell table"),
    ("/manage/codes", "action-cell table"),
    ("/manage/routing", "action-cell table"),
]

# Pages with a table that has no action column; the row-height rule still applies.
PLAIN_TABLE_PAGES = [
    ("/manage/audit", "per-visitor table"),
    ("/manage/top-pages", "ranked bars"),
]

ALL_PAGES = [
    "/manage",
    "/manage/rules",
    "/manage/rules/10",
    "/manage/codes",
    "/manage/routing",
    "/manage/logs",
    "/manage/audit",
    "/manage/top-pages",
    "/manage/settings",
    "/manage/backup",
]

WIDTHS = [1440, 1280, 1024, 820, 600, 420]

OLD_CONTAINER_MAX_WIDTH = 1100


class _FakeResponse:
    def __init__(self, payload: Any = None) -> None:
        self.status_code = 200
        self._payload = payload
        self.text = ""
        self.content = b""
        self.headers: dict[str, str] = {}

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
        return _FakeResponse({})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})


management_app._get_httpx = lambda: _FakeClient()  # type: ignore[assignment]

app = management_app.create_app()
config = uvicorn.Config(app, host="127.0.0.1", port=8732, log_level="error")
server = uvicorn.Server(config)
thread = threading.Thread(target=server.run, daemon=True)
thread.start()
for _ in range(100):
    if server.started:
        break
    time.sleep(0.05)
assert server.started, "uvicorn did not start"

TOKEN = create_manage_token()
BASE_URL = "http://127.0.0.1:8732"

# The stylesheet the stat cards used before this pass, taken from git history.
LEGACY_STAT_CSS = """
.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:1.5rem}
.stat-number{font-family:'JetBrains Mono',monospace;font-size:2rem;font-weight:700;color:var(--accent);line-height:1.2}
.stat-label{font-size:.875rem;color:var(--text-secondary);margin-top:.25rem}
"""  # noqa: E501

STRIP_MEASURE = """
() => {
  const strip = document.querySelector('.stat-strip');
  if (!strip) return null;
  const rect = strip.getBoundingClientRect();
  const stats = strip.querySelectorAll('.stat');
  return {
    height: rect.height,
    width: rect.width,
    stats: stats.length,
    valueFontSize: getComputedStyle(strip.querySelector('.stat-value')).fontSize,
    firstBorder: getComputedStyle(stats[0]).borderLeftWidth,
    secondBorder: stats.length > 1 ? getComputedStyle(stats[1]).borderLeftWidth : null,
    cardChrome: getComputedStyle(strip).backgroundColor,
    borderRadius: getComputedStyle(strip).borderRadius,
  };
}
"""

# Rebuild the three numbers in the old card markup inside the same container, then
# measure. Same content, same page, same browser: the delta is the change.
LEGACY_STAT_INJECT = """
(css) => {
  const strip = document.querySelector('.stat-strip');
  const container = strip.parentElement;
  const style = document.createElement('style');
  style.id = 'legacy-stat-css';
  style.textContent = css;
  document.head.appendChild(style);
  const numbers = Array.from(strip.querySelectorAll('.stat-value')).map(e => e.textContent.trim());
  const labels = Array.from(strip.querySelectorAll('.stat-label')).map(e => e.textContent.trim());
  const row = document.createElement('div');
  row.className = 'stats-row';
  row.id = 'legacy-stats';
  for (let i = 0; i < numbers.length; i++) {
    const card = document.createElement('div');
    card.className = 'stat-card';
    const n = document.createElement('div');
    n.className = 'stat-number';
    n.textContent = numbers[i];
    const l = document.createElement('div');
    l.className = 'stat-label';
    l.textContent = labels[i];
    card.appendChild(n);
    card.appendChild(l);
    row.appendChild(card);
  }
  container.appendChild(row);
  const rect = row.getBoundingClientRect();
  const cardRect = row.querySelector('.stat-card').getBoundingClientRect();
  return {
    rowHeight: rect.height,
    cardHeight: cardRect.height,
    cardPadding: getComputedStyle(row.querySelector('.stat-card')).padding,
    numberFontSize: getComputedStyle(row.querySelector('.stat-number')).fontSize,
    cardBackground: getComputedStyle(row.querySelector('.stat-card')).backgroundColor,
    numberOfCards: row.querySelectorAll('.stat-card').length,
  };
}
"""

LAYOUT_MEASURE = """
() => {
  const container = document.querySelector('.container');
  const main = document.querySelector('.main');
  const sidebar = document.querySelector('.sidebar');
  return {
    containerWidth: container ? container.getBoundingClientRect().width : null,
    containerMaxWidth: container ? getComputedStyle(container).maxWidth : null,
    mainWidth: main ? main.getBoundingClientRect().width : null,
    sidebarWidth: sidebar ? sidebar.getBoundingClientRect().width : null,
    viewport: document.documentElement.clientWidth,
    pageOverflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    statCards: document.querySelectorAll('.stat-card').length,
  };
}
"""

TABLE_INVARIANTS = """
() => {
  const tables = Array.from(document.querySelectorAll('table'));
  const out = [];
  tables.forEach((table, tableIndex) => {
    const rows = Array.from(table.querySelectorAll('tbody tr'))
      .filter(r => !r.querySelector('td[colspan]'));
    const rowData = rows.map((row, rowIndex) => {
      const cells = Array.from(row.children);
      const last = cells[cells.length - 1];
      const inlineFlex = cells.filter(
        c => (c.getAttribute('style') || '').replace(/\\s+/g, '').includes('display:flex')
      ).length;
      return {
        rowIndex,
        rowHeight: row.offsetHeight,
        distinctCellHeights: Array.from(new Set(cells.map(c => c.offsetHeight))).length,
        lastTag: last.tagName.toLowerCase(),
        lastDisplay: getComputedStyle(last).display,
        lastClass: last.className,
        hasActionsCell: cells.some(c => c.classList.contains('actions-cell')),
        inlineFlexCells: inlineFlex,
      };
    });
    out.push({
      tableIndex,
      identifier: table.className,
      actionCells: table.querySelectorAll('td.actions-cell').length,
      innerActionsDisplay: (() => {
        const inner = table.querySelector('td.actions-cell > div');
        return inner ? getComputedStyle(inner).display : null;
      })(),
      scrollWrapper: !!table.closest('.table-scroll'),
      wrapperTabIndex: (() => {
        const w = table.closest('.table-scroll');
        return w ? w.getAttribute('tabindex') : null;
      })(),
      wrapperRole: (() => {
        const w = table.closest('.table-scroll');
        return w ? w.getAttribute('role') : null;
      })(),
      wrapperLabel: (() => {
        const w = table.closest('.table-scroll');
        return w ? w.getAttribute('aria-label') : null;
      })(),
      rows: rowData,
    });
  });
  return out;
}
"""

ARIA_TABLE_CONTROLS = """
() => {
  const out = [];
  document.querySelectorAll('table tbody tr').forEach(row => {
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

SIDEBAR_LINKS = """
() => Array.from(document.querySelectorAll('nav.sidebar a'))
  .map(a => ({href: a.getAttribute('href'), text: (a.textContent || '').trim()}))
"""


def main() -> int:
    from playwright.sync_api import sync_playwright

    failures: list[str] = []
    print("=" * 78)
    print("RENDERED-DOM PROOF — manage layout, width and table invariants")
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

        # -- 1. Stat strip vs the old card, measured on the same page ---------- #
        print("\n" + "-" * 78)
        print("1. STAT STRIP HEIGHT vs THE OLD STAT CARDS (same page, same browser)")
        print("-" * 78)
        for path in ("/manage", "/manage/codes"):
            page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
            strip = page.evaluate(STRIP_MEASURE)
            if strip is None:
                failures.append(f"{path}: no .stat-strip rendered")
                continue
            legacy = page.evaluate(LEGACY_STAT_INJECT, LEGACY_STAT_CSS)
            saved = round(legacy["rowHeight"] - strip["height"], 1)
            pct = round(saved / legacy["rowHeight"] * 100) if legacy["rowHeight"] else 0
            print(f"\n  {path}")
            print(
                f"    strip : height={strip['height']:.1f}px  value_font={strip['valueFontSize']}  "
                f"background={strip['cardChrome']}  radius={strip['borderRadius']}  "
                f"dividers={strip['firstBorder']}/{strip['secondBorder']}  pairs={strip['stats']}"
            )
            print(
                f"    cards : height={legacy['rowHeight']:.1f}px  "
                f"card={legacy['cardHeight']:.1f}px  "
                f"padding={legacy['cardPadding']}  value_font={legacy['numberFontSize']}  "
                f"background={legacy['cardBackground']}  cards={legacy['numberOfCards']}"
            )
            print(
                f"    saved : {saved:.1f}px of vertical space ({pct}% of the old block), "
                f"and {legacy['numberOfCards']} bordered boxes became {strip['stats']} inline pairs"
            )
            if strip["height"] >= legacy["rowHeight"]:
                failures.append(f"{path}: the strip is not shorter than the old cards")
            if strip["cardChrome"] != "rgba(0, 0, 0, 0)":
                failures.append(f"{path}: the strip still paints a card background")

        # -- 2. Width at the three named breakpoints --------------------------- #
        print("\n" + "-" * 78)
        print(
            "2. CONTENT WIDTH (the old container was "
            f"`max-width:{OLD_CONTAINER_MAX_WIDTH}px`, so the width it actually used "
            "was the smaller of that and its column)"
        )
        print("-" * 78)
        print(
            f"{'viewport':>9} {'sidebar':>9} {'main':>9} {'container':>10} {'max_width':>11} "
            f"{'old_used':>9} {'gain':>7} {'overflow':>9}"
        )
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(f"{BASE_URL}/manage", wait_until="networkidle")
            page.wait_for_timeout(120)
            m = page.evaluate(LAYOUT_MEASURE)
            # What the previous stylesheet would have rendered at this viewport:
            # the old container was capped at 1100px, so it used the narrower of
            # that cap and its own column inside the sidebar.
            old_used = min(OLD_CONTAINER_MAX_WIDTH, m["mainWidth"])
            gain = m["containerWidth"] - old_used
            print(
                f"{width:>9} {m['sidebarWidth']:>9.0f} {m['mainWidth']:>9.0f} "
                f"{m['containerWidth']:>10.0f} {m['containerMaxWidth']:>11} "
                f"{old_used:>9.0f} {gain:>+7.0f} {m['pageOverflow']:>9.0f}"
            )
            if abs(m["containerWidth"] - m["mainWidth"]) > 0.5:
                failures.append(
                    f"{width}px: container is {m['containerWidth']:.0f}px inside a "
                    f"{m['mainWidth']:.0f}px column, so it is not fluid"
                )
            if gain < 0:
                failures.append(f"{width}px: the new container is narrower than the old one")
            if width >= 1440 and gain <= 0:
                failures.append(
                    f"{width}px: no width gain over the {OLD_CONTAINER_MAX_WIDTH}px ceiling"
                )
            if m["pageOverflow"] > 0:
                failures.append(f"{width}px: page scrolls sideways by {m['pageOverflow']}px")

        print("\n  every /manage page at 1440 and 600 (sideways scroll, stat cards):")
        print(f"{'page':>28} {'1440 ovf':>9} {'600 ovf':>8} {'stat-card':>10}")
        for path in ALL_PAGES:
            row: list[str] = []
            cards = 0
            for width in (1440, 600):
                page.set_viewport_size({"width": width, "height": 900})
                page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
                page.wait_for_timeout(80)
                m = page.evaluate(LAYOUT_MEASURE)
                row.append(
                    f"{m['pageOverflow']:>9.0f}" if width == 1440 else f"{m['pageOverflow']:>8.0f}"
                )
                cards = m["statCards"]
                if m["pageOverflow"] > 0:
                    failures.append(f"{path} @{width}px: sideways scroll {m['pageOverflow']}px")
                if m["statCards"]:
                    failures.append(f"{path} @{width}px: {m['statCards']} .stat-card elements")
            print(f"{path:>28} {row[0]} {row[1]} {cards:>10}")

        # -- 3. Table invariants on every table -------------------------------- #
        print("\n" + "-" * 78)
        print("3. TABLE INVARIANT FROM 9c1e318, RE-ASSERTED ON EVERY TABLE TOUCHED")
        print("-" * 78)
        for path, label in TABLE_PAGES + PLAIN_TABLE_PAGES:
            page.set_viewport_size({"width": 1440, "height": 900})
            page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
            tables = page.evaluate(TABLE_INVARIANTS)
            print(f"\n  {path}  ({label})")
            if not tables:
                failures.append(f"{path}: no table rendered")
                continue
            for table in tables:
                print(
                    f"    table[{table['tableIndex']}] class={table['identifier']!r} "
                    f"rows={len(table['rows'])} action_cells={table['actionCells']} "
                    f"inner_actions={table['innerActionsDisplay']}"
                )
                print(
                    f"      scroll wrapper: present={table['scrollWrapper']} "
                    f"tabindex={table['wrapperTabIndex']} role={table['wrapperRole']} "
                    f"aria-label={table['wrapperLabel']!r}"
                )
                if not table["scrollWrapper"]:
                    failures.append(f"{path}: table is not inside a .table-scroll wrapper")
                if table["actionCells"] and table["innerActionsDisplay"] != "flex":
                    failures.append(f"{path}: inner .actions is not flex")
                for row in table["rows"]:
                    ok = row["distinctCellHeights"] == 1
                    mark = "OK " if ok else "BAD"
                    inline_flex = row["inlineFlexCells"]
                    print(
                        f"      {mark} row {row['rowIndex']}: row_height={row['rowHeight']} "
                        f"distinct_cell_heights={row['distinctCellHeights']} "
                        f"last={row['lastTag']}/{row['lastDisplay']} "
                        f"actions_cell={row['hasActionsCell']} inline_flex_tds={inline_flex}"
                    )
                    if not ok:
                        failures.append(
                            f"{path} row {row['rowIndex']}: cells do not share the row height"
                        )
                    if row["lastTag"] == "td" and row["lastDisplay"] != "table-cell":
                        failures.append(
                            f"{path} row {row['rowIndex']}: last td display={row['lastDisplay']}"
                        )
                    if inline_flex:
                        failures.append(
                            f"{path} row {row['rowIndex']}: {inline_flex} td(s) with inline flex"
                        )
            if tables[0]["actionCells"]:
                aria = page.evaluate(ARIA_TABLE_CONTROLS)
                missing = [a for a in aria if not a["aria"] or not a["title"]]
                print(f"    row controls={len(aria)}  missing aria-label/title={len(missing)}")
                if missing:
                    failures.append(f"{path}: controls without an accessible name: {missing}")

        # -- 4. Sidebar: no dead links, no Warnings entry ---------------------- #
        print("\n" + "-" * 78)
        print("4. SIDEBAR AFTER THE RENAME AND THE DELETION")
        print("-" * 78)
        page.set_viewport_size({"width": 1440, "height": 900})
        page.goto(f"{BASE_URL}/manage", wait_until="networkidle")
        links = page.evaluate(SIDEBAR_LINKS)
        print(f"  {'href':>22}  {'status':>6}  text")
        for link in links:
            response = context.request.get(f"{BASE_URL}{link['href']}")
            print(f"  {link['href']:>22}  {response.status:>6}  {link['text']}")
            if response.status != 200:
                failures.append(f"sidebar link {link['href']} -> {response.status}")
            if "warnings" in link["href"]:
                failures.append(f"sidebar still links to {link['href']}")

        warnings_response = context.request.get(f"{BASE_URL}/manage/warnings")
        print(f"\n  GET /manage/warnings -> {warnings_response.status}")
        if warnings_response.status != 404:
            failures.append(f"/manage/warnings answered {warnings_response.status}, not 404")

        alias = context.request.get(f"{BASE_URL}/manage/monitoring", max_redirects=0)
        print(f"  GET /manage/monitoring -> {alias.status} {alias.headers.get('location', '')}")
        if alias.status != 302 or alias.headers.get("location") != "/manage/audit":
            failures.append("/manage/monitoring is not a 302 to /manage/audit")

        # -- 5. The banner appears only when there is something to say --------- #
        print("\n" + "-" * 78)
        print("5. WARNING BANNER: ABSENT WHEN EMPTY, PRESENT WHEN NOT")
        print("-" * 78)
        page.goto(f"{BASE_URL}/manage", wait_until="networkidle")
        empty = page.evaluate("() => document.querySelectorAll('.warn-banner').length")
        print(f"  /api/warnings -> {{groups: [], rules: []}}   banner elements: {empty}")
        if empty:
            failures.append("the dashboard renders a banner with nothing to report")

        PAYLOADS["/api/warnings"] = {
            "groups": [{"id": 11, "name": "beta", "reason": "matched by an earlier group"}],
            "rules": [
                {"id": 7, "path": "/docs", "reason": "hidden by /* above it"},
                {"id": 8, "path": "/api", "reason": "hidden by /* above it"},
            ],
        }
        page.goto(f"{BASE_URL}/manage", wait_until="networkidle")
        present = page.evaluate(
            """() => {
              const b = document.querySelector('.warn-banner');
              if (!b) return null;
              return {
                count: document.querySelectorAll('.warn-banner').length,
                text: (b.textContent || '').replace(/\\s+/g, ' ').trim(),
                link: (b.querySelector('a') || {}).getAttribute
                  ? b.querySelector('a').getAttribute('href') : null,
                borderColor: getComputedStyle(b).borderTopColor,
              };
            }"""
        )
        if present is None:
            failures.append("the dashboard renders no banner with shadowed rules present")
        else:
            print(
                f"  /api/warnings -> 2 shadowed rules                banner elements: "
                f"{present['count']}"
            )
            print(f"    text   : {present['text']}")
            print(f"    link   : {present['link']}   border: {present['borderColor']}")
            if present["link"] != "/manage/rules":
                failures.append("the banner does not link to /manage/rules")

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
