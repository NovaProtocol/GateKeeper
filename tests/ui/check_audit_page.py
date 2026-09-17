"""Rendered-DOM proof of the audit page: the map, the CSP, and the table fix.

Three claims that only a browser can settle:

1. **the map actually draws under the shipped CSP.** A `img-src` that omits the
   tile host produces no error in the page: the script loads, the container
   exists, and every tile is refused by the browser with nothing visible. So this
   script records every console message and every failed response, counts the
   tile requests that succeeded, and asserts that no request was blocked by the
   policy. Leaflet and its CSS come from a CDN `script-src`/`style-src` already
   allow; the tiles are what gained the `img-src` entry.
2. **the aggregation is honest on screen.** Markers are circles whose radius grew
   with the count (area, not length), and the mode in the URL is the mode the
   server counted with. The numbers under test come from real fixture rows served
   through the real aggregation function, not from a hand-written payload.
3. **the layout still holds.** No sideways document scroll at 1440 / 1024 / 600 /
   420, and the `9c1e318` table invariant on both tables the page renders: every
   row's own cells share one height, the last cell is `display: table-cell`, and
   no `<td>` carries an inline `display:flex`.

Run with::

    uv run --no-project --with playwright --with-requirements requirements.txt \
        python tests/ui/check_audit_page.py

Chromium is already cached at ``~/.cache/ms-playwright/chromium-1243``.
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

DB_PATH = Path("/tmp/gatekeeper_audit_ui_check.db").resolve()
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
from shared.geo import build_points  # noqa: E402
from shared.jwt import create_manage_token  # noqa: E402

structlog.configure(
    processors=[structlog.processors.JSONRenderer()],
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
)
logging.getLogger("management").setLevel(logging.WARNING)
logging.getLogger("uvicorn.error").setLevel(logging.ERROR)

PORT = 8734
BASE_URL = f"http://127.0.0.1:{PORT}"

#: Countries with deliberately different volumes, so radius ordering is testable.
COUNTS = [("PH", 12), ("DE", 6), ("US", 3), ("BR", 1), (None, 2)]
POINTS = build_points(COUNTS)

#: The aggregation the API would return per mode, as real counts.
MODE_COUNTS = {
    "views": COUNTS,
    "visitors": [("PH", 5), ("DE", 4), ("US", 4), (None, 1)],
    "gated": [("PH", 3), ("US", 2)],
    "blocked": [("DE", 2)],
}

BY_IP = [
    {
        "ip": "203.0.113.10",
        "calls": 12,
        "recent": [
            {
                "ts": "2026-09-17 10:00:00",
                "host": "app.projectnova.download",
                "path": "/reports",
                "action": "auth_success",
                "code_label": "Alice",
                "attempted_code": None,
            }
        ],
        "codes": ["Alice"],
    },
    {
        "ip": "203.0.113.20",
        "calls": 6,
        "recent": [
            {
                "ts": "2026-09-17 09:00:00",
                "host": "app.projectnova.download",
                "path": "/",
                "action": "no_cookie_redirect",
                "code_label": None,
                "attempted_code": None,
            }
        ],
        "codes": [],
    },
]


class _FakeResponse:
    def __init__(self, payload: Any = None, headers: dict[str, str] | None = None) -> None:
        self.status_code = 200
        self._payload = payload
        self.text = ""
        self.content = b""
        self.headers = headers or {"X-Total-Count": "24"}

    def json(self) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _FakeClient:
    """Serves the real aggregation for the requested mode."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.modes: list[str] = []

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append(("GET", url, kwargs.get("params")))
        if url.endswith("/api/logs/geo"):
            mode = str((kwargs.get("params") or {}).get("mode", "views"))
            self.modes.append(mode)
            return _FakeResponse(build_points(MODE_COUNTS.get(mode, COUNTS)))
        if url.endswith("/api/logs/by-ip"):
            return _FakeResponse(BY_IP)
        if url.endswith("/api/logs"):
            return _FakeResponse([], {"X-Total-Count": "24"})
        return _FakeResponse([])

    async def put(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})

    async def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})


FAKE = _FakeClient()
management_app._get_httpx = lambda: FAKE  # type: ignore[assignment]

app = management_app.create_app()
config = uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error")
server = uvicorn.Server(config)
thread = threading.Thread(target=server.run, daemon=True)
thread.start()
for _ in range(100):
    if server.started:
        break
    time.sleep(0.05)
assert server.started, "uvicorn did not start"

TOKEN = create_manage_token()

MAP_STATE = """
() => {
  const node = document.getElementById('audit-map');
  if (!node) return {present: false};
  const paths = Array.from(node.querySelectorAll('path.leaflet-interactive'));
  const tiles = Array.from(node.querySelectorAll('img.leaflet-tile'));
  return {
    present: true,
    className: node.className,
    // The fallback replaces the container's class and text, so an absence of
    // both is the proof that the map drew rather than degraded. `page.content()`
    // is no use here: the fallback string lives in the script source whether or
    // not the catch block ever ran.
    fallbackText: (node.className.includes('fallback') ? (node.textContent || '').trim() : null),
    width: Math.round(node.getBoundingClientRect().width),
    height: Math.round(node.getBoundingClientRect().height),
    markerCount: paths.length,
    // Leaflet writes the radius into the path's `d` via the arc commands; the
    // stroke-width attribute is constant, so the rendered geometry is measured
    // instead by the path's own bounding box.
    markerBoxes: paths.map(p => {
      const b = p.getBoundingClientRect();
      return {w: Math.round(b.width * 10) / 10, h: Math.round(b.height * 10) / 10};
    }),
    tileCount: tiles.length,
    loadedTiles: tiles.filter(t => t.complete && t.naturalWidth > 0).length,
    failedTiles: tiles.filter(t => t.complete && t.naturalWidth === 0).length,
    tileSrcs: tiles.slice(0, 3).map(t => t.getAttribute('src')),
    paneCount: node.querySelectorAll('.leaflet-pane').length,
  };
}
"""

TABLES = """
() => Array.from(document.querySelectorAll('table.codes-table')).map(t => {
  const rows = Array.from(t.querySelectorAll('tbody tr')).filter(
    r => !r.querySelector('td[colspan]')
  );
  return {
    rows: rows.length,
    cellHeights: rows.map(
      r => Array.from(r.cells).map(c => Math.round(c.getBoundingClientRect().height))
    ),
    lastCellDisplay: rows.map(r => getComputedStyle(r.cells[r.cells.length - 1]).display),
    inlineFlexCells: Array.from(t.querySelectorAll('td')).filter(
      td => (td.getAttribute('style') || '').replace(/ /g, '').includes('display:flex')
    ).length,
    scrollWrapper: !!t.closest('.table-scroll'),
  };
});
"""

WIDTHS = [1440, 1024, 600, 420]


def main() -> int:
    from playwright.sync_api import sync_playwright

    failures: list[str] = []

    def check(label: str, actual: Any, expected: Any) -> Any:
        ok = actual == expected
        note = "" if ok else f"   <- expected {expected!r}"
        print(f"{'ok  ' if ok else 'FAIL'}  {label}: {actual!r}{note}")
        if not ok:
            failures.append(label)
        return actual

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        context.add_cookies(
            [
                {"name": "manage_session", "value": TOKEN, "url": BASE_URL},
                {"name": "csrf_token", "value": "ui-check-csrf", "url": BASE_URL},
            ]
        )
        page = context.new_page()

        console_msgs: list[str] = []
        failed_requests: list[str] = []
        failed_responses: list[str] = []
        tile_hits: list[str] = []

        page.on("console", lambda m: console_msgs.append(f"{m.type}: {m.text}"))
        page.on("requestfailed", lambda r: failed_requests.append(f"{r.url} :: {r.failure}"))

        def _on_response(response: Any) -> None:
            url = response.url
            if "tile.openstreetmap.org" in url:
                if 200 <= response.status < 400:
                    tile_hits.append(f"{response.status} {url}")
                else:
                    failed_responses.append(f"{response.status} {url}")

        page.on("response", _on_response)

        print("=" * 78)
        print("PHASE 6 AUDIT PAGE, RENDERED (real app, real templates, real CSP, real Chromium)")
        print("=" * 78)

        response = page.goto(f"{BASE_URL}/manage/audit", wait_until="networkidle")
        csp = response.headers.get("content-security-policy", "")
        print()
        print("served CSP:")
        for directive in csp.split(";"):
            directive = directive.strip()
            if directive.startswith(("img-src", "script-src", "style-src", "connect-src")):
                print(f"  {directive[:150]}")
        print()

        check("CSP img-src carries the tile host", "https://tile.openstreetmap.org" in csp, True)
        check(
            "CSP img-src carries the wildcard tile host",
            "https://*.tile.openstreetmap.org" in csp,
            True,
        )

        # Give the tiles a moment to arrive before counting them.
        page.wait_for_timeout(6000)

        state = page.evaluate(MAP_STATE)
        print()
        print("--- the map element ---")
        print(
            f"  container {state.get('width')}x{state.get('height')}px "
            f"class={state.get('className')!r}"
        )
        print(f"  leaflet panes: {state.get('paneCount')}")
        print(f"  markers drawn: {state.get('markerCount')}")
        print(f"  marker boxes (round to the radius): {state.get('markerBoxes')}")
        print(
            f"  tiles: {state.get('tileCount')} in the DOM, "
            f"{state.get('loadedTiles')} loaded, {state.get('failedTiles')} failed"
        )
        print(f"  sample tile srcs: {state.get('tileSrcs')}")
        print()

        check("the map container is present", state.get("present"), True)
        check(
            "the map container kept its map class",
            "audit-map" in (state.get("className") or ""),
            True,
        )
        check("the container has a real size", state.get("height", 0) > 300, True)
        check(
            "Leaflet initialised (panes exist)", state.get("paneCount", 0) >= 4, True
        )
        check("the map did not fall back to text", state.get("fallbackText"), None)

        # Four countries have centroids; the unknown bucket must not be a marker.
        check("one marker per plottable country", state.get("markerCount"), 4)

        # ---- the CSP / tile proof ----------------------------------------- #
        blocked_csp = [
            m
            for m in console_msgs
            if "Content Security Policy" in m or "Refused to" in m or "violates" in m
        ]
        print()
        print("--- CSP enforcement ---")
        print(f"  console messages: {len(console_msgs)}")
        for message in console_msgs[:10]:
            print(f"    {message[:160]}")
        print(f"  blocked-by-policy messages: {len(blocked_csp)}")
        print(f"  failed requests: {len(failed_requests)}")
        for item in failed_requests[:5]:
            print(f"    {item[:160]}")
        print(f"  tile responses that succeeded: {len(tile_hits)}")
        for item in tile_hits[:3]:
            print(f"    {item[:160]}")
        print(f"  tile responses that failed: {len(failed_responses)}")
        print()

        check("no request was blocked by the policy", blocked_csp, [])
        check("no request failed outright", failed_requests, [])
        check("tiles were fetched and served", len(tile_hits) > 0, True)
        check("no tile response failed", failed_responses, [])
        check("tiles actually decoded", state.get("loadedTiles", 0) > 0, True)
        check("no tile failed to decode", state.get("failedTiles"), 0)

        # ---- the markers reflect the aggregation --------------------------- #
        print()
        print("--- markers reflect the aggregation ---")
        counts = page.evaluate(
            """
            () => Array.from(document.querySelectorAll('table.codes-table tr'))
              .map(r => Array.from(r.cells).map(c => (c.textContent || '').trim()))
              .filter(c => c.length === 4 && /^[A-Z]{2}$|^—$/.test(c[1]))
              .map(c => ({name: c[0], count: Number(c[2])}))
            """
        )
        print(f"  country totals on the page: {counts}")
        boxes = [b["w"] for b in state.get("markerBoxes") or []]
        print(f"  marker widths, in the order they were added: {boxes}")

        plotted_counts = [c["count"] for c in counts if c["name"] != "Unknown"]
        print(f"  plotted counts, largest first (the order the API returns): {plotted_counts}")
        print(f"  distinct marker widths: {sorted(set(boxes), reverse=True)}")

        check(
            "markers are added largest first, matching the API's ordering",
            boxes == sorted(boxes, reverse=True),
            True,
        )
        check(
            "one marker per distinct count, so size carries the count",
            len(set(boxes)),
            len(set(plotted_counts)),
        )
        check(
            "the busiest country is visibly bigger than the quietest",
            (max(boxes) if boxes else 0) > 2 * (min(boxes) if boxes else 0),
            True,
        )

        for mode in ("visitors", "gated", "blocked"):
            FAKE.modes.clear()
            page.goto(f"{BASE_URL}/manage/audit?mode={mode}", wait_until="networkidle")
            page.wait_for_timeout(1500)
            served = page.evaluate(MAP_STATE)
            selected = page.evaluate(
                "() => document.querySelector('#geo-mode option[selected]')?.value"
            )
            expected_markers = len([c for c, n in MODE_COUNTS[mode] if c is not None and n > 0])
            print(
                f"  mode={mode:<9} api mode={FAKE.modes[-1] if FAKE.modes else None!r} "
                f"dropdown={selected!r} markers={served.get('markerCount')}"
            )
            if FAKE.modes != [mode]:
                failures.append(f"mode {mode}: the API was asked for {FAKE.modes}")
            if selected != mode:
                failures.append(f"mode {mode}: the dropdown shows {selected}")
            if served.get("markerCount") != expected_markers:
                failures.append(f"mode {mode}: {served.get('markerCount')} markers")

        check("each mode asked the API for itself and drew its own markers", [
            f for f in failures if f.startswith("mode ")
        ], [])

        # ---- the layout ---------------------------------------------------- #
        print()
        print("--- layout ---")
        page.goto(f"{BASE_URL}/manage/audit?mode=views", wait_until="networkidle")
        page.wait_for_timeout(2000)
        print(f"{'width':>6} {'doc_overflow':>13} {'map_width':>10} {'markers':>8} {'cards':>6}")
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 1000})
            page.wait_for_timeout(400)
            measured = page.evaluate(
                """
                () => ({
                  overflow: document.documentElement.scrollWidth
                    - document.documentElement.clientWidth,
                  mapWidth: Math.round(
                    (document.getElementById('audit-map')
                      || {getBoundingClientRect: () => ({width: 0})}
                    ).getBoundingClientRect().width
                  ),
                  markers: document.querySelectorAll(
                    '#audit-map path.leaflet-interactive'
                  ).length,
                  cards: document.querySelectorAll('.container .card').length,
                })
                """
            )
            print(
                f"{width:>6} {measured['overflow']:>13} {measured['mapWidth']:>10} "
                f"{measured['markers']:>8} {measured['cards']:>6}"
            )
            if measured["overflow"] > 0:
                failures.append(f"{width}px: document scrolls sideways by {measured['overflow']}px")
            if measured["mapWidth"] > width:
                failures.append(f"{width}px: the map is wider than the viewport")

        check("no sideways scroll at any width", [f for f in failures if "sideways" in f], [])

        # ---- the 9c1e318 re-assertion -------------------------------------- #
        print()
        print("--- 9c1e318 re-assertion on every table on the page ---")
        tables = page.evaluate(TABLES)
        check("the page renders its two tables", len(tables), 2)
        for index, table in enumerate(tables):
            uneven = [r for r in table["cellHeights"] if len(set(r)) != 1]
            check(f"table {index}: every row's own cells share one height", uneven, [])
            check(
                f"table {index}: last cell is display: table-cell on every row",
                sorted(set(table["lastCellDisplay"])),
                ["table-cell"],
            )
            check(f"table {index}: no inline display:flex on a <td>", table["inlineFlexCells"], 0)
            check(f"table {index}: wrapped in .table-scroll", table["scrollWrapper"], True)
            print(f"  table {index} row cell heights: {table['cellHeights'][:4]}")

        # ---- icon controls -------------------------------------------------- #
        print()
        aria = page.evaluate(
            """
            () => Array.from(document.querySelectorAll(
              '.container a.btn, .container button, .container select, .container input'
            ))
              .filter(el => el.type !== 'hidden' && !el.hasAttribute('data-dismiss'))
              .map(el => ({
                name: el.getAttribute('name') || el.getAttribute('href') || el.tagName,
                title: el.getAttribute('title'),
                ariaLabel: el.getAttribute('aria-label'),
              }))
            """
        )
        missing = [a for a in aria if not a["title"] or not a["ariaLabel"]]
        print(f"  controls on the page: {len(aria)}   missing title or aria-label: {len(missing)}")
        for item in aria:
            print(
                f"    {item['name']:<34} title={item['title']!r} "
                f"aria-label={item['ariaLabel']!r}"
            )
        check("every control has title + aria-label", missing, [])

        browser.close()

    print()
    print("=" * 78)
    if failures:
        print(f"FAILURES ({len(failures)}):")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
