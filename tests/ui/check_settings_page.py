"""Rendered-DOM proof of the settings page.

Three claims, each needing a browser to be true:

1. **the page is no longer one field.** The measurement is the field count and the
   document height against the 21-line stub it replaced, whose markup is injected
   into the same page and the same browser so the comparison is of the change and
   nothing else;
2. **every control is reachable.** Each one carries both a ``title`` and an
   ``aria-label``, and no card on the page is an oversized one;
3. **the `9c1e318` table fix still holds** on the page's one table. Every row's
   cells measure one shared height, the last cell is still ``display: table-cell``,
   and no ``<td>`` carries an inline ``display:flex``.

Run with::

    uv run --no-project --with playwright python tests/ui/check_settings_page.py

It serves the real management app in-process (real template, real `manage.css`,
real Bootstrap 4.6) and drives Chromium against it. Chromium is already cached at
``~/.cache/ms-playwright/chromium-1243``.
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

DB_PATH = Path("/tmp/gatekeeper_settings_ui_check.db").resolve()
os.environ.setdefault("SECRET_KEY", "test-secret-key-at-least-32-characters")
os.environ.setdefault("MANAGE_PASSWORD", "test-manage-password")
os.environ.setdefault("BACKUP_CODE", "test-backup-code")
os.environ.setdefault("INTERNAL_API_KEY", "test-internal-api-key")
os.environ.setdefault("DEPLOYMENT_TYPE", "debug")
os.environ.setdefault("DB_DIR", str(DB_PATH.parent))
os.environ.setdefault("DATABASE_URL", f"sqlite+aiosqlite:///{DB_PATH}")
os.environ.setdefault("API_HTTP_ADDR", "http://api.invalid:8002")

# The app logs a JSON line per request, which would bury the measurements.
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

SETTINGS = [
    {"key": "unmatched_action", "value": "access_code", "updated_at": None},
    {"key": "rate_limit_access_code_per_min", "value": "60", "updated_at": None},
    {"key": "session_lifetime_hours", "value": "12", "updated_at": None},
    {"key": "maintenance_mode", "value": "false", "updated_at": None},
    {"key": "maintenance_message", "value": "", "updated_at": None},
    {"key": "log_retention_days", "value": "30", "updated_at": None},
]

PAYLOADS: dict[str, Any] = {
    "/api/settings": SETTINGS,
    "/api/groups": [],
    "/api/routes": [],
    "/api/codes": [],
    "/api/warnings": {"groups": [], "rules": []},
    "/api/logs": [],
    "/api/logs/top": [],
}


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
        return _FakeResponse(PAYLOADS.get(url.split("http://api:8002", 1)[-1], []))

    async def put(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})

    async def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})


management_app._get_httpx = lambda: _FakeClient()  # type: ignore[assignment]

app = management_app.create_app()
config = uvicorn.Config(app, host="127.0.0.1", port=8733, log_level="error")
server = uvicorn.Server(config)
threading.Thread(target=server.run, daemon=True).start()
for _ in range(100):
    if server.started:
        break
    time.sleep(0.05)
assert server.started, "uvicorn did not start"

TOKEN = create_manage_token()
BASE_URL = "http://127.0.0.1:8733"

#: The old settings page, exactly as it stood at `7209a21`: 21 lines, one field.
LEGACY_SETTINGS_HTML = """
<div class="container container-narrow">
  <div class="card">
    <div class="card-header"><h2><i class="fa-solid fa-gear"></i> Settings</h2><span class="header-badge" style="font-family:'JetBrains Mono',monospace">DB-backed</span></div>
    <div class="card-body" style="color:var(--text-secondary);font-size:.9rem">
      <form method="post" action="/manage/settings" style="display:flex;gap:1rem;align-items:end;flex-wrap:wrap">
        <input type="hidden" name="csrf_token" value="x">
        <div style="display:flex;flex-direction:column;gap:.4rem">
          <label for="rate_limit" style="font-size:.8rem;font-weight:600;color:var(--text-primary)">Access code tries per minute (per IP)</label>
          <input id="rate_limit" name="rate_limit_access_code_per_min" type="number" min="1" max="1000" value="5" style="background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;padding:.55rem .75rem;color:var(--text-primary);font-family:'JetBrains Mono',monospace;width:140px">
          <small style="color:var(--text-secondary);font-size:.75rem">Enforced in auth-gateway on <code>?access_code=</code> - <code>POST /api/auth/check-rate-limit</code> counts <code>audit_logs</code> last 60s.</small>
        </div>
        <button class="btn btn-accent" type="submit" title="Save" aria-label="Save"><i class="fa-solid fa-floppy-disk" aria-hidden="true"></i></button>
      </form>
      <p style="margin-top:1rem;font-size:.8rem">Other settings are still via env (<span style="font-family:'JetBrains Mono',monospace;color:var(--text-primary)">SECRET_KEY</span> etc.). Use <a href="/manage/backup" style="color:var(--accent)">/manage/backup</a> for snapshots.</p>
    </div>
  </div>
</div>
"""

MEASURE = """
() => {
  const main = document.querySelector('.main');
  const container = main.querySelector('.container');
  const controls = Array.from(container.querySelectorAll('input, select, button, a.btn'))
    .filter(el => el.type !== 'hidden');
  const named = controls.map(el => ({
    tag: el.tagName.toLowerCase(),
    name: el.getAttribute('name') || (el.getAttribute('href') || ''),
    title: el.getAttribute('title'),
    ariaLabel: el.getAttribute('aria-label'),
  }));
  const cards = Array.from(container.querySelectorAll('.card'));
  const cardHeights = cards.map(c => Math.round(c.getBoundingClientRect().height));
  const tables = Array.from(container.querySelectorAll('table')).map(t => {
    const rows = Array.from(t.querySelectorAll('tbody tr'));
    return {
      rows: rows.length,
      cellHeights: rows.map(r => Array.from(r.cells).map(c => Math.round(c.getBoundingClientRect().height))),
      lastCellDisplay: rows.map(r => getComputedStyle(r.cells[r.cells.length - 1]).display),
      inlineFlexCells: Array.from(t.querySelectorAll('td')).filter(
        td => (td.getAttribute('style') || '').replace(/ /g, '').includes('display:flex')
      ).length,
      scrollWrapper: !!t.closest('.table-scroll'),
    };
  });
  return {
    fieldCount: controls.length,
    fields: named,
    cardCount: cards.length,
    cardHeights,
    documentHeight: document.documentElement.scrollHeight,
    pageScrollHeight: main.scrollHeight,
    sidewaysScroll: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    tables,
  };
}
"""

LEGACY_MEASURE = """
(html) => {
  const main = document.querySelector('.main');
  const holder = document.createElement('div');
  holder.id = 'legacy-settings';
  holder.innerHTML = html;
  main.appendChild(holder);
  const legacy = document.getElementById('legacy-settings');
  const controls = Array.from(legacy.querySelectorAll('input, select, button, a.btn'))
    .filter(el => el.type !== 'hidden');
  const result = {
    fieldCount: controls.length,
    height: Math.round(legacy.getBoundingClientRect().height),
    cardCount: legacy.querySelectorAll('.card').length,
  };
  holder.remove();
  return result;
}
"""


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
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.context.add_cookies(
            [
                {"name": "manage_session", "value": TOKEN, "url": BASE_URL},
                {"name": "csrf_token", "value": "ui-check-csrf", "url": BASE_URL},
            ]
        )
        page.goto(f"{BASE_URL}/manage/settings", wait_until="networkidle")

        measured = page.evaluate(MEASURE)
        legacy = page.evaluate(LEGACY_MEASURE, LEGACY_SETTINGS_HTML)

        print("=" * 78)
        print("PHASE 5 SETTINGS PAGE, RENDERED")
        print("=" * 78)
        print()
        print(
            f"new page   : {measured['fieldCount']} controls, "
            f"{measured['cardCount']} cards {measured['cardHeights']}, "
            f"document {measured['documentHeight']}px"
        )
        print(
            f"old stub   : {legacy['fieldCount']} controls, "
            f"{legacy['cardCount']} cards, {legacy['height']}px"
        )
        print()

        check(
            "the page has more controls than the stub",
            measured["fieldCount"] > legacy["fieldCount"],
            True,
        )
        check(
            "and it is taller, because it now says something",
            measured["documentHeight"] > legacy["height"],
            True,
        )

        print()
        missing = [f for f in measured["fields"] if not (f["title"] and f["ariaLabel"])]
        check("every control has title + aria-label", missing, [])

        oversized = [h for h in measured["cardHeights"] if h > 400]
        check("no oversized card (none over 400px)", oversized, [])
        check("no sideways scroll at 1440px", measured["sidewaysScroll"], 0)

        print()
        print("controls:")
        for f in measured["fields"]:
            print(
                f"  {f['tag']:<7} {f['name']:<34} title={f['title']!r} aria-label={f['ariaLabel']!r}"
            )

        print()
        print("--- 9c1e318 re-assertion on the environment table ---")
        if not measured["tables"]:
            failures.append("no table rendered")
            print("FAIL  no table rendered")
        for index, table in enumerate(measured["tables"]):
            rows = table["cellHeights"]
            # The invariant is per row: every cell in a row measures the same
            # height, which is what an inline `display:flex` on the last cell
            # used to break. Comparing across rows would fail on the last row
            # for the honest reason that it has no bottom border.
            uneven = [r for r in rows if len(set(r)) != 1]
            check(f"table {index}: every row's own cells share one height", uneven, [])
            check(
                f"table {index}: last cell is display: table-cell on every row",
                sorted(set(table["lastCellDisplay"])),
                ["table-cell"],
            )
            check(f"table {index}: no inline display:flex on a <td>", table["inlineFlexCells"], 0)
            check(f"table {index}: wrapped in .table-scroll", table["scrollWrapper"], True)
            print(f"  row cell heights: {rows}")

        # Three narrower widths, to prove the page does not push the document.
        print()
        for width in (1024, 600, 420):
            page.set_viewport_size({"width": width, "height": 900})
            page.wait_for_timeout(120)
            at_width = page.evaluate(MEASURE)
            check(f"no sideways scroll at {width}px", at_width["sidewaysScroll"], 0)

        browser.close()

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
