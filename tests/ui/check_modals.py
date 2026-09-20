"""Rendered-DOM proof that every row action opens its modal and fits the viewport.

Plan `gatekeeper-ui-and-wbs-api-bugfixes.md` §6 / §8.  Three defects were fixed:

  * BUG 1, inline handlers interpolated Jinja data into HTML attributes / JS
    strings, so a quote or apostrophe in a row value shattered the handler and
    the button went dead.  Fixed by carrying row data in `data-*` attributes and
    one delegated listener per page.
  * BUG 2b, `routing.html` was one `</div>` short, so its two modals parsed
    *inside* `addProxyModal` and measured 0x0 behind a live backdrop.  The
    routing page is therefore a first-class target here, not an afterthought.
  * BUG 2, dialogs taller than the viewport were clipped, leaving a backdrop
    and a partial dialog.

Two harness rules make the difference between a proof and a false pass:

  1. **Bootstrap's `fade` is asynchronous.**  `$('#m').modal('show')` returns
     before the element has `display:block` and `.show`; the class lands after a
     backdrop transition (measured ~200ms).  Measuring in the same synchronous
     turn reports `show=False box=0x0` on a modal that opens perfectly, and an
     "is it on screen" test then passes or fails for the wrong reason.  Every
     measurement here waits for the modal to actually reach `.show`.
  2. **The display:none walk must start at the parent.**  A *closed* Bootstrap
     modal is itself `display:none`, so starting the walk at the modal flags
     every modal on the page and hides the real nested case.

Hostile fixtures (apostrophe, quote, `<`, `>`, `&`, backslash, closing-script)
go into the page/code/group/rule payloads so the edit fields carry the exact
values that used to break the old inline handlers, and each field is asserted
byte-equal to its fixture.

Run with::

    uv run --no-project --with playwright --with-requirements requirements.txt \\
        python tests/ui/check_modals.py
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

DB_PATH = Path("/tmp/gatekeeper_modal_check.db").resolve()
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


# Hostile values: every character class that used to break an inline handler.
HOSTILE = 'Bob\'s "site" </script> <b>&</b> \\n backslash'
HOSTILE_LABEL = 'O\'Brien "x" & <ok>'
HOSTILE_PATTERN = "*.projectnova.download/robots.txt"

GROUPS = [
    {
        "id": 10,
        "name": "projectnova.download",
        "domain": "projectnova.download",
        "display_order": 0,
        "is_default": False,
        "rules_count": 2,
    },
    {
        "id": 11,
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
        "path": HOSTILE,
        "action": "access_code",
        "rate_limit": None,
        "display_order": 0,
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
CODES = [
    {
        "id": 3,
        "code": 'CO"D\\E',
        "label": HOSTILE_LABEL,
        "display_name": HOSTILE_LABEL,
        "active": True,
        "created_at": "2026-01-01 10:00:00",
        "last_accessed": None,
    },
]
# `app.projectnova.download` splits to sub='app', domain='projectnova.download'.
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
]
PAGE_ROWS = [
    {
        "id": 7,
        "pattern": HOSTILE_PATTERN,
        "body": HOSTILE,
        "content_type": "text/plain; charset=utf-8",
        "active": True,
        "display_order": 0,
    },
    {
        "id": 8,
        "pattern": "gatekeeper.projectnova.download/health",
        "body": "ok\n",
        "content_type": "text/plain; charset=utf-8",
        "active": False,
        "display_order": 1,
    },
]

PAYLOADS: dict[str, Any] = {
    "/api/groups": GROUPS,
    "/api/groups/10/rules": RULES,
    "/api/groups/11/rules": [RULES[1]],
    "/api/routes": ROUTES,
    "/api/pages": PAGE_ROWS,
    "/api/codes": CODES,
    "/api/logs": [],
    "/api/logs/top": [],
    "/api/logs/by-ip": [],
    "/api/settings": [],
    "/api/warnings": {"groups": [], "rules": []},
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
        return _FakeResponse(PAYLOADS.get(url.split("http://api:8002", 1)[-1], {}))

    async def delete(self, url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse({})


management_app._get_httpx = lambda: _FakeClient()  # type: ignore[assignment]

PORT = 8733
app = management_app.create_app()
server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="error"))
threading.Thread(target=server.run, daemon=True).start()
for _ in range(100):
    if server.started:
        break
    time.sleep(0.05)
assert server.started, "uvicorn did not start"

TOKEN = create_manage_token()
BASE_URL = f"http://127.0.0.1:{PORT}"

# (page, trigger selector, modal id, {field id: expected value after the click}).
# The routing entries are the BUG 2b guards: its two extra modals used to parse
# inside `addProxyModal` and never render.
TARGETS: list[tuple[str, str, str, dict[str, str]]] = [
    (
        "/manage/pages",
        "[data-page-edit]",
        "#editPageModal",
        {"edit-pattern": HOSTILE_PATTERN, "edit-body": HOSTILE},
    ),
    (
        "/manage/codes",
        "[data-code-edit]",
        "#editCodeModal",
        {"edit-label": HOSTILE_LABEL, "edit-code": 'CO"D\\E'},
    ),
    (
        "/manage/rules",
        "[data-group-edit]",
        "#editGroupModal",
        {"edit-group-name": "projectnova.download", "edit-group-domain": "projectnova.download"},
    ),
    (
        "/manage/rules/10",
        "[data-rule-edit]",
        "#editRuleModal",
        {"edit-rule-path": HOSTILE, "edit-rule-action": "access_code"},
    ),
    ("/manage/routing", '[data-target="#addProxyModal"]', "#addProxyModal", {}),
    ("/manage/routing", '[data-target="#addRedirectModal"]', "#addRedirectModal", {}),
    (
        "/manage/routing",
        'button[title="Edit route"]',
        "#editRouteModal",
        {"edit-sub": "app", "edit-domain": "projectnova.download", "edit-path": "/"},
    ),
]

VIEWPORT_HEIGHTS = [940, 752, 627, 600, 500]

# Every id any target may need, so one probe serves all of them.
FIELD_IDS = [
    "edit-pattern",
    "edit-body",
    "edit-content-type",
    "edit-label",
    "edit-code",
    "edit-group-name",
    "edit-group-domain",
    "edit-rule-path",
    "edit-rule-action",
    "edit-sub",
    "edit-domain",
    "edit-path",
]

# Click the trigger and report post-transition DOM facts.  Runs after the caller
# has waited for `.show`, so the box is the settled layout, not the pre-transition
# state.
MEASURE = """
({sel, modalId, fieldIds}) => {
  const modal = document.querySelector(modalId);
  if (!modal) return {modalFound: false};
  const dialog = modal.querySelector('.modal-dialog') || modal;
  const rect = dialog.getBoundingClientRect();
  // Walk ancestors ABOVE the modal: a closed modal is itself display:none.
  let hiddenAncestor = false, nestedInModal = false, node = modal.parentElement;
  while (node && node !== document.body) {
    if (getComputedStyle(node).display === 'none') hiddenAncestor = true;
    if (node.classList && node.classList.contains('modal')) nestedInModal = true;
    node = node.parentElement;
  }
  const fields = {};
  fieldIds.forEach(id => {
    const el = modal.querySelector('#' + id);
    if (el) fields[id] = el.value;
  });
  const submit = modal.querySelector('.modal-footer .btn-accent');
  const header = modal.querySelector('.modal-header');
  return {
    modalFound: true,
    hasShow: modal.className.includes('show'),
    boxW: Math.round(rect.width), boxH: Math.round(rect.height),
    top: Math.round(rect.top), bottom: Math.round(rect.bottom),
    hiddenAncestor: hiddenAncestor, nestedInModal: nestedInModal,
    backdrops: document.querySelectorAll('.modal-backdrop').length,
    fields: fields,
    submitBottom: submit ? Math.round(submit.getBoundingClientRect().bottom) : null,
    headerTop: header ? Math.round(header.getBoundingClientRect().top) : null,
  };
}
"""


def _open_and_wait(page: Any, sel: str, modal_id: str, failures: list[str], where: str) -> bool:
    """Click the trigger, wait for the modal to settle into `.show`, measure it.

    Returns False when the modal never became visible, the caller should report
    that and skip the geometry assertions, because a modal that did not open is
    not a "clipped" modal.
    """
    trigger = page.query_selector(sel)
    if trigger is None:
        failures.append(f"{where}: trigger {sel!r} not found in the page")
        return False
    trigger.click()
    try:
        # Settle, don't just pray.  Three things land asynchronously, and
        # measuring before all three are done reports a modal that "does not
        # open" or "is clipped" when it is neither:
        #   1. `.show` is added after the backdrop transition,
        #   2. `.modal.fade .modal-dialog` starts at `transform: translate(0,-50px)`
        #      and animates to `none` over 300ms, mid-flight the dialog reads
        #      50px higher than it settles, which a naive `top >= 0` check calls
        #      "above the viewport",
        #   3. the dialog needs a real box (a nested/`display:none` dialog is 0x0
        #      and would let an on-screen assertion pass vacuously).
        page.wait_for_function(
            """(mid) => {
                 const m = document.querySelector(mid);
                 if (!m || !m.className.includes('show')) return false;
                 const d = m.querySelector('.modal-dialog');
                 const r = d.getBoundingClientRect();
                 if (r.width <= 20 || r.height <= 20) return false;
                 return getComputedStyle(d).transform === 'none';
               }""",
            arg=modal_id,
            timeout=4000,
        )
    except Exception:
        failures.append(f"{where}: {modal_id} never settled into a rendered `.show` state")
        return False
    return True


def main() -> int:
    from playwright.sync_api import sync_playwright

    failures: list[str] = []
    print("=" * 78)
    print("RENDERED-DOM PROOF, manage modals open, fit, and carry their data")
    print("=" * 78)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 940})
        context.add_cookies(
            [
                {"name": "manage_session", "value": TOKEN, "url": BASE_URL},
                {"name": "csrf_token", "value": "ui-check-csrf", "url": BASE_URL},
            ]
        )
        page = context.new_page()
        page_errors: list[str] = []
        page.on("pageerror", lambda e: page_errors.append(str(e)))

        # ---- 1. every row action opens its modal, data intact ---------------- #
        print("\n" + "-" * 78)
        print("1. TRIGGER -> MODAL, hostile fixtures round-tripped into the form")
        print("-" * 78)
        for path, sel, modal_id, expected in TARGETS:
            page.set_viewport_size({"width": 1440, "height": 940})
            page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
            where = f"{path} {sel}"
            if not _open_and_wait(page, sel, modal_id, failures, where):
                print(f"  {where:52} NEVER OPENED")
                continue
            res = page.evaluate(MEASURE, {"sel": sel, "modalId": modal_id, "fieldIds": FIELD_IDS})
            if res.get("nestedInModal"):
                failures.append(f"{where}: {modal_id} is nested inside another modal (BUG 2b)")
            if res.get("hiddenAncestor"):
                failures.append(f"{where}: {modal_id} has a display:none ancestor (BUG 2b)")
            if res.get("backdrops") != 1:
                failures.append(f"{where}: expected exactly 1 backdrop, saw {res.get('backdrops')}")
            for field_id, want in expected.items():
                got = res.get("fields", {}).get(field_id)
                if got != want:
                    failures.append(
                        f"{where}: #{field_id} round-trip mismatch: got {got!r} want {want!r}"
                    )
            print(
                f"  {where:52} box={res['boxW']}x{res['boxH']} "
                f"nested={res['nestedInModal']} bd={res['backdrops']}"
            )
        if page_errors:
            failures.append(f"uncaught JS errors on the page: {page_errors}")

        # ---- 2. dialog + submit button fit at every tested height ------------ #
        print("\n" + "-" * 78)
        print(f"2. DIALOG AND SUBMIT BUTTON WITHIN VIEWPORT at {VIEWPORT_HEIGHTS}")
        print("-" * 78)
        for path in sorted({t[0] for t in TARGETS}):
            for h in VIEWPORT_HEIGHTS:
                # A fresh load per target: dismissing via Escape needs focus the
                # modal may not have, and navigating is deterministic.
                for _, sel, modal_id, _ in [t for t in TARGETS if t[0] == path]:
                    page.set_viewport_size({"width": 1280, "height": h})
                    page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
                    where = f"{path}@{h} {modal_id}"
                    if not _open_and_wait(page, sel, modal_id, failures, where):
                        continue
                    res = page.evaluate(
                        MEASURE, {"sel": sel, "modalId": modal_id, "fieldIds": FIELD_IDS}
                    )
                    vh = page.evaluate("() => document.documentElement.clientHeight")
                    if res["top"] < -1:
                        failures.append(f"{where}: dialog top {res['top']} above viewport")
                    if res["bottom"] > vh + 1:
                        failures.append(
                            f"{where}: dialog bottom {res['bottom']} exceeds viewport {vh}"
                        )
                    if res["headerTop"] is not None and res["headerTop"] < -1:
                        failures.append(f"{where}: header top above viewport")
                    if res["submitBottom"] is not None and res["submitBottom"] > vh + 1:
                        failures.append(
                            f"{where}: submit bottom {res['submitBottom']} exceeds "
                            f"viewport {vh} (BUG 2 clipping)"
                        )
                    print(
                        f"  {where:44} vh={vh:4} top={res['top']:5} "
                        f"bottom={res['bottom']:5} submit={res['submitBottom']}"
                    )

        browser.close()

    print("\n" + "=" * 78)
    if failures:
        print(f"FAILED, {len(failures)} problem(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("PASSED, every trigger opens a non-nested, on-screen modal with its hostile data intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
