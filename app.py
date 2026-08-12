from __future__ import annotations

import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from flask import Flask, request, redirect, render_template, g
from itsdangerous import URLSafeSerializer

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

serializer = URLSafeSerializer(app.secret_key, salt="cookie")

DB_PATH = Path(os.environ.get("DB_DIR", str(Path(__file__).parent))) / "gatekeeper.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("""CREATE TABLE IF NOT EXISTS codes (
        id INTEGER PRIMARY KEY,
        code TEXT UNIQUE NOT NULL,
        label TEXT,
        active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_accessed TIMESTAMP
    )""")
    try:
        db.execute("ALTER TABLE codes ADD COLUMN last_accessed TIMESTAMP")
    except sqlite3.OperationalError:
        pass
    backup = os.environ.get("BACKUP_CODE")
    if backup:
        existing = db.execute("SELECT 1 FROM codes WHERE code = ?", (backup,)).fetchone()
        if not existing:
            db.execute("INSERT INTO codes (code, label) VALUES (?, ?)", (backup, "backup"))
    db.commit()
    db.close()


app.teardown_appcontext(close_db)

init_db()


def apex_domain():
    host = request.host.split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:])


def same_origin():
    """CSRF guard for state-changing requests: the Origin (or Referer) must
    belong to this deployment's own apex domain."""
    origin = request.headers.get("Origin")
    if origin is None:
        origin = request.headers.get("Referer")
    if not origin:
        return False
    origin_host = urlsplit(origin).hostname or ""
    return origin_host == request.host.split(":")[0] or origin_host.endswith("." + apex_domain()) or origin_host == apex_domain()


def require_manage_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        manage_pw = os.environ.get("MANAGE_PASSWORD")
        if not manage_pw:
            return "MANAGE_PASSWORD not configured", 500
        if not auth or not secrets.compare_digest(auth.password, manage_pw):
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="GateKeeper Manage"'})
        if request.method == "POST" and not same_origin():
            return ("Cross-site request rejected", 403)
        return f(*args, **kwargs)
    return decorated


def _safe_redirect_target(target: str) -> bool:
    """Only allow same-host paths or https URLs on this deployment's own
    apex domain (the family of gated apps). Kills the open redirect."""
    apex = apex_domain()
    parts = urlsplit(target)
    if not parts.scheme and not parts.netloc:
        return target.startswith("/")
    if parts.scheme in ("http", "https") and parts.netloc:
        host = parts.netloc.split(":")[0].lower()
        return host == apex or host.endswith("." + apex)
    return False


def get_redirect_target():
    target = request.args.get("redirect", "").strip()
    if target and _safe_redirect_target(target):
        return target
    apex = apex_domain()
    return f"https://portfolio.{apex}"


def set_auth_cookie(response, code):
    apex = apex_domain()
    response.set_cookie(
        "gatekeeper_token",
        serializer.dumps(code),
        domain=f".{apex}",
        path="/",
        httponly=True,
        samesite="Lax",
        secure=True,
    )


@app.route("/", methods=["GET"])
def login():
    token = request.cookies.get("gatekeeper_token")
    if token:
        try:
            serializer.loads(token)
            return redirect(get_redirect_target())
        except Exception:
            pass

    code = request.args.get("access_code", "").strip()
    if code:
        db = get_db()
        row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code,)).fetchone()
        if row:
            db.execute("UPDATE codes SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
            db.commit()
            resp = redirect(get_redirect_target())
            set_auth_cookie(resp, code)
            return resp

    return render_template("login.html")


@app.route("/", methods=["POST"])
def login_post():
    code = request.form.get("code", "").strip()
    db = get_db()
    row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code,)).fetchone()
    if row:
        db.execute("UPDATE codes SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
        db.commit()
        resp = redirect(get_redirect_target())
        set_auth_cookie(resp, code)
        return resp

    return render_template("login.html", error="Invalid code")


@app.route("/api/authz/forward-auth", methods=["GET"])
def authz_forward_auth():
    token = request.cookies.get("gatekeeper_token")
    if token:
        try:
            code = serializer.loads(token)
        except Exception:
            code = None
        if code:
            db = get_db()
            row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code,)).fetchone()
            if row:
                db.execute("UPDATE codes SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
                db.commit()
                return "", 200

    original_uri = request.headers.get("X-Forwarded-Uri", "")
    parts = urlsplit(original_uri)
    query = parse_qsl(parts.query)
    code_param = next((v for k, v in query if k == "access_code"), "")
    if code_param:
        db = get_db()
        row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code_param,)).fetchone()
        if row:
            db.execute("UPDATE codes SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
            db.commit()
            clean_query = urlencode([(k, v) for k, v in query if k != "access_code"])
            resp = redirect(urlunsplit(("", "", parts.path, clean_query, parts.fragment)))
            set_auth_cookie(resp, code_param)
            return resp

    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    host = host.split(":")[0].lower()
    apex = apex_domain()
    if host != apex and not host.endswith("." + apex):
        host = apex
    target = quote(f"{proto}://{host}{original_uri}", safe="")
    return redirect(f"https://gatekeeper.{apex_domain()}/?redirect={target}")


@app.route("/manage")
@require_manage_auth
def manage():
    db = get_db()
    codes = db.execute("SELECT id, code, label, active, created_at, last_accessed FROM codes ORDER BY created_at DESC").fetchall()
    return render_template("manage.html", codes=codes)


@app.route("/manage/create", methods=["POST"])
@require_manage_auth
def manage_create():
    new_code = secrets.token_hex(8)
    label = request.form.get("label", "").strip() or None
    db = get_db()
    try:
        db.execute("INSERT INTO codes (code, label) VALUES (?, ?)", (new_code, label))
        db.commit()
    except sqlite3.IntegrityError:
        return "Code generation collision, try again", 500
    return redirect("/manage")


@app.route("/manage/invalidate", methods=["POST"])
@require_manage_auth
def manage_invalidate():
    code_id = request.form.get("id", type=int)
    if not code_id:
        return "Missing code id", 400
    db = get_db()
    db.execute("UPDATE codes SET active = 0 WHERE id = ?", (code_id,))
    db.commit()
    return redirect("/manage")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)
