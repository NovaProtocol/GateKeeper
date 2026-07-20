import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, request, redirect, render_template, jsonify, g
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

serializer = URLSafeSerializer(app.secret_key, salt="cookie")
ticket_serializer = URLSafeTimedSerializer(app.secret_key, salt="ticket")

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


def require_manage_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        manage_pw = os.environ.get("MANAGE_PASSWORD")
        if not manage_pw:
            return "MANAGE_PASSWORD not configured", 500
        if not auth or auth.password != manage_pw:
            return ("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="GateKeeper Manage"'})
        return f(*args, **kwargs)
    return decorated


def get_redirect_target():
    target = request.args.get("redirect", "").strip()
    if target:
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


@app.route("/api/verify", methods=["GET"])
def api_verify():
    token = request.args.get("token", "").strip()
    if not token:
        return jsonify({"valid": False})

    try:
        code = serializer.loads(token)
    except Exception:
        return jsonify({"valid": False})

    db = get_db()
    row = db.execute("SELECT id FROM codes WHERE code = ? AND active = 1", (code,)).fetchone()
    if not row:
        return jsonify({"valid": False})

    db.execute("UPDATE codes SET last_accessed = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
    db.commit()

    import time
    ticket = ticket_serializer.dumps({"code_id": row["id"], "iat": int(time.time())})
    return jsonify({"valid": True, "ticket": ticket})


@app.route("/manage")
@require_manage_auth
def manage():
    db = get_db()
    codes = db.execute("SELECT id, code, label, active, created_at, last_accessed FROM codes ORDER BY created_at DESC").fetchall()
    return render_template("manage.html", codes=codes)


@app.route("/manage/create", methods=["POST"])
@require_manage_auth
def manage_create():
    import secrets
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
    init_db()
    app.run(host="0.0.0.0", port=7000)
