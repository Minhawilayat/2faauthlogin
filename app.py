"""Secure Login System with Two-Factor Authentication (TOTP).

Academic demonstration project. Features:
  * Registration / login with Werkzeug password hashing
  * TOTP 2FA with QR-code setup (secret stored encrypted with Fernet)
  * Failed-login detection, temporary lockout and rate limiting
  * Session fixation protection (session reset after each auth step)
  * CSRF protection, security headers
  * Security dashboard (2FA status, recent login activity, security logs)
"""
import base64
import io
import math
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import pyotp
import qrcode
from cryptography.fernet import Fernet
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")

MAX_FAILED_ATTEMPTS = 5      # failures before temporary lockout
LOCK_MINUTES = 15            # lockout length / counting window
PRE_AUTH_SECONDS = 300       # time allowed between password step and OTP step
ISSUER = "SecureLogin Demo"

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Used to keep response time similar for unknown usernames.
DUMMY_HASH = generate_password_hash("dummy-password-for-timing")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS two_factor (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    secret_enc BLOB NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    last_counter INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT NOT NULL,
    ts TEXT NOT NULL,
    stage TEXT NOT NULL,          -- password | otp
    outcome TEXT NOT NULL,        -- fail | success | password_ok | blocked
    ip TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_attempts_user ON login_attempts(username, ts);
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ts TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT
);
"""


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds")


def _load_or_create(path, generator):
    """Read a secret from disk or create it (file mode 600)."""
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read().strip()
    value = generator()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(value)
    return value


def create_app(config=None):
    app = Flask(__name__)
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    app.config.update(
        DATABASE=os.path.join(INSTANCE_DIR, "secure_login.db"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Set SESSION_COOKIE_SECURE=1 when serving over HTTPS.
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        RATELIMIT_ENABLED=True,
    )
    if config:
        app.config.update(config)

    app.config["SECRET_KEY"] = (
        os.environ.get("SECRET_KEY")
        or app.config.get("SECRET_KEY")
        or _load_or_create(os.path.join(INSTANCE_DIR, "secret_key"),
                           lambda: secrets.token_hex(32).encode()).decode()
    )
    fernet_key = (
        os.environ.get("FERNET_KEY", "").encode()
        or app.config.get("FERNET_KEY")
        or _load_or_create(os.path.join(INSTANCE_DIR, "fernet.key"), Fernet.generate_key)
    )
    app.fernet = Fernet(fernet_key)

    limiter = Limiter(get_remote_address, app=app,
                      default_limits=["200 per hour"], storage_uri="memory://")

    # ------------------------------------------------------------------ DB
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with app.app_context():
        get_db().executescript(SCHEMA)
        get_db().commit()

    # ------------------------------------------------------------- logging
    def log_attempt(username, user_id, stage, outcome):
        get_db().execute(
            "INSERT INTO login_attempts (user_id, username, ts, stage, outcome, ip, user_agent) "
            "VALUES (?,?,?,?,?,?,?)",
            (user_id, username, iso(utcnow()), stage, outcome,
             request.remote_addr, (request.user_agent.string or "")[:200]))
        get_db().commit()

    def log_event(user_id, event, detail=""):
        get_db().execute(
            "INSERT INTO security_logs (user_id, ts, event, detail) VALUES (?,?,?,?)",
            (user_id, iso(utcnow()), event, detail))
        get_db().commit()

    def lock_status(username):
        """Return (locked, minutes_remaining) based on recent failures."""
        db = get_db()
        now = utcnow()
        window_start = iso(now - timedelta(minutes=LOCK_MINUTES))
        last_ok = db.execute(
            "SELECT MAX(ts) m FROM login_attempts WHERE username=? AND outcome='success'",
            (username,)).fetchone()["m"] or ""
        since = max(window_start, last_ok)
        row = db.execute(
            "SELECT COUNT(*) c, MAX(ts) last FROM login_attempts "
            "WHERE username=? AND outcome='fail' AND ts>?", (username, since)).fetchone()
        if row["c"] >= MAX_FAILED_ATTEMPTS:
            until = datetime.fromisoformat(row["last"]) + timedelta(minutes=LOCK_MINUTES)
            remaining = (until - now).total_seconds()
            if remaining > 0:
                return True, math.ceil(remaining / 60)
        return False, 0

    # ----------------------------------------------------------- 2FA utils
    def get_secret(user_id):
        row = get_db().execute("SELECT * FROM two_factor WHERE user_id=?", (user_id,)).fetchone()
        return row

    def decrypt_secret(row):
        return app.fernet.decrypt(row["secret_enc"]).decode()

    def check_totp(secret, code):
        """Return the matching time-step counter or None (allows +-1 step drift)."""
        code = (code or "").strip().replace(" ", "")
        if not re.fullmatch(r"\d{6}", code):
            return None
        totp = pyotp.TOTP(secret)
        now = utcnow().timestamp()
        for offset in (-1, 0, 1):
            t = now + offset * totp.interval
            if secrets.compare_digest(totp.at(t), code):
                return int(t // totp.interval)
        return None

    def qr_data_uri(uri):
        buf = io.BytesIO()
        qrcode.make(uri).save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

    # ------------------------------------------------------------- session
    def finalize_login(user):
        """Reset the session (new identifier) and mark the user authenticated."""
        session.clear()
        session.permanent = True
        session["uid"] = user["id"]
        session["sid"] = secrets.token_hex(16)
        get_db().execute("UPDATE users SET last_login=? WHERE id=?", (iso(utcnow()), user["id"]))
        get_db().commit()
        log_attempt(user["username"], user["id"], "otp", "success")
        log_event(user["id"], "login_success", "Password and 2FA verified")

    def pre_auth_user():
        data = session.get("pre_auth")
        if not data or utcnow().timestamp() - data["ts"] > PRE_AUTH_SECONDS:
            session.pop("pre_auth", None)
            return None
        return get_db().execute("SELECT * FROM users WHERE id=? AND is_active=1",
                                (data["uid"],)).fetchone()

    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if uid:
            g.user = get_db().execute(
                "SELECT * FROM users WHERE id=? AND is_active=1", (uid,)).fetchone()
            if g.user is None:
                session.clear()

    def login_required(view):
        @wraps(view)
        def wrapped(*a, **kw):
            if g.user is None:
                flash("Please log in to access that page.", "warning")
                return redirect(url_for("login"))
            return view(*a, **kw)
        return wrapped

    # ---------------------------------------------------------------- CSRF
    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = session.get("_csrf")
            sent = request.form.get("_csrf", "")
            if not token or not secrets.compare_digest(token, sent):
                abort(400, "Invalid or missing CSRF token.")

    @app.context_processor
    def inject_globals():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return {"csrf_token": session["_csrf"], "current_user": g.get("user")}

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # -------------------------------------------------------------- routes
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def register():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")
            errors = []
            if not USERNAME_RE.match(username):
                errors.append("Username must be 3-30 characters: letters, digits, underscore.")
            if not EMAIL_RE.match(email) or len(email) > 254:
                errors.append("Enter a valid email address.")
            if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
                errors.append("Password must be at least 8 characters and include a letter and a digit.")
            if password != confirm:
                errors.append("Passwords do not match.")
            if not errors:
                try:
                    db = get_db()
                    cur = db.execute(
                        "INSERT INTO users (username, email, password_hash, created_at) VALUES (?,?,?,?)",
                        (username, email, generate_password_hash(password), iso(utcnow())))
                    db.commit()
                    log_event(cur.lastrowid, "registered", "Account created")
                    flash("Account created. Please log in; you will set up 2FA on first login.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    errors.append("That username or email is already in use.")
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", username=username, email=email), 400
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()[:64]
            password = request.form.get("password", "")
            user = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            uid = user["id"] if user else None

            locked, mins = lock_status(username)
            if locked:
                log_attempt(username, uid, "password", "blocked")
                flash(f"Too many failed attempts. Try again in about {mins} minute(s).", "danger")
                return render_template("login.html"), 429

            hash_to_check = user["password_hash"] if user else DUMMY_HASH
            valid = check_password_hash(hash_to_check, password) and user is not None and user["is_active"]
            if not valid:
                log_attempt(username, uid, "password", "fail")
                if lock_status(username)[0]:
                    log_event(uid, "account_locked",
                              f"{MAX_FAILED_ATTEMPTS} failed attempts for '{username}'")
                flash("Invalid username or password.", "danger")
                return render_template("login.html"), 401

            log_attempt(username, uid, "password", "password_ok")
            session.clear()  # new session before the 2FA step
            session["pre_auth"] = {"uid": user["id"], "ts": utcnow().timestamp()}
            tf = get_secret(user["id"])
            if tf and tf["enabled"]:
                return redirect(url_for("verify_2fa"))
            return redirect(url_for("setup_2fa"))
        return render_template("login.html")

    @app.route("/2fa/setup", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def setup_2fa():
        user = pre_auth_user()
        if user is None:
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login"))
        db = get_db()
        tf = get_secret(user["id"])
        if tf and tf["enabled"]:
            return redirect(url_for("verify_2fa"))
        if tf is None:
            secret = pyotp.random_base32()
            db.execute("INSERT INTO two_factor (user_id, secret_enc, enabled, updated_at) VALUES (?,?,0,?)",
                       (user["id"], app.fernet.encrypt(secret.encode()), iso(utcnow())))
            db.commit()
            tf = get_secret(user["id"])
        secret = decrypt_secret(tf)

        if request.method == "POST":
            locked, mins = lock_status(user["username"])
            if locked:
                log_attempt(user["username"], user["id"], "otp", "blocked")
                flash(f"Too many failed attempts. Try again in about {mins} minute(s).", "danger")
                return redirect(url_for("login"))
            counter = check_totp(secret, request.form.get("code"))
            if counter is None:
                log_attempt(user["username"], user["id"], "otp", "fail")
                flash("Invalid code. Check your authenticator app and try again.", "danger")
            else:
                db.execute("UPDATE two_factor SET enabled=1, last_counter=?, updated_at=? WHERE user_id=?",
                           (counter, iso(utcnow()), user["id"]))
                db.commit()
                log_event(user["id"], "2fa_enabled", "TOTP configured")
                finalize_login(user)
                flash("Two-factor authentication enabled. You are logged in.", "success")
                return redirect(url_for("dashboard"))

        uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name=ISSUER)
        return render_template("setup_2fa.html", qr=qr_data_uri(uri), secret=secret)

    @app.route("/2fa/verify", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def verify_2fa():
        user = pre_auth_user()
        if user is None:
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login"))
        tf = get_secret(user["id"])
        if not tf or not tf["enabled"]:
            return redirect(url_for("setup_2fa"))

        if request.method == "POST":
            locked, mins = lock_status(user["username"])
            if locked:
                log_attempt(user["username"], user["id"], "otp", "blocked")
                session.pop("pre_auth", None)
                flash(f"Too many failed attempts. Try again in about {mins} minute(s).", "danger")
                return redirect(url_for("login"))
            counter = check_totp(decrypt_secret(tf), request.form.get("code"))
            # Reject codes that were already used (replay protection).
            if counter is None or counter <= tf["last_counter"]:
                log_attempt(user["username"], user["id"], "otp", "fail")
                if lock_status(user["username"])[0]:
                    log_event(user["id"], "account_locked", "Repeated failed 2FA codes")
                    session.pop("pre_auth", None)
                    flash("Too many failed attempts. Account temporarily locked.", "danger")
                    return redirect(url_for("login"))
                flash("Invalid or already-used code.", "danger")
                return render_template("verify_2fa.html"), 401
            get_db().execute("UPDATE two_factor SET last_counter=? WHERE user_id=?", (counter, user["id"]))
            get_db().commit()
            finalize_login(user)
            return redirect(url_for("dashboard"))
        return render_template("verify_2fa.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        db = get_db()
        uid = g.user["id"]
        tf = get_secret(uid)
        attempts = db.execute(
            "SELECT * FROM login_attempts WHERE user_id=? OR username=? ORDER BY id DESC LIMIT 10",
            (uid, g.user["username"])).fetchall()
        logs = db.execute(
            "SELECT * FROM security_logs WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)).fetchall()
        since = iso(utcnow() - timedelta(hours=24))
        failed_24h = db.execute(
            "SELECT COUNT(*) c FROM login_attempts WHERE username=? AND outcome='fail' AND ts>?",
            (g.user["username"], since)).fetchone()["c"]
        return render_template("dashboard.html", twofa_enabled=bool(tf and tf["enabled"]),
                               attempts=attempts, logs=logs, failed_24h=failed_24h)

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        log_event(g.user["id"], "logout", "")
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    @app.errorhandler(429)
    def too_many(_e):
        return render_template("error.html", code=429,
                               message="Rate limit exceeded. Please slow down and try again shortly."), 429

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("error.html", code=400, message=getattr(e, "description", "Bad request")), 400

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
