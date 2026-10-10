import os
import re
import sqlite3
import sys
from datetime import timedelta

import pyotp
import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as appmod  # noqa: E402

PASSWORD = "Passw0rdX1"


def make_app(tmp_path, **extra):
    cfg = {
        "TESTING": True,
        "DATABASE": str(tmp_path / "test.db"),
        "SECRET_KEY": "test-secret-key",
        "FERNET_KEY": Fernet.generate_key(),
        "RATELIMIT_ENABLED": False,
    }
    cfg.update(extra)
    return appmod.create_app(cfg)


@pytest.fixture
def app(tmp_path):
    return make_app(tmp_path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def clock(monkeypatch):
    """Controllable clock so tests can move to the next TOTP time step."""
    state = {"offset": 0}
    real = appmod.utcnow
    monkeypatch.setattr(appmod, "utcnow", lambda: real() + timedelta(seconds=state["offset"]))
    return state


# ------------------------------------------------------------------ helpers
def token(client, path):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)


def register(client, username="alice", password=PASSWORD):
    return client.post("/register", data={
        "_csrf": token(client, "/register"), "username": username,
        "email": f"{username}@example.com", "password": password, "confirm": password})


def password_login(client, username="alice", password=PASSWORD):
    return client.post("/login", data={
        "_csrf": token(client, "/login"), "username": username, "password": password})


def post_code(client, path, code):
    return client.post(path, data={"_csrf": token(client, path), "code": code})


def get_secret(app, username="alice"):
    con = sqlite3.connect(app.config["DATABASE"])
    row = con.execute("SELECT t.secret_enc FROM two_factor t JOIN users u ON u.id=t.user_id "
                      "WHERE u.username=?", (username,)).fetchone()
    con.close()
    return app.fernet.decrypt(row[0]).decode()


def wrong_code(secret):
    totp = pyotp.TOTP(secret)
    import time
    valid = {totp.at(time.time() + o * 30) for o in (-2, -1, 0, 1, 2)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in valid)


def enroll(client, app, username="alice"):
    """Register, log in with password, finish 2FA setup. Leaves the user logged in."""
    register(client, username)
    r = password_login(client, username)
    assert r.headers["Location"].endswith("/2fa/setup")
    client.get("/2fa/setup")
    secret = get_secret(app, username)
    r = post_code(client, "/2fa/setup", pyotp.TOTP(secret).now())
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    return secret


# -------------------------------------------------------------------- tests
def test_password_not_stored_in_plain_text(app, client):
    register(client)
    con = sqlite3.connect(app.config["DATABASE"])
    stored = con.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
    con.close()
    assert stored != PASSWORD and PASSWORD not in stored
    assert stored.startswith(("scrypt:", "pbkdf2:"))


def test_registration_rejects_weak_password(client):
    r = register(client, password="short")
    assert r.status_code == 400


def test_duplicate_username_rejected(client):
    register(client)
    assert register(client).status_code == 400


def test_totp_secret_is_encrypted_at_rest(app, client):
    secret = enroll(client, app)
    con = sqlite3.connect(app.config["DATABASE"])
    blob = con.execute("SELECT secret_enc FROM two_factor").fetchone()[0]
    con.close()
    assert secret.encode() not in blob


def test_protected_page_requires_login(client):
    r = client.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_invalid_password_rejected_with_generic_message(client):
    register(client)
    r = password_login(client, password="WrongPass123")
    assert r.status_code == 401
    assert "Invalid username or password" in r.get_data(as_text=True)


def test_unknown_user_gets_same_message(client):
    r = password_login(client, username="ghost")
    assert r.status_code == 401
    assert "Invalid username or password" in r.get_data(as_text=True)


def test_dashboard_rejected_before_2fa_completed(client):
    register(client)
    r = password_login(client)
    assert r.status_code == 302 and r.headers["Location"].endswith("/2fa/setup")
    r = client.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_setup_with_wrong_code_fails(app, client):
    register(client)
    password_login(client)
    client.get("/2fa/setup")
    r = post_code(client, "/2fa/setup", wrong_code(get_secret(app)))
    assert r.status_code == 200  # stays on setup page
    assert client.get("/dashboard").status_code == 302


def test_full_login_flow_with_correct_otp(app, client, clock):
    secret = enroll(client, app)
    page = client.get("/dashboard")
    assert page.status_code == 200 and "Enabled" in page.get_data(as_text=True)
    token_ = token(client, "/dashboard")
    client.post("/logout", data={"_csrf": token_})

    r = password_login(client)
    assert r.headers["Location"].endswith("/2fa/verify")
    r = post_code(client, "/2fa/verify", wrong_code(secret))
    assert r.status_code == 401
    clock["offset"] += 60  # next time step -> fresh code
    r = post_code(client, "/2fa/verify", pyotp.TOTP(secret).at(appmod.utcnow()))
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert client.get("/dashboard").status_code == 200


def test_otp_replay_is_rejected(app, client):
    secret = enroll(client, app)  # consumed the current time step
    client.post("/logout", data={"_csrf": token(client, "/dashboard")})
    password_login(client)
    r = post_code(client, "/2fa/verify", pyotp.TOTP(secret).now())
    assert r.status_code == 401


def test_session_reset_after_authentication(app, client):
    enroll(client, app)
    with client.session_transaction() as s:
        assert "uid" in s and "sid" in s and "pre_auth" not in s


def test_repeated_failed_passwords_lock_account(client):
    register(client)
    for _ in range(appmod.MAX_FAILED_ATTEMPTS):
        assert password_login(client, password="WrongPass123").status_code == 401
    r = password_login(client)  # even the correct password is refused now
    assert r.status_code == 429
    assert "Too many failed attempts" in r.get_data(as_text=True)


def test_repeated_failed_otp_lock_account(app, client):
    secret = enroll(client, app)
    client.post("/logout", data={"_csrf": token(client, "/dashboard")})
    password_login(client)
    bad = wrong_code(secret)
    last = None
    for _ in range(appmod.MAX_FAILED_ATTEMPTS):
        last = post_code(client, "/2fa/verify", bad)
    assert last.status_code == 302 and "/login" in last.headers["Location"]
    assert password_login(client).status_code == 429


def test_failed_attempts_are_logged(app, client):
    register(client)
    password_login(client, password="WrongPass123")
    con = sqlite3.connect(app.config["DATABASE"])
    n = con.execute("SELECT COUNT(*) FROM login_attempts WHERE outcome='fail'").fetchone()[0]
    con.close()
    assert n == 1


def test_logout_ends_session(app, client):
    enroll(client, app)
    client.post("/logout", data={"_csrf": token(client, "/dashboard")})
    assert client.get("/dashboard").status_code == 302


def test_post_without_csrf_token_rejected(app, client):
    enroll(client, app)
    assert client.post("/logout").status_code == 400


def test_security_headers_present(client):
    r = client.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_rate_limit_applied(tmp_path):
    limited = make_app(tmp_path, RATELIMIT_ENABLED=True)
    c = limited.test_client()
    codes = []
    for i in range(12):  # different usernames so account lockout is not what triggers
        codes.append(password_login(c, username=f"user{i}").status_code)
    assert codes[:10] == [401] * 10
    assert 429 in codes[10:]
