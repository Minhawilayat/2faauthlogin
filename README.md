# Secure Login System with Two-Factor Authentication (2FA)

Academic demo: a small Flask web app that combines password hashing, TOTP-based 2FA,
brute-force protection and secure session handling.

## Features
- Registration and login (Werkzeug password hashes, never plain text)
- TOTP 2FA (works with Google Authenticator, Microsoft Authenticator, Authy)
- QR-code setup on first login; the TOTP secret is stored **encrypted** (Fernet)
- 2FA code replay protection (a code can only be used once)
- Failed-login detection + temporary lockout (5 failures -> 15 minutes)
- Rate limiting with Flask-Limiter (e.g. 10 login attempts/minute per IP)
- Session reset after each authentication step, HttpOnly + SameSite cookies, 30 min lifetime
- CSRF tokens on all forms, security headers (CSP, X-Frame-Options, ...)
- Security dashboard: 2FA status, recent login activity, security events
- SQLite database: `users`, `two_factor`, `login_attempts`, `security_logs`

## Run
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 , register, log in, scan the QR code, enter the 6-digit code.

Secrets (`instance/secret_key`, `instance/fernet.key`) are generated automatically on first run.
You can override them with the `SECRET_KEY` and `FERNET_KEY` environment variables.
When serving over HTTPS set `SESSION_COOKIE_SECURE=1`.

## Authentication flow
1. Register -> 2. Login (username + password) -> 3. Password verified ->
4. 2FA code requested (first login: QR setup) -> 5. Code validated ->
6. Session regenerated and dashboard unlocked. Any failure is logged.

## Tests
```bash
pytest -v
```
Covers: valid/invalid password, correct/wrong OTP, dashboard blocked before 2FA, repeated
failures + lockout, rate limiting, logout, protected pages, no plain-text passwords or secrets.

## Project layout
```
app.py              Flask application
templates/          Bootstrap pages
tests/test_app.py   Security tests
requirements.txt
```

## Scope
Built as an academic demonstration. It is not a complete enterprise identity-management system
(no password reset, email verification, or recovery codes).
