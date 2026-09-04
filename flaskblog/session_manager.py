# -*- coding: utf-8 -*-
"""
session_manager.py
Secure Session Management (requirement #11) — fully self-issued.

Instead of relying on Flask-Login's default behavior (which stores the
user id in Flask's built-in session cookie, signed via itsdangerous under
the hood), authentication here works like this:

  1. On successful login, we generate a random 32-byte session_id, record
     it server-side in the UserSession table (bound to the user, a client
     fingerprint, and an expiry), and send the browser a cookie containing
     "<session_id>.<hmac_signature>" — signed with OUR OWN hmac_custom
     module, not itsdangerous.
  2. On every request, Flask-Login calls load_user_from_request() (a
     "request_loader", registered in __init__.py) instead of reading its
     own session key. We verify the cookie's signature ourselves, look up
     the session row, check it hasn't expired/been revoked, and check the
     current request's fingerprint (IP + User-Agent) still matches the one
     recorded at login — if it doesn't, we treat it as a possible hijack,
     kill the session server-side, and the user is logged out.
  3. Logout / account deletion destroys the server-side row immediately —
     the session is dead even if someone has a copy of the old cookie.

Flask's `session` object (and its itsdangerous signing) is still used
elsewhere in the app ONLY for short-lived, low-value pre-authentication
UI state (e.g. staging a 2FA code between the password step and the OTP
step) and for one-time flash() messages — never for the authentication
token itself, which is what requirement #11 is actually protecting.
"""

import secrets as _secrets
from datetime import datetime, timedelta
from flask import request, current_app, flash
from flaskblog import db, hmac_custom

COOKIE_NAME = 'vd_auth'
SHORT_LIFETIME_SECONDS = 2 * 60 * 60        # 2 hours, normal login
LONG_LIFETIME_SECONDS = 7 * 24 * 60 * 60    # 7 days, "remember me"


# ---------- low-level helpers ----------

def _secret() -> bytes:
    return current_app.config['SECRET_KEY'].encode('utf-8')


def _get_client_ip() -> str:
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'


def _get_user_agent() -> str:
    return request.headers.get('User-Agent', 'Unknown-Agent')


def compute_fingerprint(user_id: int) -> str:
    """HMAC-bind a session to the client's IP + User-Agent at issue time."""
    payload = f"UID:{user_id}|IP:{_get_client_ip()}|UA:{_get_user_agent()}".encode('utf-8')
    return hmac_custom.hmac_sha256_hex(_secret(), payload)


def _sign(session_id: str) -> str:
    return hmac_custom.hmac_sha256_hex(_secret(), session_id.encode('utf-8'))


def _build_cookie_value(session_id: str) -> str:
    return f"{session_id}.{_sign(session_id)}"


def _parse_cookie_value(cookie_value: str):
    """Verify the cookie's HMAC signature. Returns session_id, or None if invalid/tampered."""
    try:
        session_id, signature = cookie_value.rsplit('.', 1)
    except (ValueError, AttributeError):
        return None

    if not hmac_custom.verify_hmac(_secret(), session_id.encode('utf-8'), bytes.fromhex(signature)):
        return None  # tampered or forged cookie
    return session_id


# ---------- session lifecycle ----------

def create_session(user, remember: bool = False):
    """
    Called after successful authentication (password + 2FA if enabled).
    Creates a server-side session row and returns (cookie_value, max_age_seconds)
    for the caller to attach to the response with resp.set_cookie(...).
    """
    from flaskblog.models import UserSession

    session_id = _secrets.token_hex(32)
    fingerprint = compute_fingerprint(user.id)
    lifetime = LONG_LIFETIME_SECONDS if remember else SHORT_LIFETIME_SECONDS
    expires_at = datetime.utcnow() + timedelta(seconds=lifetime)

    row = UserSession()
    row.session_id = session_id
    row.user_id = user.id
    row.fingerprint = fingerprint
    row.expires_at = expires_at
    db.session.add(row)
    db.session.commit()

    return _build_cookie_value(session_id), lifetime


def _get_session_row_from_request():
    """Read + verify the request's cookie, return the matching UserSession row, or None."""
    from flaskblog.models import UserSession

    cookie_value = request.cookies.get(COOKIE_NAME)
    if not cookie_value:
        return None

    session_id = _parse_cookie_value(cookie_value)
    if not session_id:
        return None

    row = UserSession.query.filter_by(session_id=session_id).first()
    if not row or not row.is_valid():
        return None
    return row


def load_user_from_request(req):
    """
    Registered as Flask-Login's request_loader (see __init__.py). Called on
    every request in place of Flask-Login's default session-based lookup.
    """
    from flaskblog.models import User

    row = _get_session_row_from_request()
    if not row:
        return None

    current_fp = compute_fingerprint(row.user_id)
    if current_fp != row.fingerprint:
        # Client environment changed since login — possible session hijack.
        row.revoked = True
        db.session.commit()
        flash('Security Notice: Session invalidated due to client environment change (anti-hijacking protection).', 'warning')
        return None

    return User.query.get(row.user_id)


def destroy_session_from_request():
    """Revoke the server-side session tied to the current request's cookie (logout)."""
    row = _get_session_row_from_request()
    if row:
        row.revoked = True
        db.session.commit()
