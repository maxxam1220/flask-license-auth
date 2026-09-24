"""Management credentials are deployment secrets, never client-wide defaults."""
from functools import wraps
import hashlib
import hmac
import os
import secrets

from flask import current_app, jsonify, request, session


MANAGEMENT_KEYS = ("ADMIN_API_KEY", "BACKUP_READ_API_KEY", "BACKUP_RESTORE_API_KEY")
# Fingerprint of the retired public token; the credential itself is not retained.
REVOKED_KEY_SHA256 = "3111d93682b4e200d201dc7d5571c67b34b2d83f4825e9725d533f847fe94ddb"


def configure_security(app):
    secret = os.environ.get("FLASK_SECRET_KEY", "")
    if len(secret) < 32 or secret == "dev-only-change-me":
        raise RuntimeError("FLASK_SECRET_KEY must be a private random value of at least 32 characters")
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    configured = []
    for name in MANAGEMENT_KEYS:
        value = os.environ.get(name, "").strip()
        if value and (len(value) < 32 or hashlib.sha256(value.encode()).hexdigest() == REVOKED_KEY_SHA256):
            raise RuntimeError(f"{name} must be a new random value of at least 32 characters")
        if value:
            if value in configured or value == os.environ.get("SESSIONS_API_KEY"):
                raise RuntimeError("Management, backup and client session keys must be distinct")
            configured.append(value)
        app.config[name] = value


def require_api_key(config_name):
    """Fail closed; accept the existing Bearer transport or X-API-KEY."""
    expected = current_app.config.get(config_name, "")
    if not expected:
        return jsonify(ok=False, error="AUTH_NOT_CONFIGURED", message="此功能尚未設定驗證金鑰"), 503
    authorization = request.headers.get("Authorization", "")
    if authorization:
        parts = authorization.split()
        supplied = parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else ""
    else:
        supplied = request.headers.get("X-API-KEY", "")
    if not supplied or not hmac.compare_digest(supplied.encode(), expected.encode()):
        return jsonify(ok=False, error="unauthorized", message="需要有效的管理權限"), 401
    return None


def api_key_required(config_name):
    def decorate(view):
        @wraps(view)
        def guarded(*args, **kwargs):
            denied = require_api_key(config_name)
            if denied is not None:
                return denied
            return view(*args, **kwargs)
        return guarded
    return decorate


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def valid_csrf_token():
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "")
    return bool(expected and supplied and hmac.compare_digest(expected.encode(), supplied.encode()))
