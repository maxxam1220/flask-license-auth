"""Separate scan access from management access; enforce it on the server."""
import hashlib
import hmac
import secrets
import threading
import time

from flask import abort, jsonify, request, session


class AccessControl:
    def __init__(self, app):
        self.app = app
        self.attempts = {}
        self.grants = {}
        self.lock = threading.Lock()

    def configured(self):
        value = self.app.config.get("ADMIN_PASSWORD", "")
        ordinary = self.app.config.get("APP_PASSWORD", "")
        return isinstance(value, str) and 8 <= len(value) <= 256 and value != ordinary

    def local_mode(self):
        # The existing no-password workflow is restricted to loopback in protect().
        return not self.app.config["APP_PASSWORD"] and request.remote_addr in {"127.0.0.1", "::1"}

    def authenticated(self):
        return self.local_mode() or bool(session.get("authenticated"))

    def admin_tag(self):
        secret = self.app.secret_key
        if isinstance(secret, str):
            secret = secret.encode()
        return hmac.new(secret, self.app.config.get("ADMIN_PASSWORD", "").encode(), hashlib.sha256).hexdigest()

    def is_admin(self):
        if self.local_mode():
            return True
        tag = session.get("admin_tag", "")
        with self.lock:
            valid_grant = self.grants.get(session.get("admin_grant", ""), 0) > time.monotonic()
        return (self.authenticated() and self.configured() and session.get("role") == "admin"
                and valid_grant and isinstance(tag, str) and secrets.compare_digest(tag, self.admin_tag()))

    def revoke(self):
        with self.lock:
            self.grants.pop(session.get("admin_grant", ""), None)
        session.pop("admin_grant", None)
        session.pop("admin_tag", None)

    def grant(self):
        self.revoke()
        now = time.monotonic()
        identifier = secrets.token_urlsafe(32)
        with self.lock:
            self.grants = {key:expiry for key, expiry in self.grants.items() if expiry > now}
            if len(self.grants) >= 4096:
                abort(503, description="管理員登入工作階段較多，請稍後再試。")
            self.grants[identifier] = now + self.app.permanent_session_lifetime.total_seconds()
        session.update(role="admin", admin_tag=self.admin_tag(), admin_grant=identifier)

    def require_admin(self):
        if not self.authenticated():
            abort(401, description="請先登入。")
        if not self.is_admin():
            response = jsonify(error="此功能需要管理員權限，請輸入管理碼解鎖。", code="admin_required")
            response.status_code = 403
            abort(response)

    def payload(self):
        session.setdefault("csrf", secrets.token_urlsafe(32))
        authenticated, admin = self.authenticated(), self.is_admin()
        return dict(csrf=session["csrf"], requires_login=bool(self.app.config["APP_PASSWORD"]),
                    authenticated=authenticated, is_admin=admin,
                    role="admin" if admin else "operator" if authenticated else "anonymous",
                    admin_configured=self.configured() or self.local_mode(),
                    permissions={"manage_standards":admin, "cleanup_history":admin})

    def password(self):
        body = request.get_json(silent=True)
        value = body.get("password", "") if isinstance(body, dict) else None
        if not isinstance(value, str) or len(value) > 256:
            return None
        return value

    def matches(self, value, expected):
        return isinstance(value, str) and secrets.compare_digest(value.encode(), expected.encode())

    def check_attempts(self):
        now = time.monotonic()
        addr = request.remote_addr or "unknown"
        with self.lock:
            # Login and privilege elevation share the same failed-attempt budget.
            self.attempts = {key:[t for t in values if now-t < 300]
                             for key, values in self.attempts.items() if values and now-values[-1] < 300}
            recent = self.attempts.get(addr, [])
            if len(recent) >= 10 or len(self.attempts) >= 4096 and addr not in self.attempts:
                abort(429, description="嘗試次數過多，請 5 分鐘後再試。")
            # Reserve an attempt while comparing. Successful attempts remove only
            # their own reservation so they cannot reset a parallel attack.
            recent.append(now)
            self.attempts[addr] = recent
        return addr, now

    def success(self, attempt):
        addr, stamp = attempt
        with self.lock:
            if stamp in self.attempts.get(addr, []):
                self.attempts[addr].remove(stamp)

    def login(self):
        attempt, value = self.check_attempts(), self.password()
        admin = self.configured() and self.matches(value, self.app.config["ADMIN_PASSWORD"])
        ordinary = self.matches(value, self.app.config["APP_PASSWORD"])
        if not (admin or ordinary):
            abort(401, description="登入密碼或管理碼不正確。")
        self.success(attempt)
        self.revoke()
        session.clear()
        session.update(authenticated=True, role="admin" if admin else "operator", csrf=secrets.token_urlsafe(32))
        if admin:
            self.grant()
        session.permanent = True
        return jsonify(self.payload())

    def unlock(self):
        if not self.authenticated():
            abort(401, description="請先登入。")
        if not self.configured():
            abort(503, description="管理碼尚未正確設定，請在 Render 設定至少 8 字元且不同於登入密碼的 LABELCHECK_ADMIN_PASSWORD。")
        attempt, value = self.check_attempts(), self.password()
        if not self.matches(value, self.app.config["ADMIN_PASSWORD"]):
            abort(403, description="管理碼不正確。")
        self.success(attempt)
        self.grant()
        session.update(authenticated=True, csrf=secrets.token_urlsafe(32))
        session.permanent = True
        return jsonify(self.payload())

    def lock_admin(self):
        if not self.authenticated():
            abort(401, description="請先登入。")
        self.revoke()
        session.update(role="operator", csrf=secrets.token_urlsafe(32))
        return jsonify(self.payload())
