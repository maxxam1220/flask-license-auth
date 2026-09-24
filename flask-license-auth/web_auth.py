"""Website-only authentication; desktop/API credentials remain independent."""
from datetime import datetime, timedelta, timezone
import hmac
import math

from flask import flash, get_flashed_messages, redirect, render_template, request, session
from itsdangerous import BadData, URLSafeTimedSerializer
from psycopg2.extras import Json, RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash

from security import csrf_token, valid_csrf_token


SESSION_MAX_AGE = 8 * 60 * 60
REMEMBER_MAX_AGE = 30 * 24 * 60 * 60
REMEMBER_COOKIE_NAME = "web_admin_username"
MAX_FAILURES = 5
LOCK_SECONDS = 5 * 60
MAX_PASSWORD_LENGTH = 128
PROTECTED_ENDPOINTS = frozenset({"admin", "audit_list", "audit_export_csv", "audit_prune", "change_password"})
WEB_ENDPOINTS = PROTECTED_ENDPOINTS | {"login", "logout"}


def _utcnow():
    return datetime.now(timezone.utc)


def _secure_equal(left, right):
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _password_matches(password, stored_hash, initial_password):
    if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH:
        return False
    if stored_hash is not None:
        # A configured hash is authoritative even if corrupt: never try the old env password.
        try:
            return check_password_hash(stored_hash, password)
        except (TypeError, ValueError):
            return False
    return bool(initial_password and _secure_equal(password, initial_password))


def _retry_after(row, now):
    until = row.get("locked_until")
    if until is None:
        return 0
    if not isinstance(until, datetime):
        raise ValueError("Invalid web authentication lock timestamp")
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    return max(0, math.ceil((until - now).total_seconds()))


def _version(value):
    if type(value) is not int or value < 1:
        raise ValueError("Invalid web authentication version")
    return value


def register_web_auth(app, get_db, admin_username, initial_password):
    """Register website routes without adding authentication to application APIs."""
    serializer = URLSafeTimedSerializer(app.secret_key, salt="web-admin-remember-username")

    def remembered_username():
        cookie = request.cookies.get(REMEMBER_COOKIE_NAME)
        if not cookie:
            return "", False
        try:
            username = serializer.loads(cookie, max_age=REMEMBER_MAX_AGE)
            if not isinstance(username, str) or not username or len(username) > 128:
                raise ValueError("Invalid remembered username")
            return username, False
        except (BadData, TypeError, ValueError):
            # This optional preference never authenticates a request.
            return "", True

    def render_form(template, *, error="", status=200, retry_after=0):
        remembered, invalid_cookie = remembered_username()
        username = (request.form.get("username", "")[:128] if request.method == "POST" and template == "login.html"
                    else remembered if template == "login.html" else admin_username)
        remember = (request.form.get("remember_username") in ("1", "on", "true", "yes")
                    if request.method == "POST" and template == "login.html" else bool(remembered))
        context = {
            "username": username, "remember_username": remember,
            "error": error, "message": "\n".join(get_flashed_messages()),
            "retry_after": retry_after, "csrf_token": csrf_token,
        }
        response = app.make_response((render_template(template, **context), status))
        if retry_after:
            response.headers["Retry-After"] = str(retry_after)
        if invalid_cookie:
            response.delete_cookie(REMEMBER_COOKIE_NAME, secure=True, httponly=True, samesite="Lax")
        return response

    def invalidate_session(message="登入已失效，請重新登入。"):
        session.clear()
        flash(message)
        return redirect("/login")

    def read_locked_auth(cursor, *, ensure_row):
        if ensure_row:
            cursor.execute("INSERT INTO web_admin_auth (username) VALUES (%s) ON CONFLICT (username) DO NOTHING",
                           (admin_username,))
        cursor.execute("""
            SELECT username, password_hash, session_version, failed_attempts, locked_until
            FROM web_admin_auth WHERE username = %s FOR UPDATE
        """, (admin_username,))
        row = cursor.fetchone()
        if row is None:
            raise ValueError("Website administrator record is unavailable")
        _version(row.get("session_version"))
        return row

    def audit(cursor, username, action, note, reason):
        cursor.execute("""
            INSERT INTO audit_login (event_time, username, action, note, source, public_ip, extra)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (_utcnow(), username[:128] or "(未提供)", action, note, "web_admin",
              request.remote_addr, Json({"reason": reason})))

    def record_failure(cursor, row, now, username, action):
        # One shared row makes the limit consistent across workers and unknown
        # usernames. The tradeoff is a temporary account-wide denial of login.
        previous = 0 if row.get("locked_until") is not None else row.get("failed_attempts", 0)
        if type(previous) is not int or previous < 0:
            raise ValueError("Invalid web authentication failure count")
        failures = previous + 1
        locked_until = now + timedelta(seconds=LOCK_SECONDS) if failures >= MAX_FAILURES else None
        cursor.execute("""
            UPDATE web_admin_auth SET failed_attempts = %s, locked_until = %s, updated_at = %s
            WHERE username = %s
        """, (failures, locked_until, now, admin_username))
        audit(cursor, username, action, "網站管理驗證失敗。", "invalid_credentials")
        return LOCK_SECONDS if locked_until else 0

    @app.before_request
    def validate_web_session():
        if request.endpoint not in PROTECTED_ENDPOINTS:
            return None
        issued_at = session.get("issued_at")
        auth_version = session.get("auth_version")
        if (session.get("logged_in") is not True or session.get("admin_user") != admin_username
                or type(issued_at) is not int or type(auth_version) is not int or auth_version < 1
                or not 0 <= _utcnow().timestamp() - issued_at < SESSION_MAX_AGE):
            return invalidate_session()
        if request.endpoint == "change_password" and request.method == "POST" and not valid_csrf_token():
            return render_form("change_password.html", error="表單已失效，請重新整理後再試。", status=400)
        try:
            with get_db() as connection:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute("SELECT session_version FROM web_admin_auth WHERE username = %s", (admin_username,))
                    row = cursor.fetchone()
            if row is None or _version(row.get("session_version")) != auth_version:
                return invalidate_session()
        except Exception:
            app.logger.exception("Website session verification failed")
            session.clear()
            return render_form("login.html", error="暫時無法驗證登入狀態，請稍後重新登入。", status=503)
        return None

    def login():
        if request.method == "GET":
            return render_form("login.html")
        if not valid_csrf_token():
            return render_form("login.html", error="表單已失效，請重新整理後再試。", status=400)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password or len(username) > 128 or len(password) > MAX_PASSWORD_LENGTH:
            return render_form("login.html", error="請填寫帳號與密碼；每個欄位不可超過 128 個字元。", status=400)
        status, retry, authenticated_version = 401, 0, None
        error = "帳號或密碼不正確。"
        try:
            with get_db() as connection:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    row = read_locked_auth(cursor, ensure_row=True)
                    now = _utcnow()
                    retry = _retry_after(row, now)
                    if retry:
                        status, error = 429, "登入嘗試過多，請稍後再試。"
                        audit(cursor, username, "login_fail", "網站管理登入暫時鎖定。", "locked")
                    elif row.get("password_hash") is None and not initial_password:
                        status, error = 503, "網站管理登入尚未完成設定，請聯絡管理人員。"
                    else:
                        password_ok = _password_matches(password, row.get("password_hash"), initial_password)
                        username_ok = len(username) <= 128 and _secure_equal(username, admin_username)
                        if username_ok and password_ok:
                            cursor.execute("""
                                UPDATE web_admin_auth SET failed_attempts = 0, locked_until = NULL, updated_at = %s
                                WHERE username = %s
                            """, (now, admin_username))
                            audit(cursor, admin_username, "login_success", "網站管理登入成功。", "authenticated")
                            authenticated_version = row["session_version"]
                        else:
                            retry = record_failure(cursor, row, now, username, "login_fail")
                            if retry:
                                status, error = 429, "登入嘗試過多，請稍後再試。"
        except Exception:
            app.logger.exception("Website login transaction failed")
            return render_form("login.html", error="暫時無法登入，請稍後再試。", status=503)
        if authenticated_version is None:
            return render_form("login.html", error=error, status=status, retry_after=retry)
        session.clear()
        session.update(logged_in=True, admin_user=admin_username, auth_version=authenticated_version,
                       issued_at=int(_utcnow().timestamp()))
        response = redirect("/admin")
        if request.form.get("remember_username") in ("1", "on", "true", "yes"):
            response.set_cookie(REMEMBER_COOKIE_NAME, serializer.dumps(admin_username), max_age=REMEMBER_MAX_AGE,
                                secure=True, httponly=True, samesite="Lax")
        else:
            response.delete_cookie(REMEMBER_COOKIE_NAME, secure=True, httponly=True, samesite="Lax")
        return response

    def logout():
        if request.method == "GET":
            if not session.get("logged_in"):
                return redirect("/login")
            return render_form("logout.html")
        if not valid_csrf_token():
            return render_form("logout.html", error="表單已失效，請重新整理後再試。", status=400)
        session.clear()
        flash("已登出。")
        return redirect("/login")

    def change_password():
        if request.method == "GET":
            return render_form("change_password.html")
        if not valid_csrf_token():
            return render_form("change_password.html", error="表單已失效，請重新整理後再試。", status=400)
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirmation = request.form.get("confirm_password", "")
        if not 15 <= len(new_password) <= MAX_PASSWORD_LENGTH:
            return render_form("change_password.html", error="新密碼須為 15～128 個字元，可使用空白與 Unicode 字元。", status=400)
        if not new_password.strip():
            return render_form("change_password.html", error="新密碼不可全部都是空白字元。", status=400)
        if len(current_password) > MAX_PASSWORD_LENGTH or len(confirmation) > MAX_PASSWORD_LENGTH:
            return render_form("change_password.html", error="密碼不可超過 128 個字元。", status=400)
        if not _secure_equal(new_password, confirmation):
            return render_form("change_password.html", error="兩次輸入的新密碼不一致。", status=400)
        if _secure_equal(current_password, new_password):
            return render_form("change_password.html", error="新密碼不可與目前密碼相同。", status=400)

        changed, version_changed, retry, status = False, False, 0, 401
        error = "目前密碼不正確。"
        try:
            # The expensive new hash is computed outside the lock. The current
            # credential and session version are checked again under the row lock.
            new_hash = generate_password_hash(new_password, method="scrypt")
            with get_db() as connection:
                with connection.cursor(cursor_factory=RealDictCursor) as cursor:
                    row = read_locked_auth(cursor, ensure_row=False)
                    now = _utcnow()
                    if row["session_version"] != session["auth_version"]:
                        version_changed = True
                    else:
                        retry = _retry_after(row, now)
                        if retry:
                            status, error = 429, "驗證嘗試過多，請稍後再試。"
                            audit(cursor, admin_username, "password_change_fail", "網站管理密碼修改暫時鎖定。", "locked")
                        elif not _password_matches(current_password, row.get("password_hash"), initial_password):
                            retry = record_failure(cursor, row, now, admin_username, "password_change_fail")
                            if retry:
                                status, error = 429, "驗證嘗試過多，請稍後再試。"
                        else:
                            cursor.execute("""
                                UPDATE web_admin_auth SET password_hash = %s,
                                    session_version = session_version + 1,
                                    failed_attempts = 0, locked_until = NULL, updated_at = %s
                                WHERE username = %s AND session_version = %s
                            """, (new_hash, now, admin_username, row["session_version"]))
                            if cursor.rowcount != 1:
                                raise ValueError("Website password version changed during update")
                            audit(cursor, admin_username, "password_change", "網站管理密碼已修改，所有舊登入均已失效。", "password_changed")
                            changed = True
        except Exception:
            app.logger.exception("Website password change transaction failed")
            return render_form("change_password.html", error="暫時無法修改密碼，變更未儲存，請稍後再試。", status=503)
        if version_changed:
            session.clear()
            return render_form("login.html", error="登入狀態已變更，請重新登入後再修改密碼。", status=409)
        if not changed:
            return render_form("change_password.html", error=error, status=status, retry_after=retry)
        session.clear()
        flash("密碼已修改，所有舊登入均已失效，請使用新密碼重新登入。")
        return redirect("/login")

    app.add_url_rule("/login", endpoint="login", view_func=login, methods=["GET", "POST"])
    app.add_url_rule("/logout", endpoint="logout", view_func=logout, methods=["GET", "POST"])
    app.add_url_rule("/account/password", endpoint="change_password", view_func=change_password, methods=["GET", "POST"])

    @app.after_request
    def web_auth_headers(response):
        if request.endpoint in WEB_ENDPOINTS:
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "same-origin"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            )
        return response
