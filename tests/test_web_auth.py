"""Offline website-auth regressions; all credentials and DB state are synthetic."""
import base64
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
import zlib

from flask import Flask, jsonify, session, template_rendered
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "flask-license-auth"))
import web_auth
from security import csrf_token

USER = "offline-admin"
INITIAL_PASSWORD = "Initial-offline-password-2026!"
NEW_PASSWORD = "Changed-offline-password-2026!"
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)


class AuthDatabase:
    """Transactional in-memory state; records row locks without claiming PG concurrency."""
    def __init__(self, username=USER, initialized=False):
        self.username = username
        self.state = self.initial_state() if initialized else None
        self.calls, self.transactions, self.audits = [], [], []
        self.fail_open = self.fail_audit = False
        self.used_preview_hashes = set()
        self.before_lock = None

    def initial_state(self):
        return dict(username=self.username, password_hash=None, session_version=1,
                    failed_attempts=0, locked_until=None)

    @contextmanager
    def __call__(self):
        if self.fail_open:
            raise RuntimeError("offline database unavailable")
        before = deepcopy((self.state, self.audits, self.used_preview_hashes))
        transaction = dict(calls=[], committed=False, rolled_back=False)
        self.transactions.append(transaction)
        database = self

        class Cursor:
            rowcount = 2

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql, params=None):
                self.sql = " ".join(str(sql).split())
                self.params = tuple(params or ())
                call = (self.sql, self.params)
                database.calls.append(call)
                transaction["calls"].append(call)
                upper = self.sql.upper()
                if "FROM WEB_ADMIN_AUTH" in upper and "FOR UPDATE" in upper and database.before_lock:
                    callback, database.before_lock = database.before_lock, None
                    callback(database.state)
                if upper.startswith("INSERT INTO WEB_ADMIN_AUTH"):
                    if database.state is None:
                        database.state = database.initial_state()
                elif upper.startswith("UPDATE WEB_ADMIN_AUTH"):
                    self.rowcount = 1
                    assignments = re.split(r"\bWHERE\b", re.split(r"\bSET\b", self.sql, flags=re.I)[1], flags=re.I)[0]
                    index = 0
                    for assignment in assignments.split(","):
                        column, expression = assignment.strip().split("=", 1)
                        column, expression = column.strip(), expression.strip()
                        if expression == "%s":
                            value = self.params[index]
                            index += 1
                        elif expression.upper() == "NULL":
                            value = None
                        elif expression == "0":
                            value = 0
                        elif re.fullmatch(r"[a-z_]+\s*\+\s*1", expression):
                            value = database.state[column] + 1
                        else:
                            index += expression.count("%s")
                            continue
                        database.state[column] = value
                elif upper.startswith("INSERT INTO AUDIT_LOGIN"):
                    if database.fail_audit:
                        raise RuntimeError("offline audit insert failed")
                    database.audits.append(self.params)
                    for value in self.params:
                        extra = getattr(value, "adapted", {})
                        if isinstance(extra, dict) and extra.get("preview_hash"):
                            database.used_preview_hashes.add(extra["preview_hash"])

            def fetchone(self):
                if "FROM web_admin_auth" in self.sql:
                    return deepcopy(database.state)
                if "MAX(" in self.sql.upper():
                    return {"count": 2, "max_id": 44}
                if "preview_hash" in self.sql:
                    return {"used": 1} if self.params[0] in database.used_preview_hashes else None
                return None

            def fetchall(self):
                return []

        class Connection:
            def cursor(self, **kwargs):
                return Cursor()

        try:
            yield Connection()
        except Exception:
            self.state, self.audits, self.used_preview_hashes = before
            transaction["rolled_back"] = True
            raise
        else:
            transaction["committed"] = True

    def clear_calls(self):
        self.calls.clear()
        self.transactions.clear()


def seed_authenticated(client, username=USER, version=1, issued_at=None):
    with client.session_transaction() as state:
        state.clear()
        state.update(logged_in=True, admin_user=username, auth_version=version,
                     issued_at=int((issued_at or datetime.now(timezone.utc)).timestamp()),
                     csrf_token="offline-csrf")


class WebAuthTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.create_connection", "socket.socket.connect", "socket.getaddrinfo", "psycopg2.connect"):
            self.enterContext(patch(target, side_effect=AssertionError("External access prohibited")))
        self.enterContext(patch.object(web_auth, "_utcnow", return_value=NOW))
        self.db = AuthDatabase()
        self.app = self.make_app()
        self.client = self.app.test_client()
        self.contexts = []

        def capture(sender, template, context, **kwargs):
            self.contexts.append(context)

        template_rendered.connect(capture, self.app, weak=False)
        self.addCleanup(template_rendered.disconnect, capture, self.app)

    def make_app(self, initial_password=INITIAL_PASSWORD):
        app = Flask(__name__, template_folder=str(ROOT / "flask-license-auth" / "templates"))
        app.config.update(TESTING=True, SECRET_KEY="offline-web-auth-session-" + "s" * 32,
                          SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
        app.jinja_env.globals["csrf_token"] = csrf_token
        app.add_url_rule("/admin", "admin", lambda: "protected admin")
        app.add_url_rule("/audit", "audit_list", lambda: "protected audit")
        for endpoint, path in (("public_api", "/api/ping"), ("check_license", "/check_license")):
            app.add_url_rule(path, endpoint, lambda: jsonify(ok=True), methods=["GET", "POST"])
        web_auth.register_web_auth(app, self.db, USER, initial_password)
        return app

    def token(self, client=None):
        client = client or self.client
        with client.session_transaction() as state:
            if "csrf_token" not in state:
                state["csrf_token"] = "offline-csrf"
            return state["csrf_token"]

    def login(self, client=None, username=USER, password=INITIAL_PASSWORD, remember=False):
        client = client or self.client
        data = dict(username=username, password=password, csrf_token=self.token(client))
        if remember:
            data["remember_username"] = "on"
        return client.post("/login", data=data)

    def change(self, **overrides):
        data = dict(current_password=INITIAL_PASSWORD, new_password=NEW_PASSWORD,
                    confirm_password=NEW_PASSWORD, csrf_token=self.token())
        data.update(overrides)
        return self.client.post("/account/password", data=data)

    def test_initial_environment_login_rotates_session_and_uses_locked_shared_state(self):
        with self.client.session_transaction() as state:
            state["untrusted_old_session_value"] = "old"
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/admin")
        with self.client.session_transaction() as state:
            self.assertTrue(state["logged_in"])
            self.assertEqual((state["admin_user"], state["auth_version"], state["issued_at"]), (USER, 1, int(NOW.timestamp())))
            self.assertNotIn("untrusted_old_session_value", state)
            self.assertNotIn(INITIAL_PASSWORD, json.dumps(dict(state)))
        self.assertTrue(any("FOR UPDATE" in sql for sql, _ in self.db.calls))
        self.assertTrue(self.db.transactions[-1]["committed"])
        self.assertEqual(self.client.get("/admin").status_code, 200)

    def test_login_get_is_database_free_and_has_secure_headers_and_empty_password(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.db.calls, [])
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertTrue(response.headers.get("X-Frame-Options") or "frame-ancestors" in response.headers.get("Content-Security-Policy", ""))
        for flag in ("Secure", "HttpOnly", "SameSite=Lax"):
            self.assertIn(flag, response.headers.get("Set-Cookie", ""))
        self.assertIn('name="password"', response.get_data(as_text=True))
        self.assertNotIn(INITIAL_PASSWORD, response.get_data(as_text=True))

    def test_login_csrf_missing_fields_and_unicode_fail_without_exposing_passwords(self):
        for data in ({"username": USER, "password": INITIAL_PASSWORD},
                     {"username": USER, "password": INITIAL_PASSWORD, "csrf_token": "wrong"},
                     {"username": USER, "csrf_token": self.token()},
                     {"password": INITIAL_PASSWORD, "csrf_token": self.token()}):
            self.assertEqual(self.client.post("/login", data=data).status_code, 400)
        self.assertEqual(self.db.calls, [])
        password = '不可回顯的密碼<script>alert("offline")</script>'
        response = self.login(username='陌生帳號<script>alert("offline")</script>', password=password)
        self.assertEqual(response.status_code, 401)
        html = response.get_data(as_text=True)
        self.assertNotIn(password, html)
        self.assertNotIn('<script>alert("offline")</script>', html)
        self.assertNotIn("password", self.contexts[-1])
        self.assertFalse(any(password in repr(parameters) for _, parameters in self.db.calls))

    def test_remember_username_cookie_is_signed_username_only_and_uncheck_removes_it(self):
        self.assertEqual(self.login(remember=True).status_code, 302)
        cookie = self.client.get_cookie("web_admin_username")
        self.assertIsNotNone(cookie)
        self.assertTrue(cookie.secure)
        self.assertTrue(cookie.http_only)
        self.assertEqual(cookie.same_site, "Lax")
        encoded = cookie.value.split(".")[1 if cookie.value.startswith(".") else 0]
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if cookie.value.startswith("."):
            decoded = zlib.decompress(decoded)
        value = json.loads(decoded)
        self.assertIn(value, (USER, {"username": USER}))
        self.client.post("/logout", data={"csrf_token": self.token()})
        self.client.get("/login")
        self.assertEqual(self.contexts[-1]["username"], USER)
        self.assertTrue(self.contexts[-1]["remember_username"])
        self.assertEqual(self.login(remember=False).status_code, 302)
        self.assertIsNone(self.client.get_cookie("web_admin_username"))

    def test_tampered_remember_cookie_is_ignored(self):
        self.client.set_cookie("web_admin_username", "<script>malicious</script>.invalid")
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.contexts[-1]["username"], "")
        self.assertNotIn("<script>malicious</script>", response.get_data(as_text=True))
        self.assertEqual(self.db.calls, [])

    def test_failure_limit_is_shared_across_clients_and_unknown_usernames(self):
        other = self.app.test_client()
        for attempt in range(5):
            response = self.login(client=self.client if attempt % 2 else other,
                                  username=USER if attempt % 2 else "unknown-user", password="wrong-password")
            self.assertEqual(response.status_code, 429 if attempt == 4 else 401)
            self.assertTrue(self.db.transactions[-1]["committed"])
            self.assertTrue(any("FOR UPDATE" in sql for sql, _ in self.db.transactions[-1]["calls"]))
        self.assertEqual(self.db.state["failed_attempts"], 5)
        self.assertEqual(self.db.state["locked_until"], NOW + timedelta(seconds=300))
        self.assertEqual(self.login(password=INITIAL_PASSWORD).status_code, 429)
        with patch.object(web_auth, "_utcnow", return_value=NOW + timedelta(seconds=301)):
            self.assertEqual(self.login(password=INITIAL_PASSWORD).status_code, 302)
        self.assertEqual(self.db.state["failed_attempts"], 0)
        self.assertIsNone(self.db.state["locked_until"])

    def test_change_password_commits_hash_and_version_together_and_invalidates_sessions(self):
        other = self.app.test_client()
        self.assertEqual(self.login(remember=True).status_code, 302)
        self.assertEqual(self.login(client=other).status_code, 302)
        self.db.clear_calls()
        spaced_password = "  " + NEW_PASSWORD + "  "
        response = self.change(new_password=spaced_password, confirm_password=spaced_password)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertEqual(self.db.state["session_version"], 2)
        self.assertNotEqual(self.db.state["password_hash"], spaced_password)
        self.assertTrue(check_password_hash(self.db.state["password_hash"], spaced_password))
        self.assertFalse(check_password_hash(self.db.state["password_hash"], spaced_password.strip()))
        mutation = [transaction for transaction in self.db.transactions
                    if any("password_hash" in sql and sql.startswith("UPDATE") for sql, _ in transaction["calls"])]
        self.assertEqual(len(mutation), 1)
        self.assertTrue(mutation[0]["committed"])
        self.assertTrue(any("FOR UPDATE" in sql for sql, _ in mutation[0]["calls"]))
        self.assertTrue(any("password_change" in params for _, params in mutation[0]["calls"]))
        with self.client.session_transaction() as state:
            self.assertFalse(state.get("logged_in", False))
        self.assertEqual(other.get("/admin").status_code, 302)
        self.assertEqual(self.login(password=INITIAL_PASSWORD).status_code, 401)
        self.assertEqual(self.login(password=spaced_password).status_code, 302)

    def test_persisted_hash_works_without_initial_environment_password_and_never_falls_back(self):
        self.db.state = self.db.initial_state()
        self.db.state["password_hash"] = generate_password_hash(NEW_PASSWORD)
        self.db.state["session_version"] = 2
        app = self.make_app(initial_password="")
        client = app.test_client()
        self.assertEqual(self.login(client=client, password=NEW_PASSWORD).status_code, 302)
        self.assertEqual(self.login(password=INITIAL_PASSWORD).status_code, 401)
        self.db.state["password_hash"] = "unsupported:corrupt-hash"
        self.assertEqual(self.login(password=INITIAL_PASSWORD).status_code, 401)
        self.db.state["password_hash"] = ""
        self.assertEqual(self.login(password=INITIAL_PASSWORD).status_code, 401)

    def test_wrong_current_password_weak_password_and_confirmation_mismatch_do_not_change_credentials(self):
        self.assertEqual(self.login().status_code, 302)
        original_hash, original_version = self.db.state["password_hash"], self.db.state["session_version"]
        for changes, expected in (({"current_password": "錯誤目前密碼"}, 401),
                                  ({"new_password": "short", "confirm_password": "short"}, 400),
                                  ({"new_password": " " * 15, "confirm_password": " " * 15}, 400),
                                  ({"confirm_password": "different-password"}, 400)):
            with self.subTest(fields=list(changes)):
                self.assertEqual(self.change(**changes).status_code, expected)
                self.assertEqual((self.db.state["password_hash"], self.db.state["session_version"]), (original_hash, original_version))
        self.assertFalse(any("password_change" in audit for audit in self.db.audits))

    def test_change_password_invalid_csrf_stops_before_database(self):
        self.assertEqual(self.login().status_code, 302)
        self.db.clear_calls()
        self.assertEqual(self.change(csrf_token="wrong").status_code, 400)
        self.assertEqual(self.db.calls, [])

    def test_legacy_expired_and_future_sessions_are_rejected(self):
        self.db.state = self.db.initial_state()
        for state in ({"logged_in": True},
                      dict(logged_in=True, admin_user=USER, auth_version=1, issued_at=int((NOW - timedelta(hours=8, seconds=1)).timestamp())),
                      dict(logged_in=True, admin_user=USER, auth_version=1, issued_at=int((NOW + timedelta(hours=1)).timestamp()))):
            with self.subTest(fields=list(state)):
                with self.client.session_transaction() as current:
                    current.clear()
                    current.update(state)
                self.assertEqual(self.client.get("/admin").status_code, 302)
        self.assertEqual(self.db.calls, [])

    def test_password_version_change_invalidates_old_cookie_session(self):
        self.assertEqual(self.login().status_code, 302)
        self.db.state["session_version"] += 1
        self.assertEqual(self.client.get("/audit").status_code, 302)
        with self.client.session_transaction() as state:
            self.assertFalse(state.get("logged_in", False))

    def test_version_changed_between_session_check_and_row_lock_rejects_password_write(self):
        self.assertEqual(self.login().status_code, 302)
        old_hash = self.db.state["password_hash"]
        self.db.clear_calls()
        self.db.before_lock = lambda state: state.update(session_version=2)
        response = self.change()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.db.state["password_hash"], old_hash)
        self.assertFalse(any(sql.startswith("UPDATE") and "password_hash" in sql for sql, _ in self.db.calls))
        with self.client.session_transaction() as state:
            self.assertFalse(state.get("logged_in", False))

    def test_api_routes_ignore_web_session_middleware_even_when_database_is_down(self):
        with self.client.session_transaction() as state:
            state["logged_in"] = True
        self.db.fail_open = True
        for path in ("/api/ping", "/check_license"):
            self.assertEqual(self.client.post(path, json={}).status_code, 200)
        self.assertEqual(self.db.calls, [])

    def test_web_database_failure_fails_closed_without_exposing_error(self):
        self.assertEqual(self.login().status_code, 302)
        self.db.fail_open = True
        with self.assertLogs(self.app.logger, level="ERROR"):
            response = self.client.get("/admin")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("protected admin", response.get_data(as_text=True))
        self.assertNotIn("offline database unavailable", response.get_data(as_text=True))

    def test_audit_failure_rolls_back_password_hash_and_version(self):
        self.assertEqual(self.login().status_code, 302)
        original = deepcopy(self.db.state)
        self.db.fail_audit = True
        with self.assertLogs(self.app.logger, level="ERROR"):
            response = self.change()
        self.assertIn(response.status_code, (500, 503))
        self.assertEqual(self.db.state, original)
        self.assertTrue(self.db.transactions[-1]["rolled_back"])
        self.assertFalse(self.db.transactions[-1]["committed"])

    def test_logout_get_only_confirms_and_post_requires_csrf(self):
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get("/logout").status_code, 200)
        with self.client.session_transaction() as state:
            self.assertTrue(state["logged_in"])
        self.assertEqual(self.client.post("/logout", data={"csrf_token": "wrong"}).status_code, 400)
        with self.client.session_transaction() as state:
            self.assertTrue(state["logged_in"])
        response = self.client.post("/logout", data={"csrf_token": self.token()})
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as state:
            self.assertFalse(state.get("logged_in", False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
