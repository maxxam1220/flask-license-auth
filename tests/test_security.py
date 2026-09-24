"""Route-level regression tests: no network, migrations, or real database."""
import importlib.util
import os
from pathlib import Path
import sys
import types
import unittest
from contextlib import contextmanager
from unittest.mock import MagicMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "flask-license-auth"))
from flask import Flask
from security import configure_security

ENV = {
    "APPDATA": os.environ.get("APPDATA", str(ROOT)),
    "DATABASE_URL": "postgresql://offline:offline@invalid.invalid/offline",
    "FLASK_SECRET_KEY": "test-only-session-secret-" + "s" * 32,
    "ADMIN_USER": "offline-admin", "ADMIN_PASS": "test-only-password",
    "ADMIN_API_KEY": "test-only-admin-" + "a" * 32,
    "BACKUP_READ_API_KEY": "test-only-read-" + "b" * 32,
    "BACKUP_RESTORE_API_KEY": "test-only-restore-" + "c" * 32,
    "SESSIONS_API_KEY": "test-only-client-session-key",
}

ADMIN_ROUTES = [
    ("GET", "/accounts"), ("POST", "/accounts"),
    ("POST", "/accounts/delete"), ("POST", "/accounts/reset_password"),
    ("POST", "/accounts/update_meta"), ("POST", "/rbac/role_tabs"),
    ("POST", "/rbac/module_tabs"), ("GET", "/get_licenses"),
    ("POST", "/update_license"), ("POST", "/delete_license"),
    ("POST", "/reset_mac"), ("POST", "/api/sessions/kick"),
    ("POST", "/sessions/kick"), ("POST", "/api/sessions/config"),
    ("POST", "/sessions/config"),
]
READ_ROUTES = [("GET", path) for path in
               ("/export_licenses", "/export_auth_backup", "/export_barcode53_backup")]
RESTORE_ROUTES = [("POST", path) for path in
                  ("/import_licenses", "/import_auth_backup", "/import_barcode53_backup",
                   "/import_barcode53_bclog_reset", "/import_barcode53_bclog_chunk")]


def bearer(key):
    return {"Authorization": "Bearer " + ENV[key]}


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guards = [
            patch.dict(os.environ, ENV, clear=True),
            patch("socket.create_connection", side_effect=AssertionError("Network prohibited")),
            patch("socket.socket.connect", side_effect=AssertionError("Network prohibited")),
            patch("socket.getaddrinfo", side_effect=AssertionError("Network prohibited")),
            patch("psycopg2.connect", side_effect=AssertionError("Real DB prohibited")),
        ]
        for guard in cls.guards:
            guard.start()
            cls.addClassCleanup(guard.stop)
        migrations = types.ModuleType("migrations")
        migrations.ensure_audit_login_table = Mock()
        migrations.ensure_barcode53_tables = Mock()
        spec = importlib.util.spec_from_file_location("security_test_app", ROOT / "flask-license-auth/app.py")
        cls.module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"migrations": migrations}):
            spec.loader.exec_module(cls.module)
        cls.module.app.config["TESTING"] = True

    def setUp(self):
        self.app = self.module.app
        self.client = self.app.test_client()
        for key in ("ADMIN_API_KEY", "BACKUP_READ_API_KEY", "BACKUP_RESTORE_API_KEY"):
            self.app.config[key] = ENV[key]
        self.db = Mock(side_effect=AssertionError("Unexpected DB access"))
        self.db_patch = patch.object(self.module, "db_conn", self.db)
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.module.ensure_barcode53_tables.reset_mock()

    def test_anonymous_management_routes_stop_before_database(self):
        for method, path in ADMIN_ROUTES + READ_ROUTES + RESTORE_ROUTES:
            with self.subTest(path=path, method=method):
                response = self.client.open(path, method=method, json={})
                self.assertEqual(response.status_code, 401)
        self.db.assert_not_called()
        self.module.ensure_barcode53_tables.assert_not_called()

    def test_wrong_keys_cannot_cross_permission_scopes(self):
        for key, routes in [("BACKUP_READ_API_KEY", ADMIN_ROUTES + RESTORE_ROUTES),
                            ("ADMIN_API_KEY", READ_ROUTES + RESTORE_ROUTES),
                            ("BACKUP_RESTORE_API_KEY", ADMIN_ROUTES + READ_ROUTES),
                            ("SESSIONS_API_KEY", ADMIN_ROUTES + READ_ROUTES + RESTORE_ROUTES)]:
            for method, path in routes:
                with self.subTest(key=key, path=path, method=method):
                    self.assertEqual(self.client.open(path, method=method, json={}, headers=bearer(key)).status_code, 401)
        self.db.assert_not_called()

    def test_missing_key_configuration_fails_closed(self):
        for key, route in [("ADMIN_API_KEY", "/accounts"),
                           ("BACKUP_READ_API_KEY", "/export_auth_backup"),
                           ("BACKUP_RESTORE_API_KEY", "/import_auth_backup")]:
            with self.subTest(key=key):
                self.app.config[key] = ""
                method = "POST" if key == "BACKUP_RESTORE_API_KEY" else "GET"
                self.assertEqual(self.client.open(route, method=method, json={}, headers=bearer(key)).status_code, 503)
        self.db.assert_not_called()

    def test_cookie_login_alone_does_not_authorize_management_api(self):
        with self.client.session_transaction() as session:
            session["logged_in"] = True
        self.assertEqual(self.client.post("/accounts/reset_password", json={}).status_code, 401)
        self.db.assert_not_called()

    @contextmanager
    def fake_database(self):
        cursor = Mock()
        cursor.__enter__ = Mock(return_value=cursor)
        cursor.__exit__ = Mock(return_value=False)
        cursor.fetchone.return_value = {"mac": None}
        cursor.fetchall.return_value = []
        cursor.rowcount = 0
        connection = Mock()
        connection.cursor.return_value = cursor
        with patch.object(self.module, "db_conn") as database:
            @contextmanager
            def opened():
                yield connection
            database.side_effect = opened
            yield cursor

    def test_valid_admin_credentials_reach_expected_writes(self):
        for headers in (bearer("ADMIN_API_KEY"), {"X-API-KEY": ENV["ADMIN_API_KEY"]}):
            with self.subTest(transport=list(headers)), self.fake_database() as cur:
                response = self.client.post("/update_license", headers=headers,
                    json={"auth_code": "TEST", "expiry": "2099-12-31", "remaining": 2})
                self.assertEqual(response.status_code, 200)
                self.assertTrue(any("INSERT INTO licenses" in call.args[0] for call in cur.execute.call_args_list))

    def test_backup_reader_can_export_without_restore_permission(self):
        with self.fake_database() as cur:
            response = self.client.get("/export_auth_backup", headers=bearer("BACKUP_READ_API_KEY"))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["schema_version"], 1)
            self.assertEqual(cur.execute.call_count, 5)

    def test_invalid_backup_bodies_are_rejected_before_db_or_migration(self):
        for path in ("/import_auth_backup", "/import_licenses", "/import_barcode53_backup"):
            for body in ({}, [], None, {"licenses": []}, {"barcode53": {}}):
                with self.subTest(path=path, body=body):
                    response = self.client.post(path, headers=bearer("BACKUP_RESTORE_API_KEY"), json=body)
                    self.assertEqual(response.status_code, 400)
            response = self.client.post(path, headers=bearer("BACKUP_RESTORE_API_KEY"),
                                        data="{invalid", content_type="application/json")
            self.assertEqual(response.status_code, 400)
        self.db.assert_not_called()
        self.module.ensure_barcode53_tables.assert_not_called()

    def test_valid_auth_restore_keeps_existing_export_format(self):
        from test_backup_validation import auth_backup
        with self.fake_database() as cur:
            response = self.client.post("/import_auth_backup", headers=bearer("BACKUP_RESTORE_API_KEY"),
                                        json=auth_backup())
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["import_counts"], dict.fromkeys(
                ("licenses", "bindings", "accounts", "rbac_tabs", "rbac_modules"), 1))
            self.assertEqual(sum("TRUNCATE TABLE" in call.args[0] for call in cur.execute.call_args_list), 5)

    def test_restore_failure_rolls_back_the_transaction(self):
        from test_backup_validation import auth_backup
        self.db_patch.stop()
        pool, conn, cur = MagicMock(), MagicMock(), MagicMock()
        pool.getconn.return_value = conn
        conn.cursor.return_value.__enter__.return_value = cur
        def fail_on_insert(sql, *args):
            if "INSERT INTO" in sql:
                raise RuntimeError("simulated insert failure")
        cur.execute.side_effect = fail_on_insert
        with patch.object(self.module, "_get_pool", return_value=pool):
            response = self.client.post("/import_auth_backup", headers=bearer("BACKUP_RESTORE_API_KEY"),
                                        json=auth_backup())
        self.assertEqual(response.status_code, 500)
        conn.commit.assert_not_called()
        conn.rollback.assert_called_once()
        pool.putconn.assert_called_once_with(conn, close=True)

    def test_unknown_only_barcode_rows_do_not_silently_succeed(self):
        with patch.object(self.module, "_get_table_columns", return_value={"CodeNo"}):
            with self.assertRaises(ValueError):
                self.module._insert_rows_by_existing_columns(Mock(), "barcode53", "BcMst", [{"typo": "value"}])

    def test_log_reset_requires_explicit_confirmation_before_any_db_call(self):
        for body in ({}, {"confirm": True}, {"confirm": "wrong"}, []):
            with self.subTest(body=body):
                response = self.client.post("/import_barcode53_bclog_reset",
                                            headers=bearer("BACKUP_RESTORE_API_KEY"), json=body)
                self.assertEqual(response.status_code, 400)
        self.db.assert_not_called()
        self.module.ensure_barcode53_tables.assert_not_called()

    def test_unicode_and_malformed_credentials_are_rejected(self):
        for headers in ({"Authorization": "Bearer 非法"}, {"Authorization": "Basic value"},
                        {"Authorization": "Bearer invalid", "X-API-KEY": ENV["ADMIN_API_KEY"]}):
            self.assertEqual(self.client.get("/accounts", headers=headers).status_code, 401)
        self.db.assert_not_called()

    def test_login_requires_csrf_and_sets_secure_cookie(self):
        self.assertEqual(self.client.post("/login", data={"username": ENV["ADMIN_USER"],
                                                         "password": ENV["ADMIN_PASS"]}).status_code, 400)
        response = self.client.get("/login")
        self.assertIn(b'name="csrf_token"', response.data)
        cookie = response.headers["Set-Cookie"]
        for flag in ("Secure", "HttpOnly", "SameSite=Lax"):
            self.assertIn(flag, cookie)
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        response = self.client.post("/login", data={"username": ENV["ADMIN_USER"],
                   "password": ENV["ADMIN_PASS"], "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/admin")

    def test_audit_prune_rejects_missing_csrf_before_delete(self):
        with self.client.session_transaction() as session:
            session["logged_in"] = True
            session["csrf_token"] = "test-csrf"
        self.assertEqual(self.client.post("/audit/prune", data={"days": 180}).status_code, 400)
        self.db.assert_not_called()
        with self.fake_database() as cur:
            response = self.client.post("/audit/prune", data={"days": 180, "csrf_token": "test-csrf"})
            self.assertEqual(response.status_code, 302)
            self.assertTrue(any("DELETE FROM audit_login" in call.args[0] for call in cur.execute.call_args_list))

    def test_public_login_and_license_contracts_still_reach_validation(self):
        for route in ("/check_account", "/check_license"):
            self.assertEqual(self.client.post(route, json={}).status_code, 400)
        self.assertEqual(self.client.get("/healthz").status_code, 200)
        self.db.assert_not_called()

    def test_missing_client_keys_fail_closed(self):
        with patch.object(self.module, "SESSIONS_API_KEY", ""):
            self.assertEqual(self.client.post("/api/sessions/heartbeat", json={}).status_code, 503)
        self.assertEqual(self.client.post("/api/gsheet/pur_hist_upload", json={}).status_code, 503)
        self.db.assert_not_called()


class ConfigurationTests(unittest.TestCase):
    def test_missing_or_default_session_secret_is_rejected(self):
        for value in ("", "dev-only-change-me", "short"):
            with self.subTest(value=value), patch.dict(os.environ, {"FLASK_SECRET_KEY": value}, clear=True):
                with self.assertRaises(RuntimeError):
                    configure_security(Flask(__name__))

    def test_management_and_backup_keys_must_be_distinct(self):
        with patch.dict(os.environ, {**ENV, "BACKUP_READ_API_KEY": ENV["ADMIN_API_KEY"]}, clear=True):
            with self.assertRaises(RuntimeError):
                configure_security(Flask(__name__))


if __name__ == "__main__":
    unittest.main()
