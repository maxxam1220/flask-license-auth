"""Offline audit-route regressions; no migrations, real database, or network."""
import csv
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from flask import Flask, template_rendered

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "flask-license-auth"))
import audit_views
from security import csrf_token

NOW = datetime(2026, 9, 24, 0, 0, tzinfo=timezone.utc)
ROW = dict(id=44, event_time="2026-09-24 08:00:00", username="offline-user",
           action="login_success", success=True, machine_name="OFFLINE-PC", local_ip="127.0.0.1",
           public_ip="127.0.0.1", app_version="test", client_os="offline", note="測試紀錄")


class AuditDatabase:
    """Small query recorder with only the shapes used by the audit routes."""
    def __init__(self):
        self.rows = [dict(ROW)]
        self.summary = {"total": 1, "success": 1, "failed": 0}
        self.preview = {"count": 7, "max_id": 44}
        self.calls = []
        self.transactions = []
        self.fail_insert = False
        self.used_preview_hashes = set()

    @contextmanager
    def __call__(self):
        transaction = {"calls": [], "committed": False, "rolled_back": False}
        self.transactions.append(transaction)
        database = self

        class Cursor:
            rowcount = 7

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql, params=None):
                self.sql = " ".join(str(sql).split())
                call = (self.sql, tuple(params or ()))
                self.params = call[1]
                database.calls.append(call)
                transaction["calls"].append(call)
                if database.fail_insert and self.sql.upper().startswith("INSERT"):
                    raise RuntimeError("offline audit insert failure")
                if self.sql.upper().startswith("INSERT"):
                    for parameter in self.params:
                        extra = getattr(parameter, "adapted", {})
                        if isinstance(extra, dict) and extra.get("preview_hash"):
                            transaction["preview_hash"] = extra["preview_hash"]

            def fetchone(self):
                if "preview_hash" in self.sql:
                    return {"used": 1} if self.params[0] in database.used_preview_hashes else None
                return dict(database.preview if "MAX(" in self.sql.upper() else database.summary)

            def fetchall(self):
                return list(database.rows)

        class Connection:
            def cursor(self, **kwargs):
                return Cursor()

        try:
            yield Connection()
        except Exception:
            transaction["rolled_back"] = True
            raise
        else:
            transaction["committed"] = True
            if transaction.get("preview_hash"):
                self.used_preview_hashes.add(transaction["preview_hash"])

    def clear_calls(self):
        self.calls.clear()
        self.transactions.clear()


class AuditTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.create_connection", "socket.socket.connect", "socket.getaddrinfo",
                       "psycopg2.connect"):
            self.enterContext(patch(target, side_effect=AssertionError("External access prohibited")))
        self.enterContext(patch.object(audit_views, "_utcnow", return_value=NOW))
        self.db = AuditDatabase()
        self.app = Flask(__name__, template_folder=str(ROOT / "flask-license-auth" / "templates"))
        self.app.config.update(TESTING=True, SECRET_KEY="offline-audit-session-" + "x" * 32)
        self.app.jinja_env.globals["csrf_token"] = csrf_token
        for endpoint in ("login", "logout", "admin"):
            self.app.add_url_rule("/" + endpoint, endpoint, lambda: "offline placeholder")
        audit_views.register_audit_routes(self.app, self.db, "offline-admin")
        self.client = self.app.test_client()
        self.contexts = []

        def capture(sender, template, context, **kwargs):
            self.contexts.append(context)

        template_rendered.connect(capture, self.app, weak=False)
        self.addCleanup(template_rendered.disconnect, capture, self.app)
        self.login()

    def login(self):
        with self.client.session_transaction() as session:
            session["logged_in"] = True
            session["csrf_token"] = "offline-csrf"

    def post(self, **data):
        return self.client.post("/audit/prune", data={"csrf_token": "offline-csrf", **data})

    def preview(self, days="180"):
        response = self.post(operation="preview", days=days)
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            return dict(session["_audit_prune_preview"])

    def confirm(self, preview, **overrides):
        data = {"operation": "confirm", "preview_token": preview["token"],
                "confirm_scope": "all_users"}
        data.update(overrides)
        return self.post(**data)

    def test_all_audit_routes_require_browser_login_before_database(self):
        with self.client.session_transaction() as session:
            session.clear()
        for method, path in (("GET", "/audit"), ("GET", "/audit/export.csv"),
                             ("POST", "/audit/prune")):
            with self.subTest(path=path):
                response = self.client.open(path, method=method,
                    headers={"Authorization": "Bearer offline-admin-api-key"})
                self.assertEqual(response.status_code, 302)
                self.assertIn("/login", response.headers["Location"])
        self.assertEqual(self.db.calls, [])
        self.assertEqual(self.db.transactions, [])

    def test_invalid_filters_and_pagination_fail_before_database(self):
        invalid = [{"limit": value} for value in ("9", "501", "ten", "10.5")]
        invalid += [{"page": value} for value in ("0", "-1", "one", "1.5")]
        invalid += [{"from": "2026-02-29T10:00"}, {"to": "not-a-date"},
                    {"from": "2026-09-25T12:00", "to": "2026-09-24T12:00"},
                    {"from": "0001-01-01T00:00"}, {"to": "9999-12-31T23:59"},
                    {"username": "x" * 2000}, {"action": "x" * 2000}]
        for path in ("/audit", "/audit/export.csv"):
            for query in invalid:
                with self.subTest(path=path, query=query):
                    self.assertEqual(self.client.get(path, query_string=query).status_code, 400)
        self.assertEqual(self.db.transactions, [])

    def test_list_export_share_exact_filters_and_taipei_minute_boundaries(self):
        query = {"username": "name' OR 1=1 --", "action": "unknown_action'", "limit": "10",
                 "from": "2026-09-24T00:00", "to": "2026-09-24T23:59"}
        self.assertEqual(self.client.get("/audit", query_string=query).status_code, 200)
        summary, listing = self.db.calls
        self.db.clear_calls()
        self.assertEqual(self.client.get("/audit/export.csv", query_string=query).status_code, 200)
        export = self.db.calls[0]
        expected = (query["username"], query["action"],
                    datetime(2026, 9, 23, 16, tzinfo=timezone.utc),
                    datetime(2026, 9, 24, 16, tzinfo=timezone.utc))
        self.assertEqual(summary[1], expected)
        self.assertEqual(listing[1], expected + (10, 0))
        self.assertEqual(export[1], expected + (5001,))
        for sql, _ in (summary, listing, export):
            self.assertNotIn(query["username"], sql)
            self.assertNotIn(query["action"], sql)
            self.assertIn("a.username = %s", sql)
            self.assertIn("a.action = %s", sql)
            self.assertIn("a.event_time >= %s", sql)
            self.assertIn("a.event_time < %s", sql)
        for sql, _ in (listing, export):
            self.assertRegex(sql, r"ORDER BY a\.event_time DESC\s*,\s*a\.id DESC")

    def test_equal_from_to_keeps_the_whole_last_minute_at_year_boundary(self):
        query = {"from": "2026-12-31T23:59", "to": "2026-12-31T23:59"}
        self.assertEqual(self.client.get("/audit", query_string=query).status_code, 200)
        start, end = self.db.calls[0][1]
        self.assertEqual(end - start, timedelta(minutes=1))
        self.assertEqual(end, datetime(2026, 12, 31, 16, tzinfo=timezone.utc))

    def test_summary_page_clamping_empty_state_and_limit_boundaries(self):
        self.db.summary = {"total": 23, "success": 20, "failed": 3}
        self.db.rows = [dict(ROW)] * 3
        self.assertEqual(self.client.get("/audit?limit=10&page=999").status_code, 200)
        context = self.contexts[-1]
        self.assertEqual(context["summary"], self.db.summary)
        self.assertEqual((context["page"], context["total_pages"]), (3, 3))
        self.assertEqual((context["start_row"], context["end_row"]), (21, 23))
        self.assertIsNone(context["next_url"])
        self.assertIsNotNone(context["prev_url"])
        self.assertEqual(self.db.calls[-1][1][-2:], (10, 20))
        self.db.summary = dict.fromkeys(("total", "success", "failed"), 0)
        self.db.rows = []
        self.assertEqual(self.client.get("/audit?limit=500&page=99").status_code, 200)
        context = self.contexts[-1]
        self.assertEqual((context["page"], context["total_pages"]), (1, 1))
        self.assertEqual((context["start_row"], context["end_row"]), (0, 0))
        self.assertIsNone(context["prev_url"])
        self.assertIsNone(context["next_url"])

    def test_template_escapes_rows_and_preserves_unknown_action_filter(self):
        attack = "<script>alert('offline')</script>"
        self.db.rows = [{**ROW, "username": attack, "note": '<img src=x onerror="offline()">',
                         "action": "future_action"}]
        response = self.client.get("/audit", query_string={"username": attack, "action": "future_action"})
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertNotIn(attack, html)
        self.assertNotIn('<img src=x onerror=', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img", html)
        self.assertIn("future_action", html)

    def test_csv_has_bom_and_escapes_formula_prefixes(self):
        for attack in ("=SUM(1,2)", "+command", "-command", "@command", "\t=command", "\r=command", "\n=command", "  =command"):
            with self.subTest(prefix=repr(attack[:3])):
                self.db.rows = [{**ROW, "username": attack, "note": attack}]
                response = self.client.get("/audit/export.csv")
                self.assertEqual(response.status_code, 200)
                self.assertTrue(response.data.startswith(b"\xef\xbb\xbf"))
                self.assertIn("attachment", response.headers["Content-Disposition"])
                rows = list(csv.reader(io.StringIO(response.data.decode("utf-8-sig"))))
                self.assertEqual(len(rows), 2)
                self.assertGreaterEqual(rows[1].count("'" + attack), 2)

    def test_csv_cap_never_silently_truncates(self):
        self.db.rows = [dict(ROW)] * 5000
        response = self.client.get("/audit/export.csv")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(list(csv.reader(io.StringIO(response.data.decode("utf-8-sig"))))), 5001)
        self.assertEqual(self.db.calls[-1][1][-1], 5001)
        self.db.rows = [dict(ROW)] * 5001
        response = self.client.get("/audit/export.csv")
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("attachment", response.headers.get("Content-Disposition", ""))

    def test_prune_invalid_csrf_days_and_missing_preview_never_open_database(self):
        for token in (None, "wrong"):
            data = {"operation": "preview", "days": "180"}
            if token is not None:
                data["csrf_token"] = token
            self.assertEqual(self.client.post("/audit/prune", data=data).status_code, 400)
        for days in ("0", "3651", "-1", "1.5", "bad"):
            self.assertEqual(self.post(operation="preview", days=days).status_code, 400)
        self.assertEqual(self.post(operation="confirm", preview_token="made-up", confirm_scope="all_users").status_code, 400)
        self.assertEqual(self.post(operation="delete", days="180").status_code, 400)
        self.assertEqual(self.db.transactions, [])

    def test_prune_preview_only_counts_all_users_and_exposes_reviewable_scope(self):
        response = self.client.post("/audit/prune?username=filtered-user&action=login", data={
            "csrf_token": "offline-csrf", "days": "180"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(self.db.calls), 1)
        sql, params = self.db.calls[0]
        self.assertIn("COUNT", sql.upper())
        self.assertIn("MAX", sql.upper())
        self.assertNotIn("username =", sql)
        self.assertNotIn("action =", sql)
        self.assertEqual(params, (NOW - timedelta(days=180),))
        with self.client.session_transaction() as session:
            preview = dict(session["_audit_prune_preview"])
        self.assertEqual((preview["count"], preview["max_id"], preview["days"]), (7, 44, 180))
        self.assertEqual(datetime.fromisoformat(preview["cutoff"]), params[0])
        self.assertEqual(self.client.get(response.headers["Location"]).status_code, 200)
        self.assertEqual(self.contexts[-1]["prune_preview"]["count"], 7)
        self.assertEqual(self.contexts[-1]["prune_preview"]["token"], preview["token"])

    def test_prune_wrong_token_scope_or_changed_days_cannot_delete(self):
        preview = self.preview()
        self.db.clear_calls()
        for overrides in ({"preview_token": "wrong"}, {"confirm_scope": "filtered_users"},
                          {"confirm_scope": ""}, {"days": "1"}, {"csrf_token": "wrong"}):
            with self.subTest(fields=list(overrides)):
                self.assertEqual(self.confirm(preview, **overrides).status_code, 400)
        self.assertEqual(self.db.transactions, [])

    def test_prune_expired_preview_is_rejected_before_database(self):
        preview = self.preview()
        self.db.clear_calls()
        with patch.object(audit_views, "_utcnow", return_value=NOW + timedelta(minutes=11)):
            self.assertEqual(self.confirm(preview).status_code, 400)
        self.assertEqual(self.db.transactions, [])
        with self.client.session_transaction() as session:
            self.assertNotIn("_audit_prune_preview", session)

    def test_cancel_consumes_preview_without_database_and_still_requires_csrf(self):
        self.preview()
        self.db.clear_calls()
        self.assertEqual(self.post(operation="cancel", csrf_token="wrong").status_code, 400)
        with self.client.session_transaction() as session:
            self.assertIn("_audit_prune_preview", session)
        self.assertEqual(self.post(operation="cancel").status_code, 302)
        with self.client.session_transaction() as session:
            self.assertNotIn("_audit_prune_preview", session)
        self.assertEqual(self.db.transactions, [])

    def test_prune_confirm_uses_snapshot_and_logs_in_same_transaction_then_blocks_replay(self):
        preview = self.preview()
        self.db.clear_calls()
        with patch.object(audit_views, "_utcnow", return_value=NOW + timedelta(minutes=3)):
            self.assertEqual(self.confirm(preview).status_code, 302)
        self.assertEqual(len(self.db.transactions), 1)
        lock, lookup, delete, insert = self.db.calls
        self.assertIn("pg_advisory_xact_lock", lock[0])
        self.assertIsInstance(lock[1][0], int)
        self.assertIn("preview_hash", lookup[0])
        self.assertEqual(lookup[1][1], NOW - timedelta(minutes=7))
        self.assertRegex(delete[0], r"DELETE FROM audit_login")
        self.assertRegex(delete[0], r"event_time < %s")
        self.assertRegex(delete[0], r"id <= %s")
        self.assertEqual(delete[1], (datetime.fromisoformat(preview["cutoff"]), 44))
        self.assertIn("INSERT INTO audit_login", insert[0])
        self.assertTrue("audit_prune" in insert[0] or "audit_prune" in insert[1])
        self.assertIn("offline-admin", insert[1])
        self.assertTrue(self.db.transactions[0]["committed"])
        with self.client.session_transaction() as session:
            self.assertNotIn("_audit_prune_preview", session)
        self.db.clear_calls()
        self.assertEqual(self.confirm(preview).status_code, 400)
        self.assertEqual(self.db.transactions, [])

    def test_old_signed_cookie_replay_hits_server_nonce_check_before_delete(self):
        preview = self.preview()
        original_cookie = self.client.get_cookie(self.app.config["SESSION_COOKIE_NAME"]).value
        self.assertEqual(self.confirm(preview).status_code, 302)
        self.assertEqual(len(self.db.used_preview_hashes), 1)
        self.db.clear_calls()
        self.client.set_cookie(self.app.config["SESSION_COOKIE_NAME"], original_cookie)
        self.assertEqual(self.confirm(preview).status_code, 409)
        self.assertEqual(len(self.db.calls), 2)
        self.assertIn("pg_advisory_xact_lock", self.db.calls[0][0])
        self.assertIn("preview_hash", self.db.calls[1][0])
        self.assertFalse(any(sql.startswith(("DELETE", "INSERT")) for sql, _ in self.db.calls))
        self.assertTrue(self.db.transactions[0]["rolled_back"])

    def test_prune_audit_insert_failure_rolls_back_delete(self):
        preview = self.preview()
        self.db.clear_calls()
        self.db.fail_insert = True
        with self.assertLogs(self.app.logger, level="ERROR"):
            response = self.confirm(preview)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(len(self.db.transactions), 1)
        self.assertTrue(self.db.transactions[0]["rolled_back"])
        self.assertFalse(self.db.transactions[0]["committed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
