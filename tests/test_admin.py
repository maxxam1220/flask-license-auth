"""Offline admin-page regressions against real routes/templates and license rules."""
import ast
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

from flask import Flask, jsonify, request, template_rendered

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "flask-license-auth"))
import admin_views
from audit_views import register_audit_routes
from security import csrf_token
from test_audit import AuditDatabase

TODAY = date(2026, 9, 24)


class AdminDatabase:
    def __init__(self):
        self.licenses = [
            dict(auth_code="A-TODAY-ZERO", expiry=TODAY, remaining=0, mac="STALE-LAST-MAC"),
            dict(auth_code="B-EXPIRED", expiry=TODAY - timedelta(days=1), remaining=4),
            dict(auth_code="C-FUTURE", expiry=(TODAY + timedelta(days=90)).isoformat(), remaining=2),
            dict(auth_code="D-TOMORROW", expiry=datetime(2026, 9, 25), remaining=1),
            dict(auth_code="E-BAD-DATE", expiry="invalid-date", remaining=9),
            dict(auth_code="F-BAD-SLOTS", expiry=TODAY + timedelta(days=90), remaining=True),
        ]
        self.bindings = [dict(auth_code="A-TODAY-ZERO", mac=f"AA:00:00:00:00:0{n}") for n in range(1, 4)]
        self.bindings += [dict(auth_code="C-FUTURE", mac="CC:10:20:30:40:50"),
                          dict(auth_code="MISSING-LICENSE", mac="ORPHAN-MAC")]
        self.calls = []
        self.connections = 0
        self.fail = False

    @contextmanager
    def __call__(self):
        self.connections += 1
        database = self

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def execute(self, sql, params=None):
                self.sql = " ".join(str(sql).split())
                database.calls.append((self.sql, tuple(params or ())))
                if not self.sql.upper().startswith("SELECT"):
                    raise AssertionError("Admin listing must be read-only")
                if database.fail:
                    raise RuntimeError("offline database error must not be exposed")

            def fetchall(self):
                return list(database.bindings if "FROM bindings" in self.sql else database.licenses)

        class Connection:
            def cursor(self, **kwargs):
                return Cursor()

        yield Connection()


class NavigationParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.append(dict(attrs))


class AdminTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.create_connection", "socket.socket.connect", "socket.getaddrinfo", "psycopg2.connect"):
            self.enterContext(patch(target, side_effect=AssertionError("External access prohibited")))
        self.enterContext(patch.object(admin_views, "_today", return_value=TODAY))
        self.db = AdminDatabase()
        self.app = Flask(__name__, template_folder=str(ROOT / "flask-license-auth" / "templates"))
        self.app.config.update(TESTING=True, SECRET_KEY="offline-admin-session-" + "s" * 32)
        self.app.jinja_env.globals["csrf_token"] = csrf_token
        for endpoint in ("login", "logout"):
            self.app.add_url_rule("/" + endpoint, endpoint, lambda: "offline placeholder")
        admin_views.register_admin_routes(self.app, self.db)
        register_audit_routes(self.app, AuditDatabase(), "offline-admin")
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["logged_in"] = True
            session["csrf_token"] = "offline-csrf"
        self.contexts = []

        def capture(sender, template, context, **kwargs):
            self.contexts.append(context)

        template_rendered.connect(capture, self.app, weak=False)
        self.addCleanup(template_rendered.disconnect, capture, self.app)

    def get(self, **query):
        response = self.client.get("/admin", query_string=query)
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        return response

    def rows(self):
        return {row["auth_code"]: row for row in self.contexts[-1]["rows"]}

    def test_unauthenticated_browser_redirects_without_database_even_with_api_key(self):
        with self.client.session_transaction() as session:
            session.clear()
        response = self.client.get("/admin", headers={"Authorization": "Bearer dummy-admin-key"})
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        self.assertEqual(self.db.connections, 0)

    def test_complete_bindings_replace_stale_mac_without_n_plus_one_reads(self):
        response = self.get()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.db.connections, 1)
        self.assertEqual(len(self.db.calls), 2)
        self.assertIn("FROM licenses", self.db.calls[0][0])
        self.assertIn("ORDER BY auth_code", self.db.calls[0][0])
        self.assertIn("FROM bindings", self.db.calls[1][0])
        row = self.rows()["A-TODAY-ZERO"]
        self.assertEqual(row["device_count"], 3)
        self.assertEqual(row["devices"], [f"AA:00:00:00:00:0{n}" for n in range(1, 4)])
        html = response.get_data(as_text=True)
        for mac in row["devices"]:
            self.assertIn(mac, html)
        self.assertNotIn("STALE-LAST-MAC", html)
        self.assertNotIn("ORPHAN-MAC", html)
        self.assertIn("<details", html)

    def test_expiry_includes_today_and_zero_slots_does_not_disable_bound_devices(self):
        self.assertEqual(self.get().status_code, 200)
        rows = self.rows()
        self.assertEqual((rows["A-TODAY-ZERO"]["status"], rows["A-TODAY-ZERO"]["days_left"]), ("expiring", 0))
        self.assertTrue(rows["A-TODAY-ZERO"]["exhausted"])
        self.assertEqual(rows["B-EXPIRED"]["status"], "expired")
        self.assertEqual(rows["C-FUTURE"]["status"], "valid")
        self.assertEqual(rows["D-TOMORROW"]["expiry"], "2026-09-25")
        self.assertEqual(rows["D-TOMORROW"]["days_left"], 1)
        self.assertEqual(rows["E-BAD-DATE"]["status"], "invalid")
        self.assertEqual(rows["F-BAD-SLOTS"]["status"], "invalid")
        self.assertIsNone(rows["F-BAD-SLOTS"]["remaining"])

    def test_same_today_and_zero_slot_cases_follow_actual_check_license_function(self):
        # Compile the existing business handler unchanged, with a frozen server
        # date and an in-memory cursor; do not import app.py or run migrations.
        tree = ast.parse((ROOT / "flask-license-auth" / "app.py").read_text(encoding="utf-8-sig"))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "check_license")
        function.decorator_list = []
        cursor, connection = MagicMock(), MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor

        @contextmanager
        def database():
            yield connection

        class FrozenDateTime(datetime):
            @classmethod
            def today(cls):
                return cls(2026, 9, 24, 23, 59)

        namespace = dict(request=request, jsonify=jsonify, db_conn=database,
                         datetime=FrozenDateTime, RealDictCursor=object)
        exec(compile(ast.Module(body=[function], type_ignores=[]), "real_check_license", "exec"), namespace)
        self.app.add_url_rule("/_offline_contract_check", view_func=namespace["check_license"], methods=["POST"])
        for expiry, bound, expected in ((TODAY, True, 200), (TODAY, False, 403),
                                       (TODAY - timedelta(days=1), True, 403)):
            with self.subTest(expiry=expiry, bound=bound):
                cursor.fetchone.side_effect = [{"auth_code": "DEMO"} if bound else None,
                    dict(auth_code="DEMO", expiry=expiry, remaining=0)]
                response = self.client.post("/_offline_contract_check", json={"auth_code": "DEMO", "mac": "OFFLINE-MAC"})
                self.assertEqual(response.status_code, expected)

    def test_summary_and_status_filters_keep_distinct_license_counts(self):
        self.assertEqual(self.get().status_code, 200)
        summary = self.contexts[-1]["summary"]
        for key, expected in dict(total=6, valid=3, expiring=2, expired=1, exhausted=1,
                                  bound_devices=4, remaining_slots=3).items():
            self.assertEqual(summary[key], expected, key)
        expected = {"expired": {"B-EXPIRED"}, "exhausted": {"A-TODAY-ZERO"},
                    "invalid": {"E-BAD-DATE", "F-BAD-SLOTS"},
                    "valid": {"A-TODAY-ZERO", "C-FUTURE", "D-TOMORROW"}}
        for status, codes in expected.items():
            with self.subTest(status=status):
                self.assertEqual(self.get(status=status).status_code, 200)
                self.assertEqual(set(self.rows()), codes)
                self.assertEqual(self.contexts[-1]["summary"]["total"], len(codes))

    def test_search_matches_code_or_any_mac_case_insensitively_and_treats_wildcards_literally(self):
        for query, expected in (("future", {"C-FUTURE"}), ("aa:00:00:00:00:03", {"A-TODAY-ZERO"}),
                                ("%", set()), ("_", set()), ("' OR 1=1 --", set())):
            with self.subTest(query=query):
                self.assertEqual(self.get(q=query).status_code, 200)
                self.assertEqual(set(self.rows()), expected)
        self.assertEqual(self.get(q="AA:00", status="expired").status_code, 200)
        self.assertEqual(self.rows(), {})

    def test_bad_query_values_fail_without_database(self):
        for query in ({"q": "x" * 257}, {"status": "disabled"}, {"limit": "24"},
                      {"limit": "26"}, {"limit": "101"}, {"limit": "ten"},
                      {"page": "0"}, {"page": "-1"}, {"page": "1.5"}, {"page": "nan"}):
            with self.subTest(query={key: str(value)[:20] for key, value in query.items()}):
                self.assertEqual(self.get(**query).status_code, 400)
        self.assertEqual(self.db.connections, 0)

    def test_pagination_clamps_and_empty_result_has_no_bogus_ranges(self):
        self.db.licenses = [dict(auth_code=f"DEMO-{index:03}", expiry=TODAY, remaining=1) for index in range(63)]
        self.db.bindings = []
        self.assertEqual(self.get(page="999", limit="25").status_code, 200)
        context = self.contexts[-1]
        self.assertEqual((context["page"], context["total_pages"], context["total_count"]), (3, 3, 63))
        self.assertEqual((context["start_row"], context["end_row"]), (51, 63))
        self.assertEqual(len(context["rows"]), 13)
        self.assertIsNone(context["next_url"])
        self.assertIsNotNone(context["prev_url"])
        self.assertEqual(self.get(q="missing", page="99", limit="100").status_code, 200)
        context = self.contexts[-1]
        self.assertEqual((context["page"], context["total_pages"], context["start_row"], context["end_row"]), (1, 1, 0, 0))
        self.assertEqual(context["rows"], [])
        self.assertIsNone(context["prev_url"])
        self.assertIsNone(context["next_url"])

    def test_database_failure_is_safe_and_not_rendered_as_a_successful_empty_list(self):
        self.db.fail = True
        with self.assertLogs(self.app.logger, level="ERROR"):
            response = self.get()
        self.assertEqual(response.status_code, 500)
        self.assertTrue(self.contexts[-1]["error"])
        self.assertNotIn("offline database error", response.get_data(as_text=True))

    def test_license_mac_and_query_are_html_escaped(self):
        attack = '<script>alert("offline")</script>'
        self.db.licenses = [dict(auth_code=attack, expiry=TODAY, remaining=1)]
        self.db.bindings = [dict(auth_code=attack, mac='<img src=x onerror="offline()">')]
        response = self.get(q=attack)
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertNotIn(attack, html)
        self.assertNotIn('<img src=x onerror=', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("&lt;img", html)

    def test_admin_and_audit_navigation_link_both_pages_and_mark_only_current_page(self):
        for path in ("/admin", "/audit"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                parser = NavigationParser()
                parser.feed(response.get_data(as_text=True))
                self.assertTrue(any(link.get("href") == "/admin" for link in parser.links))
                self.assertTrue(any(link.get("href") == "/audit" for link in parser.links))
                current = [link["href"] for link in parser.links if link.get("aria-current") == "page"]
                self.assertEqual(current, [path])


if __name__ == "__main__":
    unittest.main(verbosity=2)
