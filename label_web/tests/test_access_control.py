import io
from pathlib import Path
import tempfile
import time
import unittest

from PIL import Image
from sqlalchemy import insert

import database as db
from server import create_app


class FakeOCR:
    def recognize(self, _path):
        return {"lines":[], "engine":"TEST", "elapsed":0.01}


class AccessControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING":True, "DATA_DIR":Path(self.temp.name), "DATABASE_URL":"",
            "APP_PASSWORD":"test-operator-code", "ADMIN_PASSWORD":"test-manager-code"}, ocr=FakeOCR())
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.app.extensions["label_engine"].dispose()
        self.temp.cleanup()

    def post(self, path, body=None):
        return self.client.post(path, json=body or {}, headers=self.headers)

    def login(self, admin=False):
        response = self.post("/api/login", {"password":"test-manager-code" if admin else "test-operator-code"})
        self.assertEqual(response.status_code, 200, response.json)
        self.headers["X-CSRF-Token"] = response.json["csrf"]
        return response.json

    def test_anonymous_has_no_permissions_or_library_access(self):
        data = self.client.get("/api/session").json
        self.assertEqual(data["role"], "anonymous")
        self.assertFalse(data["is_admin"])
        self.assertFalse(any(data["permissions"].values()))
        self.assertEqual(self.client.get("/api/templates").status_code, 401)
        self.assertEqual(self.post("/api/admin/unlock", {"password":"test-manager-code"}).status_code, 401)

    def test_operator_cannot_bypass_management_routes_by_api(self):
        data = self.login()
        self.assertEqual(data["role"], "operator")
        self.assertFalse(any(data["permissions"].values()))
        for path in ["/api/templates", "/api/manual-standards", "/api/source-labels/123",
                     "/api/inspections/example/standard", "/api/inspections/example/standard/preview",
                     "/api/inspections/example/manual-standard"]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 403, response.json)
                self.assertEqual(response.json["code"], "admin_required")
        for path in ["/api/templates", "/api/inspections/example/standard",
                     "/api/inspections/example/manual-standard", "/api/inspections/example/manual-standard/preview"]:
            with self.subTest(path=path):
                self.assertEqual(self.post(path).status_code, 403)

    def test_operator_scan_and_history_remain_usable(self):
        self.login()
        photo = io.BytesIO()
        Image.new("RGB", (200, 120), "white").save(photo, "PNG")
        photo.seek(0)
        response = self.client.post("/api/jobs", data={"kind":"recognition", "base_date":"2026-11-13",
            "photo":(photo,"label.png")}, headers=self.headers)
        self.assertEqual(response.status_code, 202, response.json)
        for _ in range(100):
            job = self.client.get("/api/jobs/" + response.json["id"]).json
            if job["state"] in {"done", "failed"}:
                break
            time.sleep(.01)
        self.assertEqual(job["state"], "done", job)
        self.assertEqual(len(self.client.get("/api/inspections").json["items"]), 1)
        self.assertEqual(self.client.get("/api/inspections/"+job["result"]["inspection_id"]).status_code,200)

    def test_scan_options_do_not_expose_standard_contents(self):
        with self.app.extensions["label_engine"].begin() as conn:
            conn.execute(insert(db.templates).values(id="template", family_id="family", version=1, active=True,
                name="標準名稱", image_id="private-photo", fields={"address":"private standard"}, rules={},
                reference_dates={}, approved_by="private reviewer", created_at=db.now()))
        self.login()
        response = self.client.get("/api/inspection-options")
        self.assertEqual(response.json["items"], [{"id":"template", "name":"標準名稱", "version":1}])

    def test_reference_jobs_require_admin_on_create_read_and_retry(self):
        self.login()
        self.assertEqual(self.client.post("/api/jobs", data={"kind":"reference"}, headers=self.headers).status_code,403)
        with self.app.extensions["label_engine"].begin() as conn:
            conn.execute(insert(db.jobs).values(id="reference-job", image_id="photo", kind="reference",
                state="failed", created_at=db.now()))
        self.assertEqual(self.client.get("/api/jobs/reference-job").status_code,403)
        self.assertEqual(self.post("/api/jobs/reference-job/retry").status_code,403)

    def test_admin_direct_login_and_privilege_unlock_rotate_csrf(self):
        initial = self.headers["X-CSRF-Token"]
        operator = self.login()
        self.assertNotEqual(initial, operator["csrf"])
        response = self.post("/api/admin/unlock", {"password":"test-manager-code"})
        self.assertEqual(response.status_code,200,response.json)
        self.assertTrue(response.json["is_admin"])
        self.assertNotEqual(operator["csrf"], response.json["csrf"])
        self.assertEqual(self.post("/api/admin/lock").status_code,403)  # old CSRF is revoked
        self.headers["X-CSRF-Token"] = response.json["csrf"]
        self.assertEqual(self.client.get("/api/templates").status_code,200)
        response = self.post("/api/admin/lock")
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json["role"],"operator")
        self.headers["X-CSRF-Token"] = response.json["csrf"]
        self.assertEqual(self.client.get("/api/templates").status_code,403)
        self.assertTrue(self.login(admin=True)["is_admin"])

    def test_ordinary_password_cannot_elevate(self):
        self.login()
        response = self.post("/api/admin/unlock", {"password":"test-operator-code"})
        self.assertEqual(response.status_code,403)
        self.assertEqual(self.client.get("/api/session").json["role"],"operator")

    def test_existing_sessions_and_forged_role_do_not_gain_admin(self):
        with self.client.session_transaction() as session:
            session.update(authenticated=True, role="admin")
        self.assertEqual(self.client.get("/api/session").json["role"],"operator")
        self.assertEqual(self.client.get("/api/templates").status_code,403)

    def test_admin_password_rotation_invalidates_elevation(self):
        self.login(admin=True)
        self.app.config["ADMIN_PASSWORD"] = "a-different-manager-code"
        self.assertFalse(self.client.get("/api/session").json["is_admin"])
        self.assertEqual(self.client.get("/api/templates").status_code,403)

    def test_unset_short_or_same_admin_password_fail_closed(self):
        self.login()
        for value in ["", "1234567", "test-operator-code"]:
            self.app.config["ADMIN_PASSWORD"] = value
            self.assertFalse(self.client.get("/api/session").json["admin_configured"])
            self.assertEqual(self.post("/api/admin/unlock", {"password":value}).status_code,503)
            self.assertEqual(self.client.get("/api/templates").status_code,403)

    def test_failed_attempts_shared_between_login_and_unlock(self):
        self.login()
        for _ in range(5):
            self.assertEqual(self.post("/api/login", {"password":"wrong"}).status_code,401)
            self.assertEqual(self.post("/api/admin/unlock", {"password":"wrong"}).status_code,403)
        self.assertEqual(self.post("/api/admin/unlock", {"password":"test-manager-code"}).status_code,429)

    def test_successful_login_does_not_reset_failed_attempts(self):
        for _ in range(9):
            self.assertEqual(self.post("/api/login", {"password":"wrong"}).status_code,401)
        self.login()
        self.assertEqual(self.post("/api/admin/unlock", {"password":"wrong"}).status_code,403)
        self.assertEqual(self.post("/api/admin/unlock", {"password":"test-manager-code"}).status_code,429)

    def test_non_object_and_overlong_password_fail_without_error_or_escalation(self):
        for body in [["bad"], {"password":None}, {"password":"a"*257}]:
            self.assertEqual(self.client.post("/api/login", json=body, headers=self.headers).status_code,401)

    def test_logout_clears_elevated_permissions(self):
        self.login(admin=True)
        self.assertEqual(self.post("/api/logout").status_code,200)
        self.assertEqual(self.client.get("/api/session").json["role"],"anonymous")
        self.assertEqual(self.client.get("/api/templates").status_code,401)

    def test_locked_or_logged_out_admin_cookie_cannot_be_replayed(self):
        for path in ["/api/admin/lock", "/api/logout"]:
            with self.subTest(path=path):
                self.headers["X-CSRF-Token"] = self.client.get("/api/session").json["csrf"]
                self.login(admin=True)
                old_cookie = self.client.get_cookie("session").value
                self.assertEqual(self.post(path).status_code, 200)
                self.client.set_cookie("session", old_cookie)
                self.assertEqual(self.client.get("/api/templates").status_code, 403)
                self.assertFalse(self.client.get("/api/session").json["is_admin"])

    def test_non_ascii_csrf_token_is_rejected_without_server_error(self):
        response = self.client.post("/api/login", json={"password":"test-operator-code"},
                                    headers={"X-CSRF-Token":"é"})
        self.assertEqual(response.status_code,403)


if __name__ == "__main__":
    unittest.main()
