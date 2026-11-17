"""Barcode rule previews and writes require the existing administrator boundary."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from server import create_app


class BarcodeRuleAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "DATA_DIR": Path(self.temp.name),
            "DATABASE_URL": "", "APP_PASSWORD": "qa-operator-2026",
            "ADMIN_PASSWORD": "qa-manager-2026"}, ocr=object())
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token": self.client.get("/api/session").json["csrf"]}
        self.url = "/api/inspections/sample/barcode-rule"

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.app.extensions["label_engine"].dispose()
        self.temp.cleanup()

    def login(self, admin=False):
        response = self.client.post("/api/login", headers=self.headers,
            json={"password": "qa-manager-2026" if admin else "qa-operator-2026"})
        self.headers["X-CSRF-Token"] = response.json["csrf"]

    def test_guest_cannot_read_evidence_or_write(self):
        with patch("barcode_rule_authoring.suggest") as read, patch("barcode_rule_authoring.save") as write:
            self.assertEqual(self.client.get(self.url).status_code, 401)
            self.assertEqual(self.client.post(self.url, json={}, headers=self.headers).status_code, 401)
            read.assert_not_called()
            write.assert_not_called()

    def test_operator_can_read_but_cannot_preview_or_save(self):
        self.login()
        with patch("barcode_rule_authoring.suggest", return_value={"candidates": []}) as read, \
                patch("barcode_rule_authoring.preview") as preview, patch("barcode_rule_authoring.save") as save:
            self.assertEqual(self.client.get(self.url).json, {"candidates": []})
            self.assertEqual(read.call_count, 1)
            for suffix in ("", "/preview"):
                self.assertEqual(self.client.post(self.url + suffix, json={}, headers=self.headers).status_code, 403)
            preview.assert_not_called()
            save.assert_not_called()

    def test_admin_writes_still_require_valid_csrf(self):
        self.login(admin=True)
        with patch("barcode_rule_authoring.preview") as preview, patch("barcode_rule_authoring.save") as save:
            for suffix in ("", "/preview"):
                self.assertEqual(self.client.post(self.url + suffix, json={}).status_code, 403)
                self.assertEqual(self.client.post(self.url + suffix, json={}, headers={**self.headers,
                    "Sec-Fetch-Site": "cross-site"}).status_code, 403)
            preview.assert_not_called()
            save.assert_not_called()

    def test_admin_previews_without_calling_save(self):
        self.login(admin=True)
        with patch("barcode_rule_authoring.preview", return_value={"preview_hash": "reviewed"}) as preview, \
                patch("barcode_rule_authoring.save") as save:
            response = self.client.post(self.url + "/preview", json={"candidate_id": "candidate"}, headers=self.headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, {"preview_hash": "reviewed"})
            self.assertEqual(preview.call_args.args[1:], ("sample", {"candidate_id": "candidate"}))
            save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
