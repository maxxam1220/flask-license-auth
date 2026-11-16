"""Offline checks for cloud-first webpage defaults; no model request is issued."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from sqlalchemy import func, select

import cloud_budget
from server import create_app


class ScanDefaultTests(unittest.TestCase):
    def setUp(self):
        self.environment=patch.dict(os.environ,{"OPENAI_API_KEY":"", "LABELCHECK_CLOUD_TRIAL_LIMIT":"20"})
        self.environment.start()
        self.temp=tempfile.TemporaryDirectory()
        self.local=Mock()
        self.app=create_app({"TESTING":True,"DATA_DIR":Path(self.temp.name),"DATABASE_URL":"",
                             "APP_PASSWORD":""},ocr=self.local)
        self.engine=self.app.extensions["label_engine"]
        self.client=self.app.test_client()
        self.client.get("/api/session")

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()
        self.environment.stop()

    def settings(self):
        response=self.client.get("/api/scan-config")
        self.assertEqual(response.status_code,200,response.json)
        return response.json["recognition"]

    def call_count(self):
        with self.engine.connect() as conn:
            return conn.scalar(select(func.count()).select_from(cloud_budget.calls))

    def test_key_and_available_trial_default_cloud_without_reserving_or_calling(self):
        with patch.dict(os.environ,{"OPENAI_API_KEY":"offline-test-key"}), \
             patch("cloud_vision.CloudVisionEngine") as provider:
            for _ in range(3):
                settings=self.settings()
                self.assertTrue(settings["cloud_available"])
                self.assertEqual(settings["default_engine"],"cloud")
                self.assertEqual((settings["cloud_limit"],settings["cloud_remaining"]),(20,20))
            provider.assert_not_called()
        self.local.recognize.assert_not_called()
        self.assertEqual(self.call_count(),0)

    def test_missing_or_blank_key_defaults_local_without_consuming_trial(self):
        for key in ("", "   "):
            with self.subTest(key_present=bool(key)),patch.dict(os.environ,{"OPENAI_API_KEY":key}):
                settings=self.settings()
                self.assertFalse(settings["cloud_available"])
                self.assertEqual(settings["default_engine"],"local")
                self.assertEqual(settings["cloud_remaining"],20)
        self.local.recognize.assert_not_called()
        self.assertEqual(self.call_count(),0)

    def test_exhausted_persistent_trial_defaults_local_even_with_key(self):
        # Reservations are test database rows only; no recognition is submitted.
        for index in range(20):
            cloud_budget.reserve(self.engine,f"{index:032x}","offline",20)
            cloud_budget.finish(self.engine,f"{index:032x}","failed",error_code="offline")
        with patch.dict(os.environ,{"OPENAI_API_KEY":"offline-test-key"}):
            settings=self.settings()
        self.assertFalse(settings["cloud_available"])
        self.assertEqual(settings["default_engine"],"local")
        self.assertEqual((settings["cloud_limit"],settings["cloud_remaining"]),(20,0))
        self.assertEqual(self.call_count(),20)
        self.local.recognize.assert_not_called()

    def test_injected_cloud_provider_follows_same_default_without_being_called(self):
        provider=Mock()
        self.app.config["CLOUD_OCR"]=provider
        self.assertEqual(self.settings()["default_engine"],"cloud")
        self.app.config["CLOUD_TRIAL_LIMIT"]=0
        settings=self.settings()
        self.assertFalse(settings["cloud_available"])
        self.assertEqual(settings["default_engine"],"local")
        provider.recognize.assert_not_called()
        self.assertEqual(self.call_count(),0)


if __name__=="__main__":
    unittest.main()
