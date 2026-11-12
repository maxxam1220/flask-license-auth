import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from PIL import Image
from sqlalchemy import func, insert, select

import database as db
from server import create_app


class MemoryOCR:
    def __init__(self):
        self.calls = 0
        self.started = threading.Event()
        self.release = threading.Event()

    def recognize(self, path):
        self.started.set()
        self.release.wait(3)
        return {"lines": [], "engine": "test", "elapsed": .01}

    def read_memory_status(self):
        return {"status": "ok", "busy": False, "service_current_mb": 250, "service_limit_mb": 2048}

    def cleanup_memory(self):
        self.calls += 1
        return {"status": "ok", "before": self.read_memory_status(),
                "after": {**self.read_memory_status(), "service_current_mb": 200}}


class MemoryAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ocr = MemoryOCR()
        self.app = create_app({"TESTING": True, "DATA_DIR": Path(self.temp.name),
                               "DATABASE_URL": "", "APP_PASSWORD": ""}, ocr=self.ocr)
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token": self.client.get("/api/session").json["csrf"]}

    def tearDown(self):
        self.ocr.release.set()
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.app.extensions["label_engine"].dispose()
        self.temp.cleanup()

    def test_cleanup_is_protected_and_does_not_change_persistent_data(self):
        self.assertEqual(self.client.post("/api/memory/cleanup").status_code, 403)
        with self.app.extensions["label_engine"].connect() as conn:
            before = [conn.execute(select(func.count()).select_from(t)).scalar_one()
                      for t in (db.images, db.templates, db.jobs, db.inspections)]
        response = self.client.post("/api/memory/cleanup", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["after"]["service_current_mb"], 200)
        with self.app.extensions["label_engine"].connect() as conn:
            after = [conn.execute(select(func.count()).select_from(t)).scalar_one()
                     for t in (db.images, db.templates, db.jobs, db.inspections)]
        self.assertEqual(before, after)
        self.assertEqual(self.client.post("/api/memory/cleanup", headers=self.headers).status_code, 429)
        self.assertEqual(self.ocr.calls, 1)

    def test_other_users_cannot_clear_during_recognition(self):
        photo = io.BytesIO()
        Image.new("RGB", (500, 500), "white").save(photo, "PNG")
        photo.seek(0)
        job = self.client.post("/api/jobs", data={"kind": "recognition", "photo": (photo, "test.png")}, headers=self.headers)
        self.assertEqual(job.status_code, 202)
        self.assertTrue(self.ocr.started.wait(2))
        self.assertTrue(self.client.get("/api/memory").json["busy"])
        self.assertEqual(self.client.post("/api/memory/cleanup", headers=self.headers).status_code, 409)
        self.assertEqual(self.ocr.calls, 0)
        self.assertEqual(self.client.get("/healthz").status_code, 200)

    def test_login_and_cross_site_protection(self):
        self.app.config["APP_PASSWORD"] = "test-password-only"
        self.assertEqual(self.client.get("/api/memory").status_code, 401)
        self.assertEqual(self.client.post("/api/memory/cleanup", headers=self.headers).status_code, 401)
        self.app.config["APP_PASSWORD"] = ""
        self.assertEqual(self.client.post("/api/memory/cleanup", headers={**self.headers, "Sec-Fetch-Site": "cross-site"}).status_code, 403)

    def test_cleanup_failure_releases_upload_lock(self):
        with patch.object(self.ocr, "cleanup_memory", side_effect=OSError("test cleanup failure")):
            self.assertEqual(self.client.post("/api/memory/cleanup", headers=self.headers).status_code, 500)
        self.assertEqual(self.client.post("/api/memory/cleanup", headers=self.headers).status_code, 200)

    def test_pending_job_blocks_cleanup_before_worker_has_started(self):
        with self.app.extensions["label_engine"].begin() as conn:
            conn.execute(insert(db.jobs).values(id="pending-test", image_id="pending-image",
                kind="recognition", state="pending", result={}, created_at=db.now()))
        report=self.client.get("/api/memory").json
        self.assertTrue(report["busy"])
        self.assertEqual(report["queued_jobs"],1)
        self.assertEqual(self.client.post("/api/memory/cleanup",headers=self.headers).status_code,409)
        self.assertEqual(self.ocr.calls,0)
        self.assertFalse(self.ocr.started.is_set())

    def test_simultaneous_cleanup_requests_do_not_overlap(self):
        entered,released=threading.Event(),threading.Event()
        first_client=self.app.test_client()
        first_headers={"X-CSRF-Token":first_client.get("/api/session").json["csrf"]}
        responses=[]
        def cleanup():
            entered.set()
            if not released.wait(3):
                raise RuntimeError("test cleanup was not released")
            return {"status":"ok"}
        def request_cleanup():
            responses.append(first_client.post("/api/memory/cleanup",headers=first_headers).status_code)
        with patch.object(self.ocr,"cleanup_memory",side_effect=cleanup) as execute:
            thread=threading.Thread(target=request_cleanup)
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.client.post("/api/memory/cleanup",headers=self.headers).status_code,409)
                self.assertTrue(self.client.get("/api/memory").json["busy"])
                self.assertEqual(self.client.get("/healthz").status_code,200)
            finally:
                released.set()
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(responses,[200])
            execute.assert_called_once()


if __name__ == "__main__":
    unittest.main()
