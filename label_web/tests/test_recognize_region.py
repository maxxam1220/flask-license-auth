import io
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image
from sqlalchemy import select, insert, update, func

import database as db
from server import create_app
from photo_regions import validate_region
from test_validation import make_lines, STANDARD


class ObservedOCR:
    def __init__(self):
        self.calls = []

    def recognize(self, path):
        with Image.open(path) as image:
            self.calls.append(image.size)
        return {"lines":make_lines(), "engine":"TEST", "elapsed":.01}


class RegionRecognitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ocr = ObservedOCR()
        self.app = create_app({"TESTING":True, "DATA_DIR":self.root, "DATABASE_URL":"", "APP_PASSWORD":""}, self.ocr)
        self.engine = self.app.extensions["label_engine"]
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}
        photo = io.BytesIO()
        Image.new("RGB", (640, 480), "white").save(photo,"PNG")
        photo.seek(0)
        response = self.client.post("/api/jobs",data={"kind":"recognition", "base_date":"2026-11-11",
            "photo":(photo,"region.png")},headers=self.headers)
        job = self.wait_job(response.json["id"])
        self.identifier = job["result"]["inspection_id"]
        self.original = self.client.get("/api/inspections/"+self.identifier).json

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def wait_job(self, identifier):
        for _ in range(200):
            job = self.client.get("/api/jobs/"+identifier).json
            if job["state"] in {"done","failed"}:
                self.assertEqual(job["state"],"done",job)
                return job
            time.sleep(.01)
        self.fail("OCR job did not finish")

    def post(self, body=None, headers=None):
        return self.client.post(f"/api/inspections/{self.identifier}/recognize",json=body or {
            "request_id":"a"*32, "crop":{"x":100,"y":80,"width":320,"height":240}},headers=headers if headers is not None else self.headers)

    def count(self, table):
        with self.engine.connect() as conn:
            return conn.execute(select(func.count()).select_from(table)).scalar_one()

    def test_crop_really_changes_worker_input_preserves_original_and_date(self):
        path = self.root/"images"/self.original["image_id"]/"image.jpg"
        original_bytes = path.read_bytes()
        response = self.post()
        self.assertEqual(response.status_code,202,response.json)
        job = self.wait_job(response.json["id"])
        result = self.client.get("/api/inspections/"+job["result"]["inspection_id"]).json
        self.assertNotEqual(result["image_id"],self.original["image_id"])
        self.assertEqual(self.ocr.calls,[(640,480),(320,240)])
        self.assertEqual(result["result"]["inputs"]["base_date"],"2026-11-11")
        self.assertEqual(result["result"]["recognition_of"]["inspection_id"],self.identifier)
        self.assertIsNone(result["manual_revision"])
        self.assertEqual(path.read_bytes(),original_bytes)
        self.assertEqual(self.client.get("/api/inspections/"+self.identifier).json,self.original)

    def test_duplicate_submit_after_done_returns_same_job_and_no_new_photo(self):
        first = self.post()
        self.wait_job(first.json["id"])
        second = self.post()
        self.assertEqual(first.json,second.json)
        self.assertEqual(len(self.ocr.calls),2)
        self.assertEqual(self.count(db.images),2)
        changed = self.post({"request_id":"a"*32,"crop":{"x":10,"y":10,"width":200,"height":200}})
        self.assertEqual(changed.status_code,409)

    def test_invalid_regions_never_create_photos_or_jobs(self):
        invalid = [{"x":-1,"y":0,"width":100,"height":100}, {"x":600,"y":0,"width":100,"height":100},
            {"x":0,"y":0,"width":99,"height":200}, {"x":True,"y":0,"width":100,"height":100},
            {"x":0,"y":0,"width":10**400,"height":100}, {"x":float("nan"),"y":0,"width":100,"height":100},
            {"x":.5,"y":0,"width":10**400,"height":100}, {"x":10**400,"y":0,"width":100.5,"height":100},
            {},[],"all"]
        for region in invalid:
            with self.subTest(region=region):
                self.assertEqual(self.post({"request_id":"a"*32,"crop":region}).status_code,400)
        self.assertEqual(self.count(db.images),1)
        self.assertEqual(self.count(db.jobs),1)

    def test_full_photo_reuses_file_and_recomputes_ocr(self):
        response = self.post({"request_id":"a"*32})
        job = self.wait_job(response.json["id"])
        self.assertEqual(job["image_id"],self.original["image_id"])
        self.assertEqual(self.ocr.calls,[(640,480),(640,480)])
        self.assertEqual(self.count(db.images),1)

    def test_auth_and_csrf_required(self):
        self.assertEqual(self.post(headers={}).status_code,403)
        self.app.config["APP_PASSWORD"] = "test-only-operator"
        self.assertEqual(self.post().status_code,401)

    def test_archived_source_cannot_be_recognized(self):
        preview = self.client.post("/api/admin/history/preview",json={"filters":{"ids":[self.identifier]}},headers=self.headers).json
        response = self.client.post("/api/admin/history/archive",json={"preview_id":preview["preview_id"],
            "preview_hash":preview["preview_hash"],"confirmed":True,"reviewer":"QA","note":"archive test"},headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        self.assertEqual(self.post().status_code,404)

    def test_photo_standard_uses_immutable_snapshot_even_when_current_changed(self):
        standard = {"id":"old-template","name":"original","version":1,"image_id":self.original["image_id"],
                    "fields":STANDARD["fields"],"rules":STANDARD["rules"]}
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id==self.identifier).values(
                template_id="old-template",template_snapshot=standard))
        response=self.post()
        job=self.wait_job(response.json["id"])
        row=self.client.get("/api/inspections/"+job["result"]["inspection_id"]).json
        self.assertEqual(row["template_snapshot"],standard)

    def test_changed_database_selection_is_not_forced_on_new_crop(self):
        with self.engine.begin() as conn:
            result=dict(self.original["result"])
            result["inputs"]["source_code"]="old-forced-source"
            conn.execute(update(db.inspections).where(db.inspections.c.id==self.identifier).values(result=result))
        response=self.post()
        job=self.wait_job(response.json["id"])
        self.assertEqual(job["result"]["request"]["source_code"],"")

    def test_fractional_region_rounds_outward(self):
        self.assertEqual(validate_region({"x":10.2,"y":11.7,"width":101.1,"height":100.1},640,480),
                         {"x":10,"y":11,"width":102,"height":101})

    def test_failed_db_commit_removes_only_new_derivative(self):
        from sqlalchemy.exc import OperationalError
        original_files = sorted(str(p.relative_to(self.root)) for p in (self.root/"images").rglob("*"))
        with patch("server.history_cleanup.ensure_active",side_effect=[None,None,OperationalError("test",{},Exception())]):
            self.assertEqual(self.post().status_code,500)
        self.assertEqual(sorted(str(p.relative_to(self.root)) for p in (self.root/"images").rglob("*")), original_files)


if __name__ == "__main__":
    unittest.main()
