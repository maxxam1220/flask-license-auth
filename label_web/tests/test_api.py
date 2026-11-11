import io
import tempfile
import time
import unittest
import threading
from unittest.mock import patch
from pathlib import Path
from PIL import Image
from server import create_app
from test_validation import make_lines, STANDARD


class FakeOCR:
    def recognize(self, _path):
        return {"lines": make_lines(), "engine": "TEST ONLY", "elapsed": .01}


class APITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({"TESTING":True,"DATA_DIR":Path(self.temp.name),"DATABASE_URL":"","APP_PASSWORD":""},ocr=FakeOCR())
        self.client=self.app.test_client()
        self.csrf=self.client.get("/api/session").json["csrf"]
        self.headers={"X-CSRF-Token":self.csrf}

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.app.extensions["label_engine"].dispose()
        self.temp.cleanup()

    def photo(self):
        file=io.BytesIO();Image.new("RGB",(500,500),"white").save(file,"PNG");file.seek(0);return file

    def job(self, kind="reference", template_id="", **inputs):
        response=self.client.post("/api/jobs",data={"kind":kind,"template_id":template_id,"photo":(self.photo(),"標籤.png"),**inputs},headers=self.headers)
        self.assertEqual(response.status_code,202,response.json)
        for _ in range(100):
            job=self.client.get("/api/jobs/"+response.json["id"]).json
            if job["state"] in {"done","failed"}:break
            time.sleep(.01)
        self.assertEqual(job["state"],"done",job)
        return job

    def standard(self, **changes):
        job=self.job()
        body={"job_id":job["id"],"name":"測試標準","fields":STANDARD["fields"],"rules":STANDARD["rules"],
              "reference_dates":{"manufacture":"2026.11.10","expiry":"2026.11.13"},"approved_by":"測試員","confirmed":True}
        body.update(changes)
        return self.client.post("/api/templates",json=body,headers=self.headers)

    def test_full_workflow_persists_review_and_version(self):
        standard=self.standard();self.assertEqual(standard.status_code,201,standard.json)
        job=self.job("inspection",standard.json["id"])
        identifier=job["result"]["inspection_id"]
        result=self.client.get("/api/inspections/"+identifier).json
        self.assertEqual(result["status"],"pass")
        review=self.client.post(f"/api/inspections/{identifier}/reviews",json={"decision":"confirmed_bad","reviewer":"複核員","note":"人工對照發現問題"},headers=self.headers)
        self.assertEqual(review.status_code,201)
        updated=self.standard(supersedes_id=standard.json["id"])
        self.assertEqual(updated.json["version"],2)
        history=self.client.get("/api/inspections/"+identifier).json
        self.assertEqual(history["template_snapshot"]["version"],1)
        self.assertEqual(history["status"],"pass")
        self.assertEqual(history["reviews"][0]["decision"],"confirmed_bad")
        self.assertEqual(len(self.client.get("/api/templates").json["items"]),1)
        self.assertEqual(len(self.client.get("/api/inspections").json["items"]),1)

    def test_standard_requires_confirmation_and_all_fields(self):
        self.assertEqual(self.standard(confirmed=False).status_code,400)
        self.assertEqual(self.standard(fields={"product":"水果"}).status_code,400)

    def test_bad_reference_date_cannot_be_approved(self):
        self.assertEqual(self.standard(reference_dates={"manufacture":"2026.11.13","expiry":"2026.11.10"}).status_code,400)

    def test_invalid_upload_and_csrf(self):
        bad=self.client.post("/api/jobs",data={"kind":"reference","photo":(io.BytesIO(b"not an image"),"label.jpg")},headers=self.headers)
        self.assertEqual(bad.status_code,400)
        self.assertEqual(self.client.post("/api/templates",json={}).status_code,403)

    def test_no_fake_results_for_unknown_standard(self):
        response=self.client.post("/api/jobs",data={"kind":"inspection","template_id":"missing","photo":(self.photo(),"label.png")},headers=self.headers)
        self.assertEqual(response.status_code,404)

    def test_no_reference_recognition_is_saved_but_never_passes(self):
        job = self.job("recognition")
        result = self.client.get("/api/inspections/" + job["result"]["inspection_id"]).json
        self.assertEqual(result["status"], "review")
        self.assertIsNone(result["reference_image"])
        self.assertEqual(result["result"]["fields"]["product"]["value"], STANDARD["fields"]["product"])
        self.assertTrue(all(c["status"] == "review" for c in result["result"]["checks"][:3]))
        self.assertEqual(self.client.get("/api/inspections").json["items"][0]["version"], 0)

    def test_source_standard_without_photo_and_stale_revision(self):
        source = {"code":"123", "name":"系統標籤", "revision":"revision1", "keep_days":9,
                  "date_settings":[{"content":"到店日", "shift_days":1}]}
        body = {"source_code":"123", "source_revision":"old", "name":"已確認系統標準",
                "fields":STANDARD["fields"], "rules":STANDARD["rules"], "approved_by":"測試員", "confirmed":True}
        with patch("server.label_source.available", return_value=True), patch("server.label_source.draft", return_value=source):
            self.assertEqual(self.client.post("/api/templates",json=body,headers=self.headers).status_code,409)
            body["source_revision"] = "revision1"
            response = self.client.post("/api/templates",json=body,headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        self.assertIsNone(response.json["image"])
        self.assertEqual(response.json["rules"]["keep_days"],3)
        self.assertEqual(response.json["rules"]["source"]["keep_days"],9)
        job = self.job("inspection",response.json["id"])
        result = self.client.get("/api/inspections/"+job["result"]["inspection_id"]).json
        self.assertEqual(result["status"],"pass")
        self.assertIsNone(result["reference_image"])

    def test_local_source_search_does_not_invent_data(self):
        self.assertEqual(self.client.get("/api/source-labels?q=雙拼").json,{"available":False,"items":[]})

    def test_source_arrival_only_requires_no_frozen_reference_date(self):
        source = {"code":"1017","name":"系統標籤","revision":"current","keep_days":0,
                  "date_settings":[{"content":"到 店 日:","shift_days":1}]}
        body = {"source_code":"1017","source_revision":"current","name":"到店日來源測試",
                "fields":dict(STANDARD["fields"],phone="0800-200-859"),
                "rules":{"dates":False,"arrival":True,"keep_days":None},
                "approved_by":"測試員","confirmed":True}
        with patch("server.label_source.available",return_value=True), patch("server.label_source.draft",return_value=source):
            response = self.client.post("/api/templates",json=body,headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        self.assertEqual(response.json["reference_dates"]["arrival"],"")
        self.assertTrue(response.json["rules"]["arrival"])
        self.assertFalse(response.json["rules"]["dates"])

    def test_busy_upload_does_not_block_health_requests(self):
        started, release = threading.Event(), threading.Event()
        def slow_ocr(_path):
            started.set()
            release.wait(5)
            return {"lines": make_lines(), "engine": "TEST ONLY", "elapsed": .01}
        with patch.object(FakeOCR, "recognize", side_effect=slow_ocr):
            try:
                first = self.client.post("/api/jobs", data={"kind":"recognition", "photo":(self.photo(),"label.png")}, headers=self.headers)
                self.assertEqual(first.status_code, 202)
                self.assertTrue(started.wait(2))
                before = time.monotonic()
                second = self.client.post("/api/jobs", data={"kind":"reference", "photo":(self.photo(),"label.png")}, headers=self.headers)
                self.assertEqual(second.status_code, 429)
                self.assertLess(time.monotonic() - before, 2)
                self.assertEqual(self.client.get("/healthz").status_code, 200)
            finally:
                release.set()

    def test_invalid_history_page_and_original_access(self):
        self.assertEqual(self.client.get("/api/inspections?page=bad").status_code,400)
        job=self.job()
        self.assertEqual(self.client.get(f"/media/{job['image_id']}/original").status_code,404)
        with self.client.get(job["image"]["url"]) as response:
            self.assertEqual(response.status_code,200)

    def test_extended_fields_and_arrival_are_saved_and_versioned(self):
        fields = dict(STANDARD["fields"], spec="1.8kg/盒", storage="7℃~18℃",
                      company="福和生鮮農產股份有限公司", phone="0800-200-859")
        rules = {"dates": False, "arrival": True, "keep_days": None}
        response = self.standard(fields=fields, rules=rules, reference_dates={"arrival":"2026.11.12"})
        self.assertEqual(response.status_code, 201, response.json)
        self.assertEqual(response.json["fields"], fields)
        self.assertTrue(response.json["rules"]["arrival"])
        self.assertEqual(response.json["reference_dates"]["arrival"], "2026.11.12")
        job = self.job("inspection", response.json["id"], arrival_date="2026-11-14")
        self.assertEqual(job["result"]["request"]["arrival_date"], "2026-11-14")
        result = self.client.get("/api/inspections/" + job["result"]["inspection_id"]).json
        self.assertEqual(result["template_snapshot"]["fields"]["phone"], fields["phone"])
        self.assertEqual(result["result"]["inputs"]["arrival_date"], "2026-11-14")
        self.assertNotEqual(result["status"], "pass")

    def test_invalid_optional_fields_and_arrival_are_rejected(self):
        self.assertEqual(self.standard(fields=dict(STANDARD["fields"], phone=123)).status_code, 400)
        self.assertEqual(self.standard(fields=dict(STANDARD["fields"], company="x"*501)).status_code, 400)
        self.assertEqual(self.standard(rules={"dates":False,"arrival":True}, reference_dates={"arrival":"2026.02.30"}).status_code,400)
        self.assertEqual(self.standard(rules={"dates":True,"arrival":True}, reference_dates={"manufacture":"2026.11.10","expiry":"2026.11.13","arrival":"2026.11.14"}).status_code,400)
        response = self.client.post("/api/jobs",data={"kind":"recognition","arrival_date":"2026-02-30","photo":(self.photo(),"label.png")},headers=self.headers)
        self.assertEqual(response.status_code, 400)

    def test_eight_character_password_and_attempt_limit(self):
        self.app.config["APP_PASSWORD"] = "testpass"
        response = self.client.post("/api/login", json={"password":"testpass"}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.headers = {"X-CSRF-Token":response.json["csrf"]}
        self.client.post("/api/logout",json={},headers=self.headers)
        self.headers = {"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}
        # The successful sign-in above is also one attempt in the five-minute window.
        for _ in range(9):
            self.assertEqual(self.client.post("/api/login",json={"password":"wrong"},headers=self.headers).status_code,401)
        self.assertEqual(self.client.post("/api/login",json={"password":"wrong"},headers=self.headers).status_code,429)

    def test_auth_media_and_api_protection(self):
        self.app.config["APP_PASSWORD"]="a-test-password"
        self.assertEqual(self.client.get("/api/templates").status_code,401)
        self.assertEqual(self.client.get("/media/missing/image.jpg").status_code,401)
        response=self.client.post("/api/login",json={"password":"a-test-password"},headers=self.headers)
        self.assertEqual(response.status_code,200)
        self.assertNotEqual(response.json["csrf"],self.csrf)
        self.assertEqual(self.client.get("/api/templates").status_code,200)


if __name__=="__main__":unittest.main()
