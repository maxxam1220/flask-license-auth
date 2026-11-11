import io
import tempfile
import time
import unittest
import threading
from unittest.mock import patch
from pathlib import Path
from PIL import Image
from server import create_app
from ocr_worker import OCRMemoryLimitError
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
        response=self.client.post("/api/jobs",data={"kind":kind,"template_id":template_id,"base_date":"2026-11-10","photo":(self.photo(),"標籤.png"),**inputs},headers=self.headers)
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

    def test_direct_scan_without_database_keeps_text_unverified_and_has_no_builtin(self):
        job = self.job("recognition")
        result = self.client.get("/api/inspections/" + job["result"]["inspection_id"]).json
        self.assertEqual(result["status"], "review")
        self.assertIsNone(result["reference_image"])
        self.assertTrue(any(STANDARD["fields"]["product"] in c.get("actual", "") for c in result["result"]["checks"]))
        self.assertEqual(result["result"]["source_match"]["status"], "unavailable")
        self.assertFalse(any(c.get("source") == "builtin" for c in result["result"]["checks"]))
        self.assertTrue(any(c["status"] == "read" for c in result["result"]["checks"]))
        self.assertEqual(result["result"]["coverage"]["total_lines"], result["result"]["coverage"]["covered_lines"])
        self.assertEqual(self.client.get("/api/inspections").json["items"][0]["version"], 0)

    def test_scan_config_exposes_today_without_hardcoded_standards_after_login(self):
        self.app.config["APP_PASSWORD"] = "testpass"
        self.assertEqual(self.client.get("/api/scan-config").status_code,401)
        response = self.client.post("/api/login",json={"password":"testpass"},headers=self.headers)
        self.assertEqual(response.status_code,200)
        response = self.client.get("/api/scan-config")
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json["standards"], [])
        self.assertEqual(response.json["mode"], "system_label")
        self.assertRegex(response.json["today"], r"^\d{4}-\d{2}-\d{2}$")

    def test_system_source_is_selected_and_snapshotted_without_creating_template(self):
        source = {"code":"1013", "name":"測試來源", "revision":"r1", "lines":make_lines()[:3],
                  "fields":STANDARD["fields"], "rules":{"dates":True}, "keep_days":3,
                  "date_settings":[{"content":"製造日期:","format":"A","shift_days":0},
                                   {"content":"有效日期:","format":"B","shift_days":0}]}
        with patch("server.label_source.resolve", return_value={"status":"matched","code":"1013","name":"測試來源","reason":"test","candidates":[],"source":source}) as resolver:
            job = self.job("recognition",source_code="1013")
        self.assertEqual(resolver.call_args.args[2],"1013")
        row = self.client.get("/api/inspections/"+job["result"]["inspection_id"]).json
        self.assertEqual(row["result"]["source_match"]["code"],"1013")
        self.assertEqual(row["result"]["inputs"]["base_date"],"2026-11-10")
        self.assertEqual(row["template_snapshot"]["source"]["revision"],"r1")
        self.assertEqual(self.client.get("/api/templates").json["items"],[])

    def test_recheck_reuses_ocr_and_preserves_original_result(self):
        job = self.job("recognition")
        identifier = job["result"]["inspection_id"]
        original = self.client.get("/api/inspections/"+identifier).json
        with patch.object(FakeOCR,"recognize",side_effect=AssertionError("must reuse OCR")):
            response = self.client.post(f"/api/inspections/{identifier}/recheck",json={"base_date":"2027-11-10"},headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        updated = self.client.get("/api/inspections/"+response.json["inspection_id"]).json
        self.assertEqual(updated["image_id"],original["image_id"])
        self.assertEqual(updated["ocr"],original["ocr"])
        self.assertEqual(updated["result"]["recheck_of"],identifier)
        self.assertEqual(updated["status"],"fail")
        self.assertEqual(self.client.get("/api/inspections/"+identifier).json["result"],original["result"])

    def test_invalid_base_date_and_mixed_references_are_rejected(self):
        for inputs in ({"base_date":"2026-02-30"},{"source_code":"1013","template_id":"x"}):
            response = self.client.post("/api/jobs",data={"kind":"recognition","photo":(self.photo(),"label.png"),**inputs},headers=self.headers)
            self.assertEqual(response.status_code,400,response.json)

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

    def test_memory_stopped_job_is_safe_and_releases_capacity_for_next_photo(self):
        # One available slot makes a leaked permit observable on the very next upload.
        single_slot = threading.BoundedSemaphore(1)
        recognizer = FakeOCR()
        with patch("server.threading.BoundedSemaphore", return_value=single_slot):
            app = create_app({"TESTING":True, "DATA_DIR":Path(self.temp.name)/"memory-guard",
                              "DATABASE_URL":"", "APP_PASSWORD":""}, ocr=recognizer)
        client = app.test_client()
        headers = {"X-CSRF-Token":client.get("/api/session").json["csrf"]}
        success = {"lines":make_lines(), "engine":"TEST ONLY", "elapsed":.01}
        error = OCRMemoryLimitError("worker_budget", 361*1024*1024, 360*1024*1024)
        try:
            with patch.object(recognizer, "recognize", side_effect=[error, success]), patch.object(app.logger, "exception"):
                response = client.post("/api/jobs", data={"kind":"recognition", "base_date":"2026-11-10",
                                       "photo":(self.photo(),"label.png")}, headers=headers)
                self.assertEqual(response.status_code, 202, response.json)
                # Wait for the submitted work (including its finally block), not a timer.
                app.extensions["label_worker"].submit(lambda: None).result(timeout=3)
                failed = client.get("/api/jobs/" + response.json["id"]).json
                self.assertEqual(failed["state"], "failed")
                self.assertEqual(failed["error"], "這張照片的辨識用量超過目前服務可用記憶體，已停止本次辨識。請裁切至單張標籤後重試。")
                self.assertNotIn("worker_budget", str(failed))
                self.assertNotIn("361", str(failed["error"]))
                self.assertNotIn("inspection_id", failed["result"])
                self.assertEqual(client.get("/healthz").status_code, 200)
                self.assertEqual(client.get("/api/inspections").json["items"], [])
                again = client.post("/api/jobs", data={"kind":"recognition", "base_date":"2026-11-10",
                                    "photo":(self.photo(),"next.png")}, headers=headers)
                self.assertEqual(again.status_code, 202, again.json)
                app.extensions["label_worker"].submit(lambda: None).result(timeout=3)
                recovered = client.get("/api/jobs/" + again.json["id"]).json
                self.assertEqual(recovered["state"], "done", recovered)
                self.assertIsNone(recovered["error"])
                self.assertTrue(recovered["result"]["inspection_id"])
                self.assertEqual(client.get("/healthz").status_code, 200)
        finally:
            app.extensions["label_worker"].shutdown(wait=True)
            app.extensions["label_engine"].dispose()

    def test_non_memory_worker_error_keeps_generic_client_message(self):
        with patch.object(FakeOCR, "recognize", side_effect=RuntimeError("private model path and process details")), patch.object(self.app.logger, "exception"):
            response = self.client.post("/api/jobs", data={"kind":"recognition",
                                        "photo":(self.photo(),"label.png")}, headers=self.headers)
            self.assertEqual(response.status_code, 202, response.json)
            self.app.extensions["label_worker"].submit(lambda: None).result(timeout=3)
        failed = self.client.get("/api/jobs/" + response.json["id"]).json
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["error"], "照片辨識失敗。請稍後重新上傳，或改用更清楚的照片。")
        self.assertNotIn("private model", str(failed))

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
