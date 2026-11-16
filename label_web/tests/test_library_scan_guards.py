"""Offline removal races: never pay or pass against a removed local standard."""
from copy import deepcopy
import io
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from PIL import Image
from sqlalchemy import insert, select, update, func

import cloud_budget
import database as db
import label_source
import manual_reference
from server import create_app
from test_validation import make_lines, STANDARD


class ScanOCR:
    def __init__(self):
        self.calls = 0
        self.hook = None

    def recognize(self, path):
        self.calls += 1
        if self.hook:
            self.hook()
        return {"lines":make_lines(), "engine":"offline test", "elapsed":.01,
                "usage":{"input_tokens":123,"output_tokens":45}}


class LibraryScanGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.local, self.cloud = ScanOCR(), ScanOCR()
        self.app = create_app({"TESTING":True,"DATA_DIR":self.root,"DATABASE_URL":"",
            "APP_PASSWORD":"","CLOUD_OCR":self.cloud,"CLOUD_TRIAL_LIMIT":20}, self.local)
        self.engine = self.app.extensions["label_engine"]
        self.worker = self.app.extensions["label_worker"]
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}
        self.logs = patch.object(self.app.logger, "exception")
        self.logs.start()
        self.addCleanup(self.logs.stop)
        self.photo_standard = dict(id="photo-v1",family_id="photo-family",version=1,active=True,
            name="Offline photo standard",image_id="",fields=deepcopy(STANDARD["fields"]),
            rules=deepcopy(STANDARD["rules"]),reference_dates={},approved_by="QA",created_at=db.now())
        with self.engine.begin() as conn:
            conn.execute(insert(db.templates).values(**self.photo_standard))
        source, digest = manual_reference.definition({"name":STANDARD["fields"]["product"],
            "lines":[{"text":"品名："+STANDARD["fields"]["product"]},
                     {"text":"產地："+STANDARD["fields"]["origin"]}]})
        self.source = dict(source, code="manual:scan-test")
        with self.engine.begin() as conn:
            conn.execute(insert(db.manual_sources).values(code=self.source["code"],name=self.source["name"],
                inspection_id="manual-origin",reference_hash=digest,snapshot=self.source,active=True,
                reviewer="QA",note="Offline fixture",created_at=db.now()))

    def tearDown(self):
        self.worker.shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def count(self, table):
        with self.engine.connect() as conn:
            return conn.scalar(select(func.count()).select_from(table))

    def photo(self):
        output = io.BytesIO()
        with Image.new("RGB", (500,400), "white") as image:
            image.save(output, "PNG")
        output.seek(0)
        return output

    def upload(self, **options):
        data = {"kind":"inspection","template_id":"photo-v1","base_date":"2026-11-10",
                "label_scope":"full","recognition_engine":"cloud", **options,
                "photo":(self.photo(),"scan.png")}
        return self.client.post("/api/jobs", data=data, headers=self.headers)

    def finish(self, response, state="done"):
        self.assertEqual(response.status_code, 202, response.json)
        self.worker.submit(lambda: None).result(timeout=5)
        result = self.client.get("/api/jobs/"+response.json["id"]).json
        self.assertEqual(result["state"], state, result)
        return result

    def deactivate(self, kind="photo"):
        return self.change_library_state(kind, "remove")

    def change_library_state(self, kind, operation):
        key = "photo-family" if kind=="photo" else self.source["code"]
        path = f"/api/standard-library/{kind}/{key}"
        detail = self.client.get(path)
        self.assertEqual(detail.status_code,200,detail.json)
        response = self.client.post(path+"/state",json={"item_revision":detail.json["item_revision"],
            "base_revision":detail.json["base_revision"],"operation":operation},headers=self.headers)
        self.assertEqual(response.status_code,200,response.json)
        return response.json

    def recognize(self, identifier, request_id="c"*32):
        return self.client.post(f"/api/inspections/{identifier}/recognize",json={"request_id":request_id,
            "recognition_engine":"cloud","label_scope":"full"},headers=self.headers)

    def test_removed_manual_and_photo_selections_stop_before_paid_call(self):
        self.deactivate("manual")
        response = self.upload(kind="recognition",template_id="",source_code=self.source["code"])
        self.assertEqual(response.status_code,409,response.json)
        self.deactivate()
        response = self.upload()
        self.assertEqual(response.status_code,409,response.json)
        self.assertEqual((self.cloud.calls,self.count(cloud_budget.calls),self.count(db.jobs)),(0,0,0))

    def test_queued_job_removed_before_start_spends_no_trial_call(self):
        for kind in ("photo","manual"):
            with self.subTest(kind=kind):
                gate = threading.Event()
                self.worker.submit(lambda: gate.wait(5))
                options = {} if kind=="photo" else {"kind":"recognition","template_id":"","source_code":self.source["code"]}
                try:
                    response = self.upload(**options)
                    self.assertEqual(response.status_code,202,response.json)
                    self.deactivate(kind)
                finally:
                    gate.set()
                failed = self.finish(response,"failed")
                self.assertNotIn("inspection_id",failed["result"])
        self.assertEqual((self.cloud.calls,self.count(cloud_budget.calls),self.count(db.inspections)),(0,0,0))

    def test_removal_during_paid_call_preserves_usage_but_creates_no_pass(self):
        for kind in ("photo","manual"):
            with self.subTest(kind=kind):
                entered, release = threading.Event(), threading.Event()
                def block():
                    entered.set()
                    if not release.wait(5):
                        raise RuntimeError("test deadline")
                self.cloud.hook = block
                options = {} if kind=="photo" else {"kind":"recognition","template_id":"","source_code":self.source["code"]}
                try:
                    response = self.upload(**options)
                    self.assertTrue(entered.wait(3))
                    self.deactivate(kind)
                finally:
                    release.set()
                failed = self.finish(response,"failed")
                self.assertNotIn("inspection_id",failed["result"])
                self.assertEqual(self.count(db.inspections),0)
                with self.engine.connect() as conn:
                    charge = dict(conn.execute(select(cloud_budget.calls).where(
                        cloud_budget.calls.c.job_id==failed["id"])).mappings().one())
                self.assertEqual(charge["state"],"failed")
                self.assertEqual(charge["usage"],{"input_tokens":123,"output_tokens":45})
        self.assertEqual(self.cloud.calls,2)

    def test_automatic_source_removed_after_resolution_is_checked_at_commit(self):
        actual_resolve = label_source.resolve
        def remove_after_resolve(engine, lines, code):
            result = actual_resolve(engine,lines,code)
            self.assertEqual(result["source"]["code"],self.source["code"])
            self.deactivate("manual")
            return result
        with patch("server.label_source.resolve",side_effect=remove_after_resolve):
            self.finish(self.upload(kind="recognition",template_id=""),"failed")
        self.assertEqual(self.count(db.inspections),0)
        self.assertEqual(self.cloud.calls,1)

    def test_removed_snapshot_cannot_re_recognize_or_retry_but_history_is_readable(self):
        original_job = self.finish(self.upload())
        identifier = original_job["result"]["inspection_id"]
        original = self.client.get("/api/inspections/"+identifier).json
        with self.engine.begin() as conn:
            conn.execute(insert(db.jobs).values(id="failed-snapshot",image_id=original["image_id"],
                kind="inspection",template_id="photo-v1",batch_date="",state="failed",created_at=db.now(),
                result={"request":{"recognition_engine":"cloud","label_scope":"full","base_date":"2026-11-10"},
                        "recognition_standard":deepcopy(original["template_snapshot"])}))
        self.deactivate()
        self.assertEqual(self.recognize(identifier).status_code,409)
        retried = self.client.post("/api/jobs/failed-snapshot/retry",headers=self.headers)
        self.assertEqual(retried.status_code,409,retried.json)
        self.assertEqual(self.client.get("/api/inspections/"+identifier).json,original)
        reviewed = self.client.post(f"/api/inspections/{identifier}/reviews",json={
            "decision":"confirmed_good","reviewer":"QA","note":"Historical evidence retained"},headers=self.headers)
        self.assertEqual(reviewed.status_code,201,reviewed.json)
        correction = self.client.post(f"/api/inspections/{identifier}/corrections",json={
            "base_revision":0,"operation":"replace","line_id":0,"kind":"ocr_misread",
            "text":make_lines()[0]["text"],"reviewer":"QA","note":"Check the old photo"},headers=self.headers)
        self.assertEqual(correction.status_code,201,correction.json)
        self.assertEqual(self.cloud.calls,1)

    def test_superseded_photo_snapshot_remains_usable_without_reactivating_it(self):
        original_job = self.finish(self.upload())
        identifier = original_job["result"]["inspection_id"]
        with self.engine.begin() as conn:
            conn.execute(update(db.templates).where(db.templates.c.id=="photo-v1").values(active=False))
            conn.execute(insert(db.templates).values(**dict(self.photo_standard,id="photo-v2",version=2,name="New version")))
        self.assertEqual(self.upload().status_code,409)
        rerun = self.finish(self.recognize(identifier))
        row = self.client.get("/api/inspections/"+rerun["result"]["inspection_id"]).json
        self.assertEqual(row["template_snapshot"],self.photo_standard)
        with self.engine.connect() as conn:
            self.assertFalse(conn.scalar(select(db.templates.c.active).where(db.templates.c.id=="photo-v1")))

    def test_existing_upload_and_recognition_requests_replay_after_removal(self):
        initial = self.upload(request_id="a"*32)
        job = self.finish(initial)
        identifier = job["result"]["inspection_id"]
        repeated = self.recognize(identifier)
        self.finish(repeated)
        self.deactivate()
        self.assertEqual(self.upload(request_id="a"*32).json,initial.json)
        self.assertEqual(self.recognize(identifier).json,repeated.json)
        self.assertEqual((self.cloud.calls,self.count(db.jobs)),(2,2))

    def test_explicit_removed_manual_recheck_is_rejected_without_changing_history(self):
        job = self.finish(self.upload(kind="recognition",template_id="",source_code=self.source["code"]))
        identifier = job["result"]["inspection_id"]
        original = self.client.get("/api/inspections/"+identifier).json
        self.deactivate("manual")
        response = self.client.post(f"/api/inspections/{identifier}/recheck",json={
            "source_code":self.source["code"],"base_date":"2026-11-10"},headers=self.headers)
        self.assertEqual(response.status_code,409,response.json)
        self.assertEqual(self.count(db.inspections),1)
        self.assertEqual(self.client.get("/api/inspections/"+identifier).json,original)

    def test_restored_standards_are_selectable_again_and_old_versions_stay_inactive(self):
        with self.engine.begin() as conn:
            conn.execute(update(db.templates).where(db.templates.c.id=="photo-v1").values(active=False))
            conn.execute(insert(db.templates).values(**dict(self.photo_standard,id="photo-v2",version=2)))
        self.deactivate()
        self.change_library_state("photo","restore")
        self.assertEqual(self.upload().status_code,409)
        self.finish(self.upload(template_id="photo-v2"))
        self.deactivate("manual")
        self.change_library_state("manual","restore")
        self.finish(self.upload(kind="recognition",template_id="",source_code=self.source["code"]))
        self.assertEqual(self.cloud.calls,2)

    def test_new_photo_version_cannot_revive_removed_family(self):
        reference = self.finish(self.upload(kind="reference",template_id="",recognition_engine="local"))
        self.deactivate()
        body = {"job_id":reference["id"],"name":"Attempted new version","fields":STANDARD["fields"],
            "rules":STANDARD["rules"],"reference_dates":{"manufacture":"2026.11.10","expiry":"2026.11.13"},
            "approved_by":"QA","confirmed":True,"supersedes_id":"photo-v1"}
        response = self.client.post("/api/templates",json=body,headers=self.headers)
        self.assertEqual(response.status_code,409,response.json)
        self.assertEqual(self.count(db.templates),1)

    def test_retry_replays_existing_child_after_removal_but_no_new_child_is_created(self):
        completed = self.finish(self.upload())
        saved = {"request":{"recognition_engine":"cloud","label_scope":"full","base_date":"2026-11-10"},
                 "recognition_standard":deepcopy(self.photo_standard)}
        base = dict(image_id=completed["image_id"],kind="inspection",template_id="photo-v1",
                    batch_date="",state="failed",created_at=db.now())
        with self.engine.begin() as conn:
            conn.execute(insert(db.jobs).values(id="failed-parent",result=saved,**base))
            conn.execute(insert(db.jobs).values(id="failed-child",result=dict(saved,retry_of="failed-parent",retry_root="failed-parent"),**base))
        self.deactivate()
        replay = self.client.post("/api/jobs/failed-parent/retry",headers=self.headers)
        self.assertEqual(replay.status_code,202,replay.json)
        self.assertEqual(replay.json["id"],"failed-child")
        fresh = self.client.post("/api/jobs/failed-child/retry",headers=self.headers)
        self.assertEqual(fresh.status_code,409,fresh.json)
        self.assertEqual((self.cloud.calls,self.count(db.jobs)),(1,3))


if __name__=="__main__":
    unittest.main()
