from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import insert, select, update, func, event
from sqlalchemy.dialects import postgresql

import database as db
import history_cleanup
import manual_reference as manual
import reference_photos
from server import create_app


class PendingStandardTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({"TESTING":True,"DATA_DIR":Path(self.temp.name),"DATABASE_URL":"",
            "APP_PASSWORD":"operator-secret","ADMIN_PASSWORD":"manager-secret"},ocr=object())
        self.engine=self.app.extensions["label_engine"];self.client=self.app.test_client()
        self.headers={"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}
        bounds=manual._pending_today_bounds(datetime(2026,11,16,7,tzinfo=timezone.utc))
        self.assertEqual(bounds,("2026-11-15T16:00:00+00:00","2026-11-16T16:00:00+00:00"))
        clock=patch("manual_reference._pending_today_bounds",return_value=bounds)
        clock.start();self.addCleanup(clock.stop)

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose();self.temp.cleanup()

    def login(self,admin=True):
        response=self.client.post("/api/login",json={"password":"manager-secret" if admin else "operator-secret"},headers=self.headers)
        self.assertEqual(response.status_code,200,response.json)
        self.headers["X-CSRF-Token"]=response.json["csrf"]

    def add(self,identifier,image_id=None,created="2026-11-16T04:00:00+00:00",source=None,template="",text="品名：待確認蘋果",product=""):
        image_id=image_id or "image-"+identifier
        row={"id":identifier,"image_id":image_id,"created_at":created,"status":"review","template_id":template,
            "template_snapshot":{"name":"直接掃描","version":0,"image_id":"","source":source},
            "ocr":{"lines":[{"id":0,"text":text,"score":.95,"box":[[0,0],[500,0],[500,25],[0,25]]}]},
            "result":{"fields":{"product":{"value":product}} if product else {},"checks":[],"inputs":{"base_date":"2026-11-16"}}}
        with self.engine.begin() as conn:
            if not conn.execute(select(db.images.c.id).where(db.images.c.id==image_id)).first():
                conn.execute(insert(db.images).values(id=image_id,filename="label.jpg",width=600,height=400,created_at=created))
            conn.execute(insert(db.inspections).values(**row))
        return row

    def get(self,**query):
        response=self.client.get("/api/manual-standards/pending",query_string=query)
        self.assertEqual(response.status_code,200,response.json)
        return response.json

    def test_admin_only_for_pending_metadata(self):
        self.add("one")
        self.assertEqual(self.client.get("/api/manual-standards/pending").status_code,401)
        self.login(False)
        response=self.client.get("/api/manual-standards/pending")
        self.assertEqual(response.status_code,403)
        self.assertEqual(response.json["code"],"admin_required")
        self.login();self.assertEqual(self.get()["total"],1)

    def test_taiwan_today_uses_utc_half_open_boundaries(self):
        self.login()
        self.add("before",created="2026-11-15T15:59:59.999999+00:00")
        self.add("start",created="2026-11-15T16:00:00+00:00")
        self.add("last",created="2026-11-16T15:59:59.999999+00:00")
        self.add("next",created="2026-11-16T16:00:00+00:00")
        today=self.get();all_rows=self.get(range="all")
        self.assertEqual({row["inspection_id"] for row in today["items"]},{"start","last"})
        self.assertEqual((today["total"],all_rows["total"]),(2,4))

    def test_latest_active_inspection_per_image_and_stable_tie_break(self):
        self.login()
        self.add("old","shared",created="2026-11-15T14:00:00+00:00")
        self.add("new-a","shared")
        self.add("new-b","shared")
        self.assertEqual([row["inspection_id"] for row in self.get()["items"]],["new-b"])
        with self.engine.begin() as conn:
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="new-b",batch_id="qa",archived=True,revision=1,updated_at=db.now()))
        self.assertEqual([row["inspection_id"] for row in self.get()["items"]],["new-a"])

    def test_existing_sources_templates_and_reference_photo_exclude_same_image(self):
        self.login()
        self.add("source","matched",source={"code":"1013"})
        self.add("raw-recheck","matched",created="2026-11-16T05:00:00+00:00")
        self.add("template",template="approved-template")
        self.add("attached","attached-image")
        self.add("attached-recheck","attached-image",created="2026-11-16T05:00:00+00:00")
        self.add("pending")
        with self.engine.begin() as conn:
            conn.execute(insert(reference_photos.photos).values(id=db.uid(),image_id="attached-image",inspection_id="attached",
                source_code="manual:existing",source_revision="approved",standard_revision=1,reviewer="QA",note="same product",created_at=db.now()))
        self.assertEqual([row["inspection_id"] for row in self.get(range="all")["items"]],["pending"])

    def test_created_manual_standard_disappears_without_mutating_inspection(self):
        self.login();original=self.add("original","same");self.add("recheck","same",created="2026-11-16T05:00:00+00:00")
        self.assertEqual(self.get()["total"],1)
        body={"name":"待確認蘋果","lines":[{"text":"品名：待確認蘋果"}]}
        preview=self.client.post("/api/inspections/original/manual-standard/preview",json=body,headers=self.headers)
        self.assertEqual(preview.status_code,200,preview.json)
        self.assertEqual(self.get()["total"],1)  # Draft preview is not approval.
        response=self.client.post("/api/inspections/original/manual-standard",json=dict(body,
            preview_hash=preview.json["preview_hash"],reviewer="確認員",note="已核對",confirmed=True),headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        self.assertEqual(self.get(range="all")["total"],0)
        with self.engine.connect() as conn:
            self.assertEqual(dict(conn.execute(select(db.inspections).where(db.inspections.c.id=="original")).mappings().one()),original)

    def test_read_only_paginated_summary_exposes_no_full_ocr_or_result(self):
        self.login()
        for index in range(27):self.add(f"item-{index:02}",product="確認品名" if index==26 else "")
        first=self.get();second=self.get(page=2)
        self.assertEqual((first["total"],len(first["items"]),first["has_more"],len(second["items"]),second["has_more"]),(27,24,True,3,False))
        self.assertEqual(set(first["items"][0]),{"inspection_id","image_id","created_at","name","thumbnail",
            "pending_revision","pending_removed","pending_updated_at","pending_note"})
        self.assertEqual(first["items"][0]["name"],"確認品名")
        self.assertEqual(first["items"][1]["name"],"待確認蘋果")
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(select(func.count()).select_from(db.manual_sources)),0)
            self.assertEqual(conn.scalar(select(func.count()).select_from(db.corrections)),0)

    def test_unrecognised_name_does_not_borrow_dates_or_arbitrary_first_text(self):
        self.login()
        for identifier,text in (("date","到店日：2026.11.19"),("phone","電話：0800-200-859"),("unknown","隨便第一行")):
            self.add(identifier,text=text)
        self.assertTrue(all(row["name"]=="" for row in self.get()["items"]))

    def test_archived_only_record_and_invalid_query_are_rejected_or_excluded(self):
        self.login();self.add("archived")
        with self.engine.begin() as conn:
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="archived",batch_id="qa",archived=True,revision=1,updated_at=db.now()))
        self.assertEqual(self.get()["total"],0)
        for query in ({"range":"yesterday"},{"page":0},{"page":"nan"},{"limit":25},{"limit":0}):
            self.assertEqual(self.client.get("/api/manual-standards/pending",query_string=query).status_code,400)

    def test_quality_gate_excludes_invalid_but_not_clear_business_failures(self):
        self.login()
        for identifier,lines in (
            ("blur",[{"id":0,"text":"品名：日本蘋果","score":.1}]),
            ("empty",[]),
            ("noise",[{"id":0,"text":"??? 1234 !!!","score":.99}]),
            ("partial",[{"id":0,"text":"品名：日本蘋果","score":.98},{"id":1,"text":"地址□","uncertain":True}]),
            ("printed-wrong",[{"id":0,"text":"品名：日本蘋菓","score":0.,"score_kind":"uncertainty_gate",
                "suspected_typo":True,"ambiguous":True,"ambiguity_reason":"cloud_suspected_typo"}]),
        ):
            self.add(identifier)
            with self.engine.begin() as conn:
                conn.execute(update(db.inspections).where(db.inspections.c.id==identifier).values(ocr={"lines":lines},status="fail"))
        result=self.get()
        self.assertEqual(result["total"],2)
        self.assertEqual({row["inspection_id"] for row in result["items"]},{"partial","printed-wrong"})
        for identifier,expected in (("blur",False),("partial",True),("printed-wrong",True)):
            detail=self.client.get(f"/api/inspections/{identifier}")
            draft=self.client.get(f"/api/inspections/{identifier}/manual-standard")
            self.assertEqual(detail.json["manual_standard_eligibility"]["eligible"],expected)
            self.assertEqual(draft.json["manual_standard_eligibility"]["eligible"],expected)

    def test_quality_gate_uses_confirmed_correction_and_keeps_original_ocr(self):
        self.login();original=self.add("corrected")
        bad=deepcopy(original["ocr"]);bad["lines"][0].update(score=.1,ambiguous=True)
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id=="corrected").values(ocr=bad))
        self.assertEqual(self.get()["total"],0)
        response=self.client.post("/api/inspections/corrected/corrections",headers=self.headers,json={
            "base_revision":0,"operation":"replace","line_id":0,"kind":"ocr_misread",
            "text":"品名：待確認蘋果","reviewer":"QA","note":"對照照片逐字確認"})
        self.assertEqual(response.status_code,201,response.json)
        self.assertTrue(response.json["manual_standard_eligibility"]["eligible"])
        self.assertEqual(self.get()["total"],1)
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(db.inspections.c.ocr).where(db.inspections.c.id=="corrected")).scalar_one(),bad)

    def test_quality_filter_crosses_batches_before_counting_and_paging(self):
        self.login()
        for index in range(53):self.add(f"unusable-{index:02}",text="??? 12345")
        for index in range(27):self.add(f"useful-{index:02}")
        first,second=self.get(),self.get(page=2)
        self.assertEqual((first["total"],len(first["items"]),len(second["items"])),(27,24,3))
        self.assertTrue(all(row["inspection_id"].startswith("useful-") for row in first["items"]+second["items"]))

    def test_multiple_label_scope_is_excluded_and_cannot_bypass_with_direct_create(self):
        self.login();original=self.add("multiple")
        original["result"]["label_scope"]={"blocked":True}
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id=="multiple").values(result=original["result"]))
        self.assertEqual(self.get()["total"],0)
        detail=self.client.get("/api/inspections/multiple").json
        draft=self.client.get("/api/inspections/multiple/manual-standard").json
        self.assertEqual(detail["manual_standard_eligibility"]["reason_code"],"multiple_labels")
        self.assertFalse(draft["can_create"])
        body={"name":"待確認蘋果","lines":[{"text":"品名：待確認蘋果"}]}
        self.assertEqual(self.client.post("/api/inspections/multiple/manual-standard/preview",json=body,headers=self.headers).status_code,409)
        self.assertEqual(self.client.post("/api/inspections/multiple/manual-standard",json=dict(body,
            preview_hash="not-applicable",reviewer="QA",note="不能混兩張",confirmed=True),headers=self.headers).status_code,409)

    def test_streaming_candidate_query_compiles_for_postgresql(self):
        self.login();self.add("one")
        captured=[]
        def capture(conn,statement,multiparams,params,execution_options):
            if execution_options.get("stream_results"):
                captured.append(statement)
        event.listen(self.engine,"before_execute",capture)
        try:self.get()
        finally:event.remove(self.engine,"before_execute",capture)
        self.assertEqual(len(captured),1)
        compiled=str(captured[0].compile(dialect=postgresql.dialect()))
        self.assertIn("row_number() OVER",compiled)
        self.assertIn("latest_active_image",compiled)
        self.assertIn("labelcheck_corrections",compiled)


if __name__=="__main__":unittest.main()
