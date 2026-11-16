"""Updating one existing manual standard from this inspection, never auto approval."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image
from sqlalchemy import func, insert, select, update

import database as db
import label_source
import manual_reference
import reference_photos
import standard_library
import standard_reference as standards
from server import create_app


CODE = "manual:8584935c00112233445566778899aabb"
NAME = "紐西蘭黃金奇異果切片69元"
OLD_BARCODE = "2758887132038"
NEW_BARCODE = "2758887131932"


def line(identifier, text, score=.99):
    y = identifier * 28
    return {"id": identifier, "text": text, "score": score,
            "box": [[10,y],[430,y],[430,y+20],[10,y+20]]}


class InspectionStandardUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = create_app({"TESTING": True, "DATA_DIR": self.root, "DATABASE_URL": "",
            "APP_PASSWORD": "qa-operator-2026", "ADMIN_PASSWORD": "qa-manager-2026"}, ocr=object())
        self.engine = self.app.extensions["label_engine"]
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token": self.client.get("/api/session").json["csrf"]}
        response = self.client.post("/api/login", json={"password":"qa-manager-2026"}, headers=self.headers)
        self.headers["X-CSRF-Token"] = response.json["csrf"]
        with self.app.app_context():
            self.base, digest = manual_reference.definition({"name": NAME, "keep_days": 3,
                "date_settings": [{"kind":"manufacture","shift_days":0},{"kind":"expiry","shift_days":3}],
                "lines": [{"text":text} for text in ["品名："+NAME,"產地：紐西蘭","舊包裝說明",OLD_BARCODE]]})
        self.base["code"] = CODE
        texts = ["品名："+NAME,"產地：紐西蘭","營養標示","每一份量120公克","本包裝含1份",
                 "每份 每100公克","熱量 60大卡 50大卡","脂肪 0.1公克 0.1公克",
                 "飽和脂防 0公克 0公克","本行印錯","模糊文字",
                 "製造日期：2026.11.16","有效日期：2026.11.19",NEW_BARCODE,"貨號：12345678","12345"]
        self.original = {"id":"latest","image_id":"new-image","template_id":"","status":"fail",
            "template_snapshot":{"source":deepcopy(self.base),"image_id":"","name":"比對","version":0},
            "ocr":{"lines":[line(i,text) for i,text in enumerate(texts)]},
            "result":{"inputs":{"base_date":"2026-11-16"},"checks":[]},"created_at":db.now()}
        self.creation = dict(deepcopy(self.original), id="creation", image_id="old-image",
            ocr={"lines":[line(0,"品名："+NAME),line(1,"舊包裝說明")]})
        for identifier in ("old-image","new-image"):
            folder=self.root/"images"/identifier
            folder.mkdir(parents=True)
            Image.new("RGB",(450,500),"white").save(folder/"image.jpg")
        with self.engine.begin() as conn:
            for identifier in ("old-image","new-image"):
                conn.execute(insert(db.images).values(id=identifier,filename=identifier+".jpg",width=450,height=500,created_at=db.now()))
            conn.execute(insert(db.inspections),[self.creation,self.original])
            conn.execute(insert(db.manual_sources).values(code=CODE,name=NAME,inspection_id="creation",reference_hash=digest,
                snapshot=self.base,active=True,reviewer="QA",note="舊版已核准",created_at=db.now()))
            conn.execute(insert(standards.heads).values(code=CODE,revision=1))
            conn.execute(insert(standards.versions).values(id=db.uid(),code=CODE,revision=1,source_revision=digest,
                operation="create",snapshot=self.base,changes={},inspection_id="creation",reviewer="QA",note="已確認",created_at=db.now()))
            conn.execute(insert(standard_library.categories).values(id="fruit",name="鮮果",name_key="鮮果",revision=1,removed=False,updated_at=db.now()))
            conn.execute(insert(standard_library.items).values(kind="manual",key=CODE,revision=1,category_id="fruit",removed=False,updated_at=db.now()))
        self.add_correction(1)

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def add_correction(self, revision):
        patches = [{"line_id":8,"kind":"ocr_misread","text":"飽和脂肪 0公克 0公克"},
                   {"line_id":9,"kind":"label_misprint","text":"確定印錯"},
                   {"line_id":10,"kind":"uncertain","text":""}]
        with self.engine.begin() as conn:
            conn.execute(insert(db.corrections).values(id=db.uid(),inspection_id="latest",revision=revision,change={},
                patches=patches,ocr=self.original["ocr"],result={},status="review",reviewer="QA",note="訂正",created_at=db.now()))

    def get(self):
        response=self.client.get("/api/inspections/latest/standard")
        self.assertEqual(response.status_code,200,response.json)
        return response.json

    def draft_body(self, photo=True):
        data=self.get()
        return {"base_revision":data["base_revision"],"source_revision":data["source_revision"],
            "draft_manual_revision":data["regrouped_manual_revision"],"use_inspection_photo":photo,
            "changes":{"replace_lines":[{"text":row["text"]} for row in data["regrouped_draft_lines"]]}}

    def post(self, body, preview=False):
        if not preview:
            body=dict(body,reviewer="QA確認人",note="依本次照片確認全文與照片",confirmed=True)
        return self.client.post("/api/inspections/latest/standard"+("/preview" if preview else ""),json=body,headers=self.headers)

    def counts(self):
        with self.engine.connect() as conn:
            return {table.name:conn.scalar(select(func.count()).select_from(table)) for table in
                    (db.images,db.inspections,db.manual_sources,standards.versions,reference_photos.photos)}

    def test_draft_uses_this_photo_corrections_without_dates_or_new_batch_barcode(self):
        data=self.get()
        texts=[row["text"] for row in data["regrouped_draft_lines"]]
        self.assertTrue(data["regrouped_can_apply"])
        self.assertEqual(data["regrouped_draft_basis"],"manual_correction")
        self.assertEqual(data["regrouped_inspection_id"],"latest")
        self.assertIn("飽和脂肪 0公克 0公克",texts)
        self.assertNotIn("舊包裝說明",texts)
        self.assertNotIn("飽和脂防 0公克 0公克",texts)
        self.assertNotIn(NEW_BARCODE,texts)
        self.assertIn("貨號：12345678",texts)
        self.assertIn("12345",texts)
        self.assertEqual({row["id"] for row in data["regrouped_excluded_date_lines"]},{11,12})
        self.assertEqual({row["id"] for row in data["regrouped_excluded_unconfirmed_lines"]},{9,10})
        self.assertEqual(data["regrouped_excluded_barcode_lines"][0]["value"],NEW_BARCODE)
        self.assertEqual(data["current_reference_image"]["id"],"old-image")

    def test_preview_read_only_and_save_same_code_rules_category_old_photos_and_ocr(self):
        body=self.draft_body()
        counts=self.counts()
        preview=self.post(body,True)
        self.assertEqual(preview.status_code,200,preview.json)
        self.assertEqual(preview.json["source"]["reference_image_id"],"new-image")
        self.assertEqual(self.counts(),counts)
        saved=self.post(body)
        self.assertEqual(saved.status_code,201,saved.json)
        source=label_source.draft(self.engine,CODE)
        self.assertEqual(source["reference_image_id"],"new-image")
        self.assertEqual(source["date_settings"],self.base["date_settings"])
        self.assertEqual(source["keep_days"],3)
        self.assertNotIn(NEW_BARCODE,source["barcode_values"])
        self.assertFalse(any("2026.11." in row["text"] for row in source["lines"]))
        library=self.client.get(f"/api/standard-library/manual/{CODE}").json
        self.assertEqual(library["category_id"],"fruit")
        self.assertEqual(library["current_image"]["id"],"new-image")
        self.assertEqual({row["id"] for row in library["photos"]},{"old-image","new-image"})
        self.assertEqual(library["photo_count"],2)
        with self.engine.connect() as conn:
            self.assertEqual(dict(conn.execute(select(db.inspections).where(db.inspections.c.id=="latest")).mappings().one()),self.original)
            self.assertEqual(conn.scalar(select(db.manual_sources.c.snapshot)),self.base)
            newest=conn.execute(select(standards.versions).where(standards.versions.c.revision==2)).mappings().one()
            self.assertEqual(newest["changes"]["draft_origin"],{"inspection_id":"latest","manual_revision":1})
        self.assertEqual(self.counts()[db.manual_sources.name],1)

    def test_photo_only_update_and_same_photo_association_is_idempotent(self):
        body=self.draft_body();body.pop("draft_manual_revision");body["changes"]={}
        self.assertEqual(self.post(body).status_code,201)
        second=self.draft_body();second.pop("draft_manual_revision");second["changes"]={}
        self.assertEqual(self.post(second).status_code,201)
        source=label_source.draft(self.engine,CODE)
        self.assertEqual(source["lines"],self.base["lines"])
        self.assertEqual(self.counts()[reference_photos.photos.name],1)
        self.assertEqual(self.get()["current_reference_image"]["id"],"new-image")

    def test_missing_photo_and_late_attachment_failure_rollback_entire_update(self):
        body=self.draft_body();before=self.counts()
        with patch.object(reference_photos,"attach_locked",side_effect=RuntimeError("QA rollback")):
            with self.assertLogs("server",level="ERROR"):
                self.assertEqual(self.post(body).status_code,500)
        self.assertEqual(self.counts(),before)
        self.assertEqual(self.get()["base_revision"],1)
        (self.root/"images"/"new-image"/"image.jpg").unlink()
        self.assertEqual(self.post(body,True).status_code,409)
        self.assertEqual(self.post(body).status_code,409)
        self.assertEqual(self.counts(),before)

    def test_correction_and_standard_changes_conflict_without_silent_overwrite(self):
        body=self.draft_body();self.add_correction(2)
        self.assertEqual(self.post(body,True).status_code,409)
        self.assertEqual(self.post(body).status_code,409)
        current=self.draft_body();self.assertEqual(self.post(current).status_code,201)
        self.assertEqual(self.post(current).status_code,409)
        self.assertEqual(self.counts()[standards.versions.name],2)

    def test_removed_source_cannot_be_revived_by_an_open_inspection(self):
        body=self.draft_body()
        result=self.client.post(f"/api/standard-library/manual/{CODE}/state",
            json={"item_revision":1,"base_revision":1,"operation":"remove"},headers=self.headers)
        self.assertEqual(result.status_code,200,result.json)
        self.assertEqual(self.post(body).status_code,409)
        self.assertEqual(self.counts()[standards.versions.name],1)
        self.assertEqual(self.counts()[reference_photos.photos.name],0)

    def test_bad_or_multiple_photo_cannot_be_auto_imported_but_current_standard_still_editable(self):
        for ocr,result in [({"lines":[],"image_status":"unreadable"},{}),
                           (self.original["ocr"],{"label_scope":{"blocked":True}})]:
            with self.engine.begin() as conn:
                conn.execute(update(db.inspections).where(db.inspections.c.id=="latest").values(ocr=ocr,result=result))
            data=self.get();self.assertTrue(data["editable"]);self.assertFalse(data["regrouped_can_apply"])
            body=self.draft_body();body["changes"]={}
            self.assertEqual(self.post(body,True).status_code,409)
            self.assertEqual(self.post(body).status_code,409)

    def test_dates_cannot_be_frozen_and_flags_reject_wrong_types(self):
        body=self.draft_body()
        body["changes"]["replace_lines"].append({"text":"有效日期：2026.11.19"})
        self.assertEqual(self.post(body,True).status_code,400)
        self.assertEqual(self.post(body).status_code,400)
        for field,value in [("draft_manual_revision",True),("use_inspection_photo","true")]:
            body=self.draft_body();body[field]=value
            self.assertEqual(self.post(body,True).status_code,400)
            self.assertEqual(self.post(body).status_code,400)

    def test_same_approved_barcode_kept_new_or_dynamic_excluded_without_touching_numbers(self):
        rows=[{"id":0,"text":OLD_BARCODE},{"id":1,"text":NEW_BARCODE},{"id":2,"text":"數量：12"},
              {"id":3,"text":"貨號：12345678"},{"id":4,"text":"1234567890123"}]
        kept,excluded=standards._inspection_draft_barcodes(rows,self.base,{})
        self.assertEqual([row["id"] for row in kept],[0,2,3,4])
        self.assertEqual([row["id"] for row in excluded],[1])
        kept,excluded=standards._inspection_draft_barcodes(rows,dict(self.base,barcode_config={"kind":"1","solar":"2"}),{})
        self.assertEqual([row["id"] for row in excluded],[0,1])
        kept,excluded=standards._inspection_draft_barcodes([{"text":"AB:12.5"}],self.base,
            {"barcodes":{"items":[{"text":"AB:12.5","format":"Code128"}]}})
        self.assertFalse(kept);self.assertEqual(excluded[0]["value"],"AB:12.5")

    def test_operator_and_csrf_cannot_update(self):
        body=self.draft_body()
        response=self.client.post("/api/inspections/latest/standard",json=dict(body,confirmed=True,reviewer="QA",note="原因"))
        self.assertEqual(response.status_code,403)
        response=self.client.post("/api/login",json={"password":"qa-operator-2026"},headers=self.headers)
        self.headers["X-CSRF-Token"]=response.json["csrf"]
        self.assertEqual(self.client.get("/api/inspections/latest/standard").status_code,403)
        self.assertEqual(self.post(body).status_code,403)


if __name__ == "__main__":
    unittest.main()
