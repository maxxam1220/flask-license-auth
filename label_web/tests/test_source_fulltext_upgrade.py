"""Partial catalog/desktop sources become one approved web text reference."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image
from sqlalchemy import func, insert, select

import database as db
import label_source
import reference_catalog
import standard_library
import standard_reference as standards
from source_rules import prepare_source
from source_validation import evaluate_source
from server import create_app


CODE="list:1623"
NAME="紐西蘭愛妃蘋果單顆裝"


def line(identifier,text,**extra):
    y=identifier*27
    return dict(id=identifier,text=text,score=.99,box=[[10,y],[440,y],[440,y+20],[10,y+20]],**extra)


class SourceFulltextUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name)
        self.app=create_app({"TESTING":True,"DATA_DIR":self.folder,"DATABASE_URL":"","APP_PASSWORD":""},ocr=object())
        self.engine=self.app.extensions["label_engine"];self.client=self.app.test_client()
        self.headers={"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}
        self.catalog_row={"code":"1623","name":NAME,"barcode":"4006381333931","barcode_type":"1",
            "keep_days":9,"revision":"list-base","provenance":{},"updated_at":db.now()}
        self.base=reference_catalog.build_draft(self.catalog_row)
        self.desktop=dict(deepcopy(self.base),code="1017",name="系統蘋果",revision="desktop-base",source_kind="desktop",
            comparison_scope="desktop_label",fields={"product":"系統蘋果"},
            lines=[line(0,"品名：系統蘋果")],
            rules={"dates":True,"arrival":False},date_settings=[{"content":"有效日期","format":"B","shift_days":1}],
            barcode_config={"kind":"1","barcode":"4006381333931","master_barcode":"4006381333931","solar":"2","solar_pos":3})
        self.sources={CODE:self.base,"1017":self.desktop}
        self.patches=[patch.object(label_source,"raw_draft",side_effect=lambda engine,code:deepcopy(self.sources.get(str(code)))),
            patch.object(label_source,"available",return_value=True),
            patch.object(label_source,"_desktop_available",return_value=False),
            patch.object(reference_catalog,"records",side_effect=lambda engine:[deepcopy(self.catalog_row)]),
            patch.object(label_source,"raw_catalog",side_effect=lambda engine:self.raw_catalog())]
        for mocked in self.patches:mocked.start()
        self.ocr={"lines":[line(i,text) for i,text in enumerate(["品名："+NAME,"產地：紐西蘭","規格：1顆/袋",
            "內容物：蘋果","營養標示","每一份量100公克","每份 每100公克","熱量 55大卡 55大卡",
            "55","製造日期：2026.11.16","有效日期：2026.11.25","4006381333931"])]}
        self.ocr["lines"].extend([line(12,"□□",uncertain=True,ambiguous=True),line(13,"□",uncertain=True)])
        self.original=self.seed("scan",CODE,self.ocr)

    def tearDown(self):
        for mocked in reversed(self.patches):mocked.stop()
        self.app.extensions["label_worker"].shutdown(wait=True);self.engine.dispose();self.temp.cleanup()

    def raw_catalog(self):
        result={}
        for code,source in self.sources.items():
            result[code]={"code":code,"name":source["name"],"sku":set(),"barcode":set(source["barcode_values"]),
                "spec":set(),"origin":set(),"text":set(),"text_by_kind":{},"source_kind":source["source_kind"]}
            if code==CODE:result[code]["catalog_record"]=deepcopy(self.catalog_row)
        return result

    def seed(self,identifier,code,ocr):
        image_id=identifier+"-image";folder=self.folder/"images"/image_id;folder.mkdir(parents=True)
        Image.new("RGB",(450,600),"white").save(folder/"image.jpg")
        row={"id":identifier,"image_id":image_id,"template_id":"","status":"review",
            "template_snapshot":{"source":deepcopy(self.sources[code]),"image_id":"","name":"清單比對","version":0},
            "ocr":deepcopy(ocr),"result":{"inputs":{"source_code":code,"base_date":"2026-11-16"},"checks":[]},"created_at":db.now()}
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id=image_id,filename="sample.jpg",width=450,height=600,created_at=db.now()))
            conn.execute(insert(db.inspections).values(**row))
        return row

    def payload(self,identifier="scan"):
        response=self.client.get(f"/api/inspections/{identifier}/standard")
        self.assertEqual(response.status_code,200,response.json);return response.json

    def body(self,identifier="scan"):
        data=self.payload(identifier)
        return {"base_revision":data["base_revision"],"source_revision":data["source_revision"],
            "draft_manual_revision":data["regrouped_manual_revision"],"use_inspection_photo":True,
            "changes":{"replace_lines":[{"text":row["text"]} for row in data["regrouped_draft_lines"]]}}

    def save(self,body=None,identifier="scan",preview=False):
        body=body or self.body(identifier)
        if not preview:body=dict(body,reviewer="QA",note="核對本次全文並確認",confirmed=True)
        return self.client.post(f"/api/inspections/{identifier}/standard"+("/preview" if preview else ""),json=body,headers=self.headers)

    def test_catalog_fulltext_same_identity_and_original_rules_no_master_changes(self):
        data=self.payload();self.assertTrue(data["supports_line_replacement"]);self.assertTrue(data["regrouped_can_apply"])
        text=[row["text"] for row in data["regrouped_draft_lines"]]
        self.assertIn("55",text);self.assertIn("熱量 55大卡 55大卡",text);self.assertIn("4006381333931",text)
        self.assertNotIn("□□",text);self.assertNotIn("□",text)
        self.assertEqual({row["id"] for row in data["regrouped_excluded_unconfirmed_lines"]},{12,13})
        body=self.body();preview=self.save(body,preview=True)
        self.assertEqual(preview.status_code,200,preview.json)
        self.assertEqual(preview.json["source"]["comparison_scope"],"approved_text")
        with self.engine.connect() as conn:self.assertEqual(conn.scalar(select(func.count()).select_from(standards.versions)),0)
        saved=self.save(body);self.assertEqual(saved.status_code,201,saved.json)
        source=label_source.draft(self.engine,CODE)
        self.assertEqual(source["code"],CODE);self.assertEqual(source["source_kind"],"catalog")
        self.assertTrue(source["web_text_approved"]);self.assertEqual(source["keep_days"],9)
        self.assertEqual(source["date_settings"],[]);self.assertEqual(source["barcode_config"],self.base["barcode_config"])
        self.assertEqual(source["barcode_values"],self.base["barcode_values"])
        self.assertEqual(source["fields"]["origin"],"紐西蘭")
        self.assertEqual(self.sources[CODE],self.base)
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(select(func.count()).select_from(db.manual_sources)),0)
            self.assertEqual(dict(conn.execute(select(db.inspections).where(db.inspections.c.id=="scan")).mappings().one()),self.original)

    def test_future_resolution_and_comparison_use_fulltext_and_wrong_value_fails(self):
        self.assertEqual(self.save().status_code,201)
        resolved=label_source.resolve(self.engine,self.ocr["lines"])
        self.assertEqual(resolved["status"],"matched",resolved);self.assertEqual(resolved["code"],CODE)
        source=label_source.draft(self.engine,CODE)
        lines=[row for row in self.ocr["lines"] if row["id"]<12]
        evaluated=evaluate_source(lines,source,base_date="2026-11-16")
        self.assertEqual(evaluated["verified_scope"],"approved_text")
        self.assertTrue(any(check.get("expected")=="熱量 55大卡 55大卡" and check["status"]=="pass" for check in evaluated["checks"]))
        wrong=deepcopy(lines);wrong[7]["text"]="熱量 55大卡 56大卡"
        evaluated=evaluate_source(wrong,source,base_date="2026-11-16")
        self.assertTrue(any(check.get("expected")=="熱量 55大卡 55大卡" and check["status"]=="fail" for check in evaluated["checks"]))

    def test_source_library_category_edit_remove_restore_never_falls_back_partial(self):
        self.assertEqual(self.save().status_code,201)
        items=self.client.get("/api/standard-library").json["items"]
        self.assertEqual([(item["kind"],item["key"]) for item in items],[("source",CODE)])
        path=f"/api/standard-library/source/{CODE}";detail=self.client.get(path).json
        self.assertEqual(detail["current_image"]["id"],"scan-image")
        category=self.client.post("/api/standard-library/categories",json={"name":"單顆裝"},headers=self.headers).json
        classified=self.client.post(path+"/category",json={"item_revision":0,"category_id":category["id"],"category_revision":1},headers=self.headers)
        self.assertEqual(classified.status_code,200,classified.json)
        body={key:classified.json[key] for key in ("item_revision","base_revision","source_revision")}
        body["changes"]={"replace_lines":[{"text":row["text"]} for row in classified.json["source"]["lines"]]+[{"text":"請冷藏"}]}
        preview=self.client.post(path+"/preview",json=body,headers=self.headers)
        self.assertEqual(preview.status_code,200,preview.json)
        saved=self.client.post(path+"/save",json=dict(body,preview_hash=preview.json["preview_hash"],reviewer="QA",note="補說明",confirmed=True),headers=self.headers)
        self.assertEqual(saved.status_code,201,saved.json)
        state={"item_revision":saved.json["item_revision"],"base_revision":saved.json["base_revision"],"operation":"remove"}
        removed=self.client.post(path+"/state",json=state,headers=self.headers)
        self.assertEqual(removed.status_code,200,removed.json)
        self.assertIsNone(label_source.draft(self.engine,CODE));self.assertNotEqual(label_source.resolve(self.engine,self.ocr["lines"])["code"],CODE)
        self.assertFalse(any(item["code"]==CODE for item in label_source.search(self.engine,NAME)))
        self.assertFalse(self.payload()["editable"])
        restored=self.client.post(path+"/state",json=dict(state,item_revision=removed.json["item_revision"],operation="restore"),headers=self.headers)
        self.assertEqual(restored.status_code,200,restored.json)
        self.assertEqual(restored.json["category_id"],category["id"])
        self.assertIn("請冷藏",[row["text"] for row in label_source.draft(self.engine,CODE)["lines"]])

    def test_concurrent_save_and_external_revision_change_reject(self):
        body=self.body();self.assertEqual(self.save(body).status_code,201)
        self.assertEqual(self.save(body).status_code,409)
        body=self.body();self.sources[CODE]["revision"]="new-list-revision"
        self.assertEqual(self.save(body).status_code,409)
        self.assertTrue(self.payload()["stale"])

    def test_desktop_dates_barcode_and_layout_sources_preserved(self):
        ocr=deepcopy(self.ocr);ocr["lines"][0]["text"]="品名：系統蘋果"
        self.seed("desktop","1017",ocr)
        before=deepcopy(self.desktop)
        response=self.save(identifier="desktop");self.assertEqual(response.status_code,201,response.json)
        source=label_source.draft(self.engine,"1017")
        self.assertEqual(source["source_kind"],"desktop");self.assertEqual(source["date_settings"],before["date_settings"])
        self.assertEqual(source["barcode_config"],before["barcode_config"]);self.assertEqual(source["keep_days"],9)
        self.assertEqual(self.desktop,before)
        prepared=prepare_source(source,"2026-11-16")
        self.assertEqual(prepared["barcode_values"],prepare_source(before,"2026-11-16")["barcode_values"])
        result=evaluate_source(ocr["lines"],prepared,base_date="2026-11-16")
        self.assertTrue(any(check["status"]=="fail" and "2026.11.26" in str(check.get("expected")) for check in result["checks"]))

    def test_partial_catalog_barcode_cannot_be_declared_wrong_or_complete(self):
        partial=deepcopy(self.base);partial["barcode_values"]=["28039938"]
        lines=[line(0,"品名："+NAME),line(1,"2 803993 832539")]
        result=evaluate_source(lines,partial,base_date="2026-11-16")
        checks=[check for check in result["checks"] if check.get("label")=="條碼"]
        self.assertTrue(checks);self.assertTrue(all(check["status"]=="review" for check in checks))
        self.assertIn("組成規則",checks[0]["reason"])
        result=evaluate_source([line(0,"品名："+NAME),line(1,"4006381333932")],self.base,base_date="2026-11-16")
        self.assertTrue(any(check.get("label")=="條碼" and check["status"]=="fail" for check in result["checks"]))

    def test_photo_explicit_schedule_is_not_overridden_by_keep_days_interval(self):
        source=dict(deepcopy(self.desktop),source_kind="photo",web_text_approved=True,
            date_settings=[{"content":"製造日期","format":"A","shift_days":0},
                           {"content":"有效日期","format":"B","shift_days":1}])
        lines=[line(0,"品名：系統蘋果"),line(1,"製造日期：2026.11.16"),line(2,"有效日期：2026.11.26")]
        result=evaluate_source(lines,source,base_date="2026-11-16")
        self.assertFalse(any(check["key"]=="keep_days" for check in result["checks"]))
        self.assertTrue(any(check["key"]=="expiry_schedule" and check["status"]=="pass" for check in result["checks"]))
        source["date_settings"]=[]
        result=evaluate_source(lines,source,base_date="2026-11-16")
        self.assertTrue(any(check["key"]=="keep_days" and check["status"]=="fail" for check in result["checks"]))

    def test_existing_null_date_offset_is_zero_only_for_validation_and_invalid_order_rejected(self):
        with self.app.app_context():
            source=deepcopy(self.desktop);source["date_settings"][0]["shift_days"]=None
            changed=standards.changed_snapshot(source,source,{"keep_days":4})
            self.assertIsNone(changed["date_settings"][0]["shift_days"])
            source["date_settings"].append({"content":"製造日期","format":"A","shift_days":0})
            from werkzeug.exceptions import BadRequest
            with self.assertRaises(BadRequest):
                standards.changed_snapshot(source,source,{"date_settings":[{"index":0,"shift_days":-20}]})


if __name__=="__main__":unittest.main()
