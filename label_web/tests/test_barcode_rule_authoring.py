"""Approval creates a versioned web rule, never a printer rule or OCR rewrite."""
from copy import deepcopy
from datetime import date
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import func, insert, select, update

import barcode_rule_authoring as authoring
import database as db
import label_source
import reference_catalog
import standard_library
import standard_reference as standards
from server import create_app
from source_validation import evaluate_source


RULE={"version":1,"symbology":"EAN13","prefix":"28039938","day_source":"expiry","day_width":3,"suffix":"3"}


def line(identifier,text,**extra):
    y=identifier*32
    return dict(id=identifier,text=text,score=.99,box=[[10,y],[450,y],[450,y+24],[10,y+24]],**extra)


def observed(expiry="2026.11.21",value="2803993832539"):
    return [line(0,"品名：測試單顆蘋果"),line(1,"製造日期：2026.11.12"),
            line(2,"有效日期："+expiry),line(3,value)]


class BarcodeRuleAuthoringTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({"TESTING":True,"DATA_DIR":Path(self.temp.name),"DATABASE_URL":"","APP_PASSWORD":""},ocr=object())
        self.engine=self.app.extensions["label_engine"]
        self.base=reference_catalog.build_draft({"code":"1623","name":"測試單顆蘋果","barcode":"28039938",
            "barcode_type":"1","keep_days":9,"revision":"catalog-base","provenance":{}})
        self.base.update(web_text_approved=True,comparison_scope="approved_text",reference_image_id="original-photo")
        self.base["lines"]=[line(0,"品名：測試單顆蘋果"),line(3,"2803993832539")]
        self.original={"id":"scan","image_id":"photo","template_id":"","status":"review",
            "template_snapshot":{"source":deepcopy(self.base)},"ocr":{"lines":observed()},
            "result":{"inputs":{"base_date":"2026-11-12"},"checks":[]},"created_at":db.now()}
        self.mock=patch.object(label_source,"raw_draft",side_effect=lambda engine,code:deepcopy(self.base) if code==self.base["code"] else None)
        self.mock.start()
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id="photo",filename="sample.jpg",width=500,height=500,created_at=db.now()))
            conn.execute(insert(db.inspections).values(**self.original))
            conn.execute(insert(standard_library.categories).values(id="fruit",name="水果",name_key="水果",revision=1,removed=False,updated_at=db.now()))
            conn.execute(insert(standard_library.items).values(kind="source",key="list:1623",revision=1,category_id="fruit",removed=False,updated_at=db.now()))

    def tearDown(self):
        self.mock.stop();self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose();self.temp.cleanup()

    def choice(self,fill=False):
        data=authoring.suggest(self.engine,"scan")
        candidate=next(row for row in data["candidates"] if row["rule"]==RULE)
        return {key:data[key] for key in ("base_revision","source_revision","manual_revision")}|{
            "candidate_id":candidate["id"],"fill_keep_days":fill}

    def save_body(self,fill=False):
        body=self.choice(fill);preview=authoring.preview(self.engine,"scan",body)
        return body|{"preview_hash":preview["preview_hash"],"confirmed":True,"reviewer":"管理員","note":"確認有效日期太陽日與固定尾碼假設"}

    def test_suggestion_preview_read_only_unapproved_and_keep_existing(self):
        before=deepcopy(self.original)
        data=authoring.suggest(self.engine,"scan")
        self.assertTrue(data["can_write"])
        self.assertIsNone(data["current_rule"])
        self.assertEqual(data["keep_days"],{"current":9,"suggested":None,"can_fill":False,"reason":"已有保存天數，不會用照片覆寫。"})
        candidate=next(item for item in data["candidates"] if item["rule"]==RULE)
        self.assertIn("本次觀察",candidate["parts"][3]["label"])
        self.assertTrue(any("尚未核准" in text for text in candidate["warnings"]))
        authoring.preview(self.engine,"scan",self.choice())
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(),0)
            self.assertEqual(dict(conn.execute(select(db.inspections)).mappings().one()),before)

    def test_save_version_only_preserves_standard_photo_classification_and_raw(self):
        saved=authoring.save(self.engine,"scan",self.save_body())
        self.assertTrue(saved["recheck_required"])
        with self.engine.connect() as conn:
            row=dict(conn.execute(select(standards.versions)).mappings().one())
            current=dict(conn.execute(select(db.inspections)).mappings().one())
            state=dict(conn.execute(select(standard_library.items)).mappings().one())
            self.assertEqual(conn.execute(select(func.count()).select_from(standard_library.audit)).scalar(),1)
        self.assertEqual(row["code"],"list:1623")
        self.assertEqual(row["snapshot"]["web_barcode_rule"],RULE)
        for key in ("lines","barcode_config","barcode_values","date_settings","keep_days","reference_image_id"):
            self.assertEqual(row["snapshot"][key],self.base[key],key)
        self.assertEqual(state["category_id"],"fruit")
        self.assertEqual(current,self.original)

    def test_missing_days_can_fill_but_not_existing_zero(self):
        self.base["keep_days"]=None
        data=authoring.suggest(self.engine,"scan")
        self.assertEqual(data["keep_days"]["suggested"],9)
        self.assertTrue(data["keep_days"]["can_fill"])
        saved=authoring.save(self.engine,"scan",self.save_body(True))
        self.assertEqual(saved["keep_days"],9)
        self.base["keep_days"]=0;self.base["revision"]="new-base"
        data=authoring.suggest(self.engine,"scan")
        self.assertEqual(data["keep_days"]["current"],0)
        self.assertFalse(data["keep_days"]["can_fill"])

    def test_unreliable_or_business_invalid_dates_do_not_suggest_days(self):
        self.base["keep_days"]=None
        for expiry,base_date,uncertain in (("2026.11.11","2026-11-12",False),
                ("2026.11.21","2026-11-22",False),("2025.11.21","2026-11-12",False),
                ("2026.11.21","2026-11-12",True)):
            ocr={"lines":observed(expiry)}
            ocr["lines"][2]["ambiguous"]=uncertain
            with self.engine.begin() as conn:
                conn.execute(update(db.inspections).where(db.inspections.c.id=="scan").values(
                    ocr=ocr,result={"inputs":{"base_date":base_date}}))
            data=authoring.suggest(self.engine,"scan")
            self.assertIsNone(data["keep_days"]["suggested"])
            self.assertFalse(data["keep_days"]["can_fill"])

    def test_manual_source_rule_save_preserves_manual_master(self):
        self.base.update(code="manual:rule-test",source_kind="manual")
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id=="scan").values(
                template_snapshot={"source":deepcopy(self.base)}))
            conn.execute(insert(db.manual_sources).values(code=self.base["code"],name=self.base["name"],inspection_id="scan",
                snapshot=deepcopy(self.base),reference_hash=self.base["revision"],active=True,reviewer="QA",note="已核准",created_at=db.now()))
        saved=authoring.save(self.engine,"scan",self.save_body())
        self.assertEqual(saved["source_code"],"manual:rule-test")
        with self.engine.connect() as conn:
            master=dict(conn.execute(select(db.manual_sources)).mappings().one())
        self.assertEqual(master["snapshot"],self.base)
        self.assertNotIn("web_barcode_rule",master["snapshot"])

    def test_no_source_and_photo_sources_are_explicitly_unsupported(self):
        for snapshot,template_id in (({},""),({"source":deepcopy(self.base)},"photo-template")):
            with self.engine.begin() as conn:
                conn.execute(update(db.inspections).where(db.inspections.c.id=="scan").values(
                    template_snapshot=snapshot,template_id=template_id))
            data=authoring.suggest(self.engine,"scan")
            self.assertFalse(data["can_write"])
            self.assertEqual(data["candidates"],[])
            self.assertTrue(data["reason"])

    def test_next_batch_uses_rule_not_old_fixed_hri_or_prefix(self):
        source=dict(deepcopy(self.base),web_barcode_rule=RULE)
        next_lines=observed("2026.11.22",authoring.compose(RULE,date(2026,11,22)))
        next_lines[1]["text"]="製造日期：2026.11.13"
        result=evaluate_source(next_lines,source,base_date="2026-11-13")
        check=next(item for item in result["checks"] if item["key"]=="web_barcode_rule")
        self.assertEqual(check["status"],"pass")
        self.assertFalse(any(item["status"]=="fail" for item in result["checks"]),result["checks"])
        self.assertFalse(any(item["expected"]=="28039938" for item in result["checks"]))
        self.assertEqual(source["lines"][1]["text"],"2803993832539")

    def test_valid_checksum_wrong_formula_fails_and_dates_stay_independent(self):
        source=dict(deepcopy(self.base),web_barcode_rule=RULE)
        result=evaluate_source(observed(value="2803993831631"),source,base_date="2026-11-12")
        self.assertEqual(next(row for row in result["checks"] if row["key"]=="web_barcode_rule")["status"],"fail")
        wrong_year=observed("2025.11.21")
        result=evaluate_source(wrong_year,source,base_date="2026-11-12")
        self.assertEqual(next(row for row in result["checks"] if row["key"]=="web_barcode_rule")["status"],"pass")
        self.assertEqual(result["status"],"fail")
        self.assertTrue(any(row["source"]=="date" and row["status"]=="fail" for row in result["checks"]))

    def test_uncertain_or_missing_date_never_rule_pass(self):
        source=dict(deepcopy(self.base),web_barcode_rule=RULE)
        lines=observed();lines[2]["ambiguous"]=True
        for values in (lines,[item for item in observed() if item["id"]!=2]):
            result=evaluate_source(values,source,base_date="2026-11-12")
            self.assertEqual(next(row for row in result["checks"] if row["key"]=="web_barcode_rule")["status"],"review")

    def test_static_embedded_codes_and_other_fields_not_filtered(self):
        source=dict(deepcopy(self.base),web_barcode_rule=RULE)
        source["lines"].append(line(5,"貨號：28039938"))
        lines=observed()+[line(5,"貨號：28039939")]
        result=evaluate_source(lines,source,base_date="2026-11-12")
        self.assertTrue(any(row["status"]=="fail" and row["expected"]=="貨號：28039938" for row in result["checks"]))
        for value in ("貨號：28039938","AB:12.5","2803993832534"):
            self.assertFalse(authoring.dynamic_literal(RULE,value))

    def test_save_requires_preview_and_replay_conflicts(self):
        body=self.save_body()
        with self.app.test_request_context():
            from werkzeug.exceptions import Conflict
            with self.assertRaises(Conflict):authoring.save(self.engine,"scan",dict(body,preview_hash="wrong"))
            authoring.save(self.engine,"scan",body)
            with self.assertRaises(Conflict):authoring.save(self.engine,"scan",body)
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(),1)


if __name__=="__main__":unittest.main()
