"""Explicit rule entry for a manual standard with no guessed barcode prefix."""
from copy import deepcopy
from datetime import date
from pathlib import Path
import tempfile
import unittest

from sqlalchemy import func, insert, select, update
from werkzeug.exceptions import BadRequest, Conflict

import barcode_rule_authoring as authoring
import database as db
import manual_reference
import standard_library
import standard_reference as standards
from server import create_app
from source_validation import evaluate_source


CODE="manual:papaya-rule-qa"
RULE={"version":1,"symbology":"EAN13","prefix":"28346654","day_source":"expiry","day_width":3,"suffix":"3"}


def line(identifier,text,**extra):
    y=identifier*30
    return dict(id=identifier,text=text,score=.99,box=[[10,y],[440,y],[440,y+22],[10,y+22]],**extra)


class ManualBarcodeRuleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({"TESTING":True,"DATA_DIR":Path(self.temp.name),"DATABASE_URL":"","APP_PASSWORD":""},ocr=object())
        self.engine=self.app.extensions["label_engine"]
        with self.app.app_context():
            self.source,digest=manual_reference.definition({"name":"測試蜜香木瓜55元","keep_days":3,
                "lines":[{"text":"品名：測試蜜香木瓜55元"},{"text":"2 834665 432436"},{"text":"規格：300g/盒"}],
                "date_settings":[{"kind":"manufacture","shift_days":0},{"kind":"expiry","shift_days":3}]})
        self.source.update(code=CODE,reference_image_id="photo")
        self.original={"id":"scan","image_id":"photo","template_id":"","status":"review",
            "template_snapshot":{"source":deepcopy(self.source)},
            "ocr":{"lines":[line(0,"品名：測試蜜香木瓜55元"),line(1,"2 834665 432436"),line(2,"規格：300g/盒"),
                line(3,"製造日期：2026.11.17"),line(4,"有效日期：2026.11.20 03時")],"barcodes":{"status":"not_read","items":[]}},
            "result":{"inputs":{"base_date":"2026-11-17"},"checks":[]},"created_at":db.now()}
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id="photo",filename="qa.jpg",width=450,height=500,created_at=db.now()))
            conn.execute(insert(db.inspections).values(**self.original))
            conn.execute(insert(db.manual_sources).values(code=CODE,name=self.source["name"],inspection_id="scan",reference_hash=digest,
                snapshot=self.source,active=True,reviewer="QA",note="核准人工文字",created_at=db.now()))
            conn.execute(insert(standards.heads).values(code=CODE,revision=2))
            conn.execute(insert(standards.versions).values(id=db.uid(),code=CODE,revision=2,source_revision=digest,
                operation="edit",snapshot=self.source,changes={},inspection_id="scan",reviewer="QA",note="舊標準",created_at=db.now()))
            conn.execute(insert(standard_library.categories).values(id="fruit",name="水果",name_key="水果",revision=1,removed=False,updated_at=db.now()))
            conn.execute(insert(standard_library.items).values(kind="manual",key=CODE,category_id="fruit",revision=1,removed=False,updated_at=db.now()))

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True);self.engine.dispose();self.temp.cleanup()

    def body(self,rule=None):
        payload=authoring.suggest(self.engine,"scan")
        return {key:payload[key] for key in ("base_revision","source_revision","manual_revision")}|{
            "candidate_id":"manual","manual_rule":rule or deepcopy(RULE),"confirmed_ean13":True,"fill_keep_days":False}

    def save_body(self,rule=None):
        body=self.body(rule);preview=authoring.preview(self.engine,"scan",body)
        return body|{"preview_hash":preview["preview_hash"],"reviewer":"QA","note":"人工確認EAN13種類、組碼與有效日來源","confirmed":True}

    def test_manual_entry_exposes_observation_but_does_not_guess_prefix(self):
        self.assertEqual(self.source["barcode_values"],[])
        self.assertEqual(self.source["barcode_config"],{})
        payload=authoring.suggest(self.engine,"scan")
        self.assertFalse(payload["can_write"])
        self.assertEqual(payload["candidates"],[])
        self.assertTrue(payload["manual_entry"]["available"])
        self.assertEqual(payload["manual_entry"]["observed_value"],"2834665432436")
        self.assertTrue(payload["manual_entry"]["requires_ean13_confirmation"])
        self.assertNotIn("prefix",payload["manual_entry"])

    def test_preview_does_not_write_and_requires_correct_date_and_exact_formula(self):
        body=self.body()
        preview=authoring.preview(self.engine,"scan",body)
        self.assertEqual(preview["candidate"]["rule"],RULE)
        self.assertEqual(preview["before"]["rule"],None)
        self.assertEqual(preview["after"]["keep_days"],3)
        for rule in (dict(RULE,day_source="manufacture"),dict(RULE,suffix="4"),dict(RULE,day_source="arrival")):
            with self.assertRaises(BadRequest):authoring.preview(self.engine,"scan",dict(body,manual_rule=rule))
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(),1)

    def test_save_only_rule_and_evidence_preserves_text_photo_classification_original(self):
        saved=authoring.save(self.engine,"scan",self.save_body())
        self.assertEqual(saved["base_revision"],3)
        with self.engine.connect() as conn:
            version=dict(conn.execute(select(standards.versions).where(standards.versions.c.revision==3)).mappings().one())
            state=dict(conn.execute(select(standard_library.items)).mappings().one())
            original=dict(conn.execute(select(db.inspections)).mappings().one())
            master=dict(conn.execute(select(db.manual_sources)).mappings().one())
        for key in ("code","lines","fields","barcode_values","barcode_config","reference_image_id","date_settings","keep_days"):
            self.assertEqual(version["snapshot"][key],self.source[key],key)
        self.assertEqual(version["snapshot"]["web_barcode_rule"],RULE)
        self.assertTrue(version["snapshot"]["web_barcode_rule_evidence"]["manual_entry"]["confirmed_ean13"])
        self.assertEqual(state["category_id"],"fruit")
        self.assertEqual(original,self.original)
        self.assertEqual(master["snapshot"],self.source)
        lines=deepcopy(self.original["ocr"]["lines"])
        lines[1]["text"]=authoring.compose(RULE,date(2026,11,21))
        lines[3]["text"]="製造日期：2026.11.18"
        lines[4]["text"]="有效日期：2026.11.21 03時"
        result=evaluate_source(lines,version["snapshot"],base_date="2026-11-18")
        self.assertEqual(next(item for item in result["checks"] if item["key"]=="web_barcode_rule")["status"],"pass")
        self.assertEqual(result["status"],"pass",result["checks"])

    def test_editing_to_another_matching_formula_requires_new_preview(self):
        body=self.save_body()
        equivalent=dict(RULE,prefix="283466543",day_width=2)
        self.assertEqual(authoring.compose(equivalent,date(2026,11,20)),"2834665432436")
        with self.assertRaises(Conflict):authoring.save(self.engine,"scan",dict(body,manual_rule=equivalent))
        with self.assertRaises(BadRequest):authoring.save(self.engine,"scan",dict(body,confirmed_ean13=False))
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(standards.heads.c.revision)).scalar(),2)

    def test_existing_rule_can_change_with_visible_before_and_after(self):
        authoring.save(self.engine,"scan",self.save_body())
        equivalent=dict(RULE,prefix="283466543",day_width=2)
        preview=authoring.preview(self.engine,"scan",self.body(equivalent))
        self.assertEqual(preview["before"]["rule"],RULE)
        self.assertEqual(preview["after"]["rule"],equivalent)
        self.assertEqual(authoring.save(self.engine,"scan",self.save_body(equivalent))["base_revision"],4)

    def test_manual_fields_cannot_be_smuggled_into_generated_candidate_body(self):
        with self.assertRaises(BadRequest):authoring.preview(self.engine,"scan",dict(self.body(),candidate_id="generated"))
        invalid=self.body();invalid.pop("confirmed_ean13")
        with self.assertRaises(BadRequest):authoring.preview(self.engine,"scan",invalid)

    def test_spaced_reference_and_barcode_values_are_evidence_not_next_batch_fixed_digits(self):
        source=dict(deepcopy(self.source),web_barcode_rule=deepcopy(RULE),
            barcode_values=["2834665432436","2 834665 432436"])
        immutable=deepcopy(source)
        lines=deepcopy(self.original["ocr"]["lines"])
        lines[3]["text"]="製造日期：2026.11.18"
        lines[4]["text"]="有效日期：2026.11.21 03時"
        next_code=authoring.compose(RULE,date(2026,11,21))
        lines[1]["text"]=f"{next_code[0]} {next_code[1:7]} {next_code[7:]}"
        correct=evaluate_source(lines,source,base_date="2026-11-18")
        self.assertEqual(correct["status"],"pass",correct["checks"])
        self.assertEqual([item["key"] for item in correct["checks"] if 1 in item.get("line_ids",[])],["web_barcode_rule"])
        self.assertFalse(any(item.get("expected") in source["barcode_values"] for item in correct["checks"]))
        # Yesterday's complete/checksum-valid code still fails today's formula.
        # Filtering the reference literal must never filter the observed code.
        lines[1]["text"]="2 834665 432436"
        wrong=evaluate_source(lines,source,base_date="2026-11-18")
        check=next(item for item in wrong["checks"] if item["key"]=="web_barcode_rule")
        self.assertEqual(check["status"],"fail")
        self.assertEqual(check["expected"],next_code)
        self.assertEqual(check["actual"],"2 834665 432436")
        self.assertEqual(wrong["status"],"fail")
        self.assertEqual(source,immutable)


if __name__=="__main__":unittest.main()
