"""Cross-feature rounds: corrections, versioned standards, rechecks and restart."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import insert, select

import database as db
import label_source
from server import create_app
from source_validation import evaluate_source, normalize_text


def line(identifier, text, y, score=.99):
    return {"id": identifier, "text": text, "score": score,
            "box": [[0,y],[300,y],[300,y+20],[0,y+20]]}


class ManualWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = {"TESTING": True, "DATA_DIR": Path(self.temp.name), "DATABASE_URL": "", "APP_PASSWORD": ""}
        self.source = {"code": "QA-A", "name": "測試蓮霧", "revision": "base-a-1", "source_kind": "desktop",
            "comparison_scope": "desktop_label", "fields": {"product": "測試蓮霧", "company": "測試生鮮股份有限公司"},
            "lines": [line(0,"品名：測試蓮霧",0),line(1,"測試生鮮股份有限公司",30)],
            "rules": {"dates": True, "arrival": False}, "keep_days": 3,
            "date_settings": [{"content":"製造日期：","format":"A","shift_days":0},
                              {"content":"有效日期：","format":"B","shift_days":0}], "barcode_values": []}
        self.patches = [patch.object(label_source, "available", return_value=True),
            patch.object(label_source, "raw_draft", side_effect=lambda _engine, code: deepcopy(self.source) if code=="QA-A" else None),
            patch.object(label_source, "raw_catalog", side_effect=lambda _engine: self.catalog())]
        for item in self.patches:
            item.start()
        self.start_app()
        self.ocr = {"engine": "QA synthetic error with preserved original confidence", "lines": [
            dict(line(0,"品名：測試蓮務",0,.45), ambiguous=True),
            line(1,"測試農產股份有限公司",30), line(2,"製造日期：2026.11.11",60), line(3,"有效日期：2026.11.14",90)]}
        self.identifier = self.seed(self.source)

    def catalog(self):
        source = self.source
        return {"QA-A": {"code":"QA-A", "name":source["name"], "source_kind":"desktop", "sku":set(),
            "barcode":set(), "spec":set(), "origin":set(), "text":{normalize_text(row["text"]) for row in source["lines"]}}}

    def start_app(self):
        self.app = create_app(self.config)
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}

    def stop_app(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.app.extensions["label_engine"].dispose()

    def tearDown(self):
        self.stop_app()
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def seed(self, source):
        identifier, image_id = db.uid(), db.uid()
        inputs = {"base_date":"2026-11-11", "batch_date":"", "arrival_date":"", "source_code":"QA-A" if source else ""}
        result = evaluate_source(self.ocr["lines"], source, base_date=inputs["base_date"])
        result.update(inputs=inputs, source_match={"status":"matched" if source else "unmatched", "code":"QA-A" if source else "",
            "name":source["name"] if source else "", "candidates":[]})
        standard = {"id":"", "name":"QA local fixture", "version":0, "image_id":"", "mode":"system_label", "source":deepcopy(source)}
        with self.app.extensions["label_engine"].begin() as conn:
            conn.execute(insert(db.images).values(id=image_id,filename="local-qa.png",sha256="0"*64,width=400,height=200,created_at=db.now()))
            conn.execute(insert(db.inspections).values(id=identifier,image_id=image_id,template_id="",template_snapshot=standard,
                status=result["status"],result=result,ocr=deepcopy(self.ocr),created_at=db.now()))
        return identifier

    def read(self, identifier=None):
        response = self.client.get(f"/api/inspections/{identifier or self.identifier}")
        self.assertEqual(response.status_code,200,response.json)
        return response.json

    def correct(self, identifier=None, **changes):
        body={"base_revision":0,"line_id":0,"kind":"ocr_misread","text":"品名：測試蓮霧","reviewer":"本機測試員","note":"逐字對照測試原圖","operation":"replace"}
        body.update(changes)
        return self.client.post(f"/api/inspections/{identifier or self.identifier}/corrections",json=body,headers=self.headers)

    def save_standard(self, **changes):
        current=self.client.get(f"/api/inspections/{self.identifier}/standard").json
        body={"base_revision":current["base_revision"],"source_revision":current["source_revision"],"changes":changes,
              "reviewer":"本機標準測試員","note":"獨立測試比對標準修正","confirmed":True}
        return self.client.post(f"/api/inspections/{self.identifier}/standard",json=body,headers=self.headers)

    def test_correct_standard_recheck_and_restart_preserve_all_evidence(self):
        before=self.read()
        response=self.correct()
        self.assertEqual(response.status_code,201,response.json)
        corrected=self.read()["manual_revision"]
        self.assertEqual(corrected["ocr"]["lines"][0]["score"],.45)
        self.assertTrue(corrected["ocr"]["lines"][0]["human_verified"])
        self.assertEqual(next(c for c in corrected["result"]["checks"] if c["key"]=="product")["status"],"pass")
        self.assertEqual(self.read()["ocr"],before["ocr"])
        saved=self.save_standard(lines=[{"id":1,"text":"測試農產股份有限公司"}])
        self.assertEqual(saved.status_code,201,saved.json)
        self.assertEqual(self.read()["template_snapshot"],before["template_snapshot"])
        response=self.client.post(f"/api/inspections/{self.identifier}/recheck",json=before["result"]["inputs"],headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        child_id=response.json["inspection_id"]
        child=self.read(child_id)
        self.assertEqual(child["ocr"],before["ocr"])
        self.assertEqual(child["manual_revision"]["result"]["status"],"pass",child["manual_revision"]["result"])
        self.assertEqual(child["manual_revision"]["result"]["inputs"]["base_date"],"2026-11-11")
        self.assertEqual(child["manual_revision"]["patches"][0]["reviewer"],"本機測試員")
        self.stop_app(); self.start_app()
        self.assertEqual(self.read(child_id)["manual_revision"],child["manual_revision"])
        self.assertEqual(self.read()["result"],before["result"])
        self.assertEqual(self.read()["ocr"],before["ocr"])

    def test_old_correction_version_cannot_overwrite_or_revoke_newer_version(self):
        self.assertEqual(self.correct().status_code,201)
        stale=self.correct(text="品名：其他水果",base_revision=0)
        self.assertEqual(stale.status_code,409,stale.json)
        stale=self.correct(operation="revoke",base_revision=0)
        self.assertEqual(stale.status_code,409,stale.json)
        self.assertEqual(self.read()["manual_revision"]["patches"][0]["text"],"品名：測試蓮霧")
        response=self.correct(operation="revoke",base_revision=1)
        self.assertEqual(response.status_code,201,response.json)
        self.assertEqual(self.read()["manual_revision"]["patches"],[])
        self.assertEqual(self.read()["manual_revision"]["ocr"]["lines"],self.ocr["lines"])

    def test_corrected_low_confidence_product_can_resolve_previously_unmatched_source(self):
        identifier=self.seed(None)
        response=self.correct(identifier)
        self.assertEqual(response.status_code,201,response.json)
        response=self.client.post(f"/api/inspections/{identifier}/recheck",json={"base_date":"2026-11-11"},headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        child=self.read(response.json["inspection_id"])
        self.assertEqual(child["result"]["source_match"]["code"],"QA-A")
        self.assertEqual(child["manual_revision"]["patches"][0]["text"],"品名：測試蓮霧")

    def test_original_source_change_requires_review_after_manual_standard_approval(self):
        response=self.save_standard(lines=[{"id":1,"text":"測試農產股份有限公司"}])
        self.assertEqual(response.status_code,201,response.json)
        self.source["revision"]="base-a-2"
        self.source["lines"][1]["text"]="測試另一家公司"
        context=self.client.get(f"/api/inspections/{self.identifier}/standard").json
        self.assertTrue(context["stale"])
        response=self.client.post(f"/api/inspections/{self.identifier}/recheck",json={"source_code":"QA-A","base_date":"2026-11-11"},headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        child=self.read(response.json["inspection_id"])
        self.assertTrue(any(c["key"]=="standard_reference_stale" and c["status"]=="review" for c in child["result"]["checks"]))


if __name__ == "__main__":
    unittest.main()
