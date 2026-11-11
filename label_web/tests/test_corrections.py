"""Human observations are versioned separately from immutable OCR evidence."""
from copy import deepcopy
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from sqlalchemy import insert, select, func

import database as db
import corrections
from server import create_app
from source_validation import evaluate_source
from test_source_validation import line, source
from test_validation import make_lines, STANDARD
from validation import evaluate


class CorrectionAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING":True, "DATA_DIR":Path(self.temp.name), "DATABASE_URL":"", "APP_PASSWORD":""})
        self.engine = self.app.extensions["label_engine"]
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}
        self.standard = source("品名：測試蘋果", "福和生鮮農產股份有限公司")
        self.lines = [dict(line(0,"品名：測試蘋菓",score=.35), ambiguous=True, alternatives=["品名：測試頻果"]),
                      line(1,"福和生鮮農產股份有限公司")]
        self.identifier = self.seed(self.lines, self.standard)

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def seed(self, lines, standard):
        identifier, image_id = db.uid(), db.uid()
        result = evaluate_source(lines, standard, base_date="2026-11-11")
        result["inputs"] = {"base_date":"2026-11-11", "batch_date":"", "arrival_date":"", "source_code":"TEST-ONLY"}
        result["source_match"] = {"status":"matched", "code":"TEST-ONLY"}
        snapshot = {"id":"", "image_id":"", "name":"測試來源", "version":0, "mode":"system_label", "source":standard}
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id=image_id,created_at=db.now(),filename="fixture.png",width=500,height=200))
            conn.execute(insert(db.inspections).values(id=identifier,image_id=image_id,template_id="",template_snapshot=snapshot,
                status=result["status"],result=result,ocr={"engine":"TEST", "lines":deepcopy(lines)},created_at=db.now()))
        return identifier

    def read(self):
        return self.client.get(f"/api/inspections/{self.identifier}").json

    def post(self, **changes):
        body = {"base_revision":0,"line_id":0,"kind":"ocr_misread","text":"品名：測試蘋果","reviewer":"測試員","note":"逐字核對照片"}
        body.update(changes)
        return self.client.post(f"/api/inspections/{self.identifier}/corrections",json=body,headers=self.headers)

    def count(self, table=db.corrections):
        with self.engine.connect() as conn:
            return conn.scalar(select(func.count()).select_from(table))

    def test_confirmed_low_confidence_ambiguity_becomes_human_pass_with_raw_preserved(self):
        before = self.read()
        with patch("server.label_source.resolve", side_effect=AssertionError("Must use original snapshot")):
            response = self.post()
        self.assertEqual(response.status_code,201,response.json)
        after, manual = response.json, response.json["manual_revision"]
        self.assertEqual(manual["status"],"pass")
        self.assertEqual(manual["ocr"]["lines"][0]["score"],.35)
        self.assertTrue(manual["ocr"]["lines"][0]["ambiguous"])
        self.assertTrue(manual["ocr"]["lines"][0]["original_ocr_ambiguous"])
        self.assertTrue(manual["ocr"]["lines"][0]["human_verified"])
        for key in ("ocr","result","status","template_snapshot","image_id"):
            self.assertEqual(after[key],before[key],key)
        self.assertEqual(manual["result"]["inputs"],before["result"]["inputs"])
        self.assertTrue(manual["result"]["checks"][0]["human_assessment"])

    def test_human_typo_remains_fail_no_completion_from_standard(self):
        response = self.post(text="品名：測試蘋")
        self.assertEqual(response.status_code,201)
        manual = response.json["manual_revision"]
        self.assertEqual(manual["status"],"fail")
        self.assertEqual(manual["ocr"]["lines"][0]["text"],"品名：測試蘋")

    def test_print_error_forces_fail_even_equal_expected(self):
        response = self.post(kind="label_misprint")
        self.assertEqual(response.json["manual_revision"]["status"],"fail")
        self.assertTrue(any(c["key"]=="manual_0" and c["status"]=="fail" for c in response.json["manual_revision"]["result"]["checks"]))

    def test_uncertain_blank_retains_observed_text_and_never_claims_pass(self):
        response = self.post(kind="uncertain",text="")
        manual = response.json["manual_revision"]
        self.assertEqual(manual["status"],"review")
        self.assertEqual(manual["ocr"]["lines"][0]["text"],self.lines[0]["text"])
        self.assertFalse(manual["ocr"]["lines"][0]["human_verified"])

    def test_revoke_is_new_version_and_returns_to_original_evidence(self):
        first = self.post().json["manual_revision"]
        response = self.post(base_revision=1,operation="revoke",kind=None,text=None)
        self.assertEqual(response.status_code,201,response.json)
        second = response.json["manual_revision"]
        self.assertEqual(second["revision"],2)
        self.assertEqual(second["patches"],[])
        self.assertEqual(second["ocr"]["lines"],self.lines)
        with self.engine.connect() as conn:
            stored = conn.execute(select(db.corrections).where(db.corrections.c.revision==1)).mappings().one()
        self.assertEqual(stored["result"],first["result"])
        self.assertEqual(response.json["correction_history"][0]["operation"],"revoke")

    def test_conflict_unknown_line_invalid_types_and_control_text_are_rejected(self):
        for changes in ({"base_revision":True},{"line_id":True},{"line_id":999},{"kind":"copy"},{"text":""},
                        {"text":"a"*1001},{"reviewer":""},{"note":" "},{"text":"a\x00b"},
                        {"reviewer":"a\x00b"},{"note":"a\x00b"},{"operation":"copy"},
                        {"operation":[]},{"kind":{}},{"text":[]},{"reviewer":{}},{"note":[]}):
            with self.subTest(changes=changes):
                self.assertEqual(self.post(**changes).status_code,400)
        self.assertEqual(self.count(),0)
        self.assertEqual(self.post().status_code,201)
        self.assertEqual(self.post().status_code,409)
        self.assertEqual(self.post(base_revision=1,operation="revoke",note="").status_code,400)
        self.assertEqual(self.count(),1)

    def test_authentication_and_csrf_protect_corrections(self):
        url = f"/api/inspections/{self.identifier}/corrections"
        self.assertEqual(self.client.post(url,json={}).status_code,403)
        self.app.config["APP_PASSWORD"]="testpass"
        self.assertEqual(self.client.get(url).status_code,401)
        self.assertEqual(self.post().status_code,401)
        self.assertEqual(self.count(),0)

    def test_history_pagination_and_original_status_filter(self):
        for i in range(22):
            self.assertEqual(self.post(base_revision=i,note=f"確認 {i}").status_code,201)
        detailed = self.read()
        self.assertEqual(len(detailed["correction_history"]),10)
        self.assertTrue(detailed["correction_history_has_more"])
        page1=self.client.get(f"/api/inspections/{self.identifier}/corrections").json
        page2=self.client.get(f"/api/inspections/{self.identifier}/corrections?page=2").json
        self.assertEqual(len(page1["items"]),20)
        self.assertTrue(page1["has_more"])
        self.assertEqual([x["revision"] for x in page2["items"]],[2,1])
        listed=self.client.get("/api/inspections?status=review").json["items"][0]
        self.assertEqual((listed["status"],listed["manual_status"],listed["manual_revision"]),("review","pass",22))
        self.assertEqual(self.client.get("/api/inspections?status=pass").json["items"],[])

    def test_simultaneous_edits_with_same_base_have_one_winner(self):
        barrier=threading.Barrier(2)
        responses=[]
        def save(name):
            client=self.app.test_client()
            headers={"X-CSRF-Token":client.get("/api/session").json["csrf"]}
            barrier.wait()
            responses.append(client.post(f"/api/inspections/{self.identifier}/corrections",headers=headers,json={
                "base_revision":0,"line_id":0,"kind":"ocr_misread","text":"品名：測試蘋果","reviewer":name,"note":"核對照片"}).status_code)
        workers=[threading.Thread(target=save,args=(str(i),)) for i in range(2)]
        for worker in workers:worker.start()
        for worker in workers:worker.join(timeout=10)
        self.assertEqual(sorted(responses),[201,409])
        self.assertEqual(self.count(),1)

    def test_recheck_copy_failure_rolls_back_new_inspection(self):
        self.post()
        before=self.count(db.inspections)
        with patch("server.corrections.build_revision",side_effect=RuntimeError("test rollback")), self.assertLogs(self.app.logger,level="ERROR"):
            response=self.client.post(f"/api/inspections/{self.identifier}/recheck",json={"base_date":"2026-11-12"},headers=self.headers)
        self.assertEqual(response.status_code,500)
        self.assertEqual(self.count(db.inspections),before)
        self.assertEqual(self.count(),1)

    def test_other_conflicting_candidate_is_not_resolved_by_one_human_line(self):
        self.identifier=self.seed([self.lines[0],line(2,"品名：測試蘋果",y=100)],source("品名：測試蘋果"))
        response=self.post()
        self.assertEqual(response.json["manual_revision"]["status"],"review")
        self.assertEqual(next(c for c in response.json["manual_revision"]["result"]["checks"] if c["key"]=="product")["status"],"review")

    def test_confirmed_dates_keep_original_score_and_detect_reversal(self):
        lines=[dict(line(0,"製造日期：2026.11.11",score=.3),ambiguous=True),line(1,"有效日期：2026.11.10")]
        self.identifier=self.seed(lines,source())
        response=self.post(text=lines[0]["text"])
        checks=response.json["manual_revision"]["result"]["checks"]
        self.assertEqual(next(c for c in checks if c["key"]=="date_order")["status"],"fail")
        self.assertEqual(response.json["manual_revision"]["ocr"]["lines"][0]["score"],.3)

    def test_legacy_template_human_confirmation_uses_original_reference(self):
        lines=make_lines();lines[0].update(text="品名：雙拼水菓盒",score=.3,ambiguous=True)
        result=evaluate(lines,STANDARD,"2026-11-10")
        result["inputs"]={"batch_date":"2026-11-10"}
        original={"id":"legacy-test","ocr":{"lines":lines},"result":result,"status":result["status"],"template_snapshot":deepcopy(STANDARD)}
        action=corrections.validate_request({"base_revision":0,"line_id":0,"kind":"ocr_misread","text":"品名：雙拼水果盒","reviewer":"測試","note":"核對"},original)
        updated=corrections.build_revision(original,None,action,db.now())
        self.assertEqual(updated["status"],"pass")
        self.assertEqual(original["ocr"]["lines"][0]["score"],.3)


if __name__ == "__main__":
    unittest.main()
