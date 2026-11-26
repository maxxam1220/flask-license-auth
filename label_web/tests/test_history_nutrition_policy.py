"""History verdicts and grouping use the same policy as new inspections."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import func, insert, select

import database as db
import history_status
from server import create_app


class HistoryNutritionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING":True, "DATA_DIR":Path(self.temp.name),
                               "DATABASE_URL":"", "APP_PASSWORD":""}, ocr=object())
        self.engine = self.app.extensions["label_engine"]
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}
        self.source = {"image_id":"", "name":"蜜香木瓜切片", "version":1,
                       "source":{"lines":[{"id":3, "text":"鈉 9 毫克"}]}}
        self.ocr = {"lines":[{"id":0, "text":"品名：蜜香木瓜切片", "box":[], "score":1},
                             {"id":1, "text":"鈉 9 毫克", "box":[], "score":1}]}
        self.old = {"checks":[{"key":"product", "status":"pass", "line_ids":[0]},
                              {"key":"nutrition_sodium", "status":"fail", "line_ids":[1]},
                              {"key":"source_nutrition_3", "status":"pass", "source_line_ids":[3], "line_ids":[1]}],
                    "fields":{"product":{"value":"蜜香木瓜切片"}}, "status":"fail",
                    "counts":{"pass":2,"fail":1,"review":0,"read":0}}
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id="photo", created_at=db.now()))

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def seed(self, identifier, result=None):
        result = self.old if result is None else result
        with self.engine.begin() as conn:
            conn.execute(insert(db.inspections).values(id=identifier, image_id="photo", template_id="",
                template_snapshot=self.source, ocr=self.ocr, result=result, status=result["status"],
                created_at="2026-11-22T16:01:00+00:00"))

    def get(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, response.json)
        return response.json

    def test_details_list_and_recycle_filters_keep_original_snapshot_and_revision(self):
        self.seed("original")
        with self.engine.begin() as conn:
            conn.execute(insert(db.corrections).values(id="a", inspection_id="original", revision=1,
                change={}, patches=[], result=self.old, ocr=self.ocr, status="fail", reviewer="A", note="", created_at=db.now()))
        original = self.get("/api/inspections/original")
        self.assertEqual(original["status"], "pass")
        self.assertEqual(original["result"]["counts"], {"pass":2, "fail":0, "review":0, "read":0})
        self.assertEqual(original["result"]["checks"], [self.old["checks"][0], self.old["checks"][2]])
        self.assertEqual(original["manual_revision"]["status"], "pass")
        self.assertEqual(original["manual_revision"]["result"]["checks"], original["result"]["checks"])
        self.assertEqual(original["correction_history"][0]["status"], "pass")
        self.assertEqual(self.get("/api/inspections/original/corrections")["items"][0]["status"], "pass")
        self.assertEqual(original["template_snapshot"], self.source)
        self.assertEqual(original["ocr"], self.ocr)
        listed = self.get("/api/inspections?status=pass")["items"][0]
        self.assertEqual((listed["status"],listed["manual_status"]),("pass","pass"))
        self.assertEqual(listed["counts"],listed["manual_counts"])
        self.assertEqual((listed["issue_reasons"],listed["manual_issue_reasons"]),([],[]))
        self.assertEqual(self.get("/api/inspections?status=fail")["items"], [])
        for verdict, count in (("fail",0), ("pass",1)):
            preview = self.client.post("/api/admin/history/preview", json={"filters":{"status":verdict}}, headers=self.headers)
            self.assertEqual(preview.json["count"],count)
        with self.engine.connect() as conn:
            for table in (db.inspections,db.corrections):
                stored = conn.execute(select(table.c.result,table.c.status)).one()
                self.assertEqual((stored.result,stored.status),(self.old,"fail"))

    def test_paginated_counts_bound_parallel_backfill_and_later_rows(self):
        for i in range(27):
            self.seed(f"old-{i:02}")
        mixed = deepcopy(self.old)
        mixed["checks"].append({"key":"barcode_hri","status":"fail","line_ids":[0]})
        self.seed("other-error", mixed)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(lambda _: history_status.ensure_index(self.engine), range(3)))
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(select(func.count()).select_from(history_status.summaries)), 28)
        with patch.object(history_status,"project", side_effect=AssertionError("warm index must not re-evaluate snapshots")):
            first = self.get("/api/inspections?status=pass")
            second = self.get("/api/inspections?status=pass&page=2")
            self.assertEqual((len(first["items"]),len(second["items"])), (24,3))
            self.assertEqual(second["day_counts"], {"2026-11-23":{"photos":1,"records":27}})
            self.assertEqual([row["id"] for row in self.get("/api/inspections?status=fail")["items"]],["other-error"])
        self.seed("new-legacy")
        with patch.object(history_status,"project", wraps=history_status.project) as project:
            result = self.get("/api/inspections?status=pass&page=2")
            self.assertEqual(result["day_counts"]["2026-11-23"]["records"],28)
            self.assertEqual(project.call_count,1)

    def test_stripe_reminder_removed_from_details_revisions_filters_and_previous_summary(self):
        rule = {"key":"web_barcode_rule","source":"database","status":"pass",
                "actual":"2 834665 432931","expected":"2834665432931"}
        unread = {"key":"barcode_unread","status":"review","actual":"2834665432931","label":"條碼圖形","reason":"未解碼"}
        result = dict(self.old, nutrition_policy="literal-text-v2", checks=[rule, unread],
                      status="review", counts={"pass":1,"fail":0,"review":1,"read":0})
        self.seed("papaya", result)
        mismatch = dict(rule, status="fail", actual="2834665430000", label="已核准條碼公式", reason="印字與標準不同")
        manual = dict(result, checks=[mismatch, unread], status="fail", counts={"pass":0,"fail":1,"review":1,"read":0})
        with self.engine.begin() as conn:
            conn.execute(insert(db.corrections).values(id="revision", inspection_id="papaya", revision=1,
                change={}, patches=[], result=manual, ocr=self.ocr, status="fail", reviewer="A", note="", created_at=db.now()))
            conn.execute(insert(history_status.summaries).values(policy="literal-text-v2/issues-v1",
                source_table=db.inspections.name, row_id="papaya", status="review",
                counts={"counts":result["counts"],"issue_reasons":[dict(unread, printed_match=True)]}))
        details = self.get("/api/inspections/papaya")
        self.assertEqual((details["status"],details["result"]["checks"]), ("pass",[rule]))
        revision = details["manual_revision"]
        self.assertEqual((revision["status"],revision["result"]["checks"]), ("fail",[mismatch]))
        self.assertEqual(details["correction_history"][0]["status"], "fail")
        history = self.get("/api/inspections?status=pass")
        self.assertEqual(history["day_counts"], {"2026-11-23":{"photos":1,"records":1}})
        listed = history["items"][0]
        self.assertEqual((listed["status"],listed["manual_status"]), ("pass","fail"))
        self.assertEqual((listed["issue_reasons"],[i["key"] for i in listed["manual_issue_reasons"]]), ([],["web_barcode_rule"]))
        self.assertEqual(listed["counts"], {"pass":1,"fail":0,"review":0,"read":0})
        self.assertEqual(listed["manual_counts"], {"pass":0,"fail":1,"review":0,"read":0})
        self.assertEqual(self.get("/api/inspections?status=review")["items"], [])
        for status, count in (("pass",1),("review",0)):
            response = self.client.post("/api/admin/history/preview", json={"filters":{"status":status}}, headers=self.headers)
            self.assertEqual(response.json["count"], count)
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(select(db.inspections.c.result)), result)
            self.assertEqual(conn.scalar(select(db.corrections.c.result)), manual)

    def test_previous_summary_reloads_recorded_date_candidates_without_rewriting_evidence(self):
        old_reason = "日期未看清楚或有多個候選，請對照原圖確認。"
        key = dict(key="manufacture", source="date", status="review", reason=old_reason,
                   actual="2026.11.26", line_ids=[11], label="製造日期格式")
        expiry = dict(key, key="expiry", actual="2026.11.29 03時", line_ids=[13], label="有效日期格式")
        formula = dict(key="web_barcode_rule", source="database", status="review", actual="2839179133336",
                       date_source="expiry", expected="", reason="缺少唯一清楚且完整的有效日期，無法核對條碼公式。")
        old_checks = [key,dict(key, key="manufacture_year"),expiry,formula]
        original = dict(self.old, nutrition_policy="literal-text-v2", checks=old_checks, status="review",
                        counts={"pass":0,"fail":0,"review":4,"read":0})
        self.ocr = {"lines":[{"id":11, "text":"製造日期: 2026.11.26", "score":0, "ambiguous":True,
                              "ambiguity_reason":"cloud_uncertain", "alternatives":[{"text":"製造日期: 2026.11.20"}]}]}
        self.seed("uncertain-date", original)
        with self.engine.begin() as conn:
            conn.execute(insert(history_status.summaries).values(policy="literal-text-v2/external-reader-v1/i1",
                source_table=db.inspections.name, row_id="uncertain-date", status="review",
                counts={"counts":original["counts"], "issue_reasons":[key]}))
        details = self.get("/api/inspections/uncertain-date")
        reason = details["result"]["checks"][0]["reason"]
        self.assertIn("2026.11.26", reason)
        self.assertIn("2026.11.20", reason)
        self.assertEqual((details["status"],details["result"]["counts"]), ("review", original["counts"]))
        self.assertEqual(details["result"]["checks"][-1]["pending_date"], {"kind":"expiry","value":"2026.11.29 03時","line_ids":[13]})
        listed = self.get("/api/inspections?status=review")["items"][0]
        self.assertEqual(listed["issue_reasons"][0]["reason"], reason)
        self.assertEqual([item["key"] for item in listed["issue_reasons"]], ["manufacture","expiry","web_barcode_rule"])
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(select(db.inspections.c.result)), original)

    def test_stripe_reminder_alone_and_unverified_printed_text_still_require_review(self):
        unread = {"key":"barcode_unread","status":"review","label":"條碼圖形"}
        unverified = {"key":"text_line_0","status":"read","source":"ocr","actual":"2834665432931"}
        for identifier, remaining in (("only",[]), ("unverified",[unverified])):
            self.seed(identifier, dict(self.old, checks=[unread,*remaining], status="review"))
            details = self.get("/api/inspections/"+identifier)
            self.assertEqual((details["status"],details["result"]["checks"]), ("review",remaining))
        history = self.get("/api/inspections?status=review")
        self.assertEqual(history["day_counts"], {"2026-11-23":{"photos":1,"records":2}})
        self.assertEqual({i["id"]:i["counts"] for i in history["items"]},
                         {"only":{"pass":0,"fail":0,"review":0,"read":0},
                          "unverified":{"pass":0,"fail":0,"review":0,"read":1}})

    def test_pre_policy_text_mismatch_keeps_its_original_judgment_and_reason(self):
        old = deepcopy(self.old)
        literal = dict(old["checks"][2], key="source_text_3", source="database", status="fail",
                       expected="鈉 9 毫克", actual="鈉 19 毫克", reason="原始逐字比對發現不同")
        old["checks"][2] = literal
        old["counts"].update({"fail":2, "pass":1})
        self.seed("saved-text", old)
        shown = self.get("/api/inspections/saved-text")
        self.assertEqual(shown["status"], "fail")
        self.assertEqual(shown["result"]["checks"], [old["checks"][0], literal])
        self.assertEqual(shown["result"]["counts"]["fail"], 1)
        self.assertEqual([row["id"] for row in self.get("/api/inspections?status=fail")["items"]], ["saved-text"])

    def test_excluded_revision_restores_only_omitted_text_from_its_own_snapshot(self):
        from test_source_validation import line, source

        correct = "熱量 135大卡 270大卡"
        wrong = "熱量 100大卡 270大卡"
        labels = ("品名：蜜香木瓜切片", "營養標示", "每一份量 50 公克", correct)
        self.source.update(mode="system_label", source=source(*labels))
        self.ocr = {"lines":[line(i, wrong if i == 3 else text, score=1) for i, text in enumerate(labels)]}
        old_check = {"key":"preserved_product","line_ids":[0],"status":"pass","reason":"當時的核對依據"}
        old = {"nutrition_policy":"excluded-v1", "fields":{"product":{"value":"當時的品名"}},
               "inputs":{"base_date":"2025-08-19"},"checks":[old_check,{"key":"barcode_unread","status":"review"}],
               "status":"review","counts":{"pass":1,"fail":0,"review":1,"read":0}}
        self.seed("hidden", old)
        corrected = deepcopy(self.ocr)
        corrected["lines"][3].update(text=correct, human_verified=True, original_ocr_text=wrong)
        with self.engine.begin() as conn:
            for revision, kind in ((1,"label_misprint"), (2,"ocr_misread")):
                patch_data = {"line_id":3,"kind":kind,"text":correct,"reviewer":"A","note":"人工確認"}
                corrected["lines"][3]["human_correction"] = patch_data
                conn.execute(insert(db.corrections).values(id=f"revision-{revision}", inspection_id="hidden",
                    revision=revision, change={}, patches=[patch_data], result=old, ocr=corrected, status="pass",
                    reviewer="A", note="人工確認", created_at=db.now()))
            conn.execute(insert(history_status.summaries).values(policy="excluded-v1", source_table=db.inspections.name,
                row_id="hidden", status="pass", counts=old["counts"]))
        shown = self.get("/api/inspections/hidden")
        self.assertEqual(shown["result"]["inputs"], old["inputs"])
        self.assertEqual(shown["result"]["fields"]["product"], old["fields"]["product"])
        self.assertIn(old_check, shown["result"]["checks"])
        self.assertNotIn("barcode_unread", [check["key"] for check in shown["result"]["checks"]])
        self.assertEqual(shown["status"], "fail")
        self.assertTrue(any(check.get("expected")==correct and check.get("actual")==wrong and check["status"]=="fail"
                            for check in shown["result"]["checks"]))
        self.assertEqual(shown["manual_revision"]["status"],"pass")
        self.assertTrue(any(check.get("expected")==correct and check.get("actual")==correct and check["status"]=="pass"
                            for check in shown["manual_revision"]["result"]["checks"]))
        self.assertEqual([item["status"] for item in shown["correction_history"]], ["pass","fail"])
        items = self.get("/api/inspections?status=fail")["items"]
        self.assertEqual([(item["id"],item["status"],item["manual_status"]) for item in items],[("hidden","fail","pass")])
        self.assertEqual(self.get("/api/inspections?status=pass")["items"],[])
        preview = self.client.post("/api/admin/history/preview", json={"filters":{"status":"fail"}}, headers=self.headers)
        self.assertEqual(preview.json["items"][0]["id"],"hidden")
        with self.engine.connect() as conn:
            stored = conn.execute(select(db.inspections.c.result,db.inspections.c.ocr,db.inspections.c.template_snapshot)).one()
            self.assertEqual((stored.result,stored.ocr,stored.template_snapshot),(old,self.ocr,self.source))
