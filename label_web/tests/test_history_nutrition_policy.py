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
                       "source":{"lines":[{"id":3, "text":"鈉 50 毫克"}]}}
        self.ocr = {"lines":[{"id":0, "text":"品名：蜜香木瓜切片", "box":[], "score":1},
                             {"id":1, "text":"鈉 9 毫克", "box":[], "score":1}]}
        self.old = {"checks":[{"key":"product", "status":"pass", "line_ids":[0]},
                              {"key":"nutrition_sodium", "status":"fail", "line_ids":[1]},
                              {"key":"source_line_3", "status":"review", "source_line_ids":[3], "line_ids":[]}],
                    "fields":{"product":{"value":"蜜香木瓜切片"}}, "status":"fail",
                    "counts":{"pass":1,"fail":1,"review":1,"read":0}}
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
        self.assertEqual(original["result"]["counts"], {"pass":1, "fail":0, "review":0, "read":0})
        self.assertEqual([item["key"] for item in original["result"]["checks"]], ["product"])
        self.assertEqual(original["manual_revision"]["status"], "pass")
        self.assertEqual(original["manual_revision"]["result"]["checks"], original["result"]["checks"])
        self.assertEqual(original["correction_history"][0]["status"], "pass")
        self.assertEqual(self.get("/api/inspections/original/corrections")["items"][0]["status"], "pass")
        self.assertEqual(original["template_snapshot"], self.source)
        self.assertEqual(original["ocr"], self.ocr)
        listed = self.get("/api/inspections?status=pass")["items"][0]
        self.assertEqual((listed["status"],listed["manual_status"]),("pass","pass"))
        self.assertEqual(listed["counts"],listed["manual_counts"])
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
