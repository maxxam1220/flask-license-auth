"""History titles may use original OCR, never alter the recorded result."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from sqlalchemy import insert, select

import database as db
import history_cleanup
from server import create_app


def line(identifier, text, y=None):
    top=identifier*40 if y is None else y
    return {"id":identifier,"text":text,"score":.95,"box":[[20,top],[500,top],[500,top+25],[20,top+25]]}


class HistoryProductTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({"TESTING":True,"DATA_DIR":Path(self.temp.name),"DATABASE_URL":"","APP_PASSWORD":""},ocr=object())
        self.engine=self.app.extensions["label_engine"]
        self.client=self.app.test_client()
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id="image",created_at=db.now(),filename="label.jpg",sha256="test",width=600,height=400))

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def add(self, identifier, lines, product="", source=None):
        row={"id":identifier,"image_id":"image","template_id":"","status":"review","created_at":db.now(),
            "template_snapshot":{"name":"直接掃描・文字與日期檢查","version":0,"image_id":"","source":source},
            "ocr":{"lines":deepcopy(lines),"engine":"test"},
            "result":{"fields":{"product":{"value":product}} if product else {},"counts":{"review":1},
                      "inputs":{"base_date":"2026-11-16"}}}
        with self.engine.begin() as conn:
            conn.execute(insert(db.inspections).values(**row))
        return row

    def items(self):
        response=self.client.get("/api/inspections")
        self.assertEqual(response.status_code,200,response.json)
        return {item["id"]:item for item in response.json["items"]}

    def test_no_source_reads_explicit_ocr_product_without_rewriting_history(self):
        original=self.add("no-source",[line(0,"品名：日本蜜桃蘋果切片"),line(1,"製造日期：2026.11.16")])
        item=self.items()["no-source"]
        self.assertEqual(item["product"],"日本蜜桃蘋果切片")
        self.assertEqual(item["name"],"直接掃描・文字與日期檢查")
        with self.engine.connect() as conn:
            stored=dict(conn.execute(select(db.inspections).where(db.inspections.c.id=="no-source")).mappings().one())
        self.assertEqual(stored,original)

    def test_existing_product_wins_with_and_without_standard(self):
        for identifier,source in (("with",{"code":"1013","name":"標準答案"}),("without",None)):
            self.add(identifier,[line(0,"品名：原圖品名")],product="原有結果品名",source=source)
        self.assertEqual({item["product"] for item in self.items().values()},{"原有結果品名"})

    def test_daily_counts_span_pages_and_distinguish_photos_from_rechecks(self):
        today = datetime.now(history_cleanup.TAIWAN).date()
        midnight = datetime.combine(today, datetime.min.time(), history_cleanup.TAIWAN).astimezone(timezone.utc)
        sample = self.add("first", [], product="柿子")
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id="other",created_at=db.now(),filename="other.jpg",width=600,height=400))
            conn.execute(db.inspections.update().where(db.inspections.c.id=="first").values(created_at=midnight.isoformat()))
            for i in range(26):
                conn.execute(insert(db.inspections).values(**{**sample, "id":str(i), "image_id":"other" if i < 25 else "hidden",
                    "created_at":(midnight+timedelta(seconds=i+1)).isoformat(), "status":"pass"}))
            conn.execute(insert(db.inspections).values(**{**sample,"id":"yesterday","created_at":(midnight-timedelta(seconds=1)).isoformat()}))
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="25",batch_id="b",archived=True,revision=1,updated_at=db.now()))
        for page in (1,2):
            response = self.client.get(f"/api/inspections?page={page}")
            self.assertEqual(response.status_code,200,response.json)
            result = response.json
            self.assertEqual(result["today"],{"date":today.isoformat(),"photos":2,"records":26})
            self.assertEqual(result["day_counts"][today.isoformat()],{"photos":2,"records":26})
        yesterday = (today - timedelta(days=1)).isoformat()
        self.assertEqual(result["day_counts"][yesterday],{"photos":1,"records":1})
        self.assertEqual(result["items"][-1]["day"],yesterday)
        filtered = self.client.get("/api/inspections?status=pass").json
        self.assertEqual(filtered["day_counts"][today.isoformat()],{"photos":1,"records":25})
        self.assertEqual(filtered["today"],result["today"])

    def test_source_name_is_not_used_to_fill_missing_observed_product(self):
        self.add("with-source",[line(0,"商品名稱：實印蘋果")],source={"code":"1013","name":"標準答案"})
        self.add("missing-observation",[line(0,"製造日期：2026.11.16")],source={"code":"1013","name":"標準答案"})
        items=self.items()
        self.assertEqual(items["with-source"]["product"],"實印蘋果")
        self.assertEqual(items["missing-observation"]["product"],"")

    def test_dates_phones_and_arbitrary_first_line_are_not_product(self):
        examples=("製造日期：2026.11.16","到店日：2026.11.17","11月16日","0800-200-859","電話：0800-200-859","其他任意文字")
        for index,text in enumerate(examples):
            self.add(str(index),[line(0,text)])
        self.assertTrue(all(item["product"]=="" for item in self.items().values()))

    def test_empty_product_heading_cannot_borrow_bare_date_or_phone(self):
        for identifier,value in (("date","2026.11.16"),("phone","0800-200-859")):
            self.add(identifier,[line(0,"品名："),line(1,value,y=30)])
        self.assertTrue(all(item["product"]=="" for item in self.items().values()))

    def test_multiple_explicit_names_and_malformed_old_ocr_do_not_choose_or_crash(self):
        self.add("two",[line(0,"品名：第一款"),line(1,"品名：第二款")])
        self.add("bad",[{"id":0,"text":"品名：不完整舊資料","score":.9,"box":[]}])
        self.assertEqual({item["product"] for item in self.items().values()},{""})


if __name__=="__main__":
    unittest.main()
