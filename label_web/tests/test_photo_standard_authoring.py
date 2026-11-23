"""Photo-family text authoring API: offline, no model calls."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image
from sqlalchemy import func, insert, select, update

import database as db
import standard_library as library
from server import create_app
from validation import evaluate


FAMILY = "e1234567890123456789012345678901"


def line(identifier, text):
    y = identifier * 30 + 10
    return {"id": identifier, "text": text, "score": .99,
            "box": [[10,y],[430,y],[430,y+22],[10,y+22]]}


class PhotoStandardAuthoringTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = create_app({"TESTING": True, "DATA_DIR": self.root, "DATABASE_URL": "",
            "APP_PASSWORD": "qa-operator-2026", "ADMIN_PASSWORD": "qa-manager-2026"}, ocr=object())
        self.engine = self.app.extensions["label_engine"]
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token": self.client.get("/api/session").json["csrf"]}
        self.login()
        self.template = {"id":"photo-v1", "family_id":FAMILY, "version":1, "active":True,
            "name":"測試蘋果", "image_id":"old-image", "fields":{"product":"測試蘋果","origin":"紐西蘭",
                "address":"新北市土城區中興路9號"},
            "rules":{"dates":True,"arrival":False,"keep_days":9,"custom_preserved":{"literal":"retain"},
                "source":{"code":"1623","revision":"desktop-old","keep_days":9,
                    "date_settings":[{"content":"製造日期","format":"A","shift_days":0},
                                     {"content":"有效日期","format":"B","shift_days":0}]}},
            "reference_dates":{"manufacture":"2026.11.12","expiry":"2026.11.21"},
            "approved_by":"建立人", "created_at":db.now()}
        texts = ["品名：測試蘋果","內容物：蘋果","產地：紐西蘭","淨重：185g/袋",
                 "保存條件：7℃以下冷藏","營養標示","每一份量100公克","每份 每100公克",
                 "脂肪 0.1公克 0.1公克","新北市土城區中興路9號","福和生鮮農產股份有限公司",
                 "0800-200-859","製造日期:2026.11.16","有效日期:2026.11.25"]
        self.original = {"id":"scan", "image_id":"new-image", "template_id":"photo-v1",
            "template_snapshot":deepcopy(self.template), "status":"fail", "ocr":{"lines":[line(i,text) for i,text in enumerate(texts)]},
            "result":{"checks":[],"inputs":{"base_date":"2026-11-16"}},"created_at":db.now()}
        for identifier in ("old-image", "new-image"):
            folder = self.root/"images"/identifier
            folder.mkdir(parents=True)
            Image.new("RGB", (450,500), "white").save(folder/"image.jpg")
        with self.engine.begin() as conn:
            for identifier in ("old-image", "new-image"):
                conn.execute(insert(db.images).values(id=identifier, filename=identifier+".jpg", width=450, height=500, created_at=db.now()))
            conn.execute(insert(db.templates).values(**self.template))
            conn.execute(insert(db.inspections).values(**self.original))
            conn.execute(insert(library.categories).values(id="fruit",name="水果",name_key="水果",revision=1,removed=False,updated_at=db.now()))
            conn.execute(insert(library.items).values(kind="photo",key=FAMILY,revision=1,category_id="fruit",removed=False,updated_at=db.now()))

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def login(self, admin=True):
        response = self.client.post("/api/login", json={"password":"qa-manager-2026" if admin else "qa-operator-2026"}, headers=self.headers)
        self.assertEqual(response.status_code,200,response.json)
        self.headers["X-CSRF-Token"] = response.json["csrf"]

    def get(self):
        response = self.client.get("/api/inspections/scan/standard")
        self.assertEqual(response.status_code,200,response.json)
        return response.json

    def body(self, photo=True):
        current = self.get()
        return {"base_revision":current["base_revision"], "source_revision":current["source_revision"],
            "draft_manual_revision":current["regrouped_manual_revision"], "use_inspection_photo":photo,
            "changes":{"replace_lines":[{"text":row["text"]} for row in current["regrouped_draft_lines"]]}}

    def post(self, body, preview=False):
        if not preview:
            body = dict(body, confirmed=True, reviewer="QA", note="核對本次完整文字與照片")
        return self.client.post("/api/inspections/scan/standard"+("/preview" if preview else ""),json=body,headers=self.headers)

    def templates(self):
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(select(db.templates).order_by(db.templates.c.version)).mappings()]

    def test_draft_and_preview_read_current_ocr_without_expected_completion_or_fixed_dates(self):
        current = self.get()
        self.assertTrue(current["editable"])
        self.assertTrue(current["supports_line_replacement"])
        self.assertFalse(current["supports_history_restore"])
        self.assertEqual(current["photo_template_id"],"photo-v1")
        self.assertEqual(current["code"],"photo:"+FAMILY)
        self.assertEqual(current["regrouped_excluded_date_lines"][0]["id"],12)
        body = self.body()
        with patch("cloud_vision._post_response",side_effect=AssertionError("must not call OCR")):
            preview = self.post(body,True)
        self.assertEqual(preview.status_code,200,preview.json)
        self.assertEqual(len(self.templates()),1)
        source = preview.json["source"]
        self.assertIn("脂肪 0.1公克 0.1公克",[row["text"] for row in source["lines"]])
        self.assertFalse(any("2026." in row["text"] for row in source["lines"]))
        self.assertEqual(source["reference_image_id"],"new-image")
        self.assertEqual(source["date_settings"],self.template["rules"]["source"]["date_settings"])

    def test_save_same_family_new_template_retains_old_photo_rules_category_and_history(self):
        body=self.body()
        with patch("cloud_vision._post_response",side_effect=AssertionError("must not call OCR")):
            response=self.post(body)
        self.assertEqual(response.status_code,201,response.json)
        old,new=self.templates()
        self.assertEqual(old,{**self.template,"active":False})
        self.assertEqual(new["family_id"],FAMILY)
        self.assertEqual(new["version"],2)
        self.assertEqual(new["image_id"],"new-image")
        self.assertEqual(response.json["photo_template_id"],new["id"])
        self.assertEqual(new["rules"]["source"],self.template["rules"]["source"])
        self.assertEqual(new["rules"]["custom_preserved"],{"literal":"retain"})
        self.assertEqual(new["reference_dates"],self.template["reference_dates"])
        self.assertEqual(new["rules"]["approved_text_source"]["revision"],new["id"])
        with self.engine.connect() as conn:
            self.assertEqual(dict(conn.execute(select(db.inspections)).mappings().one()),self.original)
            state=conn.execute(select(library.items)).mappings().one()
            self.assertEqual(state["category_id"],"fruit")
            self.assertEqual(state["revision"],2)
            self.assertEqual(conn.scalar(select(func.count()).select_from(db.images)),2)
        detail=self.client.get(f"/api/standard-library/photo/{FAMILY}").json
        self.assertEqual({row["id"] for row in detail["photos"]},{"old-image","new-image"})
        self.assertTrue(detail["supports_line_replacement"])
        self.assertEqual(detail["current_image"]["id"],"new-image")

    def test_full_text_is_used_by_real_validation_and_changed_numeric_value_fails(self):
        self.assertEqual(self.post(self.body(False)).status_code,201)
        new=self.templates()[-1]
        observed=deepcopy(self.original["ocr"]["lines"])
        good=evaluate(observed,new,base_date="2026-11-16")
        nutrition=[check for check in good["checks"] if check["key"].startswith("source_nutrition_")]
        self.assertEqual(len(nutrition),1)
        self.assertEqual(nutrition[0]["status"],"pass")
        observed[8]["text"]="脂肪 0.2公克 0.1公克"
        bad=evaluate(observed,new,base_date="2026-11-16")
        self.assertTrue(any(check["status"]=="fail" for check in bad["checks"] if check["key"].startswith("source_nutrition_")))
        self.assertEqual(new["image_id"],"old-image")

    def test_library_edit_uses_fulltext_contract_and_keeps_family_photo_and_date_rules(self):
        self.assertEqual(self.post(self.body()).status_code,201)
        path=f"/api/standard-library/photo/{FAMILY}"
        detail=self.client.get(path).json
        before=self.templates()[-1]
        self.assertTrue(detail["supports_line_replacement"])
        changed=[{"text":row["text"]} for row in detail["source"]["lines"]]
        changed.append({"text":"食用前請清洗"})
        body={key:detail[key] for key in ("item_revision","base_revision","source_revision")}
        body["changes"]={"replace_lines":changed}
        preview=self.client.post(path+"/preview",json=body,headers=self.headers)
        self.assertEqual(preview.status_code,200,preview.json)
        preview_source=preview.json["template"]["rules"]["approved_text_source"]
        self.assertEqual(preview_source["lines"][-1]["text"],"食用前請清洗")
        self.assertEqual(preview.json["nutrition_checks"], [])
        self.assertEqual(len(self.templates()),2)
        saved=self.client.post(path+"/save",json=dict(body,preview_hash=preview.json["preview_hash"],
            reviewer="QA",note="從標準庫更新全文",confirmed=True),headers=self.headers)
        self.assertEqual(saved.status_code,201,saved.json)
        newest=self.templates()[-1]
        self.assertEqual(newest["family_id"],FAMILY)
        self.assertEqual(newest["image_id"],before["image_id"])
        self.assertEqual(newest["rules"]["source"],before["rules"]["source"])
        self.assertEqual(newest["reference_dates"],before["reference_dates"])
        self.assertEqual(newest["rules"]["approved_text_source"]["revision"],newest["id"])
        self.assertEqual(saved.json["category_id"],"fruit")
        self.assertEqual(saved.json["source"]["lines"][-1]["text"],"食用前請清洗")
        current=self.get()
        self.assertEqual(current["photo_template_id"],newest["id"])
        self.assertEqual(current["source"]["lines"][-1]["text"],"食用前請清洗")

    def test_stale_version_and_stale_correction_rejected_in_preview_and_save(self):
        body=self.body()
        self.assertEqual(self.post(body).status_code,201)
        self.assertEqual(self.post(body,True).status_code,409)
        self.assertEqual(self.post(body).status_code,409)
        fresh=self.body()
        with self.engine.begin() as conn:
            conn.execute(insert(db.corrections).values(id=db.uid(),inspection_id="scan",revision=1,change={},patches=[],
                ocr=self.original["ocr"],result={},status="review",reviewer="QA",note="新訂正",created_at=db.now()))
        self.assertEqual(self.post(fresh,True).status_code,409)
        self.assertEqual(self.post(fresh).status_code,409)
        self.assertEqual(len(self.templates()),2)

    def test_photo_only_does_not_enable_fulltext_and_same_photo_can_create_version(self):
        body=self.body();body.pop("draft_manual_revision");body["changes"]={}
        self.assertEqual(self.post(body).status_code,201)
        self.assertNotIn("approved_text_source",self.templates()[-1]["rules"])
        next_body=self.body();next_body.pop("draft_manual_revision");next_body["changes"]={}
        self.assertEqual(self.post(next_body).status_code,201)
        self.assertEqual([row["image_id"] for row in self.templates()],["old-image","new-image","new-image"])

    def test_missing_image_and_late_audit_failure_rollback_entire_version(self):
        body=self.body()
        with patch.object(library,"_audit",side_effect=RuntimeError("simulate audit failure")):
            with self.assertLogs("server",level="ERROR"):
                self.assertEqual(self.post(body).status_code,500)
        self.assertEqual(self.templates(),[self.template])
        (self.root/"images"/"new-image"/"image.jpg").unlink()
        self.assertEqual(self.post(body,True).status_code,409)
        self.assertEqual(self.post(body).status_code,409)
        self.assertEqual(self.templates(),[self.template])

    def test_removed_family_and_low_quality_draft_fail_closed(self):
        body=self.body()
        with self.engine.begin() as conn:
            bad=deepcopy(self.original["ocr"])
            for row in bad["lines"]:row.update(uncertain=True,score=.2)
            conn.execute(update(db.inspections).values(ocr=bad))
        self.assertEqual(self.post(body,True).status_code,409)
        self.assertEqual(self.post(body).status_code,409)
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).values(ocr=self.original["ocr"]))
            conn.execute(update(library.items).values(removed=True,revision=2))
            conn.execute(update(db.templates).values(active=False))
        current=self.get()
        self.assertFalse(current["editable"])
        self.assertTrue(current["removed"])
        self.assertEqual(self.post(body,True).status_code,409)
        self.assertEqual(self.post(body).status_code,409)

    def test_name_and_fixed_date_validation_and_unsupported_restore(self):
        body=self.body();body["changes"]["name"]="新版蘋果"
        self.assertEqual(self.post(body,True).status_code,400)
        body["changes"]["replace_lines"][0]["text"]="品名：新版蘋果"
        self.assertEqual(self.post(body,True).status_code,200)
        self.assertEqual(self.post(body).status_code,201)
        fresh=self.body();fresh["changes"]["replace_lines"].append({"text":"製造日期:2026.11.16"})
        self.assertEqual(self.post(fresh,True).status_code,400)
        fresh=self.body();fresh["operation"]="restore";fresh["target_revision"]=1
        self.assertEqual(self.post(fresh).status_code,400)  # common guard rejects draft+restore
        fresh.pop("draft_manual_revision");fresh["use_inspection_photo"]=False
        self.assertEqual(self.post(fresh).status_code,409)

    def test_admin_and_csrf_are_required(self):
        body=self.body()
        self.assertEqual(self.client.post("/api/inspections/scan/standard/preview",json=body).status_code,403)
        self.login(False)
        self.assertEqual(self.client.get("/api/inspections/scan/standard").status_code,403)
        self.assertEqual(self.post(body,True).status_code,403)
        self.assertEqual(self.post(body).status_code,403)


if __name__ == "__main__":
    unittest.main()
