from copy import deepcopy
import unittest
from unittest.mock import patch

from flask import Flask, jsonify
from sqlalchemy import create_engine, insert, select, func
from werkzeug.exceptions import HTTPException

import database as db
import label_source
import reference_catalog
import standard_reference as standards
import history_cleanup
from source_rules import prepare_source
from source_validation import evaluate_source


def line(identifier, value):
    y = identifier * 30
    return {"id": identifier, "text": value, "score": 1., "box": [[0,y],[400,y],[400,y+20],[0,y+20]]}


def source(code="A", name="原始蘋果"):
    return {"code": code, "name": name, "revision": "base-" + code, "source_kind": "desktop",
            "comparison_scope": "desktop_label", "fields": {"product": name, "origin": "台灣"},
            "lines": [line(0, "品名：" + name), line(1, "產地：台灣"), line(2, "有效日期")],
            "keep_days": 3, "master_keep_days": 3, "source_savedays": None,
            "keep_days_source": "BcMst.KeepDays", "rules": {"dates": True, "arrival": False},
            "date_settings": [{"content": "有效日期", "format": "B", "shift_days": 0}],
            "barcode_config": {"kind": "1", "barcode": "0000000211239", "master_barcode": "0000000211239",
                               "front": "", "back": "", "solar": "2", "solar_pos": 2},
            "barcode_values": [], "notice": "原始資料"}


def catalog_item(item):
    result = {"code": item["code"], "name": item["name"], "sku": set(), "barcode": set(),
              "spec": set(), "origin": set(), "text": set(), "source_kind": item["source_kind"]}
    if item["source_kind"] == "catalog":
        result["catalog_record"] = {"code": item["code"][5:], "name": item["name"],
            "barcode": next(iter(item.get("barcode_values", [])), ""), "keep_days": item["keep_days"], "barcode_type": "1"}
        result["barcode"] = set(item.get("barcode_values", []))
    return result


class StandardReferenceTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        db.metadata.create_all(self.engine)
        self.app = Flask(__name__)
        self.app.config["TESTING"] = True
        @self.app.errorhandler(HTTPException)
        def error(error):
            return jsonify(error=error.description), error.code
        standards.register_routes(self.app, self.engine)
        self.client = self.app.test_client()
        self.sources = {"A": source(), "B": source("B", "另一款梨")}
        self.original = deepcopy(self.sources)
        self.inspection = {"id": "inspection-A", "image_id": "image", "template_id": "", "status": "fail",
            "template_snapshot": {"mode": "system_label", "source": deepcopy(self.sources["A"])},
            "ocr": {"lines": [line(0, "品名：照片錯字")]},
            "result": {"inputs": {"base_date": "2026-11-11"}}, "created_at": db.now()}
        with self.engine.begin() as conn:
            conn.execute(insert(db.inspections).values(**self.inspection))
        self.patches = [patch("label_source.raw_draft", side_effect=lambda engine, code: deepcopy(self.sources.get(code))),
                        patch("label_source.raw_catalog", side_effect=lambda engine: {code: catalog_item(item) for code, item in self.sources.items()}),
                        patch("label_source.available", return_value=True)]
        for mock in self.patches:
            mock.start(); self.addCleanup(mock.stop)
        self.addCleanup(self.engine.dispose)

    def get(self, identifier="inspection-A"):
        response = self.client.get(f"/api/inspections/{identifier}/standard")
        self.assertEqual(response.status_code, 200, response.json)
        return response.json

    def post(self, changes=None, **extra):
        current = self.get()
        body = dict(base_revision=current["base_revision"], source_revision=current["source_revision"],
                    changes=changes or {}, reviewer="核對員", note="人工確認正確印字", confirmed=True)
        body.update(extra)
        return self.client.post("/api/inspections/inspection-A/standard", json=body)

    def test_get_uses_current_source_not_ocr_or_old_inspection(self):
        result = self.get()
        self.assertEqual(result["source"]["lines"][0]["text"], "品名：原始蘋果")
        self.assertEqual(result["base_revision"], 0)
        self.assertNotIn("照片錯字", str(result))

    def test_archived_after_editor_open_cannot_write_comparison_revision(self):
        current = self.get()
        with self.engine.begin() as conn:
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="inspection-A", batch_id="archive-race",
                archived=True, revision=1, updated_at=db.now()))
        response = self.client.post("/api/inspections/inspection-A/standard", json={
            "base_revision": current["base_revision"], "source_revision": current["source_revision"],
            "changes": {"name": "新版蘋果"}, "reviewer": "A", "note": "已開啟編輯", "confirmed": True})
        self.assertEqual(response.status_code, 404, response.json)
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(), 0)
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.heads)).scalar(), 0)

    def test_first_override_created_during_auto_matching_requires_retry(self):
        original_draft = label_source.draft
        def changed_draft(engine, code):
            response = self.post({"name": "新版梨子"})
            self.assertEqual(response.status_code, 201, response.json)
            return original_draft(engine, code)
        with patch.object(label_source, "draft", side_effect=changed_draft):
            result = label_source.resolve(self.engine, [line(0, "品名：原始蘋果")])
        self.assertEqual(result["status"], "ambiguous")
        self.assertIsNone(result["source"])
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：新版梨子")])["code"], "A")

    def test_text_patch_preserves_originals_and_future_same_source_uses_new_standard(self):
        response = self.post({"lines": [{"id": 1, "text": "產地：日本"}]})
        self.assertEqual(response.status_code, 201, response.json)
        self.assertEqual(response.json["base_revision"], 1)
        self.assertEqual(label_source.draft(self.engine, "A")["fields"]["origin"], "日本")
        self.assertEqual(label_source.draft(self.engine, "B")["fields"]["origin"], "台灣")
        self.assertEqual(self.sources, self.original)
        with self.engine.connect() as conn:
            saved = dict(conn.execute(select(db.inspections).where(db.inspections.c.id == self.inspection["id"])).mappings().one())
            self.assertEqual(saved, self.inspection)
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(), 1)

    def test_name_update_syncs_printed_product_and_future_identity_without_barcode(self):
        result = self.post({"name": "確認蘋果"})
        self.assertEqual(result.status_code, 201, result.json)
        draft = label_source.draft(self.engine, "A")
        self.assertEqual((draft["name"], draft["fields"]["product"], draft["lines"][0]["text"]),
                         ("確認蘋果", "確認蘋果", "品名：確認蘋果"))
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：確認蘋果")])["code"], "A")
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：原始蘋果")])["status"], "unmatched")
        self.assertEqual(label_source.search(self.engine, "確認")[0]["code"], "A")

    def test_product_line_only_also_updates_name_index_and_conflicts_are_rejected(self):
        result = self.post({"lines": [{"id": 0, "text": "品名：新蘋果"}]})
        self.assertEqual(result.status_code, 201, result.json)
        self.assertEqual(result.json["name"], "新蘋果")
        self.assertEqual(label_source.resolve(self.engine, [line(0, "新蘋果")])["code"], "A")
        self.assertEqual(self.post({"name": "名稱甲", "lines": [{"id": 0, "text": "品名：名稱乙"}]}).status_code, 400)

    def test_stale_web_revision_never_overwrites_newer_user_changes(self):
        self.assertEqual(self.post({"name": "新版一"}).status_code, 201)
        response = self.post({"name": "舊畫面修改"}, base_revision=0)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.get()["name"], "新版一")
        self.assertEqual(self.get()["base_revision"], 1)

    def test_external_source_change_disables_overlay_and_rejects_old_patch_ids(self):
        self.post({"name": "網站核准名"})
        self.sources["A"]["revision"] = "base-changed"
        self.sources["A"]["lines"][1]["text"] = "產地：美國"
        result = self.get()
        self.assertTrue(result["stale"])
        self.assertEqual(result["source"]["lines"][1]["text"], "產地：美國")
        self.assertEqual(result["name"], "原始蘋果")
        self.assertEqual(self.post({"lines": [{"id": 1, "text": "產地：錯誤套用"}]}, source_revision="base-A").status_code, 409)
        response = self.post({"name": "重新核准名"})
        self.assertEqual(response.status_code, 201, response.json)
        self.assertFalse(response.json["stale"])
        self.assertEqual(response.json["source"]["lines"][1]["text"], "產地：美國")

    def test_zero_keep_days_and_offsets_remain_dynamic_for_each_inspection_base_date(self):
        result = self.post({"keep_days": 0, "date_settings": [{"index": 0, "shift_days": 2}]})
        self.assertEqual(result.status_code, 201, result.json)
        updated = label_source.draft(self.engine, "A")
        self.assertEqual(updated["keep_days"], 0)
        self.assertEqual(updated["date_settings"][0]["format"], "B")
        self.assertEqual(updated["barcode_config"], self.original["A"]["barcode_config"])
        self.assertNotEqual(prepare_source(updated, "2026-11-11")["barcode_values"],
                            prepare_source(updated, "2026-11-12")["barcode_values"])
        for base, expiry in (("2026-12-31", "2027.01.02"), ("2027-01-01", "2027.01.03")):
            checks = evaluate_source([line(0, "有效日期:" + expiry)], updated, base_date=base)["checks"]
            self.assertEqual(next(check for check in checks if check["key"] == "expiry")["status"], "pass")

    def test_reset_and_restore_append_versions_without_erasing_history(self):
        self.post({"name": "版本一"})
        self.post({"name": "版本二"})
        restored = self.post(operation="restore", target_revision=1)
        self.assertEqual((restored.status_code, restored.json["name"], restored.json["base_revision"]), (201, "版本一", 3))
        reset = self.post(operation="reset")
        self.assertEqual((reset.status_code, reset.json["name"], reset.json["base_revision"]), (201, "原始蘋果", 4))
        self.assertEqual([item["revision"] for item in reset.json["history"]], [4,3,2,1])
        self.sources["A"]["revision"] = "new-layout"
        self.assertEqual(self.post(operation="restore", target_revision=1).status_code, 409)

    def test_restore_and_reset_preview_returns_real_target_without_writing(self):
        self.post({"name": "版本一", "keep_days": 1})
        self.post({"name": "版本二", "keep_days": 2})
        path = "/api/inspections/inspection-A/standard/preview"
        restore = self.client.get(path, query_string={"operation": "restore", "target_revision": 1})
        self.assertEqual(restore.status_code, 200, restore.json)
        self.assertEqual((restore.json["base_revision"], restore.json["source_revision"], restore.json["target_revision"]),
                         (2, "base-A", 1))
        self.assertEqual((restore.json["source"]["name"], restore.json["source"]["keep_days"]), ("版本一", 1))
        reset = self.client.get(path, query_string={"operation": "reset"})
        self.assertEqual(reset.status_code, 200, reset.json)
        self.assertEqual((reset.json["source"]["name"], reset.json["source"]["keep_days"]), ("原始蘋果", 3))
        self.assertNotIn("target_revision", reset.json)
        self.assertEqual(self.get()["name"], "版本二")
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(), 2)
            self.assertEqual(conn.execute(select(standards.heads.c.revision)).scalar(), 2)

    def test_stale_restore_preview_rejects_but_reset_uses_latest_raw_source(self):
        self.post({"name": "網站舊版本"})
        self.sources["A"]["revision"] = "new-base-hash"
        self.sources["A"]["lines"][1]["text"] = "產地：日本"
        path = "/api/inspections/inspection-A/standard/preview"
        response = self.client.get(path, query_string={"operation": "restore", "target_revision": 1})
        self.assertEqual(response.status_code, 409)
        reset = self.client.get(path, query_string={"operation": "reset"})
        self.assertEqual(reset.status_code, 200, reset.json)
        self.assertEqual(reset.json["source_revision"], "new-base-hash")
        self.assertEqual(reset.json["source"]["lines"][1]["text"], "產地：日本")
        self.assertEqual(reset.json["base_revision"], 1)

    def test_preview_cannot_select_unknown_operation_or_another_sources_revision(self):
        self.post({"name": "版本一"})
        path = "/api/inspections/inspection-A/standard/preview"
        for parameters in ({"operation": "update"}, {"operation": "restore"},
                           {"operation": "restore", "target_revision": 2},
                           {"operation": "restore", "target_revision": "not-a-number"},
                           {"operation": "reset", "target_revision": 1}):
            with self.subTest(parameters=parameters):
                self.assertEqual(self.client.get(path, query_string=parameters).status_code, 400)
        foreign = dict(self.inspection, id="inspection-B", template_snapshot={"source": self.sources["B"]})
        with self.engine.begin() as conn:
            conn.execute(insert(db.inspections).values(**foreign))
        response = self.client.get("/api/inspections/inspection-B/standard/preview",
            query_string={"operation": "restore", "target_revision": 1})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.get()["base_revision"], 1)

    def test_reject_injection_dates_invalid_ranges_and_missing_approval(self):
        for changes in ({"code": "B"}, {"fields": {"product": "別款"}},
                        {"lines": [{"id": 1000, "text": "不存在"}]},
                        {"lines": [{"id": 0, "text": "新名", "box": []}]},
                        {"lines": [{"id": 0, "text": "新名"}, {"id": 0, "text": "重複"}]},
                        {"lines": [{"id": 2, "text": "有效日期：2026.11.11"}]},
                        {"lines": [{"id": 2, "text": "20261114"}]},
                        {"lines": [{"id": 2, "text": "民國115.11.14"}]},
                        {"name": "2026.11.11"}, {"keep_days": True}, {"keep_days": -1},
                        {"date_settings": [{"index": 0, "shift_days": 1, "format": "A"}]},
                        {"date_settings": [{"index": 4, "shift_days": 1}]}):
            with self.subTest(changes=changes):
                self.assertEqual(self.post(changes).status_code, 400)
        for extra in ({"confirmed": False}, {"reviewer": ""}, {"note": ""}, {"source_code": "B"},
                      {"operation": []}, {"operation": {}}, {"operation": None}):
            with self.subTest(extra=extra):
                self.assertEqual(self.post({"name": "確認名"}, **extra).status_code, 400)
        self.assertEqual(self.get()["base_revision"], 0)

    def test_catalog_changes_preserve_known_scope_and_update_equivalence_record(self):
        item = reference_catalog.build_draft({"code": "1", "name": "清單蘋果", "barcode": "12345678",
            "keep_days": 3, "barcode_type": "1", "revision": "list-base"})
        other = deepcopy(item); other["code"] = "list:2"
        self.sources.update({"list:1": item, "list:2": other})
        with self.engine.begin() as conn:
            conn.execute(db.inspections.update().where(db.inspections.c.id == self.inspection["id"])
                .values(template_snapshot={"source": item}))
        result = self.post({"name": "新版清單蘋果", "keep_days": 0})
        self.assertEqual(result.status_code, 201, result.json)
        current = label_source.draft(self.engine, "list:1")
        self.assertEqual(current["lines"][0], {"id": "product", "text": "品名：新版清單蘋果", "score": 1.})
        self.assertEqual(current["date_settings"], [])
        items = label_source._catalog(self.engine)
        self.assertNotEqual(reference_catalog.equivalence_key(items["list:1"]), reference_catalog.equivalence_key(items["list:2"]))
        self.assertEqual(label_source.resolve(self.engine, [line(0, "新版清單蘋果")])["code"], "list:1")

    def test_catalog_existing_barcode_edits_update_one_expected_value_and_identity(self):
        item = reference_catalog.build_draft({"code": "1", "name": "清單蘋果", "barcode": "1234567890128",
            "keep_days": 3, "barcode_type": "1", "revision": "list-base"})
        self.sources["list:1"] = item
        with self.engine.begin() as conn:
            conn.execute(db.inspections.update().where(db.inspections.c.id == self.inspection["id"])
                .values(template_snapshot={"source": item}))
        result = self.post({"lines": [{"id": "catalog_barcode", "text": "9876543210982"}]})
        self.assertEqual(result.status_code, 201, result.json)
        self.assertEqual(result.json["source_revision"], "list-base")
        current = label_source.draft(self.engine, "list:1")
        self.assertEqual(current["barcode_values"], ["9876543210982"])
        self.assertEqual(label_source.resolve(self.engine, [line(0, "9876543210982")])["code"], "list:1")
        self.assertEqual(label_source.search(self.engine, "9876543210982")[0]["code"], "list:1")
        self.assertNotEqual(label_source.resolve(self.engine, [line(0, "1234567890128")])["status"], "matched")
        checks = evaluate_source([line(0, "清單蘋果"), line(1, "9876543210982")], current, base_date="2026-11-11")["checks"]
        barcodes = [check for check in checks if check["key"].startswith("barcode")]
        self.assertEqual(len(barcodes), 1)
        self.assertEqual(barcodes[0]["status"], "pass")
        for bad in ("987654321O982", "987654321098", "9876 543210982"):
            self.assertEqual(self.post({"lines": [{"id": "catalog_barcode", "text": bad}]}).status_code, 400)
        self.assertEqual(item["barcode_values"], ["1234567890128"])

    def test_photo_and_unknown_sources_offer_existing_editor_instead_of_fake_support(self):
        with self.engine.begin() as conn:
            conn.execute(db.inspections.update().where(db.inspections.c.id == self.inspection["id"])
                .values(template_id="photo-template", template_snapshot={"fields": {"product": "照片標準"}}))
        result = self.get()
        self.assertFalse(result["editable"])
        self.assertEqual(result["kind"], "photo_template")
        response = self.client.post("/api/inspections/inspection-A/standard", json={"base_revision": 0,
            "source_revision": "none", "confirmed": True, "reviewer": "核對員", "note": "測試", "changes": {"name": "新名"}})
        self.assertEqual(response.status_code, 409)

    def test_confirmed_human_text_can_identify_source_without_rewriting_confidence(self):
        observed = line(0, "原始蘋果")
        observed.update(score=.1, ambiguous=True, human_verified=True)
        self.assertEqual(label_source.resolve(self.engine, [observed])["code"], "A")
        self.assertEqual(observed["score"], .1)
        observed["human_uncertain"] = True
        self.assertNotEqual(label_source.resolve(self.engine, [observed])["status"], "matched")


if __name__ == "__main__":
    unittest.main()
