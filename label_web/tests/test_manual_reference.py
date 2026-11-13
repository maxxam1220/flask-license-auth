from copy import deepcopy
import unittest
from unittest.mock import patch

from flask import Flask, jsonify
from sqlalchemy import create_engine, insert, select, func
from werkzeug.exceptions import HTTPException

import database as db
import label_source
import manual_reference as manual
import standard_reference as standards
import corrections
import history_cleanup
from source_rules import prepare_source
from source_validation import evaluate_source


def line(identifier, text, score=1.):
    y = identifier * 35
    return {"id": identifier, "text": text, "score": score,
            "box": [[0, y], [450, y], [450, y + 22], [0, y + 22]]}


class ManualReferenceTests(unittest.TestCase):
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
        self.original = self.add_inspection("unknown", [line(0, "品名：日本蘋果"), line(1, "貨號：ABC-001"),
            line(2, "產地：日本"), line(3, "有效日期：2026.11.15"), line(4, "11/15")])
        self.definition = {"name": "日本蘋果", "sku": "ABC-001",
            "lines": [{"text": "品名：日本蘋果"}, {"text": "貨號：ABC-001"}, {"text": "產地：日本"}],
            "keep_days": 3, "date_settings": [{"kind": "manufacture", "shift_days": 0},
                                                  {"kind": "expiry", "shift_days": 3}]}
        self.addCleanup(self.engine.dispose)

    def add_inspection(self, identifier, lines, source=None, template_id=""):
        row = {"id": identifier, "image_id": "image", "template_id": template_id,
               "template_snapshot": {"mode": "system_label", "source": source}, "status": "review",
               "ocr": {"lines": lines}, "result": {"checks": [], "inputs": {"base_date": "2026-11-12"}},
               "created_at": db.now()}
        with self.engine.begin() as conn:
            conn.execute(insert(db.inspections).values(**row))
        return row

    def preview(self, definition=None, identifier="unknown"):
        return self.client.post(f"/api/inspections/{identifier}/manual-standard/preview", json=definition or self.definition)

    def create(self, definition=None, identifier="unknown", **extra):
        body = deepcopy(definition or self.definition)
        preview = self.preview(body, identifier)
        self.assertEqual(preview.status_code, 200, preview.json)
        body.update(preview_hash=preview.json["preview_hash"], reviewer="確認人", note="已對照照片逐字核對", confirmed=True)
        body.update(extra)
        return self.client.post(f"/api/inspections/{identifier}/manual-standard", json=body)

    def correct(self, identifier, text="", kind="ocr_misread", operation="replace"):
        with self.engine.begin() as conn:
            current = corrections.latest(conn, self.original["id"])
            revision = corrections.build_revision(self.original, current,
                {"line_id": identifier, "text": text, "kind": kind, "operation": operation,
                 "reviewer": "訂正員", "note": "對照原圖"}, db.now())
            conn.execute(insert(db.corrections).values(**revision))
        return revision

    def test_draft_is_unapproved_and_excludes_full_and_short_batch_dates(self):
        data = self.client.get("/api/inspections/unknown/manual-standard").json
        self.assertTrue(data["can_create"])
        self.assertEqual(data["suggested_name"], "日本蘋果")
        self.assertEqual(data["suggested_sku"], "ABC-001")
        self.assertEqual([x["id"] for x in data["excluded_date_lines"]], [3, 4])
        self.assertIn("尚未核准", data["warning"])
        self.assertEqual(len(data["ocr_lines"]), 5)
        self.assertFalse(label_source.available(self.engine))
        self.assertTrue(self.client.get("/api/inspections/unknown/standard").json["can_create_manual"])

    def test_preview_never_writes_or_assigns_real_code(self):
        response = self.preview()
        self.assertEqual(response.status_code, 200, response.json)
        self.assertNotIn("code", response.json["source"])
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(func.count()).select_from(db.manual_sources)).scalar(), 0)
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(), 0)

    def test_draft_uses_latest_active_confirmed_corrections_only_and_keeps_raw_ocr(self):
        self.correct(0, "品名：確認蘋果")
        self.correct(1, "貨號：NEW-002")
        self.correct(3, "有效日期：2026.11.16")
        self.correct(2, "產地：日木", "label_misprint")
        final = self.correct(4, "", "uncertain")
        data = self.client.get("/api/inspections/unknown/manual-standard").json
        self.assertEqual(data["manual_revision"], final["revision"])
        self.assertEqual(data["draft_basis"], "manual_correction")
        self.assertEqual((data["suggested_name"], data["suggested_sku"]), ("確認蘋果", "NEW-002"))
        self.assertEqual(data["draft_lines"], [{"id": 0, "text": "品名：確認蘋果"}, {"id": 1, "text": "貨號：NEW-002"}])
        self.assertEqual(data["excluded_date_lines"], [{"id": 3, "text": "有效日期：2026.11.16"}])
        self.assertEqual({row["id"]: row["kind"] for row in data["excluded_unconfirmed_lines"]}, {2: "label_misprint", 4: "uncertain"})
        self.assertEqual(data["ocr_lines"], self.original["ocr"]["lines"])
        self.assertIn("仍未核准", data["warning"])
        with self.engine.connect() as conn:
            stored = dict(conn.execute(select(db.inspections).where(db.inspections.c.id == "unknown")).mappings().one())
            self.assertEqual(stored, self.original)
            self.assertEqual(conn.execute(select(func.count()).select_from(db.manual_sources)).scalar(), 0)

    def test_draft_never_suggests_misprinted_name_or_uncertain_sku(self):
        self.correct(0, "品名：日本錯果", "label_misprint")
        self.correct(1, "", "uncertain")
        data = self.client.get("/api/inspections/unknown/manual-standard").json
        self.assertEqual((data["suggested_name"], data["suggested_sku"]), ("", ""))
        self.assertTrue({0, 1}.isdisjoint(row["id"] for row in data["draft_lines"]))

    def test_revoked_correction_is_not_reused_in_manual_draft(self):
        self.correct(0, "品名：確認蘋果")
        final = self.correct(0, operation="revoke")
        data = self.client.get("/api/inspections/unknown/manual-standard").json
        self.assertEqual(data["manual_revision"], final["revision"])
        self.assertEqual(data["draft_basis"], "original_ocr")
        self.assertEqual(data["suggested_name"], "日本蘋果")
        self.assertEqual(data["draft_lines"][0]["text"], "品名：日本蘋果")
        self.assertEqual(data["excluded_unconfirmed_lines"], [])

    def test_listing_paginates_searches_sku_and_returns_only_current_metadata(self):
        code = self.create().json["code"]
        self.add_inspection("second-listing", [])
        other = deepcopy(self.definition)
        other.update(name="台灣梨", sku="PEAR-002", lines=[{"text": "品名：台灣梨"}, {"text": "貨號：PEAR-002"}])
        other_code = self.create(other, "second-listing").json["code"]
        page1 = self.client.get("/api/manual-standards?page=1&limit=1").json
        page2 = self.client.get("/api/manual-standards?page=2&limit=1").json
        self.assertEqual((page1["total"], page1["has_more"], page2["has_more"]), (2, True, False))
        self.assertEqual({page1["items"][0]["code"], page2["items"][0]["code"]}, {code, other_code})
        self.assertEqual(set(page1["items"][0]), {"code", "name", "source_kind", "revision", "reviewer", "created_at", "inspection_id"})
        self.assertEqual(self.client.get("/api/manual-standards?q=ABC-001").json["items"][0]["code"], code)
        self.assertEqual(self.client.get("/api/manual-standards?q=台灣梨").json["items"][0]["code"], other_code)
        self.assertEqual(self.client.get("/api/manual-standards?q=%25").json["total"], 0)
        self.add_inspection("listing-edit", [], label_source.draft(self.engine, code))
        current = self.client.get("/api/inspections/listing-edit/standard").json
        response = self.client.post("/api/inspections/listing-edit/standard", json={"base_revision": 1,
            "source_revision": current["source_revision"], "changes": {"name": "新版蘋果", "lines": [{"id": 1, "text": "貨號：NEW-001"}]},
            "reviewer": "更新人", "note": "確認新版", "confirmed": True})
        self.assertEqual(response.status_code, 201, response.json)
        updated = self.client.get("/api/manual-standards?q=NEW-001").json["items"][0]
        self.assertEqual((updated["name"], updated["revision"], updated["reviewer"], updated["inspection_id"]), ("新版蘋果", 2, "更新人", "unknown"))
        self.assertEqual(self.client.get("/api/manual-standards?q=ABC-001").json["total"], 0)
        self.assertEqual(self.client.get("/api/manual-standards?q=日本蘋果").json["total"], 0)
        for query in ("page=0", "page=abc", "limit=101", "limit=0"):
            self.assertEqual(self.client.get("/api/manual-standards?" + query).status_code, 400)

    def test_approval_preview_and_human_attribution_are_required(self):
        body = dict(self.definition, reviewer="A", note="確認", confirmed=True)
        self.assertEqual(self.client.post("/api/inspections/unknown/manual-standard", json=body).status_code, 409)
        for extra in ({"confirmed": False}, {"reviewer": ""}, {"note": ""}):
            self.assertEqual(self.create(**extra).status_code, 400)
        preview = self.preview().json
        body.update(preview_hash=preview["preview_hash"], lines=[*self.definition["lines"], {"text": "規格：1公斤"}])
        self.assertEqual(self.client.post("/api/inspections/unknown/manual-standard", json=body).status_code, 409)

    def test_creation_audits_original_and_is_searchable_and_explicitly_selectable(self):
        response = self.create()
        self.assertEqual(response.status_code, 201, response.json)
        code = response.json["code"]
        self.assertTrue(code.startswith("manual:"))
        self.assertEqual(response.json["source_kind"], "manual")
        self.assertEqual(response.json["source"]["lines"][0]["box"], [])
        self.assertEqual(label_source.search(self.engine, "ABC-001")[0]["code"], code)
        self.assertEqual(label_source.search(self.engine, "日本蘋果")[0]["source_kind"], "manual")
        self.assertEqual(label_source.resolve(self.engine, [], code)["code"], code)
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：日本蘋果")])["code"], code)
        self.assertEqual(label_source.resolve(self.engine, [line(0, "貨號：ABC-001")])["code"], code)
        with self.engine.connect() as conn:
            self.assertEqual(dict(conn.execute(select(db.inspections)).mappings().one()), self.original)
            audit = conn.execute(select(standards.versions)).mappings().one()
            self.assertEqual((audit["revision"], audit["operation"], audit["reviewer"]), (1, "create", "確認人"))
        again = self.client.get("/api/inspections/unknown/manual-standard").json
        self.assertFalse(again["can_create"])
        self.assertEqual(again["existing_code"], code)

    def test_existing_sources_and_photo_templates_cannot_create_another_source(self):
        for identifier, source, template in (("known", {"code": "D"}, ""), ("photo", None, "template-id")):
            self.add_inspection(identifier, [], source, template)
            self.assertFalse(self.client.get(f"/api/inspections/{identifier}/manual-standard").json["can_create"])
            self.assertEqual(self.preview(identifier=identifier).status_code, 409)

    def test_duplicate_contents_across_photos_do_not_create_ambiguous_copies(self):
        self.assertEqual(self.create().status_code, 201)
        self.add_inspection("other-photo", [])
        self.assertEqual(self.create(identifier="other-photo").status_code, 409)

    def test_dates_must_be_rules_and_not_permanent_ocr_text(self):
        for text in ("2026.11.15", "20261115", "115年11月15日", "有效日：11/15", "11/15", "到店日期"):
            body = deepcopy(self.definition)
            body["lines"].append({"text": text})
            self.assertEqual(self.preview(body).status_code, 400, text)
        body = deepcopy(self.definition)
        body["date_settings"] = [{"kind": "expiry", "shift_days": "3"}]
        self.assertEqual(self.preview(body).status_code, 400)
        for wrong_kind in ([], {}):
            body["date_settings"] = [{"kind": wrong_kind, "shift_days": 3}]
            self.assertEqual(self.preview(body).status_code, 400)

    def test_contradictory_manual_schedule_is_rejected_without_inventing_missing_dates(self):
        for settings, keep_days in (([{"kind": "manufacture", "shift_days": 3}, {"kind": "expiry", "shift_days": 1}], None),
            ([{"kind": "manufacture", "shift_days": 0}, {"kind": "arrival", "shift_days": -1}], None),
            ([{"kind": "arrival", "shift_days": 4}, {"kind": "expiry", "shift_days": 3}], None),
            ([{"kind": "manufacture", "shift_days": 0}, {"kind": "expiry", "shift_days": 3}], 5)):
            body = dict(self.definition, date_settings=settings, keep_days=keep_days)
            self.assertEqual(self.preview(body).status_code, 400, settings)
        body = dict(self.definition, date_settings=[{"kind": "expiry", "shift_days": 3}], keep_days=5)
        result = self.preview(body)
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(len(result.json["source"]["date_settings"]), 1)

    def test_manual_schedule_changes_obey_same_rule_and_rejection_does_not_write_version(self):
        code = self.create().json["code"]
        self.add_inspection("date-edit", [], label_source.draft(self.engine, code))
        current = self.client.get("/api/inspections/date-edit/standard").json
        for changes in ({"date_settings": [{"index": 0, "shift_days": 4}]}, {"keep_days": 8}):
            body = {"base_revision": 1, "source_revision": current["source_revision"], "changes": changes,
                    "reviewer": "B", "note": "修改日期", "confirmed": True}
            response = self.client.post("/api/inspections/date-edit/standard", json=body)
            self.assertEqual(response.status_code, 400, response.json)
            self.assertEqual(self.client.get("/api/inspections/date-edit/standard").json["base_revision"], 1)

    def test_manual_text_revisions_cannot_bypass_creation_date_and_line_rules(self):
        code = self.create().json["code"]
        original = label_source.draft(self.engine, code)
        self.add_inspection("fixed-edit", [], original)
        current = self.client.get("/api/inspections/fixed-edit/standard").json
        for value in ("11/15", "到店日：", "製造日期：", "產地：日本\n食用前清洗"):
            body = {"base_revision": 1, "source_revision": current["source_revision"],
                    "changes": {"lines": [{"id": 2, "text": value}]},
                    "reviewer": "B", "note": "確認標準", "confirmed": True}
            response = self.client.post("/api/inspections/fixed-edit/standard", json=body)
            self.assertEqual(response.status_code, 400, value)
            self.assertEqual(self.client.get("/api/inspections/fixed-edit/standard").json["base_revision"], 1)
        self.assertEqual(label_source.draft(self.engine, code), original)
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(), 1)
            self.assertEqual(dict(conn.execute(select(db.inspections).where(db.inspections.c.id == "unknown")).mappings().one()), self.original)
        definition = dict(self.definition, name="日本\n蘋果", lines=[{"text": "產地：日本"}])
        self.add_inspection("bad-name", [])
        self.assertEqual(self.preview(definition, "bad-name").status_code, 400)

    def test_archived_after_preview_cannot_create_manual_standard(self):
        preview = self.preview().json
        with self.engine.begin() as conn:
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="unknown", batch_id="archive-race",
                archived=True, revision=1, updated_at=db.now()))
        body = dict(self.definition, preview_hash=preview["preview_hash"], reviewer="A", note="已預覽", confirmed=True)
        response = self.client.post("/api/inspections/unknown/manual-standard", json=body)
        self.assertEqual(response.status_code, 404, response.json)
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(func.count()).select_from(db.manual_sources)).scalar(), 0)
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(), 0)

    def test_source_search_uses_current_manual_name_sku_and_text_after_edit(self):
        code = self.create().json["code"]
        self.add_inspection("search-edit", [], label_source.draft(self.engine, code))
        current = self.client.get("/api/inspections/search-edit/standard").json
        body = {"base_revision": 1, "source_revision": current["source_revision"],
                "changes": {"name": "新版蘋果", "lines": [{"id": 1, "text": "貨號：NEW-001"}, {"id": 2, "text": "產地：台灣"}]},
                "reviewer": "B", "note": "確認新版", "confirmed": True}
        self.assertEqual(self.client.post("/api/inspections/search-edit/standard", json=body).status_code, 201)
        for query in ("NEW-001", "新版蘋果", "台灣", code):
            self.assertEqual([row["code"] for row in label_source.search(self.engine, query)], [code])
        for query in ("ABC-001", "日本蘋果", "日本"):
            self.assertEqual(label_source.search(self.engine, query), [])
        body.update(base_revision=2, operation="reset", changes={})
        self.assertEqual(self.client.post("/api/inspections/search-edit/standard", json=body).status_code, 201)
        self.assertEqual([row["code"] for row in label_source.search(self.engine, "ABC-001")], [code])
        self.assertEqual(label_source.search(self.engine, "NEW-001"), [])

    def test_resolution_rejects_revision_changed_after_identity_selection(self):
        code = self.create().json["code"]
        self.add_inspection("concurrent-edit", [], label_source.draft(self.engine, code))
        current = self.client.get("/api/inspections/concurrent-edit/standard").json
        original_draft = label_source.draft
        def changed_draft(engine, selected):
            response = self.client.post("/api/inspections/concurrent-edit/standard", json={
                "base_revision": 1, "source_revision": current["source_revision"],
                "changes": {"name": "新版梨子", "lines": [{"id": 1, "text": "貨號：PEAR-002"}]},
                "reviewer": "B", "note": "另一人同時更新", "confirmed": True})
            self.assertEqual(response.status_code, 201, response.json)
            return original_draft(engine, selected)
        observed = [line(0, "品名：日本蘋果"), line(1, "貨號：ABC-001")]
        before = deepcopy(observed)
        with patch.object(label_source, "draft", side_effect=changed_draft):
            result = label_source.resolve(self.engine, observed)
        self.assertEqual(result["status"], "ambiguous")
        self.assertIsNone(result["source"])
        self.assertIn("更新", result["reason"])
        self.assertEqual(observed, before)
        self.assertNotEqual(label_source.resolve(self.engine, observed)["status"], "matched")
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：新版梨子"), line(1, "貨號：PEAR-002")])["code"], code)
        self.assertEqual(label_source.resolve(self.engine, observed, source_code=code)["source"]["name"], "新版梨子")

    def test_expiry_offset_does_not_double_add_keep_days_and_unknown_lines_stay_read(self):
        code = self.create().json["code"]
        source = prepare_source(label_source.draft(self.engine, code), "2026-11-12")
        lines = [line(0, "品名：日本蘋果"), line(1, "貨號：ABC-001"), line(2, "產地：日本"),
                 line(3, "製造日期：2026.11.12"), line(4, "有效日期：2026.11.15"), line(5, "尚未核准的文字")]
        result = evaluate_source(lines, source, base_date="2026-11-12")
        scheduled = next(check for check in result["checks"] if check["key"] == "expiry_schedule")
        self.assertEqual(scheduled["expected"], "2026.11.15")
        self.assertEqual(scheduled["status"], "pass")
        self.assertTrue(any(check["status"] == "read" and 5 in check["line_ids"] for check in result["checks"]))

    def test_future_manual_standard_edit_and_restore_use_existing_version_audit(self):
        code = self.create().json["code"]
        source = label_source.draft(self.engine, code)
        self.add_inspection("selected", [], source)
        current = self.client.get("/api/inspections/selected/standard").json
        self.assertTrue(current["editable"])
        self.assertEqual(current["kind"], "manual")
        body = {"base_revision": current["base_revision"], "source_revision": current["source_revision"],
                "changes": {"name": "確認蘋果", "lines": [{"id": 2, "text": "產地：台灣"}]},
                "reviewer": "B", "note": "確認修正", "confirmed": True}
        response = self.client.post("/api/inspections/selected/standard", json=body)
        self.assertEqual(response.status_code, 201, response.json)
        updated = label_source.draft(self.engine, code)
        self.assertEqual((updated["name"], updated["fields"]["origin"]), ("確認蘋果", "台灣"))
        self.assertEqual(label_source.search(self.engine, "確認蘋果")[0]["code"], code)
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：確認蘋果")])["code"], code)
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：日本蘋果")])["status"], "unmatched")
        body.update(base_revision=2, operation="restore", target_revision=1, changes={})
        restored = self.client.post("/api/inspections/selected/standard", json=body)
        self.assertEqual(restored.status_code, 201, restored.json)
        self.assertEqual(label_source.draft(self.engine, code)["name"], "日本蘋果")

    def test_identity_required_shared_footer_alone_does_not_match(self):
        body = deepcopy(self.definition)
        body["lines"].append({"text": "福和生鮮農產股份有限公司"})
        self.create(body)
        self.assertEqual(label_source.resolve(self.engine, [line(0, "福和生鮮農產股份有限公司")])["status"], "unmatched")
        self.assertNotEqual(label_source.resolve(self.engine, [line(0, "品名：日本蘋果", .4)])["status"], "matched")

    def test_same_name_unknown_fields_remain_ambiguous_and_known_differences_resolve(self):
        first = deepcopy(self.definition)
        first.update(sku="", lines=[{"text": "品名：日本蘋果"}, {"text": "產地：日本"}])
        code_a = self.create(first).json["code"]
        self.add_inspection("unknown-variant", [])
        second = deepcopy(first)
        second["lines"] = [{"text": "品名：日本蘋果"}, {"text": "電話：0800-200-859"}]
        self.create(second, "unknown-variant")
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：日本蘋果"), line(1, "產地：日本")])["status"], "ambiguous")
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：日本蘋果"), line(1, "電話：0800-200-859")])["status"], "ambiguous")
        with self.engine.begin() as conn:
            conn.execute(db.manual_sources.delete().where(db.manual_sources.c.code != code_a))
        self.add_inspection("different-origin", [])
        third = deepcopy(first)
        third["lines"][1]["text"] = "產地：台灣"
        self.create(third, "different-origin")
        self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：日本蘋果"), line(1, "產地：日本")])["code"], code_a)

    def test_manual_known_sku_or_footer_does_not_eliminate_unknown_desktop_peer(self):
        body = deepcopy(self.definition)
        body["lines"].append({"text": "新北市土城區中興路9號"})
        code = self.create(body).json["code"]
        catalog = label_source.raw_catalog(self.engine)
        catalog["desktop"] = {"code": "desktop", "name": "日本蘋果", "sku": set(), "barcode": set(),
            "spec": set(), "origin": set(), "text": set(), "text_by_kind": {}, "source_kind": "desktop"}
        with patch("label_source.raw_catalog", return_value=catalog):
            for extra in ("貨號：ABC-001", "新北市土城區中興路9號", "產地：日本"):
                resolution = label_source.resolve(self.engine, [line(0, "品名：日本蘋果"), line(1, extra)])
                self.assertEqual(resolution["status"], "ambiguous", extra)
            self.assertEqual(label_source.resolve(self.engine, [line(0, "貨號：ABC-001")])["code"], code)

    def test_missing_manual_text_does_not_eliminate_it_against_known_desktop_text(self):
        body = deepcopy(self.definition)
        body.update(sku="", lines=[{"text": "品名：日本蘋果"}])
        self.create(body)
        catalog = label_source.raw_catalog(self.engine)
        catalog["desktop"] = {"code": "desktop", "name": "日本蘋果", "sku": {"abc-001"}, "barcode": set(),
            "spec": set(), "origin": {"日本"}, "text": {"日本", "新北市土城區中興路9號"},
            "text_by_kind": {"origin": {"日本"}, "address": {"新北市土城區中興路9號"}}, "source_kind": "desktop"}
        with patch("label_source.raw_catalog", return_value=catalog):
            for extra in ("貨號：ABC-001", "產地：日本", "新北市土城區中興路9號"):
                self.assertEqual(label_source.resolve(self.engine, [line(0, "品名：日本蘋果"), line(1, extra)])["status"], "ambiguous", extra)


if __name__ == "__main__":
    unittest.main()
