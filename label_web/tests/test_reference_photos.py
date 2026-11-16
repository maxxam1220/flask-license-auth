from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image
from sqlalchemy import insert, select, func, update

import database as db
import corrections
import history_cleanup
import label_source
import manual_reference as manual
import reference_photos as photos
import recognition_samples
import standard_reference as standards
from server import create_app


class ReferencePhotoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app = create_app({"TESTING": True, "DATA_DIR": self.root, "DATABASE_URL": "",
            "APP_PASSWORD": "operator-secret", "ADMIN_PASSWORD": "manager-secret"}, ocr=object())
        self.engine = self.app.extensions["label_engine"]
        # Keep these tests usable before/after root integrates route injection.
        if "get_reference_photo" not in self.app.view_functions:
            def get_inspection(identifier):
                with self.engine.connect() as conn:
                    history_cleanup.ensure_active(conn, identifier)
                return standards._inspection(self.engine, identifier)
            def image_payload(identifier):
                with self.engine.connect() as conn:
                    row = dict(conn.execute(select(db.images).where(db.images.c.id == identifier)).mappings().one())
                return dict(row, url=f"/media/{identifier}/image.jpg", thumbnail=f"/media/{identifier}/thumb.jpg")
            photos.register_routes(self.app, self.engine, self.app.extensions["label_access"].require_admin,
                get_inspection, image_payload, lambda identifier: recognition_samples._image_available(self.root, identifier))
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token": self.client.get("/api/session").json["csrf"]}
        self.definition = {"name": "日本蘋果", "lines": [{"text": "品名：日本蘋果"}, {"text": "產地：日本"}],
                           "keep_days": None, "date_settings": []}
        self.original = self.add_inspection("first", "image-one", brightness=220)
        self.other = self.add_inspection("second", "image-two", brightness=130)
        self.login()

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def login(self, admin=True):
        response = self.client.post("/api/login", json={"password": "manager-secret" if admin else "operator-secret"}, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.json)
        self.headers["X-CSRF-Token"] = response.json["csrf"]

    def add_inspection(self, identifier, image_id, brightness=220, source=None):
        folder = self.root / "images" / image_id
        folder.mkdir(parents=True, exist_ok=True)
        Image.new("RGB", (320, 180), (brightness,)*3).save(folder / "image.jpg")
        row = {"id": identifier, "image_id": image_id, "template_id": "", "status": "review",
            "template_snapshot": {"name": "直接掃描", "version": 0, "image_id": "", "source": source},
            "ocr": {"lines": [{"id": 0, "text": "品名：日本蘋果", "score": .92,
                "box": [[0,0],[220,0],[220,24],[0,24]]}, {"id": 1, "text": "產地：日本", "score": .96,
                "box": [[0,35],[220,35],[220,59],[0,59]]}]},
            "result": {"checks": [], "inputs": {"base_date": "2026-11-16"}}, "created_at": db.now()}
        with self.engine.begin() as conn:
            if not conn.execute(select(db.images.c.id).where(db.images.c.id == image_id)).first():
                conn.execute(insert(db.images).values(id=image_id, filename=image_id+".jpg", sha256=image_id,
                    width=320, height=180, created_at=db.now()))
            conn.execute(insert(db.inspections).values(**row))
        return row

    def post(self, path, body):
        return self.client.post(path, json=body, headers=self.headers)

    def create(self):
        preview = self.post("/api/inspections/first/manual-standard/preview", self.definition)
        self.assertEqual(preview.status_code, 200, preview.json)
        result = self.post("/api/inspections/first/manual-standard", dict(self.definition,
            preview_hash=preview.json["preview_hash"], reviewer="確認員", note="逐字核對照片", confirmed=True))
        self.assertEqual(result.status_code, 201, result.json)
        return result.json["code"]

    def get(self, code, identifier="second"):
        response = self.client.get(f"/api/inspections/{identifier}/reference-photo", query_string={"source_code": code})
        self.assertEqual(response.status_code, 200, response.json)
        return response.json

    def attach(self, code, identifier="second", **extra):
        current = self.get(code, identifier)
        body = {key: current[key] for key in ("source_code", "source_revision", "base_revision")}
        body.update(reviewer="確認員", note="同款內容，照片光線不同", confirmed=True)
        body.update(extra)
        return self.post(f"/api/inspections/{identifier}/reference-photo", body)

    def count(self, table):
        with self.engine.connect() as conn:
            return conn.execute(select(func.count()).select_from(table)).scalar_one()

    def test_two_lighting_photos_share_one_source_and_originals_are_immutable(self):
        code = self.create()
        before = label_source.draft(self.engine, code)
        first = self.attach(code, "first")
        second = self.attach(code)
        self.assertEqual((first.status_code, second.status_code), (201, 201))
        listed = self.client.get("/api/reference-photos", query_string={"source_code": code}).json
        self.assertEqual({row["image_id"] for row in listed["items"]}, {"image-one", "image-two"})
        self.assertEqual(self.count(db.manual_sources), 1)
        self.assertEqual(self.count(standards.versions), 1)
        self.assertEqual(label_source.draft(self.engine, code), before)
        with self.engine.connect() as conn:
            for original in (self.original, self.other):
                actual = dict(conn.execute(select(db.inspections).where(db.inspections.c.id == original["id"])).mappings().one())
                self.assertEqual(actual, original)
        self.assertEqual(second.json["association"]["source_revision"], before["revision"])

    def test_get_and_equivalent_previews_are_read_only_and_offer_existing_source(self):
        code = self.create()
        before = (self.count(photos.photos), self.count(standards.versions))
        draft = self.client.get("/api/inspections/second/manual-standard").json
        preview = self.post("/api/inspections/second/manual-standard/preview", self.definition).json
        self.assertEqual(draft["suggested_source"]["code"], code)
        self.assertEqual(preview["suggested_source"]["code"], code)
        self.assertEqual(preview["equivalent_references"][0]["match_basis"], "exact_definition")
        self.assertEqual(self.get(code)["source"]["code"], code)
        self.assertEqual(before, (self.count(photos.photos), self.count(standards.versions)))
        duplicate = self.post("/api/inspections/second/manual-standard", dict(self.definition,
            preview_hash=preview["preview_hash"], reviewer="確認員", note="相同內容", confirmed=True))
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(self.count(db.manual_sources), 1)

    def test_no_automatic_source_suggestion_from_image_or_name_similarity(self):
        self.create()
        current = self.client.get("/api/inspections/second/reference-photo").json
        self.assertIsNone(current["suggested_source"])
        changed = deepcopy(self.definition)
        changed["lines"][1]["text"] = "產地：台灣"
        preview = self.post("/api/inspections/second/manual-standard/preview", changed).json
        self.assertEqual(preview["equivalent_references"], [])
        changed = deepcopy(self.definition)
        changed["keep_days"] = 3
        self.assertEqual(self.post("/api/inspections/second/manual-standard/preview", changed).json["equivalent_references"], [])

    def test_idempotent_same_image_from_recheck_and_restart(self):
        code = self.create()
        first = self.attach(code)
        second = self.attach(code)
        self.assertEqual((first.status_code, second.status_code), (201, 200))
        self.assertFalse(second.json["created"])
        self.assertEqual(first.json["association"]["id"], second.json["association"]["id"])
        self.add_inspection("recheck", "image-two")
        third = self.attach(code, "recheck")
        self.assertEqual(third.status_code, 200)
        self.assertEqual(self.count(photos.photos), 1)
        another_engine = db.open_database("", self.root)
        try:
            with another_engine.connect() as conn:
                self.assertEqual(conn.execute(select(photos.photos.c.id)).scalar_one(), first.json["association"]["id"])
        finally:
            another_engine.dispose()

    def test_source_revision_changes_are_409_and_old_association_is_marked_stale(self):
        code = self.create()
        self.attach(code, "first")
        current = self.get(code)
        self.add_inspection("edit", "image-edit", source=label_source.draft(self.engine, code))
        editor = self.client.get("/api/inspections/edit/standard").json
        response = self.post("/api/inspections/edit/standard", {"base_revision": editor["base_revision"],
            "source_revision": editor["source_revision"], "changes": {"name": "青森蘋果"},
            "reviewer": "修正員", "note": "更新品名", "confirmed": True})
        self.assertEqual(response.status_code, 201, response.json)
        stale_body = {key: current[key] for key in ("source_code", "source_revision", "base_revision")}
        response = self.post("/api/inspections/second/reference-photo", dict(stale_body,
            reviewer="確認員", note="舊畫面", confirmed=True))
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.count(photos.photos), 1)
        rows = self.client.get("/api/reference-photos", query_string={"source_code": code}).json["items"]
        self.assertTrue(rows[0]["stale"])
        preview = self.post("/api/inspections/second/manual-standard/preview", self.definition).json
        self.assertEqual(preview["equivalent_references"], [])  # Original hash cannot hide a later edit.

    def test_admin_and_csrf_are_enforced_on_all_new_routes(self):
        code = self.create()
        current = self.get(code)
        body = {key: current[key] for key in ("source_code", "source_revision", "base_revision")}
        body.update(reviewer="確認員", note="同款", confirmed=True)
        self.assertEqual(self.client.post("/api/inspections/second/reference-photo", json=body).status_code, 403)
        self.login(admin=False)
        for path in ("/api/inspections/second/reference-photo", "/api/reference-photos?source_code="+code):
            self.assertEqual(self.client.get(path).status_code, 403)
        self.assertEqual(self.post("/api/inspections/second/reference-photo", body).status_code, 403)
        self.assertEqual(self.count(photos.photos), 0)

    def test_missing_photo_and_archive_after_preview_cannot_attach(self):
        code = self.create()
        current = self.get(code)
        body = {key: current[key] for key in ("source_code", "source_revision", "base_revision")}
        body.update(reviewer="確認員", note="已預覽", confirmed=True)
        image = self.root / "images" / "image-two" / "image.jpg"
        image.unlink()
        self.assertEqual(self.post("/api/inspections/second/reference-photo", body).status_code, 409)
        Image.new("RGB", (320,180), "white").save(image)
        with self.engine.begin() as conn:
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="second", batch_id="archive",
                archived=True, revision=1, updated_at=db.now()))
        self.assertEqual(self.post("/api/inspections/second/reference-photo", body).status_code, 404)
        self.assertEqual(self.count(photos.photos), 0)

    def test_pagination_hides_archived_and_missing_photos(self):
        code = self.create()
        self.attach(code, "first")
        self.attach(code)
        page1 = self.client.get("/api/reference-photos", query_string={"source_code": code, "limit": 1}).json
        page2 = self.client.get("/api/reference-photos", query_string={"source_code": code, "limit": 1, "page": 2}).json
        self.assertEqual((len(page1["items"]), page1["has_more"], len(page2["items"]), page2["has_more"]), (1, True, 1, False))
        with self.engine.begin() as conn:
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="second", batch_id="archive",
                archived=True, revision=1, updated_at=db.now()))
        (self.root / "images" / "image-one" / "image.jpg").unlink()
        listed = self.client.get("/api/reference-photos", query_string={"source_code": code}).json
        self.assertEqual((listed["items"], listed["unavailable_on_page"]), ([], 1))

    def test_list_and_desktop_sources_use_same_association_contract(self):
        for code, kind in (("123", "desktop"), ("list:123", "catalog")):
            source = {"code": code, "name": "日本蘋果", "source_kind": kind, "revision": "raw-"+code,
                      "lines": [], "fields": {"product": "日本蘋果"}}
            with self.subTest(kind=kind), patch("label_source.raw_draft", return_value=source):
                response = self.attach(code)
                self.assertEqual(response.status_code, 201, response.json)
                self.assertEqual(response.json["association"]["standard_revision"], 0)
        self.assertEqual(self.count(standards.versions), 0)
        self.assertEqual(self.count(db.manual_sources), 0)

    def test_invalid_input_rolls_back_even_revision_seed(self):
        source = {"code": "123", "name": "日本蘋果", "revision": "base", "source_kind": "desktop"}
        with patch("label_source.raw_draft", return_value=source):
            for changes in ({"confirmed": False}, {"reviewer": ""}, {"note": ""}, {"base_revision": True},
                            {"source_revision": "stale"}, {"extra": "ignored?"}):
                response = self.attach("123", **changes)
                self.assertIn(response.status_code, (400, 409), response.json)
        self.assertEqual(self.count(photos.photos), 0)
        self.assertEqual(self.count(standards.heads), 0)

    def test_raw_source_changed_while_waiting_is_rechecked(self):
        old = {"code": "123", "name": "日本蘋果", "revision": "old", "source_kind": "desktop"}
        new = dict(old, revision="new", name="日本青森蘋果")
        with patch("label_source.raw_draft", side_effect=[old, new]):
            response = self.post("/api/inspections/second/reference-photo", {"source_code": "123",
                "source_revision": "old", "base_revision": 0, "reviewer": "確認員", "note": "等待期間主檔更新", "confirmed": True})
        self.assertEqual(response.status_code, 409, response.json)
        self.assertEqual(self.count(photos.photos), 0)
        self.assertEqual(self.count(standards.heads), 0)

    def test_seeded_zero_revision_does_not_block_first_standard_edit(self):
        source = {"code": "123", "name": "日本蘋果", "revision": "base", "source_kind": "desktop",
            "fields": {"product": "日本蘋果"}, "lines": [{"id": 0, "text": "品名：日本蘋果", "score": 1.,
                "box": [[0,0],[220,0],[220,24],[0,24]]}],
            "keep_days": None, "rules": {}, "date_settings": [], "barcode_values": []}
        self.add_inspection("editor", "image-editor", source=source)
        with patch("label_source.raw_draft", return_value=deepcopy(source)):
            self.assertEqual(self.attach("123").status_code, 201)
            editor = self.client.get("/api/inspections/editor/standard").json
            self.assertEqual(editor["base_revision"], 0)
            response = self.post("/api/inspections/editor/standard", {"base_revision": 0,
                "source_revision": "base", "changes": {"name": "日本青森蘋果"},
                "reviewer": "確認員", "note": "首次修正標準", "confirmed": True})
            self.assertEqual(response.status_code, 201, response.json)
            self.assertEqual(response.json["base_revision"], 1)
        self.assertEqual(self.count(standards.versions), 1)

    def test_archived_original_association_is_not_exposed_via_recheck_image(self):
        code = self.create()
        self.attach(code)
        self.add_inspection("recheck", "image-two")
        with self.engine.begin() as conn:
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="second", batch_id="archive",
                archived=True, revision=1, updated_at=db.now()))
        current = self.get(code, "recheck")
        self.assertEqual(current["associations"], [])
        response = self.attach(code, "recheck")
        self.assertEqual(response.status_code, 404, response.json)

    def test_equivalent_draft_uses_confirmed_correction_and_excludes_uncertain(self):
        code = self.create()
        with self.engine.begin() as conn:
            wrong = deepcopy(self.other)
            wrong["ocr"]["lines"][0]["text"] = "品名：日本錯果"
            conn.execute(update(db.inspections).where(db.inspections.c.id == "second").values(ocr=wrong["ocr"]))
            corrected = corrections.build_revision(wrong, None, {"line_id": 0, "kind": "ocr_misread",
                "text": "品名：日本蘋果", "operation": "replace", "reviewer": "人工核字", "note": "讀圖"}, db.now())
            conn.execute(insert(db.corrections).values(**corrected))
        data = self.client.get("/api/inspections/second/manual-standard").json
        self.assertEqual(data["suggested_source"]["code"], code)
        self.assertEqual(data["manual_revision"], 1)
        self.assertEqual(data["ocr_lines"][0]["text"], "品名：日本錯果")
        with self.engine.begin() as conn:
            uncertain = corrections.build_revision(wrong, corrected, {"line_id": 1, "kind": "uncertain", "text": "",
                "operation": "replace", "reviewer": "人工核字", "note": "產地反光"}, db.now())
            conn.execute(insert(db.corrections).values(**uncertain))
        self.assertEqual(self.client.get("/api/inspections/second/manual-standard").json["equivalent_references"], [])

    def test_multiple_exact_current_references_remain_explicit_choices(self):
        first_code = self.create()
        other = deepcopy(self.definition)
        other["name"] = "青森蘋果"
        other["lines"][0]["text"] = "品名：青森蘋果"
        preview = self.post("/api/inspections/second/manual-standard/preview", other).json
        created = self.post("/api/inspections/second/manual-standard", dict(other, preview_hash=preview["preview_hash"],
            reviewer="確認員", note="另一份標準", confirmed=True))
        self.assertEqual(created.status_code, 201, created.json)
        second_code = created.json["code"]
        self.add_inspection("editor", "image-editor", source=label_source.draft(self.engine, second_code))
        editor = self.client.get("/api/inspections/editor/standard").json
        changed = self.post("/api/inspections/editor/standard", {"base_revision": editor["base_revision"],
            "source_revision": editor["source_revision"], "changes": {"name": "日本蘋果"},
            "reviewer": "確認員", "note": "名稱現已一致", "confirmed": True})
        self.assertEqual(changed.status_code, 201, changed.json)
        self.add_inspection("third", "image-third")
        preview = self.post("/api/inspections/third/manual-standard/preview", self.definition).json
        self.assertEqual({item["code"] for item in preview["equivalent_references"]}, {first_code, second_code})
        self.assertIsNone(preview["suggested_source"])


if __name__ == "__main__":
    unittest.main()
