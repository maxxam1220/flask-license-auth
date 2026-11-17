"""Manual formula entry cannot bypass observed evidence or source boundaries."""
from copy import deepcopy
from datetime import date
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import insert, select, update

import barcode_rule_authoring as rules
import database as db
import label_source
import manual_reference
import standard_library
import standard_reference as standards
from server import create_app
from source_validation import evaluate_source


CODE = "manual:qaindependentpapaya001"
OBSERVED = "2834665432436"
RULE = {"version": 1, "symbology": "EAN13", "prefix": "28346654",
        "day_source": "expiry", "day_width": 3, "suffix": "3"}


def line(identifier, text, **extra):
    y = identifier * 30
    return dict(id=identifier, text=text, score=.99,
                box=[[10, y], [440, y], [440, y+22], [10, y+22]], **extra)


class ManualBarcodeIndependentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "DATA_DIR": Path(self.temp.name), "DATABASE_URL": "",
            "APP_PASSWORD": "qa-operator-2026", "ADMIN_PASSWORD": "qa-manager-2026"}, ocr=object())
        self.engine = self.app.extensions["label_engine"]
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token": self.client.get("/api/session").json["csrf"]}
        self.login("qa-manager-2026")
        with self.app.app_context():
            self.base, digest = manual_reference.definition({"name": "測試木瓜", "keep_days": 3,
                "date_settings": [{"kind": "manufacture", "shift_days": 0}, {"kind": "expiry", "shift_days": 3}],
                "lines": [{"text": text} for text in ["品名：測試木瓜", "內容物：木瓜", "產地：台灣", "保存條件：冷藏", OBSERVED]]})
        self.base.update(code=CODE, reference_image_id="manual-photo", reference_inspection_id="manual-scan")
        texts = ["品名：測試木瓜", "內容物：木瓜", "產地：台灣", "保存條件：冷藏", OBSERVED,
                 "製造日期：2026.11.17", "有效日期：2026.11.20"]
        self.original = {"id": "manual-scan", "image_id": "manual-photo", "template_id": "", "status": "review",
            "template_snapshot": {"source": deepcopy(self.base)}, "ocr": {"lines": [line(i, text) for i, text in enumerate(texts)]},
            "result": {"inputs": {"source_code": CODE, "base_date": "2026-11-17"}, "checks": []}, "created_at": db.now()}
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id="manual-photo", filename="sample.jpg", width=450, height=300, created_at=db.now()))
            conn.execute(insert(db.inspections).values(**self.original))
            conn.execute(insert(db.manual_sources).values(code=CODE, name=self.base["name"], inspection_id="manual-scan",
                reference_hash=digest, snapshot=self.base, active=True, reviewer="QA", note="已核准文字標準", created_at=db.now()))
            conn.execute(insert(standards.heads).values(code=CODE, revision=1))
            conn.execute(insert(standards.versions).values(id=db.uid(), code=CODE, revision=1, source_revision=digest,
                operation="create", snapshot=self.base, changes={}, inspection_id="manual-scan", reviewer="QA", note="舊版", created_at=db.now()))
            conn.execute(insert(standard_library.categories).values(id="fruit", name="鮮果", name_key="鮮果",
                revision=1, removed=False, updated_at=db.now()))
            conn.execute(insert(standard_library.items).values(kind="manual", key=CODE, revision=1,
                category_id="fruit", removed=False, updated_at=db.now()))
        self.url = "/api/inspections/manual-scan/barcode-rule"

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def login(self, password):
        response = self.client.post("/api/login", headers=self.headers, json={"password": password})
        self.assertEqual(response.status_code, 200, response.json)
        self.headers["X-CSRF-Token"] = response.json["csrf"]

    def get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.json)
        return response.json

    def body(self):
        data = self.get()
        return dict({key: data[key] for key in ("base_revision", "source_revision", "manual_revision")},
            candidate_id="manual", fill_keep_days=False, manual_rule=deepcopy(RULE), confirmed_ean13=True)

    def preview(self, body=None):
        return self.client.post(self.url+"/preview", headers=self.headers, json=body or self.body())

    def save(self, body, preview_hash):
        return self.client.post(self.url, headers=self.headers, json=dict(body, preview_hash=preview_hash,
            reviewer="QA", note="確認實物 EAN13 與本款組碼", confirmed=True))

    def set_ocr(self, ocr):
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id == "manual-scan").values(ocr=ocr))

    def assert_not_saved(self):
        self.assertEqual(standards._current(self.engine, CODE)["revision"], 1)

    def test_unknown_kind_requires_explicit_boolean_ean13_acknowledgement(self):
        data = self.get()
        self.assertTrue(data["manual_entry"]["available"])
        self.assertTrue(data["manual_entry"]["requires_ean13_confirmation"])
        for value in (False, 1, "true", None):
            body = self.body(); body["confirmed_ean13"] = value
            with self.subTest(value=value):
                self.assertEqual(self.preview(body).status_code, 400)
        body = self.body(); del body["confirmed_ean13"]
        self.assertEqual(self.preview(body).status_code, 400)
        self.assert_not_saved()

    def test_wrong_date_source_does_not_use_expiry_as_a_fallback(self):
        body = self.body(); body["manual_rule"]["day_source"] = "manufacture"
        self.assertEqual(self.preview(body).status_code, 400)
        self.assert_not_saved()

    def test_old_other_product_prefix_or_wrong_tail_cannot_be_approved(self):
        for changes in ({"prefix": "27411445"}, {"suffix": "4"}):
            body = self.body(); body["manual_rule"].update(changes)
            with self.subTest(changes=changes):
                self.assertEqual(self.preview(body).status_code, 400)
        self.assert_not_saved()

    def test_invalid_checksum_does_not_become_valid_by_typing_a_formula(self):
        ocr = deepcopy(self.original["ocr"]); ocr["lines"][4]["text"] = OBSERVED[:-1]+"0"
        self.set_ocr(ocr)
        self.assertFalse(self.get()["manual_entry"]["available"])
        self.assertEqual(self.preview().status_code, 409)

    def test_explicit_code128_decode_cannot_be_overridden_by_acknowledgement(self):
        ocr = deepcopy(self.original["ocr"])
        ocr["barcodes"] = {"items": [{"text": OBSERVED, "format": "CODE128", "box": []}]}
        self.set_ocr(ocr)
        self.assertFalse(self.get()["manual_entry"]["available"])
        self.assertEqual(self.preview().status_code, 409)

    def test_known_source_code128_cannot_be_overridden(self):
        base = deepcopy(self.base); base["barcode_config"] = {"kind": "4"}
        with patch.object(label_source, "raw_draft", return_value=base):
            self.assertFalse(self.get()["manual_entry"]["available"])
            self.assertEqual(self.preview().status_code, 409)

    def test_hri_decode_conflict_cannot_be_overridden(self):
        ocr = deepcopy(self.original["ocr"])
        ocr["barcodes"] = {"items": [{"text": rules.compose(RULE, date(2026, 11, 21)), "format": "EAN13", "box": []}]}
        self.set_ocr(ocr)
        self.assertFalse(self.get()["manual_entry"]["available"])
        self.assertEqual(self.preview().status_code, 409)

    def test_multiple_labels_or_multiple_barcodes_cannot_be_overridden(self):
        multiple_scope = dict(deepcopy(self.original["ocr"]), label_scope={"status": "multiple"})
        multiple_codes = deepcopy(self.original["ocr"])
        multiple_codes["lines"].append(line(7, rules.compose(RULE, date(2026, 11, 21))))
        for ocr in (multiple_scope, multiple_codes):
            with self.subTest(ocr=ocr):
                self.set_ocr(ocr)
                self.assertFalse(self.get()["manual_entry"]["available"])
                self.assertEqual(self.preview().status_code, 409)

    def test_uncertain_barcode_cannot_be_overridden(self):
        for change in ({"score": .2}, {"ambiguous": True}, {"human_uncertain": True}):
            ocr = deepcopy(self.original["ocr"]); ocr["lines"][4].update(change)
            with self.subTest(change=change):
                self.set_ocr(ocr)
                self.assertFalse(self.get()["manual_entry"]["available"])
                self.assertEqual(self.preview().status_code, 409)

    def test_uncertain_or_missing_selected_date_is_not_replaced_with_base_date(self):
        for change in ({"score": .2}, {"ambiguous": True}, {"text": "有效日期：看不清楚"}):
            ocr = deepcopy(self.original["ocr"]); ocr["lines"][6].update(change)
            with self.subTest(change=change):
                self.set_ocr(ocr)
                self.assertEqual(self.preview().status_code, 400)

    def test_catalog_source_cannot_override_known_configuration_with_manual_entry(self):
        catalog = dict(deepcopy(self.base), code="list:another", source_kind="catalog", revision="catalog-1",
            barcode_config={"kind": "1"}, barcode_values=["28346654"])
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id == "manual-scan").values(template_snapshot={"source": catalog}))
        with patch.object(label_source, "raw_draft", return_value=catalog):
            self.assertFalse(self.get()["manual_entry"]["available"])
            self.assertEqual(self.preview().status_code, 409)

    def test_operator_cannot_preview_manual_rule(self):
        body = self.body()
        self.client.post("/api/logout", headers=self.headers)
        self.headers["X-CSRF-Token"] = self.client.get("/api/session").json["csrf"]
        self.login("qa-operator-2026")
        self.assertEqual(self.preview(body).status_code, 403)
        self.assert_not_saved()

    def test_edit_to_another_matching_formula_after_preview_still_conflicts(self):
        body = self.body(); preview = self.preview(body)
        self.assertEqual(preview.status_code, 200, preview.json)
        changed = deepcopy(body)
        changed["manual_rule"].update(prefix="283466543", day_width=2)
        self.assertEqual(rules.compose(changed["manual_rule"], date(2026, 11, 20)), OBSERVED)
        self.assertEqual(self.save(changed, preview.json["preview_hash"]).status_code, 409)
        self.assert_not_saved()

    def test_save_preserves_all_existing_standard_fields_and_checks_next_batch(self):
        before = standards.apply_current(self.engine, self.base)
        before.pop("standard_reference", None)
        before["revision"] = self.base["revision"]
        body = self.body(); preview = self.preview(body)
        self.assertEqual(preview.status_code, 200, preview.json)
        saved = self.save(body, preview.json["preview_hash"])
        self.assertEqual(saved.status_code, 201, saved.json)
        snapshot = standards._current(self.engine, CODE)["snapshot"]
        for key, value in before.items():
            self.assertEqual(snapshot[key], value, key)
        self.assertEqual(snapshot["web_barcode_rule"], RULE)
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(db.manual_sources.c.snapshot).where(db.manual_sources.c.code == CODE)).scalar_one(), self.base)
            self.assertEqual(conn.execute(select(standard_library.items.c.category_id).where(standard_library.items.c.key == CODE)).scalar_one(), "fruit")
            actual = dict(conn.execute(select(db.inspections).where(db.inspections.c.id == "manual-scan")).mappings().one())
        self.assertEqual(actual, self.original)
        current = evaluate_source(self.original["ocr"]["lines"], snapshot, base_date="2026-11-17")
        self.assertEqual(next(c for c in current["checks"] if c["key"] == "web_barcode_rule")["status"], "pass")
        next_rows = deepcopy(self.original["ocr"]["lines"])
        next_rows[5]["text"] = "製造日期：2026.11.18"
        next_rows[6]["text"] = "有效日期：2026.11.21"
        next_rows[4]["text"] = rules.compose(RULE, date(2026, 11, 21))
        result = evaluate_source(next_rows, snapshot, base_date="2026-11-18")
        self.assertEqual(next(c for c in result["checks"] if c["key"] == "web_barcode_rule")["status"], "pass")
        next_rows[4]["text"] = OBSERVED
        result = evaluate_source(next_rows, snapshot, base_date="2026-11-18")
        self.assertEqual(next(c for c in result["checks"] if c["key"] == "web_barcode_rule")["status"], "fail")
        self.assertEqual(result["status"], "fail")


if __name__ == "__main__":
    unittest.main()
