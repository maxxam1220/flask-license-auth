"""Catalog composition is evidence, never automatic approval of a date basis."""
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
import reference_catalog
import source_rules
import standard_reference as standards
from server import create_app
from source_validation import evaluate_source


CODE = "list:qa-catalog-composition"
BARCODE = "2803993832539"
RULE = {"version": 1, "symbology": "EAN13", "prefix": "28039938",
        "day_source": "expiry", "day_width": 3, "suffix": "3"}
CONFIG = {"version": 1, "origin": "excel_fields", "kind": "1", "barcode": "28039938",
          "front": "", "back": "3", "solar": "3", "solar_pos": 9, "price_len": "1"}


def row():
    return {"code": "qa-catalog-composition", "name": "測試鮮果", "barcode": "28039938",
            "barcode_type": "1", "keep_days": 9, "revision": "stable-identity-1",
            "provenance": {"file": "approved-list.xlsx", "sheet": "條碼清單", "row": 325,
                "source_date": "20261008", "barcode_config": deepcopy(CONFIG)}}


def line(identifier, text, **extra):
    y = identifier * 30
    return dict(id=identifier, text=text, score=.99,
                box=[[10, y], [440, y], [440, y+22], [10, y+22]], **extra)


def observed(code=BARCODE, expiry="2026.11.21"):
    return [line(0, "品名：測試鮮果"), line(1, "製造日期：2026.11.12"),
            line(2, "有效日期："+expiry+" 03時"), line(3, code)]


class CatalogBarcodeSeparationTests(unittest.TestCase):
    def test_reference_config_is_not_an_executable_base_date_rule(self):
        source = reference_catalog.build_draft(row())
        self.assertEqual(source["catalog_barcode_config"], CONFIG)
        self.assertEqual(source["barcode_config"], {"kind": "1"})
        self.assertFalse(source.get("web_barcode_rule"))
        prepared = source_rules.prepare_source(source, "2026-11-12")
        self.assertEqual(prepared["barcode_values"], ["28039938"])
        self.assertNotIn("2803993831631", prepared["barcode_values"])
        checks = evaluate_source(observed(), prepared, base_date="2026-11-12")["checks"]
        self.assertFalse(any(check["key"] == "web_barcode_rule" for check in checks))

    def test_evidence_revision_changes_without_invalidating_identity(self):
        first = row()
        second = deepcopy(first)
        second["provenance"]["barcode_config"]["back"] = "4"
        a, b = map(reference_catalog.build_draft, (first, second))
        self.assertEqual(a["revision"], b["revision"])
        self.assertNotEqual(a["catalog_barcode_reference_revision"], b["catalog_barcode_reference_revision"])

    def test_metadata_enrichment_does_not_deactivate_existing_fulltext(self):
        old_row = row()
        del old_row["provenance"]["barcode_config"]
        old = reference_catalog.build_draft(old_row)
        snapshot = dict(deepcopy(old), web_text_approved=True, comparison_scope="approved_text",
            lines=[{"id": 0, "text": "品名：測試鮮果"}, {"id": 1, "text": "本款已核准說明"}],
            web_barcode_rule=deepcopy(RULE))
        version = {"revision": 4, "source_revision": old["revision"], "operation": "update",
                   "snapshot": snapshot, "reviewer": "QA", "created_at": db.now()}
        enriched = reference_catalog.build_draft(row())
        effective = standards.apply_current(None, enriched, version)
        self.assertEqual(effective["standard_reference"]["state"], "approved")
        self.assertEqual(effective["lines"], snapshot["lines"])
        self.assertEqual(effective["web_barcode_rule"], RULE)
        self.assertEqual(effective["keep_days"], 9)


class CatalogBarcodeAuthoringIndependentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "DATA_DIR": Path(self.temp.name),
                               "DATABASE_URL": "", "APP_PASSWORD": ""}, ocr=object())
        self.engine = self.app.extensions["label_engine"]
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token": self.client.get("/api/session").json["csrf"]}
        self.catalog = row()
        self.raw_patch = patch.object(label_source, "raw_draft", side_effect=lambda engine, code:
            reference_catalog.build_draft(deepcopy(self.catalog)) if code == CODE else None)
        self.raw_patch.start()
        self.original = {"id": "composition-scan", "image_id": "composition-photo", "template_id": "",
            "status": "review", "template_snapshot": {"source": reference_catalog.build_draft(self.catalog)},
            "ocr": {"lines": observed()},
            "result": {"inputs": {"base_date": "2026-11-12", "source_code": CODE}, "checks": []},
            "created_at": db.now()}
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id="composition-photo", filename="sample.jpg",
                width=450, height=200, created_at=db.now()))
            conn.execute(insert(db.inspections).values(**self.original))
        self.url = "/api/inspections/composition-scan/barcode-rule"

    def tearDown(self):
        self.raw_patch.stop()
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.json)
        return response.json

    def preview(self):
        data = self.get()
        candidate = next(item for item in data["candidates"] if item["rule"] == RULE)
        body = {key: data[key] for key in ("base_revision", "source_revision", "manual_revision")}
        body.update(candidate_id=candidate["id"], fill_keep_days=False)
        response = self.client.post(self.url+"/preview", json=body, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.json)
        return body, response.json

    def save(self, body, preview):
        return self.client.post(self.url, headers=self.headers, json=dict(body,
            preview_hash=preview["preview_hash"], reviewer="QA", note="核對清單結構並確認本款有效日來源", confirmed=True))

    def test_known_structure_only_offers_declared_width_and_suffix(self):
        data = self.get()
        self.assertTrue(data["can_write"], data)
        self.assertEqual([item["rule"] for item in data["candidates"]], [RULE])
        evidence = data["candidates"][0]["evidence"]
        self.assertEqual(evidence["kind"], "catalog_structure")
        self.assertEqual(evidence["config"], CONFIG)
        self.assertFalse(evidence["date_source_confirmed"])
        self.assertEqual(data["keep_days"]["current"], 9)
        self.assertFalse(data["keep_days"]["can_fill"])

    def test_ambiguous_date_source_is_not_globally_assigned_to_expiry(self):
        changed = deepcopy(self.original["result"])
        changed["inputs"]["base_date"] = "2026-11-21"
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id == "composition-scan").values(result=changed))
        candidates = self.get()["candidates"]
        self.assertEqual({item["rule"]["day_source"] for item in candidates}, {"base_date", "expiry"})
        self.assertTrue(all(item["rule"]["day_width"] == 3 and item["rule"]["suffix"] == "3" for item in candidates))

    def test_missing_config_field_cannot_fall_back_to_guessing(self):
        del self.catalog["provenance"]["barcode_config"]["back"]
        data = self.get()
        self.assertFalse(data["can_write"], data)
        self.assertFalse(data["candidates"])

    def test_conflicting_suffix_cannot_be_replaced_with_observed_suffix(self):
        self.catalog["provenance"]["barcode_config"]["back"] = "4"
        data = self.get()
        self.assertFalse(data["can_write"], data)
        self.assertFalse(data["candidates"])

    def test_config_identity_conflict_cannot_be_treated_as_this_product(self):
        self.catalog["provenance"]["barcode_config"]["barcode"] = "12345678"
        data = self.get()
        self.assertFalse(data["can_write"], data)
        self.assertFalse(data["candidates"])

    def test_code128_or_mismatched_kind_does_not_enter_ean_rules(self):
        for master_kind in ("1", "4"):
            with self.subTest(master_kind=master_kind):
                self.catalog["barcode_type"] = master_kind
                self.catalog["provenance"]["barcode_config"]["kind"] = "4"
                self.assertFalse(self.get()["can_write"])

    def test_changed_evidence_rejects_old_preview_even_with_same_identity_revision(self):
        body, preview = self.preview()
        identity = self.catalog["revision"]
        self.catalog["provenance"]["row"] = 326
        self.assertEqual(self.catalog["revision"], identity)
        self.assertEqual(self.save(body, preview).status_code, 409)
        self.assertIsNone(standards._current(self.engine, CODE))

    def test_approved_expiry_rule_checks_next_dates_and_preserves_nine_days(self):
        body, preview = self.preview()
        response = self.save(body, preview)
        self.assertEqual(response.status_code, 201, response.json)
        version = standards._current(self.engine, CODE)
        snapshot = version["snapshot"]
        self.assertEqual(snapshot["keep_days"], 9)
        self.assertEqual(snapshot["date_settings"], [])
        self.assertEqual(snapshot["barcode_config"], {"kind": "1"})
        self.assertEqual(snapshot["web_barcode_rule"], RULE)
        correct = evaluate_source(observed(), snapshot, base_date="2026-11-12")
        self.assertEqual(next(check for check in correct["checks"] if check["key"] == "web_barcode_rule")["status"], "pass")
        wrong_date = rules.compose(RULE, date(2026, 11, 12))
        wrong_suffix = rules.compose(dict(RULE, suffix="4"), date(2026, 11, 21))
        for bad_code in (wrong_date, wrong_suffix):
            with self.subTest(bad_code=bad_code):
                result = evaluate_source(observed(bad_code), snapshot, base_date="2026-11-12")
                self.assertEqual(next(check for check in result["checks"] if check["key"] == "web_barcode_rule")["status"], "fail")
                self.assertEqual(result["status"], "fail")
        next_day_code = rules.compose(RULE, date(2026, 11, 22))
        next_day_rows = observed(next_day_code, "2026.11.22")
        next_day_rows[1]["text"] = "製造日期：2026.11.13"
        result = evaluate_source(next_day_rows, snapshot, base_date="2026-11-13")
        checks = {check["key"]: check for check in result["checks"]}
        self.assertEqual(checks["web_barcode_rule"]["status"], "pass")
        self.assertEqual(checks["keep_days"]["status"], "pass")
        with self.engine.connect() as conn:
            original = dict(conn.execute(select(db.inspections).where(db.inspections.c.id == "composition-scan")).mappings().one())
        self.assertEqual(original, self.original)


if __name__ == "__main__":
    unittest.main()
