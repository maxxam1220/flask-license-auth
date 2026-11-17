"""Independent regressions for inferred barcode rules, evidence and stale previews."""
from copy import deepcopy
from datetime import date
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sqlalchemy import func, insert, select, update

import barcode_rule_authoring as rules
import database as db
import label_source
import reference_catalog
import source_rules
import standard_library
import standard_reference as standards
from server import create_app
from source_validation import evaluate_source


CODE = "list:qa-barcode"
OBSERVED = "2803993832539"
RULE = {"version": 1, "symbology": "EAN13", "prefix": "28039938",
        "day_source": "expiry", "day_width": 3, "suffix": "3"}


def line(identifier, text, **extra):
    y = identifier * 30
    return dict(id=identifier, text=text, score=.99,
                box=[[10, y], [440, y], [440, y+22], [10, y+22]], **extra)


class BarcodeRuleMathIndependentTests(unittest.TestCase):
    def test_same_sample_does_not_identify_unique_printer_configuration(self):
        day = date(2026, 11, 21)
        self.assertEqual(rules.compose(RULE, day), OBSERVED)
        # A different insertion position and two-digit day also reproduce it.
        cfg = {"kind": "1", "barcode": "28039938", "master_barcode": "28039938",
               "solar": "2", "solar_pos": 10, "back": "33"}
        self.assertEqual(source_rules.barcode_for_source(cfg, day.isoformat()), OBSERVED)
        self.assertEqual(source_rules.barcode_for_source(dict(cfg, solar="", back="3253"), day.isoformat()), OBSERVED)

    def test_leap_year_and_year_boundary_use_calendar_not_integer_day_addition(self):
        self.assertEqual(rules.compose(RULE, date(2028, 11, 20)), OBSERVED)
        self.assertNotEqual(rules.compose(RULE, date(2028, 11, 21)), OBSERVED)
        self.assertEqual(rules.compose(RULE, date(2027, 1, 1)), "2803993800132")
        self.assertEqual(rules.compose(RULE, date(2026, 12, 31)), "2803993836537")

    def test_two_digit_solar_days_repeat_and_cannot_identify_a_year(self):
        rule = dict(RULE, day_width=2, suffix="33")
        self.assertEqual(rules.compose(rule, date(2026, 1, 25)), rules.compose(rule, date(2026, 11, 21)))
        self.assertEqual(rules.compose(RULE, date(2026, 11, 21)), rules.compose(RULE, date(2027, 11, 21)))

    def test_dynamic_barcode_exclusion_does_not_remove_mixed_content(self):
        self.assertTrue(rules.dynamic_literal(RULE, "條碼："+OBSERVED))
        self.assertFalse(rules.dynamic_literal(RULE, "品名：蘋果 "+OBSERVED))
        self.assertFalse(rules.dynamic_literal(RULE, "貨號："+OBSERVED))
        self.assertFalse(rules.dynamic_literal(RULE, OBSERVED[:-1]+"0"))

    def test_expiry_formula_does_not_silently_use_global_base_date(self):
        rows = [line(0, "有效日期：2026.11.21"), line(1, OBSERVED)]
        before = deepcopy(rows)
        checked = rules.evaluate_rule(rows, RULE, "2026-11-12")
        self.assertEqual(checked["status"], "pass")
        self.assertEqual(checked["date_value"], "2026-11-21")
        self.assertEqual(rows, before)

    def test_checksum_valid_but_wrong_date_barcode_fails(self):
        wrong = rules.compose(RULE, date(2026, 11, 12))
        self.assertEqual(wrong, "2803993831631")
        checked = rules.evaluate_rule([line(0, "有效日期：2026.11.21"), line(1, wrong)], RULE, "2026-11-12")
        self.assertEqual(checked["status"], "fail")
        self.assertEqual(checked["expected"], OBSERVED)

    def test_missing_or_uncertain_expiry_does_not_fall_back_to_batch_date(self):
        for rows in ([line(0, OBSERVED)],
                     [line(0, "有效日期：2026.11.21", ambiguous=True), line(1, OBSERVED)],
                     [line(0, "有效日期：2026.02.30"), line(1, OBSERVED)]):
            with self.subTest(rows=rows):
                self.assertEqual(rules.evaluate_rule(rows, RULE, "2026-11-21")["status"], "review")

    def test_formula_match_cannot_mask_wrong_scheduled_date_or_year(self):
        source = reference_catalog.build_draft({"code": "sample", "name": "測試水果",
            "barcode": "28039938", "barcode_type": "1", "keep_days": 9,
            "revision": "source-1", "provenance": {}})
        source.update(web_barcode_rule=RULE, date_settings=[
            {"content": "製造日期", "format": "A", "shift_days": 0},
            {"content": "有效日期", "format": "B", "shift_days": 0}])
        for expiry in (date(2026, 11, 20), date(2025, 11, 21)):
            rows = [line(0, "品名：測試水果"), line(1, "製造日期：2026.11.12"),
                    line(2, "有效日期："+expiry.isoformat()), line(3, rules.compose(RULE, expiry))]
            result = evaluate_source(rows, source, base_date="2026-11-12")
            checks = {check["key"]: check for check in result["checks"]}
            self.assertEqual(checks["web_barcode_rule"]["status"], "pass")
            self.assertEqual(checks["expiry_schedule"]["status"], "fail")
            self.assertEqual(result["status"], "fail")


class BarcodeRuleEvidenceIndependentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "DATA_DIR": Path(self.temp.name),
                               "DATABASE_URL": "", "APP_PASSWORD": ""}, ocr=object())
        self.engine = self.app.extensions["label_engine"]
        self.client = self.app.test_client()
        self.headers = {"X-CSRF-Token": self.client.get("/api/session").json["csrf"]}
        self.base = reference_catalog.build_draft({"code": "qa-barcode", "name": "測試水果",
            "barcode": "28039938", "barcode_type": "1", "keep_days": 9,
            "revision": "source-1", "provenance": {}})
        self.raw_patch = patch.object(label_source, "raw_draft", side_effect=lambda engine, code:
            deepcopy(self.base) if code == CODE else None)
        self.raw_patch.start()
        self.original = {"id": "barcode-scan", "image_id": "barcode-image", "template_id": "",
            "status": "review", "template_snapshot": {"source": deepcopy(self.base)},
            "ocr": {"lines": [line(0, "品名：測試水果"), line(1, "製造日期：2026.11.12"),
                              line(2, "有效日期：2026.11.21 03時"), line(3, OBSERVED)]},
            "result": {"inputs": {"base_date": "2026-11-12", "source_code": CODE}, "checks": []},
            "created_at": db.now()}
        with self.engine.begin() as conn:
            conn.execute(insert(db.images).values(id="barcode-image", filename="sample.jpg",
                width=450, height=200, created_at=db.now()))
            conn.execute(insert(db.inspections).values(**self.original))
        self.url = "/api/inspections/barcode-scan/barcode-rule"

    def tearDown(self):
        self.raw_patch.stop()
        self.app.extensions["label_worker"].shutdown(wait=True)
        self.engine.dispose()
        self.temp.cleanup()

    def get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200, response.json)
        return response.json

    def choice(self, **overrides):
        data = self.get()
        candidate = next(row for row in data["candidates"] if row["rule"] == RULE)
        return dict({key: data[key] for key in ("base_revision", "source_revision", "manual_revision")},
                    candidate_id=candidate["id"], fill_keep_days=False, **overrides)

    def preview(self, choice=None):
        choice = choice or self.choice()
        response = self.client.post(self.url+"/preview", json=choice, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.json)
        return choice, response.json

    def save(self, choice, preview):
        return self.client.post(self.url, headers=self.headers, json=dict(choice,
            preview_hash=preview["preview_hash"], reviewer="QA", note="獨立測試確認候選", confirmed=True))

    def set_ocr(self, ocr):
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id == "barcode-scan").values(ocr=ocr))

    def count_versions(self):
        with self.engine.connect() as conn:
            return conn.scalar(select(func.count()).select_from(standards.versions))

    def test_suggestion_is_explicitly_hypothetical_and_does_not_write(self):
        data = self.get()
        candidate = next(row for row in data["candidates"] if row["rule"] == RULE)
        self.assertTrue(any("假設" in warning for warning in candidate["warnings"]))
        self.assertTrue(any("不同組成" in warning for warning in candidate["warnings"]))
        self.assertEqual(candidate["parts"][-1]["value"], "9")
        self.assertEqual(data["keep_days"]["current"], 9)
        self.assertFalse(data["keep_days"]["can_fill"])
        self.assertEqual(self.count_versions(), 0)

    def test_unknown_symbology_ocr_only_cannot_be_assumed_ean13(self):
        self.base["barcode_config"] = {}
        data = self.get()
        self.assertFalse(data["can_write"])
        self.assertFalse(data["candidates"])

    def test_explicit_code128_is_not_reinterpreted_even_with_ean_checksum(self):
        self.base["barcode_config"] = {"kind": "4"}
        data = self.get()
        self.assertFalse(data["can_write"])
        self.assertFalse(data["candidates"])

    def test_decode_ean13_can_establish_unknown_symbology(self):
        self.base["barcode_config"] = {}
        ocr = deepcopy(self.original["ocr"])
        ocr["barcodes"] = {"items": [{"text": OBSERVED, "format": "EAN13", "box": []}]}
        self.set_ocr(ocr)
        self.assertTrue(self.get()["can_write"])

    def test_decode_code128_blocks_even_when_source_kind_is_ean(self):
        ocr = deepcopy(self.original["ocr"])
        ocr["barcodes"] = {"items": [{"text": OBSERVED, "format": "CODE128", "box": []}]}
        self.set_ocr(ocr)
        self.assertFalse(self.get()["can_write"])

    def test_existing_zero_days_is_not_replaced_by_inferred_nine(self):
        self.base["keep_days"] = 0
        data = self.get()
        self.assertEqual(data["keep_days"]["current"], 0)
        self.assertFalse(data["keep_days"]["can_fill"])
        choice = self.choice()
        choice["fill_keep_days"] = True
        response = self.client.post(self.url+"/preview", json=choice, headers=self.headers)
        self.assertEqual(response.status_code, 409, response.json)
        choice["fill_keep_days"] = False
        choice, preview = self.preview(choice)
        self.assertEqual(self.save(choice, preview).status_code, 201)
        self.assertEqual(standards._current(self.engine, CODE)["snapshot"]["keep_days"], 0)

    def test_missing_days_are_only_filled_by_explicit_choice(self):
        self.base["keep_days"] = None
        data = self.get()
        self.assertEqual(data["keep_days"]["suggested"], 9)
        self.assertTrue(data["keep_days"]["can_fill"])
        choice = self.choice()
        choice["fill_keep_days"] = True
        choice, preview = self.preview(choice)
        self.assertEqual(self.save(choice, preview).status_code, 201)
        saved = standards._current(self.engine, CODE)["snapshot"]
        self.assertEqual(saved["keep_days"], 9)
        self.assertEqual(saved["date_settings"], [])
        self.assertEqual(saved["barcode_config"], {"kind": "1"})
        self.assertNotIn("base_date", saved)
        self.assertIsNone(self.base["keep_days"])

    def test_preview_then_source_revision_change_cannot_save(self):
        choice, preview = self.preview()
        self.base["revision"] = "source-2"
        self.assertEqual(self.save(choice, preview).status_code, 409)
        self.assertEqual(self.count_versions(), 0)

    def test_preview_then_correction_revision_change_cannot_save(self):
        choice, preview = self.preview()
        with self.engine.begin() as conn:
            conn.execute(insert(db.corrections).values(id=db.uid(), inspection_id="barcode-scan", revision=1,
                change={}, patches=[{"line_id": 2, "kind": "ocr_misread", "text": "有效日期：2026.11.22"}],
                ocr=self.original["ocr"], result={}, status="review", reviewer="QA", note="訂正", created_at=db.now()))
        self.assertEqual(self.save(choice, preview).status_code, 409)
        self.assertEqual(self.count_versions(), 0)

    def test_preview_then_standard_version_change_cannot_save(self):
        choice, preview = self.preview()
        self.assertEqual(self.save(choice, preview).status_code, 201)
        self.assertEqual(self.save(choice, preview).status_code, 409)
        self.assertEqual(self.count_versions(), 1)

    def test_preview_then_removed_source_cannot_save(self):
        choice, preview = self.preview()
        with self.engine.begin() as conn:
            conn.execute(insert(standard_library.items).values(kind="source", key=CODE,
                revision=1, removed=True, category_id=None, updated_at=db.now()))
        self.assertEqual(self.save(choice, preview).status_code, 409)
        self.assertEqual(self.count_versions(), 0)

    def test_changed_candidate_without_new_preview_cannot_save(self):
        choice, preview = self.preview()
        changed = dict(choice, candidate_id="another-choice")
        self.assertEqual(self.save(changed, preview).status_code, 409)
        self.assertEqual(self.count_versions(), 0)

    def test_preview_is_bound_to_original_observation_not_only_candidate(self):
        choice, preview = self.preview()
        ocr = deepcopy(self.original["ocr"])
        # The rule remains identical, but the reviewed underlying observation changes.
        ocr["lines"][2]["text"] = "有效日期：2026.11.21 04時"
        self.set_ocr(ocr)
        self.assertEqual(self.save(choice, preview).status_code, 409)
        self.assertEqual(self.count_versions(), 0)

    def test_uncertain_or_multiple_label_evidence_has_no_candidate(self):
        for marker in ({"lines": [dict(row, uncertain=True, ambiguous=True, score=0.) for row in self.original["ocr"]["lines"]]},
                       dict(deepcopy(self.original["ocr"]), label_scope={"status": "multiple"})):
            with self.subTest(marker=marker):
                self.set_ocr(marker)
                self.assertFalse(self.get()["can_write"])


if __name__ == "__main__":
    unittest.main()
