import unittest
from reference_catalog import build_draft
from source_validation import evaluate_source
from test_source_validation import line
from test_source_validation import source


class CatalogValidationTests(unittest.TestCase):
    def source(self):
        return build_draft({"code": "1659", "name": "日本麝香葡萄", "barcode": "", "keep_days": 6,
                            "barcode_type": "3", "revision": "test", "provenance": {}})

    def test_optional_duration_is_checked_but_no_schedule_is_invented(self):
        for printed, expected in (("6天", "pass"), ("5天", "fail"), ("六天", "review")):
            result = evaluate_source([line(0, "品名：日本麝香葡萄"), line(1, "保存期限：" + printed),
                line(2, "到店日：2026.11.14")], self.source(), base_date="2026-11-11")
            self.assertEqual(result["verified_scope"], "catalog_fields")
            checks = {item["key"]: item for item in result["checks"]}
            self.assertEqual(checks["shelf_days_1"]["status"], expected)
            self.assertEqual(checks["arrival"]["status"], "pass")
            self.assertNotIn("arrival_schedule", checks)
            self.assertNotIn("expiry_schedule", checks)

    def test_unprinted_duration_is_not_a_missing_text_error(self):
        result = evaluate_source([line(0, "品名：日本麝香葡萄")], self.source(), base_date="2026-11-11")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["verified_scope"], "catalog_fields")
        self.assertEqual(len(result["checks"]), 1)

    def test_unsupported_marker_requires_review_without_hiding_other_typos(self):
        expected = source("※餐盒請冷藏保存")
        for actual, status in (("餐盒請冷藏保存", "review"), ("餐盒請冷凍保存", "fail")):
            result = evaluate_source([line(0, actual)], expected,
                ocr_capabilities={"unsupported_symbols": ["※"]})
            self.assertEqual(result["checks"][0]["status"], status)
            self.assertEqual(result["checks"][0]["raw_actual"], actual)

    def test_ambiguous_date_cannot_pass_despite_high_confidence(self):
        ocr = [dict(line(0, "到店日：2026.11.12"), ambiguous=True,
                    alternatives=[{"text": "到店日：2026.11.13", "score": .95}])]
        result = evaluate_source(ocr, None, base_date="2026-11-11")
        self.assertFalse(any(item["status"] == "pass" for item in result["checks"]))
        self.assertEqual(result["status"], "review")

    def test_repeated_weak_marker_deficit_remains_review(self):
        expected = source("※餐盒※請冷藏保存")
        for actual, status in (("※餐盒請冷藏保存", "review"), ("※餐盒請冷凍保存", "fail"),
                               ("※餐盒請冷藏保存※", "fail")):
            result = evaluate_source([line(0, actual)], expected,
                ocr_capabilities={"known_weak_symbols": ["※"]})
            self.assertEqual(result["checks"][0]["status"], status)

    def test_known_weak_marker_is_review_only_when_it_is_the_only_difference(self):
        expected = source("※餐盒請冷藏保存")
        for actual, status in (("餐盒請冷藏保存", "review"), ("餐盒請冷凍保存", "fail"), ("※餐盒請冷藏保存", "pass")):
            result = evaluate_source([line(0, actual)], expected,
                ocr_capabilities={"unsupported_symbols": [], "known_weak_symbols": ["※"]})
            item = result["checks"][0]
            self.assertEqual(item["status"], status)
            self.assertEqual(item["raw_actual"], actual)
            if status == "review":
                self.assertIn("容易", item["reason"])
                self.assertNotIn("不支援", item["reason"])

