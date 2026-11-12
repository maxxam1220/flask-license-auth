from copy import deepcopy
import unittest

from label_geometry import analyze_label_scope, date_segments
from source_validation import evaluate_source, _date_fields
from validation import evaluate, extract_fields, recognize_only
from test_label_geometry import line
from test_source_validation import source, setting


class InlineDateTests(unittest.TestCase):
    def evaluate(self, text, selected=None, **kwargs):
        return evaluate_source([line(7, text, width=600)], selected, base_date="2026-11-12", **kwargs)

    def date_check(self, result, key):
        return next(check for check in result["checks"] if check["key"] == key)

    def test_production_inline_manufacture_expiry_preserves_disjoint_raw_spans(self):
        text = "製造日期:2026.11.12 有效日期:2026.11.21 03時"
        lines = [line(7, text, width=600)]
        original = deepcopy(lines)
        result = evaluate_source(lines, None, base_date="2026-11-12")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["fields"]["manufacture"]["value"], "2026.11.12")
        self.assertEqual(result["fields"]["expiry"]["value"], "2026.11.21 03時")
        self.assertEqual(result["fields"]["manufacture"]["line_ids"], [7])
        self.assertEqual(result["fields"]["expiry"]["line_ids"], [7])
        self.assertFalse(any(field["ambiguous"] for field in result["fields"].values()))
        spans = [field["evidence_spans"][0] for field in result["fields"].values()]
        self.assertLessEqual(spans[0]["end"], spans[1]["start"])
        for check in result["checks"]:
            self.assertEqual(check["source_lines"][0]["text"], text)
        self.assertEqual(lines, original)

    def test_three_inline_types_and_spaced_headings_follow_own_schedule(self):
        text = "製 造 日 期：2026.11.12 到 店 日：2026.11.13 有效期限：2026.11.21"
        selected = source(settings=[setting("製造日期"), setting("到店日", shift=1), setting("有效日期", "B")], keep=9)
        result = self.evaluate(text, selected)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(self.date_check(result, "arrival_schedule")["actual"], "2026.11.13")

    def test_both_validators_use_same_substrings_without_false_shared_id_ambiguity(self):
        lines = [line(7, "製造日期:2026.11.12 有效日期:2026.11.21 03時")]
        simple_template = {"fields": {}, "rules": {"dates": True, "keep_days": 9}}
        extracted = extract_fields(lines)
        self.assertEqual(extracted["manufacture"]["value"], "2026.11.12")
        self.assertFalse(extracted["expiry"]["ambiguous"])
        for result in (evaluate(lines, simple_template), recognize_only(lines)):
            for key in ("manufacture", "expiry", "date_order"):
                self.assertEqual(self.date_check(result, key)["status"], "pass")

    def test_repeated_kind_in_one_box_is_review_even_if_values_match(self):
        for text in ("到店日:2026.11.12 到店日:2026.11.13", "到店日:2026.11.12 到店日:2026.11.12"):
            lines = [line(7, text)]
            self.assertTrue(analyze_label_scope(lines)["blocked"])
            result = evaluate_source(lines, None, base_date="2026-11-12")
            self.assertEqual(result["status"], "review")
            self.assertEqual(result["counts"]["pass"], 0)

    def test_empty_inline_headings_cannot_share_the_one_visible_value(self):
        for text in ("製造日期: 有效日期:2026.11.21", "製造日期:2026.11.12 有效日期:"):
            result = self.evaluate(text)
            self.assertEqual(result["status"], "review")
            self.assertTrue(all(check["status"] == "review" for check in result["checks"]))
            self.assertTrue(all(field["ambiguous"] for field in result["fields"].values()))

    def test_inline_empty_heading_does_not_borrow_external_date(self):
        lines = [line(7, "製造日期: 有效日期:2026.11.21", width=300), line(8, "2026.11.12", y=25)]
        fields = _date_fields(lines)
        self.assertEqual(fields["manufacture"]["value"], "")
        self.assertEqual(fields["manufacture"]["line_ids"], [7])
        self.assertEqual(fields["expiry"]["value"], "2026.11.21")
        self.assertTrue(fields["expiry"]["ambiguous"])

    def test_invalid_date_and_confusable_digit_remain_fail(self):
        for value in ("2026.02.29", "2026.11.31", "2026.11.2I", "2026.11."):
            result = self.evaluate("製造日期:2026.11.12 有效日期:" + value)
            self.assertEqual(self.date_check(result, "manufacture")["status"], "pass")
            self.assertEqual(self.date_check(result, "expiry")["status"], "fail")
            self.assertEqual(self.date_check(result, "expiry")["raw_actual"], value)

    def test_reversed_dates_and_hours_still_fail(self):
        for text in ("製造日期:2026.11.12 有效日期:2026.11.11", "製造日期:2026.11.12 03時 有效日期:2026.11.12 02時"):
            self.assertEqual(self.date_check(self.evaluate(text), "date_order")["status"], "fail")

    def test_cross_year_schedule_and_manual_override_remain_independent(self):
        selected = source(settings=[setting("製造日期"), setting("有效日期", "B")], keep=9)
        result = evaluate_source([line(7, "製造日期:2026.12.31 有效日期:2027.01.09")], selected, base_date="2026-12-31")
        self.assertEqual(result["status"], "pass")
        result = self.evaluate("製造日期:2026.11.11 有效日期:2026.11.21", selected, batch_date="2026-11-11")
        self.assertEqual(result["status"], "pass")

    def test_unchecked_prefix_is_not_swallowed_by_date_coverage(self):
        text = "成分：忘果 製造日期:2026.11.12 有效日期:2026.11.21"
        result = self.evaluate(text)
        self.assertEqual(result["status"], "review")
        self.assertEqual(self.date_check(result, "text_line_7")["raw_actual"], text)
        self.assertEqual(self.date_check(result, "text_line_7")["status"], "read")
        self.assertEqual(date_segments(line(7, text))[0]["start"], text.index("製造日期"))

    def test_low_score_or_ocr_ambiguity_is_not_fixed_by_segmenting(self):
        for flags in ({"score": .5}, {"ambiguous": True}):
            item = dict(line(7, "製造日期:2026.11.12 有效日期:2026.11.21"), **flags)
            result = evaluate_source([item], None, base_date="2026-11-12")
            self.assertEqual(result["status"], "review")
            self.assertFalse(any(check["status"] == "pass" for check in result["checks"]))

    def test_catalog_duration_checks_complete_dates_without_inventing_schedule(self):
        selected = dict(source(keep=9), source_kind="catalog")
        for expiry, expected in (("2026.11.21", "pass"), ("2026.11.20", "fail")):
            result = self.evaluate("製造日期:2026.11.12 有效日期:" + expiry, selected)
            duration = self.date_check(result, "keep_days")
            self.assertEqual(duration["status"], expected)
            self.assertEqual(duration["label"], "清單保存天數")
            self.assertFalse(any(check["key"].endswith("_schedule") for check in result["checks"]))
        result = self.evaluate("有效日期:2026.11.21", selected)
        self.assertNotIn("keep_days", {check["key"] for check in result["checks"]})
        self.assertNotIn("manufacture", {check["key"] for check in result["checks"]})
        result = evaluate_source([line(7, "製造日期:2026.11.12 有效日期:2026.11.21", score=.5)], selected, base_date="2026-11-12")
        self.assertEqual(self.date_check(result, "keep_days")["status"], "review")

    def test_catalog_zero_days_remains_valid_and_invalid_dates_cannot_verify_duration(self):
        selected = dict(source(keep=0), source_kind="catalog")
        result = self.evaluate("製造日期:2026.11.12 有效日期:2026.11.12", selected)
        self.assertEqual(self.date_check(result, "keep_days")["status"], "pass")
        for text in ("製造日期:2026.11.12 有效日期:2026.11.31", "製造日期:2026.11.12 有效日期:"):
            result = self.evaluate(text, selected)
            self.assertNotIn("keep_days", {check["key"] for check in result["checks"]})


if __name__ == "__main__":
    unittest.main()
