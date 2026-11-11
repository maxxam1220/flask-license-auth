from copy import deepcopy
import unittest
from validation import compact, parse_date, extract_fields, evaluate


STANDARD = {"fields": {"product": "雙拼水果盒", "address": "新北市中和區中正路100號", "origin": "台灣、菲律賓"},
            "rules": {"dates": True, "keep_days": 3}}


def make_lines(changes=None):
    values = {"product": "品名：雙拼水果盒", "address": "地址：新北市中和區中正路100號", "origin": "產地：台灣、菲律賓",
              "manufacture": "製造日期：2026.11.10 03時", "expiry": "有效日期：2026.11.13"}
    values.update(changes or {})
    return [{"id": i, "text": text, "score": .99, "box": [[0,i*40],[500,i*40],[500,i*40+30],[0,i*40+30]]}
            for i, text in enumerate(values.values()) if text]


class ValidationTests(unittest.TestCase):
    def test_all_fields_match(self):
        self.assertEqual(evaluate(make_lines(), STANDARD, "2026-11-10")["status"], "pass")

    def test_single_character_typo_not_fuzzy_pass(self):
        result = evaluate(make_lines({"product":"品名：雙拚水果盒"}), STANDARD)
        self.assertEqual(result["checks"][0]["status"], "fail")
        self.assertTrue(any(x["kind"] == "replace" for x in result["checks"][0]["diff"]))

    def test_address_digit_and_tai_variant_preserved(self):
        for changes in [{"address":"地址：新北市中和區中正路101號"},{"origin":"產地：臺灣、菲律賓"}]:
            self.assertEqual(evaluate(make_lines(changes), STANDARD)["status"], "fail")

    def test_only_whitespace_ignored(self):
        self.assertEqual(compact("雙 拼\n水果盒"), "雙拼水果盒")
        self.assertNotEqual(compact("台灣,菲律賓"), compact("台灣、菲律賓"))

    def test_missing_address_never_passes(self):
        result=evaluate(make_lines({"address":""}), STANDARD)
        self.assertEqual(result["status"], "review")
        self.assertEqual(result["checks"][1]["actual"], "")

    def test_low_confidence_identical_text_review(self):
        lines=make_lines();lines[1]["score"]=.7
        self.assertEqual(evaluate(lines, STANDARD)["status"], "review")

    def test_reversed_dates(self):
        result=evaluate(make_lines({"manufacture":"製造日期：2026.11.13 03時","expiry":"有效日期：2026.11.10"}), STANDARD)
        self.assertEqual(next(x for x in result["checks"] if x["key"]=="date_order")["status"],"fail")

    def test_reversed_dates_with_low_confidence_still_warn(self):
        lines=make_lines({"manufacture":"製造日期：2026.11.1303時","expiry":"有效日期：2026.11.10"});lines[3]["score"]=.8
        result=evaluate(lines, STANDARD)
        check=next(x for x in result["checks"] if x["key"]=="date_order")
        self.assertEqual(check["status"],"review");self.assertIn("疑似",check["reason"])

    def test_invalid_date_not_guessed(self):
        result=evaluate(make_lines({"manufacture":"製造日期：2026.02.30"}), STANDARD)
        self.assertEqual(next(x for x in result["checks"] if x["key"]=="manufacture")["status"],"review")

    def test_confusable_digit_not_corrected(self):
        with self.assertRaises(ValueError):parse_date("2O26.11.10")

    def test_roc_and_fullwidth(self):
        self.assertEqual(str(parse_date("民國115年11月10日")["date"]),"2026-11-10")
        self.assertEqual(str(parse_date("２０２６．１１．１０")["date"]),"2026-11-10")

    def test_different_batch_catches_plausible_wrong_dates(self):
        result=evaluate(make_lines(),STANDARD,"2026-11-11")
        self.assertEqual(next(x for x in result["checks"] if x["key"]=="batch")["status"],"fail")

    def test_date_settings_coverage_reported(self):
        standard=deepcopy(STANDARD);standard["rules"]["keep_days"]=None
        result=evaluate(make_lines(),standard)
        self.assertEqual(len(result["notes"]),2)

    def test_ambiguous_same_key(self):
        lines=make_lines();lines.append({"id":9,"text":"產地：台灣","score":.99,"box":[[0,300],[200,300],[200,330],[0,330]]})
        self.assertEqual(evaluate(lines,STANDARD)["checks"][2]["status"],"review")

    def test_unlabelled_product_typo_located_without_correction(self):
        result=evaluate(make_lines({"product":"雙拚水果盒"}),STANDARD)
        self.assertEqual(result["checks"][0]["actual"],"雙拚水果盒")
        self.assertEqual(result["checks"][0]["status"],"fail")

    def test_wrapped_address(self):
        lines=make_lines({"address":"地址：新北市中和區中正路"})
        lines.insert(2,{"id":8,"text":"100號","score":.98,"box":[[0,72],[200,72],[200,79],[0,79]]})
        self.assertEqual(extract_fields(lines)["address"]["value"],STANDARD["fields"]["address"])

    def test_label_variation_keeps_raw_value(self):
        result=evaluate(make_lines({"origin":"産地：台湾.菲律賓"}),STANDARD)
        self.assertEqual(result["checks"][2]["actual"],"台湾.菲律賓")
        self.assertEqual(result["checks"][2]["status"],"fail")

    def test_same_day_time_order(self):
        result=evaluate(make_lines({"manufacture":"製造日期：2026.11.10 15:00","expiry":"有效日期：2026.11.10 03時"}),STANDARD)
        self.assertEqual(next(x for x in result["checks"] if x["key"]=="date_order")["status"],"fail")


if __name__ == "__main__": unittest.main()
