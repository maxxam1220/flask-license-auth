from copy import deepcopy
import unittest

from source_validation import evaluate_source, normalize_text


def line(identifier, text, y=None, score=.9, x=0, width=400):
    y = identifier * 30 if y is None else y
    return {"id": identifier, "text": text, "score": score,
            "box": [[x, y], [x + width, y], [x + width, y + 20], [x, y + 20]]}


def source(*texts, settings=None, keep=0, barcode_values=None):
    return {"code": "TEST-ONLY", "name": "測試標籤", "revision": "test-revision",
            "lines": [line(i, text, score=1.) for i, text in enumerate(texts)], "fields": {},
            "rules": {}, "date_settings": settings or [], "keep_days": keep,
            "barcode_values": barcode_values or []}


def setting(content, code="A", shift=0):
    return {"content": content, "format": code + ":日期", "shift_days": shift}


def check(result, key):
    return next(item for item in result["checks"] if item["key"] == key)


class SourceTextTests(unittest.TestCase):
    def test_full_database_text_including_codes_counts_and_notice(self):
        texts = ["品名：美國櫻桃1.3kg/盒", "貨號：211239", "入數：1盒", "<請清洗後食用>",
                 "新北市土城區中興路9號", "免付費電話：0800-200-859"]
        result = evaluate_source([line(i, text) for i, text in enumerate(texts)], source(*texts), base_date="2026-11-11")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["counts"]["pass"], 6)
        self.assertEqual(result["coverage"], {"total_lines": 6, "covered_lines": 6})
        ids = [identifier for item in result["checks"] for identifier in item.get("source_line_ids", [])]
        self.assertEqual(len(ids), len(set(ids)))

    def test_approved_format_equivalences_pass_with_raw_preserved(self):
        expected = ["品名：美國櫻桃1.3kg/盒", "規格：1.3KG/盒", "地址：新北市土城區中興路9號",
                    "免付費電話：0800-200-859", "產地：臺灣"]
        actual = ["品名:美國樱桃１.３KG／盒", "规格:1.3kg/盒", "新北市土城區中興路9號",
                  "電話:0800-200-859", "產地:台湾"]
        lines = [line(i, text) for i, text in enumerate(actual)]
        before = deepcopy(lines)
        result = evaluate_source(lines, source(*expected))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(lines, before)
        self.assertEqual(check(result, "phone")["raw_actual"], "電話:0800-200-859")
        self.assertTrue(check(result, "phone")["normalization_note"])
        self.assertFalse(any(item["key"].startswith("source_line_") for item in result["checks"]))

    def test_company_single_character_missing_added_or_changed_fails(self):
        expected = "福和生鮮農產股份有限公司"
        values = [expected.replace("農", ""), expected[:-1], expected.replace("生鮮", "生生鮮"), expected.replace("福", "褔")]
        for actual in values:
            with self.subTest(actual=actual):
                result = evaluate_source([line(0, actual)], source(expected))
                self.assertEqual(check(result, "company")["status"], "fail")
                self.assertEqual(check(result, "company")["actual"], actual)

    def test_address_digit_suffix_or_extra_character_fails(self):
        expected = "新北市土城區中興路9號"
        for actual in (expected.replace("9", ""), expected[:-1], expected.replace("中興", "中中興"), expected.replace("9", "8")):
            with self.subTest(actual=actual):
                result = evaluate_source([line(0, actual)], source(expected))
                self.assertEqual(check(result, "address")["status"], "fail")
                self.assertEqual(check(result, "address")["actual"], actual)

    def test_unknown_source_never_uses_old_global_standards(self):
        lines = [line(0, "福和生鮮農產股份有限公司"), line(1, "新北市土城區中興路9號"), line(2, "0800-200-859")]
        result = evaluate_source(lines, None, base_date="2026-11-11")
        self.assertEqual(result["counts"], {"pass": 0, "fail": 0, "review": 0, "read": 3})
        self.assertEqual(result["verified_scope"], "dates_only")

    def test_different_products_text_does_not_fill_selected_source(self):
        result = evaluate_source([line(0, "品名：美國櫻桃1.3kg/盒")], source("品名：美國櫻桃2.3kg/盒"))
        self.assertEqual(check(result, "product")["status"], "fail")

    def test_fully_unread_expected_line_is_review_not_claimed_print_error(self):
        result = evaluate_source([line(0, "品名：蘋果")], source("品名：蘋果", "福和生鮮農產股份有限公司"))
        self.assertEqual(check(result, "company")["status"], "review")
        self.assertEqual(check(result, "company")["actual"], "")

    def test_low_confidence_or_ambiguous_exact_match_never_green(self):
        for lines in ([line(0, "0800-200-859", score=.64)],
                      [line(0, "0800-200-859"), line(1, "0800-200-859")]):
            result = evaluate_source(lines, source("免付費電話：0800-200-859"))
            self.assertEqual(check(result, "phone")["status"], "review")

    def test_positive_temperature_range_punctuation_is_equivalent(self):
        result = evaluate_source([line(0, "保存條件：7℃-18℃")], source("保存條件：7℃~18℃"))
        self.assertEqual(check(result, "storage")["status"], "pass")

    def test_negative_sign_and_temperature_digits_remain_significant(self):
        for expected, actual in (("保存條件：-18℃", "保存條件：18℃"),
                                 ("保存條件：7℃~18℃", "保存條件：7℃~-18℃"),
                                 ("保存條件：7℃~18℃", "保存條件：7℃--18℃"),
                                 ("保存條件：18℃", "保存條件：8℃")):
            with self.subTest(actual=actual):
                self.assertNotEqual(normalize_text(expected), normalize_text(actual))
                result = evaluate_source([line(0, actual)], source(expected))
                self.assertEqual(check(result, "storage")["status"], "fail")

    def test_phone_digits_and_letter_digit_confusions_are_not_repaired(self):
        result = evaluate_source([line(0, "電話：0800-200-858")], source("免付費電話：0800-200-859"))
        self.assertEqual(check(result, "phone")["status"], "fail")
        result = evaluate_source([line(0, "貨號：211O39")], source("貨號：211039"))
        self.assertEqual(check(result, "item_code")["status"], "fail")

    def test_wrapped_ocr_statement_is_one_database_comparison(self):
        expected = "果皮上的白點為正常現象(保護果實避免曬傷的碳酸鈣粉)"
        lines = [line(0, "果皮上的白點為正常現象", 0), line(1, "(保護果實避免曬傷的", 25), line(2, "碳酸鈣粉)", 50)]
        result = evaluate_source(lines, source(expected))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(len(result["checks"]), 1)
        self.assertEqual(result["checks"][0]["line_ids"], [0, 1, 2])

    def test_wrapped_database_statement_can_match_one_ocr_line(self):
        a, b = "果皮上的白點為正常現象", "(保護果實避免曬傷的碳酸鈣粉)"
        result = evaluate_source([line(0, a+b)], source(a, b))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["checks"][0]["source_line_ids"], [0, 1])

    def test_only_this_sources_barcodes_can_pass(self):
        lines = [line(0, "3150000000009")]
        self.assertEqual(evaluate_source(lines, source())["counts"]["read"], 1)
        result = evaluate_source(lines, source(barcode_values=["3150000000009"]))
        self.assertEqual(check(result, "barcode")["status"], "pass")

    def test_heading_like_suffix_and_internal_colon_are_not_deleted(self):
        expected = "福和生鮮農產股份有限公司"
        result = evaluate_source([line(0, expected+"品名:")], source(expected))
        self.assertEqual(check(result, "company")["status"], "fail")
        self.assertNotEqual(normalize_text("AB:12"), normalize_text("AB12"))

    def test_code128_punctuation_internal_spaces_and_case_are_data(self):
        for expected, actual in (("AB:12.5", "AB12.5"), ("AB 12.5", "AB12.5"), ("AB:12.5", "ab:12.5")):
            with self.subTest(actual=actual):
                selected = source(barcode_values=[expected])
                selected["barcode_config"] = {"kind": "4"}
                result = evaluate_source([line(0, actual)], selected)
                self.assertEqual(check(result, "barcode")["status"], "fail")
                self.assertEqual(check(result, "barcode")["actual"], actual)

    def test_explicit_code128_heading_does_not_duplicate_expected_line(self):
        selected = source("條碼：AB:12.5", barcode_values=["AB:12.5"])
        selected["barcode_config"] = {"kind": "4"}
        result = evaluate_source([line(0, "條碼：AB:12.5")], selected)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(len(result["checks"]), 1)
        self.assertEqual(result["checks"][0]["key"], "barcode")

    def test_confirmed_literal_barcode_is_not_reinterpreted_as_schedule_date(self):
        selected = source(barcode_values=["2025.11.11"])
        selected["barcode_config"] = {"kind": "4"}
        result = evaluate_source([line(0, "2025.11.11")], selected, base_date="2026-11-11")
        self.assertEqual(result["status"], "pass")
        self.assertEqual([item["key"] for item in result["checks"]], ["barcode"])


class SourceDateTests(unittest.TestCase):
    def test_unknown_source_year_2025_fails_against_2026_base(self):
        result = evaluate_source([line(0, "到店日：2025.11.12")], None, base_date="2026-11-11")
        self.assertEqual(check(result, "arrival")["status"], "pass")
        self.assertEqual(check(result, "arrival_year")["status"], "fail")

    def test_known_source_wrong_year_fails_schedule(self):
        result = evaluate_source([line(0, "到店日：2025.11.12")], source(settings=[setting("到店日", "A", 1)]), base_date="2026-11-11")
        self.assertEqual(check(result, "arrival_schedule")["status"], "fail")
        self.assertEqual(check(result, "arrival_schedule")["expected"], "2026.11.12")

    def test_medium_confidence_date_inversion_is_red(self):
        result = evaluate_source([line(0, "製造日期：2026.11.13"), line(1, "有效日期：2026.11.10")], None, base_date="2026-11-11")
        self.assertEqual(check(result, "date_order")["status"], "fail")
        self.assertEqual(check(result, "expired")["status"], "fail")
        self.assertEqual(check(result, "future_manufacture")["status"], "fail")

    def test_low_confidence_inversion_requires_review(self):
        result = evaluate_source([line(0, "製造日期：2026.11.13", score=.6), line(1, "有效日期：2026.11.10")], None, base_date="2026-11-11")
        self.assertEqual(check(result, "date_order")["status"], "review")

    def test_zero_keep_days_is_valid_not_missing(self):
        selected = source(settings=[setting("有效日期", "B", 0)], keep=0)
        result = evaluate_source([line(0, "有效日期：2026.11.11")], selected, base_date="2026-11-11")
        self.assertEqual(check(result, "expiry_schedule")["status"], "pass")
        self.assertEqual(check(result, "expiry_schedule")["expected"], "2026.11.11")

    def test_cross_year_shift_and_keep_days_are_allowed(self):
        selected = source(settings=[setting("製造日期", "A", 1), setting("有效日期", "B", 1)], keep=3)
        result = evaluate_source([line(0, "製造日期：2027.01.01"), line(1, "有效日期：2027.01.04")], selected, base_date="2026-12-31")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(check(result, "future_manufacture")["status"], "pass")
        self.assertFalse(any(c["key"].endswith("_year") for c in result["checks"]))

    def test_leap_year_calendar_validation(self):
        valid = evaluate_source([line(0, "到店日：2024.02.29")], source(settings=[setting("到店日", "A", 1)]), base_date="2024-02-28")
        self.assertEqual(valid["status"], "pass")
        invalid = evaluate_source([line(0, "到店日：2025.02.29")], None, base_date="2025-02-28")
        self.assertEqual(check(invalid, "arrival")["status"], "fail")

    def test_all_twelve_date_formats(self):
        expected = {"A":"2026.11.12", "B":"2026.11.14", "C":"2026/11/12", "D":"2026/11/14",
                    "E":"11.12", "F":"11.14", "G":"11/12", "H":"11/14", "I":"1112", "J":"1114",
                    "K":"11121700", "L":"11142400"}
        for code, value in expected.items():
            with self.subTest(code=code):
                result = evaluate_source([line(0, "到店日："+value)], source(settings=[setting("到店日", code, 1)], keep=2), base_date="2026-11-11")
                self.assertEqual(check(result, "arrival")["status"], "pass")
                self.assertEqual(check(result, "arrival_schedule")["status"], "pass")
                self.assertEqual(check(result, "arrival_schedule")["actual"], value)
                self.assertEqual(check(result, "arrival_schedule")["expected"], value)

    def test_short_date_does_not_invent_printed_year(self):
        result = evaluate_source([line(0, "到店日：01.01")], source(settings=[setting("到店日", "E", 1)]), base_date="2026-12-31")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(check(result, "arrival_schedule")["expected"], "01.01")
        self.assertEqual(check(result, "arrival_schedule")["actual"], "01.01")
        self.assertNotIn("2027", check(result, "arrival")["actual"])

    def test_wrong_short_date_or_time_fails(self):
        for code, value in (("E", "11.13"), ("I", "1113"), ("K", "11121800"), ("L", "11121700")):
            with self.subTest(code=code):
                result = evaluate_source([line(0, "到店日："+value)], source(settings=[setting("到店日", code, 1)]), base_date="2026-11-11")
                self.assertEqual(check(result, "arrival_schedule")["status"], "fail")

    def test_explicit_batch_dates_remain_enforced(self):
        result = evaluate_source([line(0, "製造日期：2026.11.11"), line(1, "到店日：2026.11.12")], None,
                                 batch_date="2026-11-10", arrival_date="2026-11-13", base_date="2026-11-11")
        self.assertEqual(check(result, "batch")["status"], "fail")
        self.assertEqual(check(result, "arrival_expected")["status"], "fail")

    def test_bare_date_year_and_invalid_calendar_are_checked(self):
        result = evaluate_source([line(0, "2025.11.12"), line(1, "包裝日：2026.02.30")], None, base_date="2026-11-11")
        self.assertEqual(check(result, "date_year_0_0")["status"], "fail")
        self.assertEqual(check(result, "date_line_1_0")["status"], "fail")

    def test_no_source_arrival_need_not_equal_tomorrow(self):
        result = evaluate_source([line(0, "到店日：2026.11.14")], None, base_date="2026-11-11")
        self.assertEqual(result["status"], "pass")
        self.assertTrue(all(item["status"] == "pass" for item in result["checks"]))
        self.assertFalse(any(item["key"] == "arrival_schedule" for item in result["checks"]))

    def test_manual_dates_override_only_their_corresponding_schedule(self):
        selected = source(settings=[setting("製造日期", "A", 0), setting("到店日", "A", 1), setting("有效日期", "B", 0)], keep=5)
        result = evaluate_source([line(0, "製造日期：2026.11.10"), line(1, "到店日：2026.11.14"), line(2, "有效日期：2026.11.16")],
                                 selected, batch_date="2026-11-10", arrival_date="2026-11-14", base_date="2026-11-11")
        self.assertEqual(result["status"], "pass")
        self.assertEqual(check(result, "manufacture_schedule")["expected"], "2026.11.10")
        self.assertEqual(check(result, "arrival_schedule")["expected"], "2026.11.14")
        self.assertEqual(check(result, "expiry_schedule")["expected"], "2026.11.16")

    def test_date_substring_does_not_hide_unknown_text(self):
        result = evaluate_source([line(0, "成分：忘果 2026.11.11")], None, base_date="2026-11-11")
        self.assertEqual(check(result, "date_line_0_0")["status"], "pass")
        self.assertEqual(check(result, "text_line_0")["status"], "read")
        self.assertEqual(result["status"], "review")

    def test_schedule_and_order_errors_explain_the_difference(self):
        result = evaluate_source([line(0, "到店日：2025.11.12")], source(settings=[setting("到店日", "A", 1)]), base_date="2026-11-11")
        self.assertIn("應為 2026.11.12", check(result, "arrival_schedule")["reason"])
        result = evaluate_source([line(0, "製造日期：2026.11.13"), line(1, "有效日期：2026.11.10")], None, base_date="2026-11-11")
        self.assertEqual(check(result, "date_order")["reason"], "有效日期早於製造日期。")


if __name__ == "__main__":
    unittest.main()
