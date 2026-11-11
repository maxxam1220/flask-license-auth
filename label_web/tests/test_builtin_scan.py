from copy import deepcopy
import unittest

from validation import BUILTIN_FIELDS, BUILTIN_STANDARDS, evaluate, recognize_only, traditional_display


def line(identifier, text, y=0, score=.99, x=0, width=400):
    return {"id": identifier, "text": text, "score": score,
            "box": [[x, y], [x + width, y], [x + width, y + 20], [x, y + 20]]}


class BuiltinScanTests(unittest.TestCase):
    def test_four_confirmed_texts_pass_without_photo_standard(self):
        lines = [line(i, entry["value"], i * 30) for i, entry in enumerate(BUILTIN_STANDARDS)]
        result = recognize_only(lines)
        self.assertEqual(result["status"], "pass")
        self.assertEqual({check["key"] for check in result["checks"]}, set(BUILTIN_FIELDS))
        self.assertEqual(result["coverage"], {"total_lines": 4, "covered_lines": 4})

    def test_absent_fixed_text_does_not_generate_missing_errors(self):
        result = recognize_only([line(0, "品名：青森蘋果"), line(1, "規格：1.8kg/盒", 30)])
        self.assertFalse(any(check["key"] in BUILTIN_FIELDS for check in result["checks"]))
        self.assertEqual(result["counts"]["review"], 0)
        self.assertEqual(result["counts"]["read"], 2)
        self.assertEqual(result["status"], "review")
        self.assertTrue(all(check["actual"] for check in result["checks"]))

    def test_company_with_last_character_missing_is_compared(self):
        result = recognize_only([line(0, "福和生鮮農產股份有限公")])
        check = next(c for c in result["checks"] if c["key"] == "company")
        self.assertEqual(check["status"], "fail")
        self.assertEqual(check["actual"], "福和生鮮農產股份有限公")
        self.assertTrue(any(part["expected"] == "司" and part["actual"] == "" for part in check["diff"]))

    def test_wrong_detected_address_and_phone_are_flagged(self):
        result = recognize_only([line(0, "新北市土城區中興路8號"), line(1, "0800-200-858", 30)])
        self.assertEqual(result["status"], "fail")
        self.assertEqual({c["key"] for c in result["checks"] if c["status"] == "fail"}, {"address", "phone"})

    def test_similar_barcode_does_not_become_absent_phone(self):
        for barcode in ("0800200859000", "3150000000009"):
            result = recognize_only([line(0, barcode)])
            self.assertFalse(any(c["key"] == "phone" for c in result["checks"]))
            self.assertEqual(result["counts"]["read"], 1)

    def test_wrapped_advisory_joins_only_its_column(self):
        lines = [line(0, "果皮上的白點為正常現象", 0, x=250, width=220),
                 line(1, "規格：1.8kg/盒", 20, x=0, width=160),
                 line(2, "(保護果實避免曬傷的", 25, x=250, width=220),
                 line(3, "碳酸鈣粉)", 50, x=250, width=220)]
        result = recognize_only(lines)
        check = next(c for c in result["checks"] if c["key"] == "advisory")
        self.assertEqual(check["status"], "pass")
        self.assertEqual(check["line_ids"], [0, 2, 3])
        self.assertEqual(check["actual"], BUILTIN_FIELDS["advisory"])
        self.assertEqual(result["coverage"]["covered_lines"], 4)

    def test_advisory_typo_and_omitted_tail_never_pass(self):
        for text in (BUILTIN_FIELDS["advisory"].replace("碳", "炭"), "果皮上的白點為正常現象",
                     BUILTIN_FIELDS["advisory"].replace("避免", "")):
            result = recognize_only([line(0, text)])
            check = next(c for c in result["checks"] if c["key"] == "advisory")
            self.assertEqual(check["status"], "fail")

    def test_unrelated_advisory_is_read_without_inventing_expected_text(self):
        result = recognize_only([line(0, "食用前請清洗乾淨")])
        self.assertFalse(any(c["key"] == "advisory" for c in result["checks"]))
        self.assertEqual(result["counts"]["read"], 1)

    def test_display_conversion_preserves_immutable_raw_evidence(self):
        lines = [line(0, "福和生鲜農產股份有限公司"), line(1, "產地：台湾", 30)]
        before = deepcopy(lines)
        result = recognize_only(lines)
        self.assertEqual(lines, before)
        self.assertEqual(traditional_display("台湾"), "台灣")
        check = next(c for c in result["checks"] if c["key"] == "company")
        self.assertEqual(check["raw_actual"], "福和生鲜農產股份有限公司")
        self.assertEqual(check["display_actual"], BUILTIN_FIELDS["company"])
        self.assertEqual(check["status"], "review")
        self.assertNotEqual(result["status"], "pass")

    def test_correct_phone_value_does_not_hide_simplified_heading(self):
        result = recognize_only([line(0, "免付費電话：0800-200-859")])
        self.assertEqual(next(c for c in result["checks"] if c["key"] == "phone")["status"], "pass")
        source = next(c for c in result["checks"] if c["key"] == "source_line_0")
        self.assertEqual(source["status"], "review")
        self.assertEqual(source["raw_actual"], "免付費電话：0800-200-859")
        self.assertEqual(source["display_actual"], "免付費電話：0800-200-859")
        self.assertEqual(result["status"], "review")

    def test_compared_company_conversion_is_not_duplicated_as_source_review(self):
        result = recognize_only([line(0, "公司名稱：福和生鲜農產股份有限公司")])
        self.assertEqual([check["key"] for check in result["checks"]], ["company"])
        check = result["checks"][0]
        self.assertEqual(check["status"], "review")
        self.assertEqual(check["raw_actual"], "福和生鲜農產股份有限公司")
        self.assertEqual(check["source_lines"][0]["text"], "公司名稱：福和生鲜農產股份有限公司")
        self.assertEqual(result["coverage"], {"total_lines": 1, "covered_lines": 1})

    def test_unreferenced_simplified_line_is_review_with_raw_preserved(self):
        result = recognize_only([line(0, "產地：台湾")])
        check = next(c for c in result["checks"] if c["key"] == "text_line_0")
        self.assertEqual(check["status"], "review")
        self.assertEqual(check["raw_actual"], "產地：台湾")
        self.assertEqual(check["display_actual"], "產地：台灣")
        self.assertTrue(check["conversion_changed"])

    def test_unknown_suffix_on_correct_field_remains_visible(self):
        result = recognize_only([line(0, "備註 免付費電話：0800-200-859")])
        self.assertTrue(any(c["key"] == "source_line_0" and c["status"] == "read" for c in result["checks"]))
        self.assertNotEqual(result["status"], "pass")

    def test_each_ocr_line_retains_full_source_text(self):
        lines = [line(0, "公司名稱：福和生鮮農產股份有限公司"), line(1, "貨號：211341", 30),
                 line(2, "產地：日本青森縣", 60, score=.8), line(3, "保存條件：7℃-18℃", 90)]
        result = recognize_only(lines)
        sources = {source["id"]: source["text"] for check in result["checks"] for source in check["source_lines"]}
        self.assertEqual(sources, {item["id"]: item["text"] for item in lines})
        self.assertTrue(any(c["status"] == "review" and c["line_ids"] == [2] for c in result["checks"]))
        self.assertEqual(result["coverage"], {"total_lines": 4, "covered_lines": 4})

    def test_standalone_other_dates_and_calendar_errors_are_checked(self):
        result = recognize_only([line(0, "包裝日：2026.02.30"), line(1, "出貨日：2026.11.12", 30)])
        checks = {c["key"]: c for c in result["checks"]}
        self.assertEqual(checks["date_line_0_0"]["status"], "review")
        self.assertEqual(checks["date_line_1_0"]["status"], "pass")
        self.assertEqual(checks["text_line_0"]["status"], "read")

    def test_manufacture_batch_is_checked_without_expiry(self):
        result = recognize_only([line(0, "製造日期：2026.11.12")], batch_date="2026-11-13")
        self.assertEqual(next(c for c in result["checks"] if c["key"] == "batch")["status"], "fail")
        self.assertFalse(any(c["key"] == "expiry" for c in result["checks"]))

    def test_template_values_override_builtins_without_duplicate_conflict(self):
        template = {"fields": {"product": "蘋果", "address": "台北市中山區建國路1號", "origin": "日本"},
                    "rules": {"dates": False}}
        lines = [line(0, "品名：蘋果"), line(1, "地址：台北市中山區建國路1號", 30), line(2, "產地：日本", 60),
                 line(3, BUILTIN_FIELDS["company"], 90)]
        result = evaluate(lines, template)
        addresses = [c for c in result["checks"] if c["key"] == "address"]
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0]["expected"], template["fields"]["address"])
        self.assertEqual(addresses[0]["status"], "pass")
        self.assertEqual(next(c for c in result["checks"] if c["key"] == "company")["source"], "builtin")

    def test_empty_photo_produces_no_false_pass_or_missing_fixed_fields(self):
        result = recognize_only([])
        self.assertEqual(result["status"], "review")
        self.assertEqual(result["checks"], [])


if __name__ == "__main__":
    unittest.main()
