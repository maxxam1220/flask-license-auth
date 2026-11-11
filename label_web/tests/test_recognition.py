import unittest
from validation import recognize_only, extract_fields
from test_validation import make_lines


class RecognitionTests(unittest.TestCase):
    def test_hour_marker_variant_keeps_raw_evidence_and_warns(self):
        lines = make_lines()
        for line in lines:
            if "製造" in line["text"]:
                line.update(text="製造日期：2026.11.1303时", score=.93)
            elif "有效" in line["text"]:
                line["text"] = "有效日期：2026.11.10"
        result = recognize_only(lines)
        self.assertEqual(result["fields"]["manufacture"]["value"], "2026.11.1303时")
        order = next(c for c in result["checks"] if c["key"] == "date_order")
        self.assertEqual(order["status"], "review")
        self.assertIn("早於", order["reason"])

    def test_without_standard_inverted_dates_still_fail(self):
        lines = make_lines()
        for line in lines:
            if "製造" in line["text"]:
                line["text"] = "製造日期：2026.11.13"
            elif "有效" in line["text"]:
                line["text"] = "有效日期：2026.11.10"
        result = recognize_only(lines)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(next(c for c in result["checks"] if c["key"] == "date_order")["status"], "fail")

    def test_address_without_prefix_is_preserved(self):
        lines = make_lines()
        for line in lines:
            if "地址" in line["text"]:
                line["text"] = "236新北市土城區測試路100號"
        self.assertEqual(extract_fields(lines)["address"]["value"], "236新北市土城區測試路100號")
