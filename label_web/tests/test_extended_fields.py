from copy import deepcopy
import unittest

from validation import TEXT_FIELDS, evaluate, extract_fields, parse_date, recognize_only


def line(identifier, text, x, y, width=170, height=18, score=.99):
    return {"id": identifier, "text": text, "score": score,
            "box": [[x, y], [x + width, y], [x + width, y + height], [x, y + height]]}


def sample():
    return [line(0, "品名：日本青森蘋果3色禮盒6入(1.8kg)", 60, 30, 320),
            line(1, "貨號：211341", 60, 60), line(2, "產地：日本青森縣", 60, 89),
            line(3, "3150000000009", 245, 98), line(4, "入數：1盒", 60, 113),
            line(5, "<請清洗後食用>", 310, 122, 120),
            line(6, "規格：1.8kg/盒", 60, 137, 120),
            line(7, "福和生鮮農產股份有限公司", 250, 136, 180),
            line(8, "新北市土城區中興路9號", 250, 150, 165),
            line(9, "保存條件：7℃-18℃", 60, 162, 150),
            line(10, "免付費電話：0800-200-859", 250, 165, 180),
            line(11, "到 店 日：2026.11.12", 60, 185)]


STANDARD = {"fields": {"product": "日本青森蘋果3色禮盒6入(1.8kg)", "address": "新北市土城區中興路9號",
                        "origin": "日本青森縣", "spec": "1.8kg/盒", "storage": "7℃-18℃",
                        "company": "福和生鮮農產股份有限公司", "phone": "0800-200-859"},
            "rules": {"dates": False, "arrival": True}}


class ExtendedFieldsTests(unittest.TestCase):
    def test_two_columns_footer_and_spaced_arrival_label(self):
        fields = extract_fields(sample())
        self.assertEqual({key: fields[key]["value"] for key in TEXT_FIELDS}, STANDARD["fields"])
        self.assertEqual(fields["arrival"]["value"], "2026.11.12")
        self.assertEqual(evaluate(sample(), STANDARD, arrival_date="2026-11-12")["status"], "pass")
        self.assertEqual(fields["address"]["line_ids"], [8])
        self.assertEqual(fields["company"]["line_ids"], [7])

    def test_heading_variants_do_not_correct_printed_values(self):
        lines = sample()
        lines[6]["text"] = "规格：1.8kg/盒"
        lines[10]["text"] = "免付費電话：0800-200-859"
        lines[7]["text"] = "福和生鲜農產股份有限公司"
        result = evaluate(lines, STANDARD)
        self.assertEqual(result["fields"]["spec"]["value"], "1.8kg/盒")
        self.assertEqual(result["fields"]["phone"]["value"], "0800-200-859")
        check = next(c for c in result["checks"] if c["key"] == "company")
        self.assertEqual(check["actual"], "福和生鲜農產股份有限公司")
        self.assertEqual(check["status"], "fail")

    def test_each_new_text_typo_or_missing_character_is_flagged(self):
        for identifier, key, changed in ((6, "spec", "規格：1.9kg/盒"),
                                          (9, "storage", "保存條件：7℃-8℃"),
                                          (7, "company", "福和生鮮農產股份有限公"),
                                          (8, "address", "新北市土城區中興路9"),
                                          (10, "phone", "免付費電話：0800-200-8599")):
            with self.subTest(key=key):
                lines = sample()
                lines[identifier]["text"] = changed
                check = next(c for c in evaluate(lines, STANDARD)["checks"] if c["key"] == key)
                self.assertEqual(check["status"], "fail")
                self.assertTrue(any(part["kind"] != "equal" for part in check["diff"]))

    def test_missing_enabled_footer_never_passes(self):
        for identifier, key in ((7, "company"), (8, "address"), (10, "phone")):
            with self.subTest(key=key):
                lines = [x for x in sample() if x["id"] != identifier]
                check = next(c for c in evaluate(lines, STANDARD)["checks"] if c["key"] == key)
                self.assertEqual(check["status"], "review")
                self.assertEqual(check["actual"], "")

    def test_missing_product_is_not_filled_with_footer_or_food_notice(self):
        lines = [x for x in sample() if x["id"] != 0]
        self.assertNotIn("product", extract_fields(lines))

    def test_bare_wrapped_address_stays_in_its_column(self):
        lines = sample()
        lines[8]["text"] = "新北市土城區"
        lines[10] = line(10, "免付費電話：0800-200-859", 250, 190, 180)
        lines.append(line(12, "中興路9號", 250, 170, 100))
        fields = extract_fields(lines)
        self.assertEqual(fields["address"]["value"], "新北市土城區中興路9號")
        self.assertEqual(fields["address"]["line_ids"], [8, 12])
        self.assertEqual(fields["storage"]["value"], "7℃-18℃")

    def test_heading_and_value_in_separate_boxes_do_not_take_other_column(self):
        lines = sample()
        lines[6] = line(6, "規格：", 60, 137, 45)
        lines.append(line(12, "1.8kg/盒", 110, 137, 80))
        self.assertEqual(extract_fields(lines)["spec"]["value"], "1.8kg/盒")

    def test_manufacturer_address_is_not_a_company_heading(self):
        lines = [line(0, "製造商地址：新北市土城區中興路9號", 10, 10, 300)]
        fields = extract_fields(lines)
        self.assertEqual(fields["address"]["value"], "新北市土城區中興路9號")
        self.assertNotIn("company", fields)

    def test_phone_without_prefix_and_barcode_are_distinct(self):
        lines = sample()
        lines[10]["text"] = "0800-200-859"
        self.assertEqual(extract_fields(lines)["phone"]["line_ids"], [10])

    def test_low_confidence_exact_footer_requires_review(self):
        lines = sample()
        lines[8]["score"] = .93
        check = next(c for c in evaluate(lines, STANDARD)["checks"] if c["key"] == "address")
        self.assertEqual(check["status"], "review")

    def test_optional_fields_are_not_retroactively_enabled_for_old_standards(self):
        old = deepcopy(STANDARD)
        old["fields"] = {key: value for key, value in old["fields"].items() if key in ("product", "address", "origin")}
        old["rules"] = {"dates": False}
        checks = evaluate(sample(), old)["checks"]
        self.assertEqual([check["key"] for check in checks], ["product", "address", "origin"])

    def test_arrival_changes_between_batches_are_not_frozen_to_reference(self):
        standard = deepcopy(STANDARD)
        standard["fields"]["arrival"] = "2026.11.12"
        lines = sample()
        lines[11]["text"] = "到店日：2026.11.13"
        result = evaluate(lines, standard, arrival_date="2026-11-13")
        self.assertEqual(result["status"], "pass")
        result = evaluate(lines, standard, arrival_date="2026-11-12")
        self.assertEqual(next(c for c in result["checks"] if c["key"] == "arrival_expected")["status"], "fail")

    def test_arrival_invalid_missing_and_uncertain_values_require_review(self):
        for value, confidence in (("到店日：2026.02.30", .99), ("到店日：2O26.11.12", .99),
                                   ("到店日：202.11.12", .93), ("到店日：202.11.12", .99), ("", .99)):
            with self.subTest(value=value):
                lines = sample()
                lines[11].update(text=value, score=confidence)
                result = evaluate(lines, STANDARD, arrival_date="2026-11-12")
                self.assertEqual(next(c for c in result["checks"] if c["key"] == "arrival")["status"], "review")
                self.assertEqual(next(c for c in result["checks"] if c["key"] == "arrival_expected")["status"], "review")

    def test_missing_western_year_digit_is_not_guessed_as_roc_year(self):
        with self.assertRaises(ValueError):
            parse_date("202.11.12")
        self.assertEqual(str(parse_date("115.11.12")["date"]), "2026-11-12")
        self.assertEqual(str(parse_date("民國202年11月12日")["date"]), "2113-11-12")

    def test_company_whitespace_and_wrapped_suffix_are_preserved(self):
        fields = extract_fields([line(0, "福 和 生 鮮 農 產", 250, 130),
                                 line(1, "股 份 有 限 公 司", 250, 150),
                                 line(2, "規格：1.8kg/盒", 60, 149, 120)])
        self.assertEqual(fields["company"]["value"], "福 和 生 鮮 農 產股 份 有 限 公 司")
        self.assertEqual(fields["company"]["line_ids"], [0, 1])

    def test_arrival_date_order_uses_confidence_and_both_available_boundaries(self):
        lines = sample() + [line(12, "製造日期：2026.11.13", 60, 220), line(13, "有效日期：2026.11.14", 60, 250)]
        result = evaluate(lines, STANDARD)
        self.assertEqual(next(c for c in result["checks"] if c["key"] == "arrival_manufacture")["status"], "fail")
        lines[12]["score"] = .8
        result = evaluate(lines, STANDARD)
        check = next(c for c in result["checks"] if c["key"] == "arrival_manufacture")
        self.assertEqual(check["status"], "review")
        self.assertIn("疑似", check["reason"])

    def test_recognition_only_shows_all_text_without_claiming_correctness(self):
        result = recognize_only(sample())
        self.assertEqual(result["status"], "review")
        self.assertEqual({check["key"] for check in result["checks"] if check["key"] in TEXT_FIELDS}, set(TEXT_FIELDS))
        self.assertTrue(all(check["status"] == "review" for check in result["checks"] if check["key"] in TEXT_FIELDS))
        self.assertNotIn("manufacture", [check["key"] for check in result["checks"]])
        self.assertIn("本批排程", "".join(result["notes"]))


if __name__ == "__main__":
    unittest.main()
