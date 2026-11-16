"""Offline arithmetic, confidence, row-provenance and nutrition-table boundaries."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from nutrition_checks import checks_for


def line(identifier, text, y=0, x=10, width=400, **extra):
    return {"id":identifier,"text":text,"score":.99,
            "box":[[x,y],[x+width,y],[x+width,y+20],[x,y+20]],**extra}


DEFAULT_ROWS = ["熱量 120.0大卡 100.0大卡", "蛋白質 1.2公克 1.0公克", "脂肪 2.4公克 2.0公克",
    "飽和脂肪 0.6公克 0.5公克", "反式脂肪 0.12公克 0.10公克", "碳水化合物 12.0公克 10.0公克",
    "糖 6.0公克 5.0公克", "鈉 12.0毫克 10.0毫克"]


def table(*, rows=None, serving="每一份量120公克", header="每份 每100公克"):
    return {"lines":[line(0,"營養標示",x=100,width=160),line(1,serving,y=35,width=300),
        line(2,header,y=70,x=200,width=200),
        *[line(index+3,text,y=105+index*35) for index,text in enumerate(DEFAULT_ROWS if rows is None else rows)]]}


def get(checks,key):
    return next(check for check in checks if check["key"]=="nutrition_"+key)


class NutritionChecksTests(unittest.TestCase):
    def test_complete_nonzero_table_has_only_arithmetic_passes_and_preserves_input(self):
        ocr=table();before=deepcopy(ocr)
        checks=checks_for(ocr)
        self.assertEqual(ocr,before)
        self.assertEqual(len(checks),12)
        self.assertTrue(all(check["status"]=="pass" for check in checks),checks)
        self.assertTrue(all(check["source"]=="logic" for check in checks))
        self.assertEqual(len({check["key"] for check in checks}),len(checks))
        self.assertEqual(set(get(checks,"ratio_energy")["line_ids"]),{1,2,3})

    def test_rounded_values_use_intervals_not_exact_decimal_equality(self):
        checks=checks_for(table(rows=["碳水化合物 16.7公克 13.9公克", "糖 13.3公克 11.1公克"]))
        self.assertEqual(get(checks,"ratio_carbohydrate")["status"],"pass")
        self.assertEqual(get(checks,"ratio_sugar")["status"],"pass")

    def test_120g_energy_example_is_review_when_only_serving_rounding_explains_it(self):
        checks=checks_for(table(rows=["熱量 68.5大卡 57.3大卡"]))
        energy=get(checks,"ratio_energy")
        self.assertEqual(energy["status"],"review")
        self.assertIn("68.76",energy["reason"])
        self.assertIn("份量本身",energy["reason"])
        self.assertEqual(energy["actual"],"熱量 68.5大卡 57.3大卡")

    def test_precisely_printed_serving_can_demonstrate_incompatible_energy(self):
        checks=checks_for(table(rows=["熱量 68.5大卡 57.3大卡"],serving="每一份量120.0公克"))
        self.assertEqual(get(checks,"ratio_energy")["status"],"fail")

    def test_clear_ratio_error_fails_even_with_serving_rounding(self):
        checks=checks_for(table(rows=["熱量 68.5大卡 50.0大卡"]))
        self.assertEqual(get(checks,"ratio_energy")["status"],"fail")

    def test_zero_declarations_are_unknown_underlying_amounts(self):
        checks=checks_for(table(rows=["脂肪 0公克 0.0公克", "飽和脂肪 0公克 0公克", "反式脂肪 0公克 0公克",
                                     "碳水化合物 0.0公克 0.0公克", "糖 0公克 0公克"]))
        self.assertEqual(checks,[])  # No invented zero arithmetic or routine warnings.

    def test_only_one_zero_column_needs_review_without_inferring_actual_zero(self):
        checks=checks_for(table(rows=["脂肪 0公克 0.1公克"]))
        self.assertEqual(get(checks,"ratio_fat")["status"],"review")
        self.assertIn("特殊門檻",get(checks,"ratio_fat")["reason"])

    def test_positive_fat_part_still_proves_error_when_other_part_declares_zero(self):
        checks=checks_for(table(rows=["脂肪 1.0公克 1.0公克", "飽和脂肪 2.0公克 2.0公克", "反式脂肪 0公克 0公克"],serving="每一份量100公克"))
        for index in range(2):
            self.assertEqual(get(checks,f"fat_total_{index}")["status"],"fail")

    def test_positive_parts_not_provably_excessive_skip_zero_relation(self):
        checks=checks_for(table(rows=["脂肪 1.0公克 1.0公克", "飽和脂肪 0.1公克 0.1公克", "反式脂肪 0公克 0公克"],serving="每一份量100公克"))
        self.assertFalse(any(check["key"].startswith("nutrition_fat_total") for check in checks))
        self.assertFalse(any(check["status"]=="review" for check in checks))

    def test_clearly_excessive_sugar_fails_in_both_columns(self):
        checks=checks_for(table(rows=["碳水化合物 12.0公克 10.0公克", "糖 20.0公克 16.7公克"]))
        for index in range(2):
            self.assertEqual(get(checks,f"sugar_total_{index}")["status"],"fail")

    def test_saturated_plus_trans_cannot_exceed_fat_after_rounding(self):
        checks=checks_for(table(rows=["脂肪 2.4公克 2.0公克", "飽和脂肪 2.0公克 1.7公克", "反式脂肪 1.0公克 0.8公克"]))
        for index in range(2):
            self.assertEqual(get(checks,f"fat_total_{index}")["status"],"fail")

    def test_rounding_boundary_only_is_review_not_an_exact_pass(self):
        checks=checks_for(table(rows=["碳水化合物 10.0公克 10.0公克", "糖 10.1公克 10.1公克"],serving="每一份量100公克"))
        self.assertEqual(get(checks,"sugar_total_0")["status"],"review")

    def test_known_wrong_units_or_negative_values_fail_only_when_certain(self):
        for nutrient,text in (("fat","脂肪 2.4毫克 2.0毫克"),("sodium","鈉 12.0公克 10.0公克"),
                              ("energy","熱量 -1大卡 -1大卡")):
            with self.subTest(text=text):
                ocr=table(rows=[text])
                self.assertEqual(get(checks_for(ocr),"values_"+nutrient)["status"],"fail")
                ocr["lines"][-1]["score"]=.2
                self.assertEqual(get(checks_for(ocr),"values_"+nutrient)["status"],"review")

    def test_missing_units_extra_column_and_less_than_values_are_review(self):
        for text in ("脂肪 0.1 0.1公克", "脂肪 0.1公克 0.1公克 0.2公克", "脂肪 <0.1公克 <0.1公克"):
            with self.subTest(text=text):
                checks=checks_for(table(rows=[text]))
                self.assertEqual(get(checks,"values_fat")["status"],"review")
                self.assertFalse(any(check["status"]=="pass" for check in checks))

    def test_missing_heading_or_serving_never_guesses_columns(self):
        for changes in ({"header":"每份 每日參考值百分比"},{"serving":"每一份量"}):
            with self.subTest(changes=changes):
                checks=checks_for(table(**changes))
                self.assertEqual(get(checks,"columns")["status"],"review")
                self.assertFalse(any(check["key"].startswith("nutrition_ratio_") for check in checks))

    def test_ml_serving_and_reversed_columns_are_explicitly_supported(self):
        ocr=table(rows=["蛋白質 1.0公克 1.2公克"],serving="每一份量120毫升",header="每100毫升 每份")
        self.assertEqual(get(checks_for(ocr),"ratio_protein")["status"],"pass")
        ocr["lines"][2]["text"]="每100公克 每份"
        self.assertEqual(get(checks_for(ocr),"columns")["status"],"review")

    def test_separate_header_boxes_require_same_baseline_and_real_column_order(self):
        ocr=table(rows=["蛋白質 1.2公克 1.0公克"])
        ocr["lines"][2]=line(2,"每份",y=70,x=210,width=65)
        ocr["lines"].append(line(99,"每100公克",y=70,x=320,width=100))
        self.assertEqual(get(checks_for(ocr),"ratio_protein")["status"],"pass")
        ocr["lines"][-1]=line(99,"每100公克",y=35,x=320,width=100)
        self.assertEqual(get(checks_for(ocr),"columns")["status"],"review")

    def test_uncertain_numeric_cell_prevents_green_until_human_confirmation(self):
        ocr=table(rows=["蛋白質 1.2公克 1.0公克", "脂肪 2.4公克 2.0公克"])
        ocr["lines"][3]=line(3,"蛋白質",y=105,width=90)
        ocr["lines"].extend([line(90,"1.2公克",y=105,x=210,width=75,score=.2),line(91,"1.0公克",y=105,x=320,width=75)])
        check=get(checks_for(ocr),"ratio_protein")
        self.assertEqual(check["status"],"review")
        self.assertTrue({3,90,91}.issubset(check["line_ids"]))
        ocr["lines"][-2].update(human_verified=True,human_uncertain=False)
        self.assertEqual(get(checks_for(ocr),"ratio_protein")["status"],"pass")

    def test_uncertain_header_blocks_all_arithmetic(self):
        ocr=table();ocr["lines"][2]["score"]=.2
        checks=checks_for(ocr)
        self.assertEqual(get(checks,"columns")["status"],"review")
        self.assertFalse(any(check["status"]=="pass" for check in checks))

    def test_duplicate_nutrients_or_multiple_labels_never_cross_tables(self):
        for ocr in (table(rows=["脂肪 1公克 1公克","脂肪 2公克 2公克"]),
                    {**table(),"label_scope":{"status":"multiple"}}):
            checks=checks_for(ocr)
            self.assertEqual(len(checks),1)
            self.assertEqual(get(checks,"scope")["status"],"review")

    def test_ingredient_sugar_and_protein_are_not_nutrition_tables(self):
        for texts in (("內容物：水、蘋果", "糖"),("蛋白質",),("糖","脂肪")):
            self.assertEqual(checks_for({"lines":[line(i,text,y=i*35) for i,text in enumerate(texts)]}),[])

    def test_standard_draft_requires_explicit_context_and_unique_title(self):
        ocr=table()
        for row in ocr["lines"]:row["box"]=[]
        self.assertEqual(get(checks_for(ocr),"columns")["status"],"review")
        ocr["context"]="standard_draft"
        self.assertEqual(get(checks_for(ocr),"ratio_energy")["status"],"pass")
        ocr["lines"].append({**line(99,"營養標示"),"box":[]})
        self.assertEqual(get(checks_for(ocr),"scope")["status"],"review")

    def test_two_tables_cannot_share_context_even_with_distinct_nutrient_names(self):
        ocr=table(rows=["蛋白質 1.2公克 1.0公克", "脂肪 2.4公克 2.0公克"])
        ocr["lines"].append(line(99,"營養標示",x=700,width=160))
        checks=checks_for(ocr)
        self.assertEqual(len(checks),1)
        self.assertEqual(get(checks,"scope")["status"],"review")

    def test_swapped_numeric_columns_are_not_silently_reordered(self):
        checks=checks_for(table(rows=["蛋白質 1.0公克 1.2公克"]))
        self.assertEqual(get(checks,"ratio_protein")["status"],"fail")

    def test_far_serving_header_is_not_borrowed_from_other_label(self):
        ocr=table(rows=["蛋白質 1.2公克 1.0公克"])
        ocr["lines"][1]=line(1,"每一份量120公克",y=35,x=900,width=300)
        checks=checks_for(ocr)
        self.assertEqual(get(checks,"columns")["status"],"review")
        self.assertFalse(any(check["status"]=="pass" for check in checks))

    def test_missing_row_values_cannot_borrow_numbers_from_next_nutrient(self):
        ocr=table(rows=["蛋白質", "脂肪 2.4公克 2.0公克"])
        checks=checks_for(ocr)
        self.assertEqual(get(checks,"values_protein")["status"],"review")
        self.assertFalse(any(check["key"]=="nutrition_ratio_protein" for check in checks))

    def test_bounded_unexpected_line_collection_fails_closed(self):
        for lines in (None, [line(i,"文字") for i in range(501)]):
            checks=checks_for({"lines":lines})
            self.assertEqual(len(checks),1)
            self.assertEqual(get(checks,"scope")["status"],"review")

    def test_mixed_geometry_does_not_enable_standard_text_only_shortcut(self):
        ocr=table();ocr["context"]="standard_draft"
        for row in ocr["lines"][1:]:row["box"]=[]
        self.assertEqual(get(checks_for(ocr),"columns")["status"],"review")

    def test_net_weight_or_package_count_is_not_substituted_for_serving_size(self):
        ocr=table(serving="淨重120公克，本包裝含2份")
        checks=checks_for(ocr)
        self.assertEqual(get(checks,"columns")["status"],"review")
        self.assertFalse(any("weight" in check["key"] or "count" in check["key"] for check in checks))

    def test_no_4_9_energy_formula_or_ingredient_macronutrient_guessing(self):
        ocr=table(rows=["熱量 120.0大卡 100.0大卡", "蛋白質 120.0公克 100.0公克"])
        checks=checks_for(ocr)
        self.assertEqual({check["key"] for check in checks},{"nutrition_ratio_energy","nutrition_ratio_protein"})
        self.assertTrue(all(check["status"]=="pass" for check in checks))

    @unittest.skipUnless((Path(__file__).parents[1]/"qa/nutrition-production-fixture.json").is_file(), "Optional saved OCR fixture not present")
    def test_real_saved_ocr_keeps_unlabelled_sodium_as_unknown_and_energy_review(self):
        path=Path(__file__).parents[1]/"qa/nutrition-production-fixture.json"
        ocr=json.loads(path.read_text(encoding="utf-8"))["ocr"];before=deepcopy(ocr)
        checks=checks_for(ocr)
        self.assertEqual(get(checks,"ratio_energy")["status"],"review")
        self.assertFalse(any(check["key"]=="nutrition_ratio_sodium" for check in checks))
        orphan=next(check for check in checks if check["key"].startswith("nutrition_unlabelled_"))
        self.assertEqual(set(orphan["line_ids"]),{31,32})
        self.assertEqual(orphan["status"],"review")
        self.assertFalse(any(check["key"].startswith("nutrition_fat_total") or check["key"] in
                             {"nutrition_ratio_saturated","nutrition_ratio_trans"} for check in checks))
        self.assertEqual(ocr,before)


if __name__=="__main__":
    unittest.main()
