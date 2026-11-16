from copy import deepcopy
import unittest

from inspection_evidence import augment
from source_validation import evaluate_source


def observed():
    texts = ["營養標示", "每一份量120公克", "每份 每100公克",
             "熱量 68.5大卡 57.3大卡", "蛋白質 0.2公克 0.2公克", "脂肪 0.1公克 0.1公克",
             "飽和脂肪 0公克 0公克", "反式脂肪 0公克 0公克", "碳水化合物 16.7公克 13.9公克",
             "糖 13.3公克 11.1公克", "鈉 1.4毫克 1.2毫克"]
    return [{"id":i,"text":text,"score":.99,"box":[[0,i*30],[400,i*30],[400,i*30+20],[0,i*30+20]]}
            for i,text in enumerate(texts)]


def standard(texts):
    return {"code":"manual:legacy-test","name":"測試蘋果","source_kind":"manual","fields":{},"rules":{},
            "date_settings":[],"lines":[{"id":i,"text":text,"score":1.,"box":[]} for i,text in enumerate(texts)]}


class LegacyNutritionTests(unittest.TestCase):
    def test_old_headings_partial_row_and_orphan_values_are_one_review_not_false_fail(self):
        texts=["營養標示","每一份量120公克","每份 每100公克","熱量","熱量 68.5大卡 57.3大卡",
               "57.3大卡","蛋白質","蛋白質 0.2公克 0.2公克","脂肪","脂肪 0.1公克 0.1公克",
               "飽和脂肪","0公克","反式脂肪","13.9公克","碳水化合物 16.7公克","糖",
               "13.3公克","11.1公克","1.4毫克","1.2毫克"]
        source=standard(texts);lines=observed();before_source=deepcopy(source);before_lines=deepcopy(lines)
        result=evaluate_source(lines,source,base_date="2026-11-16")
        database=[c for c in result["checks"] if c.get("source")=="database"]
        self.assertFalse(any(c["status"]=="fail" for c in database),database)
        legacy=[c for c in database if c.get("incomplete_standard")]
        self.assertEqual(len(legacy),1)
        self.assertEqual(legacy[0]["status"],"review")
        self.assertEqual(set(legacy[0]["source_line_ids"]),{3,5,6,8,10,11,12,13,14,15,16,17,18,19})
        for expected in ("熱量 68.5大卡 57.3大卡","蛋白質 0.2公克 0.2公克","脂肪 0.1公克 0.1公克"):
            self.assertEqual(next(c for c in database if c["expected"]==expected)["status"],"pass")
        augment(result,{"lines":lines})
        self.assertEqual(sum(c.get("incomplete_standard",False) for c in result["checks"]),1)
        self.assertEqual(source,before_source);self.assertEqual(lines,before_lines)

    def test_full_row_numeric_and_label_errors_still_fail(self):
        lines=observed();source=standard([row["text"] for row in lines])
        for wrong in ("脂肪 0.2公克 0.1公克","脂坊 0.1公克 0.1公克"):
            changed=deepcopy(lines);changed[5]["text"]=wrong
            result=evaluate_source(changed,source,base_date="2026-11-16")
            check=next(c for c in result["checks"] if c.get("expected")=="脂肪 0.1公克 0.1公克")
            self.assertEqual(check["status"],"fail",check)
        self.assertFalse(any(c.get("incomplete_standard") for c in result["checks"]))

    def test_compatibility_is_limited_to_manual_nutrition_context(self):
        lines=observed()
        for source in (standard(["13.3公克"]),dict(standard(["營養標示","每份 每100公克","糖","13.3公克"]),source_kind="catalog")):
            result=evaluate_source(lines,source,base_date="2026-11-16")
            self.assertFalse(any(c.get("incomplete_standard") for c in result["checks"]))

    def test_unrelated_numeric_value_after_another_field_keeps_normal_comparison(self):
        source=standard(["營養標示","每份 每100公克","糖","品名：測試蘋果","250公克"])
        lines=observed()+[{"id":30,"text":"品名：測試蘋果","score":.99,"box":[]},
                          {"id":31,"text":"260公克","score":.99,"box":[]}]
        result=evaluate_source(lines,source,base_date="2026-11-16")
        check=next(c for c in result["checks"] if c.get("expected")=="250公克")
        self.assertEqual(check["status"],"fail",check)

    def test_ingredient_sugar_outside_table_block_is_not_a_legacy_nutrient(self):
        lines=observed()+[{"id":30,"text":"內容物：蘋果","score":.99,"box":[]},
                          {"id":31,"text":"糖","score":.99,"box":[]},
                          {"id":32,"text":"6公克","score":.99,"box":[]}]
        ingredients=["內容物：蘋果","糖","5公克"]
        table=["營養標示","每份 每100公克","糖 13.3公克 11.1公克"]
        for texts in (ingredients+table,table+ingredients):
            result=evaluate_source(lines,standard(texts),base_date="2026-11-16")
            check=next(c for c in result["checks"] if c.get("expected")=="5公克")
            self.assertEqual(check["status"],"fail",check)
            self.assertFalse(any(c.get("incomplete_standard") for c in result["checks"]))


if __name__=="__main__":unittest.main()
