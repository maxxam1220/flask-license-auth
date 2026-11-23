"""Nutrition is OCR display evidence only across evaluation and correction."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from corrections import build_revision
from inspection_evidence import augment, without_nutrition
from source_validation import evaluate_source
from validation import evaluate, recognize_only


def rows(*texts):
    return [{"id":i,"text":text,"score":.99,"box":[]} for i,text in enumerate(texts)]


class NutritionIntegrationTests(unittest.TestCase):
    def test_original_corrected_and_legacy_results_keep_only_other_decisions(self):
        lines=rows("品名：蘋果","成分：糖","營養標示","糖 3公克 3公克","鈉 200毫克 200毫克")
        source={"code":"manual:test","name":"蘋果","source_kind":"manual","lines":deepcopy(lines),"fields":{}}
        ocr={"lines":deepcopy(lines),"provider":"openai"}
        ocr["lines"][3].update(text="糖 0公克 9公克",suspected_typo=True,score=.2)
        original=deepcopy(ocr)
        with patch("nutrition_checks.checks_for",side_effect=AssertionError("Nutrition arithmetic called")):
            result=augment(evaluate_source(ocr["lines"],source),ocr)
            self.assertEqual(result["counts"],{"pass":2,"read":0,"review":0,"fail":0})
            self.assertEqual(result["coverage"],{"total_lines":2,"covered_lines":2})
            self.assertEqual({item["id"] for item in result["display_rows"] if item["nutrition_display_only"]},{2,3,4})
            self.assertEqual(result["nutrition_policy"],"excluded-v1")
            record={"id":"scan","template_snapshot":{"mode":"system_label","source":source},"ocr":ocr,"status":"pass","result":result}
            action={"operation":"replace","kind":"label_misprint","line_id":3,"text":"糖 9公克 9公克","reviewer":"A","note":"核對照片"}
            revision=build_revision(record,None,action,"2026-11-23")
            self.assertEqual(revision["status"],"pass")
            self.assertEqual(revision["result"]["counts"],result["counts"])
            self.assertEqual(revision["ocr"]["lines"][3]["text"],action["text"])
            self.assertEqual(revision["patches"][0]["kind"],"label_misprint")
            real_error=build_revision(record,None,dict(action,line_id=1,text="成分：鹽"),"2026-11-23")
            self.assertEqual(real_error["status"],"fail")
        self.assertEqual(ocr,original)

    def test_old_generic_ocr_reference_and_arithmetic_checks_filtered_by_own_evidence(self):
        lines=rows("規格：200公克","營養標示","每一份量 120公克","糖 20公克 10公克")
        source={"lines":rows("營養標示","每份 每100公克","糖","5公克")}
        checks=[{"key":"spec","status":"fail","line_ids":[0]},
                {"key":"source_text_1","source":"database","status":"review","source_line_ids":[1]},
                {"key":"source_text_3","source":"database","status":"review","source_line_ids":[3]},
                {"key":"cloud_word_2","status":"review","line_ids":[2]},
                {"key":"manual_3","status":"fail","line_ids":[3]},
                {"key":"source_nutrition_3","status":"fail"},
                {"key":"nutrition_ratio_sugar","source":"logic","status":"fail"}]
        saved={"checks":checks,"status":"fail","fields":{"nutrition":{"value":"糖"}}}
        original=deepcopy(saved)
        projected=without_nutrition(saved,{"lines":lines},source)
        self.assertEqual(projected["checks"],checks[:1])
        self.assertEqual(projected["counts"],{"pass":0,"fail":1,"review":0,"read":0})
        self.assertEqual(projected["fields"],{})
        self.assertEqual(original,saved)
        self.assertEqual(without_nutrition(projected,{"lines":lines},source),projected)

    def test_no_template_and_template_never_mark_only_nutrition_as_all_verified(self):
        lines=rows("營養標示","熱量 50大卡")
        source={"source_kind":"manual","name":"營養","lines":deepcopy(lines)}
        for result in (evaluate_source(lines,source),evaluate_source(lines,None),recognize_only(lines),
                       evaluate(lines,{"fields":{},"rules":{"approved_text_source":source}})):
            self.assertEqual(result["counts"],{"pass":0,"fail":0,"review":0,"read":0})
            self.assertEqual(result["status"],"review")

    def test_multi_label_scope_remains_when_table_is_read_only(self):
        result=augment({"checks":[]},{"lines":rows("營養標示","脂肪 0.3公克"),"label_scope":{"status":"multiple"}})
        self.assertEqual([row["key"] for row in result["checks"]],["photo_scope"])
        self.assertEqual(result["status"],"review")

    def test_identity_ingredients_claims_and_single_column_micronutrients(self):
        from text_rows import nutrition_line_ids
        raw=rows("品名：維生素C果汁","內容物：糖、鎂","高鈣","過敏原：牛奶","維生素C 32毫克",
                 "維生素A 8微克","營養成分","鎂 10毫克","鈣","15毫克","規格：300公克","其他資料 10毫克",
                 "熱量 55大卡 產地：台灣")
        self.assertEqual(nutrition_line_ids(raw),{4,5,6,7,8,9})
        self.assertEqual(nutrition_line_ids(rows("鎂 10毫克")),{0})

    def test_legacy_rows_without_ids_do_not_gain_an_association(self):
        result={"status":"fail","checks":[{"key":"manual_0","status":"fail","line_ids":[0]}]}
        original={"lines":[None,{"id":0},{"text":"熱量 45大卡"}]}
        self.assertEqual(without_nutrition(result,original)["checks"],result["checks"])
        self.assertNotIn("id",original["lines"][2])

    def test_legacy_null_checks_and_invalid_ocr_scores_do_not_break_history(self):
        original={"lines":[{"id":0,"text":"品名：蘋果","score":"n/a"},{"id":1,"text":"熱量 45大卡","score":None}]}
        other={"key":"product","status":"review","line_ids":[0]}
        saved={"checks":[None,other,{"key":"nutrition_ratio_energy","status":"fail"}]}
        result=without_nutrition(saved,original)
        self.assertEqual(result["checks"],[other])
        self.assertEqual(result["status"],"review")
        self.assertFalse(any(row["confidence_ok"] for row in result["display_rows"]))
        self.assertEqual(original["lines"][0]["score"],"n/a")
        self.assertIsNone(saved["checks"][0])


if __name__=="__main__":unittest.main()
