import unittest
from label_source import build_draft


class LabelSourceTests(unittest.TestCase):
    def test_footer_and_new_fields_follow_desktop_positions(self):
        entries = [
            ("2:名稱", "品名:", 12, 15),
            ("3:文字", "產地:日本青森縣", 45, 15),
            ("3:文字", "規格:1.8kg/盒", 73, 15),
            ("3:文字", "保存條件:7℃~18℃", 87, 15),
            ("A:日期", "到 店 日:", 100, 15),
            ("3:文字", "福和生鮮農產股份有限公司", 72, 102),
            ("3:文字", "新北市土城區中興路9號", 80, 102),
            ("3:文字", "免付費電話:0800-200-859", 88, 102),
            ("Z:隱藏", "電話:錯誤隱藏值", 90, 102),
        ]
        rows = [dict(CodeNo="1017",CodeName="日本青森蘋果3色禮盒6入(1.8kg)", KeepDays=3,
                     Seq=str(i), Attr=a, ObjContent=t, PosX=x, PosY=y, ShiftDate=1)
                for i,(a,t,x,y) in enumerate(entries)]
        result = build_draft(rows,"1017")
        self.assertEqual(result["fields"]["company"], "福和生鮮農產股份有限公司")
        self.assertEqual(result["fields"]["address"], "新北市土城區中興路9號")
        self.assertEqual(result["fields"]["phone"], "0800-200-859")
        self.assertEqual(result["fields"]["spec"], "1.8kg/盒")
        self.assertEqual(result["fields"]["storage"], "7℃~18℃")
        self.assertEqual(result["rules"], {"dates":False,"arrival":True})
        self.assertFalse(any("錯誤隱藏值" in x["text"] for x in result["lines"]))


if __name__ == "__main__":
    unittest.main()
