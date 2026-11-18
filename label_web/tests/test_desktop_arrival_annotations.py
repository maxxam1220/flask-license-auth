"""Dynamic desktop date items and their separately printed circled annotations."""
from copy import deepcopy
import hashlib
import json
import unittest

from label_source import build_draft
from source_validation import _source_rows, evaluate_source


def desktop_rows(marker="⑤"):
    entries = [("2:名稱", "品名:", 12, 1),
               ("3:文字", "產地:台灣", 43, 1),
               ("3:文字", "保存條件:常溫", 56, 1),
               ("3:文字", "重量:1kg", 69, 1),
               ("3:文字", "客服電話:0800-200-859", 95, 1),
               ("3:文字", "【每日檢視，依賣相管理】", 71, 75),
               ("A:日期", "到店日:", 82, 1),
               ("3:文字", marker, 82, 85)]
    return [dict(CodeNo="1457", CodeName="履歷香蕉1KG(常溫原果)", KeepDays=0,
                 Seq=str(index), Attr=attr, ObjContent=text, PosX=top, PosY=left, ShiftDate=1)
            for index, (attr, text, top, left) in enumerate(entries)]


def line(identifier, text, x, y, width=200):
    return {"id": identifier, "text": text, "score": 1.,
            "box": [[x, y], [x + width, y], [x + width, y + 24], [x, y + 24]]}


class DesktopArrivalAnnotationTests(unittest.TestCase):
    def source(self):
        return build_draft(desktop_rows(), "1457")

    def literal_circle(self, source):
        return any(row["text"] == "⑤" for row in _source_rows(source))

    def test_date_origin_is_preserved_without_changing_revision_or_print_input(self):
        rows = desktop_rows()
        before = deepcopy(rows)
        source = build_draft(rows, "1457")
        self.assertEqual(source["date_settings"][0]["layout_anchor"], [4., 328.])
        self.assertEqual(source["date_settings"][0]["shift_days"], 1)
        self.assertEqual(source["revision"], hashlib.sha256(json.dumps(
            rows, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest())
        self.assertEqual(rows, before)

    def test_real_desktop_position_circle_is_variable_date_annotation(self):
        source = self.source()
        before = deepcopy(source)
        self.assertFalse(self.literal_circle(source))
        for marker in ("⑤", "⑥", "⓿", "㊿"):
            with self.subTest(marker=marker):
                observed = [deepcopy(row) for row in source["lines"] if row["text"] != "⑤"]
                observed.append(line(20, "到店日:2026.11.18 " + marker, 4, 328, 420))
                result = evaluate_source(observed, source, base_date="2026-11-17")
                self.assertEqual(next(item for item in result["checks"] if item["key"] == "arrival_schedule")["status"], "pass")
                self.assertFalse(any(item.get("expected") == "⑤" for item in result["checks"]))
        self.assertEqual(source, before)

    def test_wrong_scheduled_date_still_fails(self):
        source = self.source()
        result = evaluate_source([line(0, "到店日:2026.11.20 ⑤", 0, 0)], source, base_date="2026-11-17")
        check = next(item for item in result["checks"] if item["key"] == "arrival_schedule")
        self.assertEqual(check["status"], "fail")
        self.assertEqual(check["expected"], "2026.11.18")

    def test_circle_on_another_row_or_too_far_right_stays_literal(self):
        for x, y in ((340, 400), (1000, 328), (0, 328)):
            source = self.source()
            source["lines"][-1] = line(6, "⑤", x, y, 80)
            self.assertTrue(self.literal_circle(source))

    def test_intervening_text_or_other_date_prevents_attachment(self):
        source = self.source()
        source["lines"].append(line(8, "組別", 200, 328, 80))
        self.assertTrue(self.literal_circle(source))
        source = self.source()
        source["date_settings"].append({"content": "有效日期", "format": "B", "shift_days": 0,
                                        "layout_anchor": [200., 328.]})
        self.assertTrue(self.literal_circle(source))

    def test_multiple_circle_candidates_or_date_anchors_remain_literal(self):
        source = self.source()
        source["lines"].append(line(8, "⑥", 440, 328, 24))
        self.assertTrue(self.literal_circle(source))
        source = self.source()
        source["date_settings"].append(deepcopy(source["date_settings"][0]))
        self.assertTrue(self.literal_circle(source))

    def test_missing_or_invalid_layout_does_not_guess(self):
        for anchor in (None, [], [4], [4, float("nan")], [4, "328"], [4, float("inf")]):
            source = self.source()
            source["date_settings"][0]["layout_anchor"] = anchor
            self.assertTrue(self.literal_circle(source))

    def test_all_known_dynamic_date_fields_can_own_annotations(self):
        for heading in ("製造日期", "有效日期", "到店日", "其他日期"):
            source = self.source()
            source["date_settings"][0]["content"] = heading
            self.assertEqual(self.literal_circle(source), heading == "其他日期")

    def test_photo_replacement_and_manual_coordinates_do_not_use_desktop_origin(self):
        source = self.source()
        source["web_text_approved"] = True
        self.assertTrue(self.literal_circle(source))
        source = self.source()
        source["source_kind"] = "manual"
        self.assertTrue(self.literal_circle(source))

    def test_normal_text_and_barcode_length_rows_are_still_literal(self):
        for text in ("第⑤組", "400000790039", "4711378333473"):
            source = build_draft(desktop_rows(text), "1457")
            self.assertTrue(any(row["text"] == text for row in _source_rows(source)))


if __name__ == "__main__":
    unittest.main()
