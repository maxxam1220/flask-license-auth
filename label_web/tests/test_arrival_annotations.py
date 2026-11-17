"""Arrival annotation regression tests using observed boxes, never reference filling."""
from copy import deepcopy
from datetime import date
import unittest

from label_geometry import date_observations, without_date_evidence
from source_validation import evaluate_source
from validation import extract_fields, parse_date, recognize_only


def line(identifier, text, x=0, y=0, width=180, height=24, **flags):
    return {"id": identifier, "text": text, "score": 1.,
            "box": [[x, y], [x + width, y], [x + width, y + height], [x, y + height]], **flags}


def check(result, key):
    return next(item for item in result["checks"] if item["key"] == key)


class ArrivalAnnotationTests(unittest.TestCase):
    def inspect(self, lines):
        original = deepcopy(lines)
        result = evaluate_source(lines, None, base_date="2026-11-17")
        self.assertEqual(lines, original)
        return result

    def test_reasonable_circled_number_families_remain_variable_raw_annotations(self):
        for marker in ("①", "⑤", "⑳", "⓪", "❺", "➄", "➎", "⓫", "⓴", "⓿", "㉑", "㉟", "㊱", "㊿"):
            with self.subTest(marker=marker):
                value = "2026.11.20" + marker
                result = self.inspect([line(0, "到店日：" + value)])
                self.assertEqual(result["status"], "pass")
                self.assertEqual(check(result, "arrival")["raw_actual"], value)
                self.assertEqual(parse_date(value, kind="arrival"), {"date": date(2026, 11, 20), "hour": None, "minute": 0})
        for marker in ("⒈", "⑴", "ⓐ", "○", "(5)", "5"):
            with self.subTest(disallowed=marker):
                self.assertEqual(check(self.inspect([line(0, "到店日：2026.11.20" + marker)]), "arrival")["status"], "fail")

    def test_heading_date_and_annotation_in_three_boxes_are_one_evidence_chain(self):
        observed = [line(0, "到店日：", width=90), line(1, "2026.11.20", x=100, width=150),
                    line(2, "⑥", x=260, width=24)]
        result = self.inspect(observed)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["fields"]["arrival"]["line_ids"], [0, 1, 2])
        self.assertEqual(result["fields"]["arrival"]["value"], "2026.11.20⑥")
        for item in observed:
            self.assertEqual(without_date_evidence(item, result["fields"]), "")
        self.assertEqual(check(recognize_only(observed), "arrival")["status"], "pass")

    def test_empty_heading_and_next_box_date_with_annotation_is_not_nfkc_folded(self):
        observed = [line(0, "到店日：", width=90), line(1, "2026.11.20 ⑤", x=100, width=180)]
        result = self.inspect(observed)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(extract_fields(observed)["arrival"]["value"], "2026.11.20 ⑤")

    def test_fragmented_date_still_does_not_invent_missing_digits(self):
        observed = [line(0, "到店日：2026.11.", width=180), line(1, "20", x=190, width=30),
                    line(2, "⑤", x=230, width=24)]
        self.assertEqual(self.inspect(observed)["status"], "pass")
        observed.pop(1)
        result = self.inspect(observed)
        self.assertEqual(check(result, "arrival")["status"], "fail")
        self.assertNotIn(2, check(result, "arrival")["line_ids"])

    def test_near_circle_does_not_cross_an_intervening_field_or_jump_to_next_line(self):
        for barrier in (line(1, "保存條件", x=185, width=28), line(1, "65", x=185, width=28, height=40)):
            observed = [line(0, "到店日：2026.11.20"), barrier, line(2, "⑤", x=220, width=24)]
            result = self.inspect(observed)
            self.assertEqual(result["fields"]["arrival"]["line_ids"], [0])
            self.assertTrue(any(item["line_ids"] == [2] and item["status"] == "read" for item in result["checks"]))
        result = self.inspect([line(0, "到店日：2026.11.20"), line(1, "⑤", x=0, y=30, width=24)])
        self.assertEqual(result["fields"]["arrival"]["line_ids"], [0])

    def test_low_confidence_annotation_and_multiple_markers_do_not_make_all_green(self):
        for flags in ({"score": .4}, {"ambiguous": True}, {"human_uncertain": True}):
            result = self.inspect([line(0, "到店日：2026.11.20"), line(1, "⑤", x=190, width=24, **flags)])
            self.assertEqual(check(result, "arrival")["status"], "review")
        result = self.inspect([line(0, "到店日：2026.11.20"), line(1, "⑤", x=190, width=24),
                               line(2, "⑥", x=220, width=24)])
        self.assertNotEqual(result["status"], "pass")

    def test_circle_alone_cannot_be_a_missing_date_or_time_digit(self):
        for value in ("", "2026.11.", "2026.11.20 03:"):
            observed = [line(0, "到店日：" + value), line(1, "⑤", x=190, width=24)]
            arrival = date_observations(observed)[0]
            self.assertEqual(arrival["lines"], [observed[0]])
            self.assertNotIn("⑤", arrival["value"])

    def test_nondate_suffix_and_date_order_are_both_preserved(self):
        observed = [line(0, "製造日期：2026.11.21", y=0),
                    line(1, "到店日：2026.11.20⑤ 保存條件：18℃", y=30, width=500),
                    line(2, "有效日期：2026.11.22", y=60)]
        result = self.inspect(observed)
        self.assertEqual(check(result, "arrival")["status"], "pass")
        self.assertEqual(check(result, "arrival_manufacture")["status"], "fail")
        self.assertEqual(without_date_evidence(observed[1], result["fields"]), "保存條件：18℃")
        self.assertEqual(check(result, "text_line_1")["status"], "read")


if __name__ == "__main__":
    unittest.main()
