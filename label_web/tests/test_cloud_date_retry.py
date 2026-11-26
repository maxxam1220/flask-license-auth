"""Synthetic date crops and blind readings. No provider calls or production writes."""
from copy import deepcopy
import unittest

from PIL import Image

from cloud_date_retry import crop_date_image, merge_date_readings, select_date_targets
from source_validation import _date_checks, _date_fields


SIZE = (640, 480)


def line(identifier, text, left=30, top=30, right=350, bottom=53, *, uncertain=False):
    result = {"id": identifier, "text": text, "box": [[left, top], [right, top], [right, bottom], [left, bottom]],
              "score": 0. if uncertain else 1., "uncertain": uncertain, "score_kind": "uncertainty_gate",
              "confidence": None}
    if uncertain:
        result.update(ambiguous=True, ambiguity_reason="cloud_uncertain")
    return result


def read(target, text, *, uncertain=False, alternatives=()):
    return {"target_id": target["target_id"], "text": text, "uncertain": uncertain, "alternatives": list(alternatives)}


class CloudDateRetryTests(unittest.TestCase):
    def test_original_pixel_crops_independent_targets_and_blind_identifiers(self):
        first = line(11, "製造日期: 2026.11.26", uncertain=True)
        first["alternatives"] = [{"text": "製造日期: 2026.11.20", "method": "cloud_visual_alternative"}]
        expiry = line(13, "有效日期: 2026.11.29 03時", 30, 58, 350, 82, uncertain=True)
        arrival = line(14, "到貨日期: 2026.11.27", 30, 88, 350, 115, uncertain=True)
        barcode = line(19, "2 839179 133336", 30, 188, 290, 222, uncertain=True)
        lines = [first, expiry, arrival, barcode]
        targets = select_date_targets(lines, SIZE)
        self.assertEqual([t["kind"] for t in targets], ["manufacture", "expiry", "arrival"])
        self.assertEqual(len({t["target_id"] for t in targets}), 3)
        image = Image.new("RGB", SIZE, "white")
        for t, row in zip(targets, lines):
            self.assertNotIn(row["text"], str(t)); self.assertEqual(t["line_ids"], [row["id"]])
            x, y = row["box"][0]; image.putpixel((x, y), (10, 20, 30))
            left, top, right, bottom = t["crop_box"]
            crop = crop_date_image(image, t)
            self.assertEqual(crop.size, (right-left, bottom-top))
            self.assertEqual(crop.getpixel((x-left, y-top)), (10, 20, 30))
        self.assertLessEqual(targets[0]["crop_box"][3], 58)
        self.assertGreaterEqual(targets[1]["crop_box"][1], 53)
        with self.assertRaises(ValueError):
            crop_date_image(image, {"crop_box": [0, 0, SIZE[0]+1, 100]})

    def test_first_alternate_is_archived_and_both_primary_reads_agree(self):
        first = line(11, "製造日期: 2026.11.26", uncertain=True)
        first["alternatives"] = [{"text": "製造日期: 2026.11.20", "method": "cloud_visual_alternative"}]
        expiry = line(13, "有效日期: 2026.11.29 03時", 30, 80, 350, 103, uncertain=True)
        source = [first, expiry]; before = deepcopy(source)
        targets = select_date_targets(source, SIZE)
        readings = [read(targets[1], "有效日期:2026.11.29 03 時"), read(targets[0], "製造日期:2026.11.26")]
        result = merge_date_readings(source, targets, readings)
        self.assertEqual(source, before)
        for old, new in zip(source, result):
            self.assertEqual(new["text"], old["text"]); self.assertEqual(new["box"], old["box"])
            self.assertFalse(new["uncertain"]); self.assertFalse(new["ambiguous"]); self.assertEqual(new["score"], 1.)
            self.assertNotIn("human_verified", new); self.assertNotIn("alternatives", new)
            self.assertEqual(new["date_retry"]["first"], old); self.assertEqual(new["date_retry"]["status"], "confirmed")
        self.assertFalse(_date_fields(result)["expiry"]["ambiguous"])
        self.assertEqual(select_date_targets(result, SIZE), [])

    def test_header_and_date_in_separate_original_boxes(self):
        for box in [(97, 28, 320, 52), (30, 56, 320, 80)]:
            with self.subTest(box=box):
                source = [line(7, "有效日期：", 30, 28, 94, 52), line(2, "2026.11.29 03時", *box, uncertain=True)]
                target, = select_date_targets(source, SIZE)
                self.assertEqual(target["line_ids"], [7, 2])
                result = merge_date_readings(source, [target], [read(target, "有效日期：\n2026.11.29 03時")])
                self.assertTrue(all(row["date_retry"]["status"] == "confirmed" for row in result))
                result = merge_date_readings(source, [target], [read(target, "有效日期：\n2026.11.28 03時")])
                self.assertTrue(_date_fields(result)["expiry"]["ambiguous"])
                self.assertNotIn("alternatives", result[1])
                self.assertIn("11.28", result[1]["date_retry"]["reading"]["text"])

    def test_time_symbols_title_other_characters_and_digit_boundaries_must_agree(self):
        original = "有效日期: 2026.11.29 03時 ※"
        source = [line(1, original, uncertain=True)]
        target, = select_date_targets(source, SIZE)
        for changed in ["製造日期: 2026.11.29 03時 ※", "2026.11.29 03時 ※", original.replace("03", "3"),
                        original.replace("※", "＊"), original.replace(".11.", "/11/"), original.replace(" 03時", ""),
                        original.replace(".29", ".2 9"), original.replace(":", "："), original + " 第三批"]:
            with self.subTest(changed=changed):
                row, = merge_date_readings(source, [target], [read(target, changed)])
                self.assertEqual(row["text"], original); self.assertEqual(row["date_retry"]["status"], "disagrees")
                self.assertEqual(row["score"], 0); self.assertEqual(row["alternatives"][-1]["text"], changed)

    def test_short_month_day_and_fixed_clocks_confirm_only_literal_ink(self):
        for value in ("11.29", "11/29", "1129", "11291700", "11292400", "０２／２９", "02.29 24時 ※"):
            with self.subTest(value=value):
                source = [line(7, "有效日期：", 30, 28, 94, 52),
                          line(2, value, 97, 28, 320, 52, uncertain=True)]
                target, = select_date_targets(source, SIZE)
                self.assertEqual(target["line_ids"], [7, 2])
                rows = merge_date_readings(source, [target], [read(target, "有效日期：" + value)])
                self.assertEqual(rows[1]["date_retry"]["status"], "confirmed")
                field = _date_fields(rows)["expiry"]
                self.assertEqual(field["value"], value)
                self.assertFalse(field["ambiguous"]); self.assertNotIn("year", field)
        for code, value in (("E", "11.29"), ("F", "11.29"), ("G", "11/29"), ("H", "11/29"),
                            ("I", "1129"), ("J", "1129"), ("K", "11291700"), ("L", "11292400")):
            with self.subTest(code=code):
                source = [line(0, "有效日期: "+value, uncertain=True)]
                target, = select_date_targets(source, SIZE)
                result = merge_date_readings(source, [target], [read(target, source[0]["text"])])
                rules = {"date_settings": [{"content": "有效日期", "format": code, "shift_days": 0}], "keep_days": 0}
                checks, *_ = _date_checks(result, rules, "", "", "2026-11-26")
                self.assertEqual(next(c["status"] for c in checks if c["key"] == "expiry"), "pass")
                self.assertEqual(next(c["status"] for c in checks if c["key"] == "expiry_schedule"), "fail")

    def test_partial_or_impossible_short_dates_and_unequal_symbols_cannot_clear_review(self):
        for value in ("13.29", "04/31", "1129170", "11292401", "112917001", "1131",
                      "11.2□", "112□", "02.29 25時", "02/29 24:01", "11.291"):
            with self.subTest(value=value):
                source = [line(2, "有效日期：" + value, uncertain=True)]
                target, = select_date_targets(source, SIZE)
                row, = merge_date_readings(source, [target], [read(target, source[0]["text"])])
                self.assertTrue(row["uncertain"]); self.assertEqual(row["date_retry"]["status"], "uncertain")
        for first, second in (("11292400", "11291700"), ("11/29", "11.29"), ("02/29", "2028/02/29"),
                              ("11.29 ※", "11.29")):
            with self.subTest(first=first, second=second):
                source = [line(0, "有效日期："+first, uncertain=True)]
                target, = select_date_targets(source, SIZE)
                row, = merge_date_readings(source, [target], [read(target, "有效日期："+second)])
                self.assertTrue(row["ambiguous"]); self.assertEqual(row["text"], source[0]["text"])
                self.assertEqual(row["date_retry"]["status"], "disagrees")

    def test_competing_short_date_boxes_are_not_selected_and_a_barcode_cannot_fill_the_heading(self):
        heading = line(1, "有效日期：", 30, 28, 94, 52, uncertain=True)
        horizontal = line(2, "02.29 24時 ※", 96, 28, 270, 52)
        vertical = line(3, "03.01 ±", 30, 55, 220, 78)
        self.assertTrue(_date_fields([heading, horizontal, vertical])["expiry"]["ambiguous"])
        self.assertEqual(select_date_targets([heading, horizontal, vertical], SIZE), [])
        for other in ("2 839179 133336", "02.29 2 839179 133336 ※"):
            with self.subTest(other=other):
                lines = [heading, line(2, other, 96, 28, 350, 52)]
                self.assertEqual(_date_fields(lines)["expiry"]["value"], "")
                self.assertEqual(select_date_targets(lines, SIZE), [])

    def test_uncertain_second_reading_and_distinct_candidates_stay_in_review(self):
        source = [line(0, "製造日期: 2026.11.26", uncertain=True)]
        alternative = "製造日期: 2026.11.20"
        source[0]["alternatives"] = [{"text": alternative, "method": "cloud_visual_alternative"}]
        target, = select_date_targets(source, SIZE)
        for second in [read(target, alternative), read(target, source[0]["text"], uncertain=True),
                       read(target, source[0]["text"], alternatives=[alternative]),
                       read(target, "製造日期: 2026.11.2□"), read(target, "", uncertain=True)]:
            with self.subTest(second=second):
                row, = merge_date_readings(source, [target], [second])
                self.assertTrue(row["ambiguous"]); self.assertEqual(row["text"], source[0]["text"])
                self.assertEqual(row["date_retry"]["reading"], second)
                choices = [a["text"] for a in row["alternatives"]]
                self.assertEqual(choices.count(alternative), 1); self.assertNotIn("", choices)
        for first in ["製造日期: 2026.11.2□", "製造日期: 2026.11.31", "製造日期: 2026.11.26 25時"]:
            with self.subTest(first=first):
                source = [line(0, first, uncertain=True)]
                target, = select_date_targets(source, SIZE)
                row, = merge_date_readings(source, [target], [read(target, first)])
                self.assertTrue(row["ambiguous"])

    def test_shared_lines_duplicate_fields_overlapping_ink_and_unsafe_boxes_are_excluded(self):
        original = line(0, "有效日期: 2026.11.29", uncertain=True)
        for rows in [[line(0, "製造日: 2026.11.26 有效日: 2026.11.29", uncertain=True)],
                     [original, line(4, "製造日", 30, 30, 110, 51)],
                     [original, line(1, original["text"], 30, 90, 240, 120)],
                     [line(0, "包裝上字樣 有效日期: 2026.11.29", uncertain=True)],
                     [line(0, "有效日期: 2026.11.29 2 839179 133336", uncertain=True)],
                     [line(0, "有效日期:", 30, 30, 130, 55, uncertain=True)],
                     [line(0, "2026.11.29", uncertain=True)], [dict(original, box=[])],
                     [dict(original, box=[[-1,0],[300,0],[300,30],[-1,30]])],
                     [line(0, original["text"], 0, 0, 640, 480, uncertain=True)],
                     [dict(original, human_uncertain=True)], [dict(original, suspected_typo=True)],
                     [line(0, original["text"])]]:
            with self.subTest(rows=rows):
                self.assertEqual(select_date_targets(rows, SIZE), [])

    def test_incomplete_or_duplicate_response_set_cannot_apply_to_other_dates(self):
        source = [line(2, "有效日期: 2026.11.29", uncertain=True)]
        targets = select_date_targets(source, SIZE); target, = targets
        exact = read(target, source[0]["text"])
        for response in [[], [dict(exact, target_id="date-2")], [exact, exact]]:
            self.assertEqual(merge_date_readings(source, targets, response), source)


if __name__ == "__main__":
    unittest.main()
