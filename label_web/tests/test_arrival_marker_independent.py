"""Independent calendar, time and evidence boundaries for arrival annotations."""
from copy import deepcopy
from datetime import date
import unittest

from source_validation import evaluate_source
from validation import evaluate, parse_date


def line(identifier, text, *, x=0, y=None, width=420, score=1., **flags):
    y = identifier * 40 if y is None else y
    return {"id": identifier, "text": text, "score": score,
            "box": [[x, y], [x + width, y], [x + width, y + 24], [x, y + 24]], **flags}


def standard(lines=(), *, offset=0, date_format="A"):
    return {"code": "manual:arrival-test", "name": "測試標籤", "source_kind": "manual",
            "comparison_scope": "approved_text", "web_text_approved": True, "revision": "test",
            "lines": list(lines), "fields": {}, "rules": {"arrival": True}, "keep_days": 0,
            "barcode_values": [], "date_settings": [{"content": "到店日", "format": date_format,
                                                       "shift_days": offset}]}


def check(result, key):
    return next(item for item in result["checks"] if item["key"] == key)


class ArrivalMarkerIndependentTests(unittest.TestCase):
    def inspect(self, value, source=None, *, base="2026-11-17", **kwargs):
        observed = [line(4, "到店日:" + value)]
        before = deepcopy(observed)
        result = evaluate_source(observed, source, base_date=base, **kwargs)
        self.assertEqual(observed, before, "Date parsing must preserve original OCR")
        return result

    def test_circle_variation_is_annotation_not_hour_and_keeps_raw_text(self):
        for value in ("2026.11.20 ⑤", "2026.11.20⑥", "２０２６．１１．２０ ⑤"):
            with self.subTest(value=value):
                result = self.inspect(value, standard(offset=3))
                self.assertEqual(check(result, "arrival")["status"], "pass")
                self.assertEqual(check(result, "arrival_schedule")["status"], "pass")
                self.assertEqual(check(result, "arrival")["raw_actual"], value)
                parsed = parse_date(value, kind="arrival")
                self.assertEqual(parsed["date"], date(2026, 11, 20))
                self.assertIsNone(parsed["hour"])

    def test_invalid_calendar_or_confusable_digits_remain_fail(self):
        for value in ("2026.02.29⑤", "2026.11.31⑤", "2026.13.20⑤", "2026.00.20⑤",
                      "2026.11.00⑤", "2026.11.2I⑤", "2026.11.⑤"):
            with self.subTest(value=value):
                self.assertEqual(check(self.inspect(value), "arrival")["status"], "fail")

    def test_previous_year_is_not_accepted_because_marker_is_valid(self):
        value = "2025.11.20⑤"
        result = self.inspect(value)
        self.assertEqual(check(result, "arrival")["status"], "pass")
        self.assertEqual(check(result, "arrival_year")["status"], "fail")
        scheduled = self.inspect(value, standard(offset=3))
        self.assertEqual(check(scheduled, "arrival_schedule")["status"], "fail")

    def test_wrong_day_or_manual_date_still_fails_schedule(self):
        result = self.inspect("2026.11.21⑥", standard(offset=3))
        self.assertEqual(check(result, "arrival_schedule")["status"], "fail")
        result = self.inspect("2026.11.20⑤", standard(offset=3), arrival_date="2026-11-21")
        self.assertEqual(check(result, "arrival_expected")["status"], "fail")

    def test_leap_day_and_cross_year_use_real_calendar(self):
        result = self.inspect("2024.02.29⑤", standard(offset=1), base="2024-02-28")
        self.assertEqual(check(result, "arrival_schedule")["status"], "pass")
        result = self.inspect("2027.01.01⑥", standard(offset=1), base="2026-12-31")
        self.assertEqual(check(result, "arrival_schedule")["status"], "pass")

    def test_real_time_is_preserved_including_end_of_the_printed_day(self):
        result = self.inspect("2026.11.20 23:59⑤")
        self.assertEqual(check(result, "arrival")["status"], "pass")
        parsed = parse_date("2026.11.20 23:59⑤", kind="arrival")
        self.assertEqual((parsed["hour"], parsed["minute"]), (23, 59))
        for suffix in ("24時", "24:00⑤", "24時00分※", "24時 00分", "24: 00", "24 時 00 分"):
            parsed = parse_date("2026.11.20 " + suffix, kind="arrival")
            self.assertEqual((parsed["date"], parsed["hour"], parsed["minute"]), (date(2026, 11, 20), 24, 0))
        for suffix in ("24:01⑤", "25時⑤", "23:60⑤", "24:001", "24:00:99", "10:59:80"):
            with self.subTest(suffix=suffix):
                self.assertEqual(check(self.inspect("2026.11.20 " + suffix), "arrival")["status"], "fail")

    def test_clock_on_standalone_date_is_checked_even_without_a_heading(self):
        for suffix, expected in (("24時", "pass"), ("#7", "pass"), ("25時", "fail"), ("24:001", "fail"),
                                 ("24:01", "fail"), ("24:00:99", "fail"), ("03:", "fail")):
            with self.subTest(suffix=suffix):
                value = "2026.11.21 " + suffix
                result = evaluate_source([line(0, value)], None, base_date="2026-11-18")
                item = check(result, "date_line_0_0")
                self.assertEqual((item["status"], item["raw_actual"]), (expected, value))

    def test_barcode_in_same_row_or_close_separate_box_stays_independent(self):
        heading = "有效日期：2026.11.21"
        for barcode in ("4 00000 79003 9", "4-00000-79003-9", "400000790039"):
            for suffix in ("", " 24時", " 24:00"):
                with self.subTest(barcode=barcode, suffix=suffix):
                    result = evaluate_source([line(0, heading + suffix + " " + barcode)], None, base_date="2026-11-18")
                    self.assertEqual(check(result, "expiry")["actual"], "2026.11.21" + suffix)
                    self.assertIn(barcode, check(result, "text_line_0")["actual"])
            rows = [line(0, heading, width=230), line(1, barcode, x=235, y=0)]
            result = evaluate_source(rows, None, base_date="2026-11-18")
            self.assertEqual(check(result, "expiry")["line_ids"], [0])
            self.assertEqual(check(result, "text_line_1")["actual"], barcode)
            rows = [line(0, "有效日期：", width=90), line(1, "2026.11.21 " + barcode, x=95, y=0)]
            result = evaluate_source(rows, None, base_date="2026-11-18")
            self.assertEqual(check(result, "expiry")["actual"], "2026.11.21")
            self.assertIn(barcode, check(result, "text_line_1")["actual"])

    def test_existing_explicit_short_2400_format_remains_supported(self):
        result = self.inspect("11202400⑤", standard(date_format="L", offset=3))
        self.assertEqual(check(result, "arrival")["status"], "pass")
        self.assertEqual(check(result, "arrival_schedule")["status"], "pass")
        self.assertEqual(check(self.inspect("11202401⑤", standard(date_format="L", offset=3)), "arrival")["status"], "fail")

    def test_general_tail_text_is_not_dropped(self):
        for suffix in ("錯", "批次5", "第5組", "⑤錯", "錯⑤", "2026.11.21"):
            with self.subTest(suffix=suffix):
                self.assertEqual(check(self.inspect("2026.11.20 " + suffix), "arrival")["status"], "fail")

    def test_circle_embedded_in_date_or_time_is_not_nfkc_converted_to_digits(self):
        for value in ("2026.⑪.20", "2026.11.②", "2026.11.20 ⑤時", "2026.11.20 ⑤:00",
                      "2026.11.20 03:⑤", "202⑥.11.20"):
            with self.subTest(value=value):
                self.assertEqual(check(self.inspect(value), "arrival")["status"], "fail")

    def test_all_date_fields_accept_attached_numbers_and_symbols(self):
        for heading, key in (("製造日期", "manufacture"), ("有效日期", "expiry"), ("到店日", "arrival")):
            for suffix in ("⑤⑥", "7", " #03", "24時（２）", " · *"):
                with self.subTest(heading=heading, suffix=suffix):
                    value = "2026.11.21" + suffix
                    observed = [line(1, heading + ":" + value)]
                    result = evaluate_source(observed, None, base_date="2026-11-21")
                    self.assertEqual(check(result, key)["status"], "pass")
                    self.assertEqual(check(result, key)["raw_actual"], value)

    def test_photo_template_public_path_uses_same_arrival_marker_policy(self):
        template = {"fields": {}, "rules": {"arrival": True, "dates": False, "keep_days": None}}
        good = evaluate([line(0, "到店日:2026.11.20⑤")], template, arrival_date="2026-11-20")
        self.assertEqual(check(good, "arrival")["status"], "pass")
        self.assertEqual(check(good, "arrival_expected")["status"], "pass")
        bad = evaluate([line(0, "到店日:2026.11.31⑤")], template, arrival_date="2026-11-20")
        self.assertNotEqual(check(bad, "arrival")["status"], "pass")

    def test_low_confidence_or_ambiguity_still_requires_review(self):
        for flags in ({"score": .2}, {"ambiguous": True}, {"human_uncertain": True}):
            with self.subTest(flags=flags):
                observed = [line(0, "到店日:2026.11.20⑤", **flags)]
                result = evaluate_source(observed, standard(offset=3), base_date="2026-11-17")
                self.assertEqual(check(result, "arrival")["status"], "review")
                self.assertEqual(check(result, "arrival_schedule")["status"], "review")

    def test_inline_storage_text_cannot_be_swallowed_by_date_success(self):
        observed = [line(0, "到店日：2026.11.20⑤保存條件：18℃")]
        before = deepcopy(observed)
        result = evaluate_source(observed, None, base_date="2026-11-17")
        self.assertEqual(check(result, "arrival")["status"], "pass")
        self.assertNotIn("保存", check(result, "arrival")["actual"])
        self.assertTrue(any(item["status"] in {"read", "review"} and "保存條件" in item.get("actual", "")
                            for item in result["checks"]))
        self.assertEqual(observed, before)

    def test_near_standalone_circle_joins_arrival_and_distant_circle_does_not(self):
        for position, joined in ((270, True), (800, False)):
            with self.subTest(position=position):
                observed = [line(0, "到店日:2026.11.20", width=260), line(1, "⑤", x=position, y=0, width=24)]
                before = deepcopy(observed)
                result = evaluate_source(observed, None, base_date="2026-11-17")
                arrival = check(result, "arrival")
                self.assertEqual(arrival["status"], "pass")
                self.assertEqual(1 in arrival["line_ids"], joined)
                self.assertEqual(observed, before)

    def test_old_adjacent_static_circle_does_not_become_missing_reference_text(self):
        old = [line(0, "到店日:2026.11.19", width=260), line(1, "④", x=270, y=0, width=24)]
        current = [line(0, "到店日:2026.11.20⑤", width=290)]
        selected = standard(old, offset=3)
        before = deepcopy(selected)
        result = evaluate_source(current, selected, base_date="2026-11-17")
        self.assertEqual(check(result, "arrival_schedule")["status"], "pass")
        self.assertFalse(any(item.get("source") == "database" and "④" in item.get("expected", "")
                             for item in result["checks"]))
        self.assertEqual(selected, before)

    def test_circle_in_normal_reference_text_is_not_a_global_ignore_character(self):
        selected = standard([line(0, "規格：第⑤組")])
        result = evaluate_source([line(0, "規格：第⑥組"), line(1, "到店日:2026.11.17⑤")],
                                 selected, base_date="2026-11-17")
        differences = [item for item in result["checks"] if item.get("source") == "database"
                       and "第⑤組" in item.get("expected", "")]
        self.assertTrue(differences)
        self.assertTrue(any(item["status"] == "fail" for item in differences))

    def test_repeated_arrival_dates_are_not_made_unique_by_annotation_handling(self):
        observed = [line(0, "到店日:2026.11.20⑤"), line(1, "到店日:2026.11.21⑥")]
        result = evaluate_source(observed, None, base_date="2026-11-17")
        self.assertEqual(result["status"], "review")
        self.assertFalse(any(item["status"] == "pass" for item in result["checks"]))


if __name__ == "__main__":
    unittest.main()
