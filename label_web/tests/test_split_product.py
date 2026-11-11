from copy import deepcopy
import unittest

from validation import extract_fields, product_row_candidates
from source_validation import evaluate_source
from label_source import resolve
from test_source_matching import FakeEngine, rows


NAME = "履歷子彈蓮霧(區-截切杯)"


def box(identifier, text, x, y, width, height=21, score=.99):
    return {"id": identifier, "text": text, "score": score,
            "box": [[x,y],[x+width,y],[x+width,y+height],[x,y+height]]}


def photo(head="履歷子彈蓮霧", suffix="(區-截切杯)"):
    return [box(0, head, 200, 76, 104.5, 20.5),
            box(1, suffix, 323.5, 75.5, 86.5), box(2, "65", 421, 79.5, 41, 33)]


def standard(name=NAME):
    return {"code":"2415", "name":name, "fields":{"product":name},
            "lines":[box(0,"品名："+name,0,0,400)], "rules":{}, "date_settings":[], "keep_days":0}


def product_check(lines, name=NAME):
    return next(check for check in evaluate_source(lines, standard(name))["checks"] if check["key"] == "product")


class SplitProductTests(unittest.TestCase):
    def test_real_coordinates_join_name_and_suffix_but_not_price(self):
        lines = photo()
        before = deepcopy(lines)
        field = extract_fields(lines)["product"]
        self.assertEqual(field["value"], NAME)
        self.assertEqual(field["line_ids"], [0, 1])
        check = product_check(lines)
        self.assertEqual(check["status"], "pass")
        self.assertEqual(check["raw_actual"], NAME)
        self.assertEqual(check["line_ids"], [0, 1])
        self.assertEqual(lines, before)
        self.assertTrue(any(item["actual"] == "65" and item["status"] == "read"
                            for item in evaluate_source(lines, standard())["checks"]))

    def test_source_resolves_complete_observed_name_without_barcode(self):
        db = FakeEngine({"2415":rows("2415", NAME), "other":rows("other", "履歷子彈蓮霧(原果盒)")})
        self.assertEqual(resolve(db, photo())["code"], "2415")

    def test_three_plain_fragments_join_in_horizontal_order(self):
        lines = [box(0,"履歷子彈",0,20,80), box(1,"蓮霧",88,19.5,40), box(2,"(區-截切杯)",140,20,95)]
        self.assertEqual(extract_fields(lines)["product"]["value"], NAME)
        self.assertEqual(product_check(lines)["status"], "pass")
        self.assertEqual(product_check(lines)["line_ids"], [0,1,2])

    def test_product_heading_and_separated_value_preserve_observed_text(self):
        lines = [box(0,"品名：",0,20,50), box(1,"履歷子彈蓮霧",58,20,120), box(2,"(區-截切杯)",190,20,95)]
        self.assertEqual(extract_fields(lines)["product"]["value"], NAME)
        self.assertEqual(product_check(lines)["status"], "pass")
        self.assertEqual(product_check(lines)["raw_actual"], "品名："+NAME)

    def test_real_missing_head_or_suffix_never_filled_from_standard(self):
        for lines in ([photo()[1]], [photo()[0]], photo(head="子彈蓮霧")):
            check = product_check(lines)
            self.assertNotEqual(check["status"], "pass")
            self.assertNotEqual(check["actual"], NAME)

    def test_wrong_characters_in_either_fragment_still_fail(self):
        for lines in (photo(head="履歷子彈蓮務"), photo(suffix="(區-載切杯)")):
            before = deepcopy(lines)
            check = product_check(lines)
            self.assertEqual(check["status"], "fail")
            self.assertEqual(check["actual"], lines[0]["text"]+lines[1]["text"])
            self.assertEqual(lines, before)

    def test_extra_same_row_word_is_not_discarded_to_force_exact_match(self):
        lines = photo()[:2] + [box(2,"多字",420,76,42)]
        check = product_check(lines)
        self.assertEqual(check["status"], "fail")
        self.assertEqual(check["actual"], NAME+"多字")
        self.assertEqual(check["line_ids"], [0,1,2])

    def test_heading_with_complete_name_and_extra_word_does_not_accept_partial_group(self):
        lines = [box(0,"品名：",0,20,50), box(1,NAME,58,20,250), box(2,"多字",316,20,42)]
        check = product_check(lines)
        self.assertEqual(check["status"], "fail")
        self.assertEqual(check["actual"], "品名："+NAME+"多字")

    def test_price_company_address_and_other_fields_stop_assembly(self):
        for boundary in ("65", "65元", "價格：65", "福和生鮮農產股份有限公司",
                         "福和生鮮農產股份有限公", "新北市土城區中興路9號", "規格：220g/杯"):
            lines = photo()[:2] + [box(2,boundary,420,76,200)]
            check = product_check(lines)
            self.assertEqual(check["status"], "pass", boundary)
            self.assertEqual(check["line_ids"], [0,1], boundary)

    def test_does_not_skip_price_to_pick_a_more_distant_suffix(self):
        lines = [box(0,"履歷子彈蓮霧",0,20,120), box(1,"65",125,20,10), box(2,"(區-截切杯)",140,20,95)]
        self.assertEqual(product_row_candidates(lines), [])
        self.assertNotEqual(product_check(lines)["status"], "pass")

    def test_different_size_intervening_price_or_extra_character_cannot_be_skipped(self):
        for middle in (box(99,"65",305,60,15,52), box(99,"新",305,82,15,9)):
            lines = photo()[:2] + [middle]
            self.assertEqual(product_row_candidates(lines), [])
            self.assertNotEqual(product_check(lines)["status"], "pass")

    def test_distant_or_different_row_suffix_is_not_attached(self):
        for suffix in (box(1,"(區-截切杯)",410,76,95), box(1,"(區-截切杯)",323,130,95)):
            lines = [photo()[0], suffix]
            self.assertEqual(product_row_candidates(lines), [])
            self.assertNotEqual(product_check(lines)["status"], "pass")

    def test_complete_single_line_and_other_source_remain_exact(self):
        lines = [box(0,NAME,200,76,210)]
        self.assertEqual(product_check(lines)["status"], "pass")
        self.assertEqual(product_check(photo(), "履歷子彈蓮霧(區-截切盒)")["status"], "fail")

    def test_uncertain_fragment_keeps_assembled_candidate_uncertain(self):
        for changed in (dict(photo()[1], score=.64), dict(photo()[1], ambiguous=True)):
            lines = [photo()[0], changed]
            self.assertEqual(product_check(lines)["status"], "review")
        self.assertTrue(extract_fields([photo()[0], dict(photo()[1], ambiguous=True)])["product"]["ambiguous"])


if __name__ == "__main__":
    unittest.main()
