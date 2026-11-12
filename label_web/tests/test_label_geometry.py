from copy import deepcopy
import unittest

from label_geometry import analyze_label_scope
from source_validation import evaluate_source, _date_fields
from validation import evaluate, recognize_only, extract_fields
from test_source_validation import source, setting
from test_extended_fields import sample, STANDARD


def line(identifier,text,x=0,y=0,width=220,height=20,score=.99):
    return {"id":identifier,"text":text,"score":score,"box":[[x,y],[x+width,y],[x+width,y+height],[x,y+height]]}


def label(offset=0,x=0,y=0,product="蘋果"):
    return [line(offset,"品名："+product,x,y),
            line(offset+1,"製造日期：2026.11.11",x,y+30),line(offset+2,"有效日期：2026.11.14",x,y+60),
            line(offset+3,"福和生鮮農產股份有限公司",x,y+90),line(offset+4,"新北市土城區中興路9號",x,y+120),
            line(offset+5,"免付費電話：0800-200-859",x,y+150)]


class LabelGeometryTests(unittest.TestCase):
    def assert_blocked(self,result,lines):
        self.assertEqual(result["status"],"review")
        self.assertTrue(result["label_scope"]["blocked"])
        self.assertEqual(result["counts"]["pass"],0)
        self.assertEqual(result["fields"],{})
        self.assertEqual(result["verified_scope"],"unresolved_label_scope")
        self.assertEqual([item["raw_actual"] for item in result["checks"] if item["key"].startswith("text_line_")],
                         [item["text"] for item in lines])

    def test_side_by_side_and_stacked_labels_never_share_dates_or_footer(self):
        for x,y in ((350,0),(0,240)):
            lines=label()+label(10,x,y,"梨子")
            before=deepcopy(lines)
            # Both references have matching fragments somewhere in the photo.
            for selected in (source(*(item["text"] for item in label())),source(*(item["text"] for item in label(product="梨子")))):
                self.assert_blocked(evaluate_source(lines,selected,base_date="2026-11-11"),lines)
            self.assertEqual(lines,before)

    def test_two_identical_labels_also_require_single_label_crop(self):
        lines=label()+label(10,350,0)
        self.assert_blocked(evaluate_source(lines,source()),lines)

    def test_partial_separated_labels_cannot_complete_each_others_fields(self):
        lines=[line(0,"品名：蘋果"),line(1,"製造日期：2026.11.11",y=30),
               line(2,"新北市土城區中興路9號",x=600),line(3,"有效日期：2026.11.14",x=600,y=30)]
        result=evaluate_source(lines,source("品名：蘋果","新北市土城區中興路9號"),base_date="2026-11-11")
        self.assert_blocked(result,lines)
        self.assertEqual(result["label_scope"]["issues"][0]["kind"],"separated_blocks")

    def test_template_direct_recognition_and_human_flags_do_not_bypass_scope(self):
        lines=label()+label(10,350,0)
        lines[0]["human_verified"]=True
        self.assert_blocked(evaluate(lines,STANDARD),lines)
        self.assert_blocked(recognize_only(lines),lines)
        self.assert_blocked(evaluate_source(lines,None),lines)

    def test_same_label_two_columns_and_three_distinct_date_types_remain_valid(self):
        lines=sample()
        lines.extend([line(20,"製造日期：2026.11.11",x=60,y=215,width=200),
                      line(21,"有效日期：2026.11.14",x=60,y=245,width=200)])
        self.assertFalse(analyze_label_scope(lines)["blocked"])
        result=evaluate_source(lines,None,base_date="2026-11-11")
        self.assertTrue(all(check["status"]=="pass" for check in result["checks"] if check.get("source")=="date"))

    def test_repeated_date_kind_is_conflict_even_when_one_matches_schedule(self):
        lines=[line(0,"到店日：2026.11.12"),line(1,"到店日：2026.11.13",y=30)]
        result=evaluate_source(lines,source(settings=[setting("到店日",shift=1)]),base_date="2026-11-11")
        self.assert_blocked(result,lines)

    def test_duplicate_footer_regions_cannot_select_only_correct_company_address_phone(self):
        for key,correct,typo in (("company","福和生鮮農產股份有限公司","福和生鮮農產股份有限公"),
                                 ("address","新北市土城區中興路9號","新北市土城區中興路8號"),
                                 ("phone","免付費電話：0800-200-859","免付費電話：0800-200-8599")):
            lines=[line(0,correct),line(1,typo,x=400)]
            self.assert_blocked(evaluate_source(lines,source(correct)),lines)

    def test_single_footer_character_or_digit_errors_still_fail_without_autocorrection(self):
        for expected,actual in (("福和生鮮農產股份有限公司","福和生鮮農產股份有限公"),
                                ("福和生鮮農產股份有限公司","福和生生鮮農產股份有限公司"),
                                ("新北市土城區中興路9號","新北市土城區中興路號"),
                                ("新北市土城區中興路9號","新北市土城區中興路99號"),
                                ("電話：0800-200-859","電話：0800-200-8599")):
            result=evaluate_source([line(0,actual)],source(expected))
            self.assertEqual(result["status"],"fail")
            self.assertEqual(result["checks"][0]["raw_actual"],actual)

    def test_empty_footer_heading_with_one_nearby_value_is_one_observation(self):
        for heading,value in (("製造廠商：","福和生鮮農產股份有限公司"),("地址：","新北市土城區中興路9號"),
                              ("電話：","0800-200-859")):
            for x,y in ((110,0),(0,25)):
                lines=[line(0,heading,width=100),line(1,value,x=x,y=y,width=220)]
                self.assertFalse(analyze_label_scope(lines)["blocked"],(heading,x,y))
                result=evaluate_source(lines,source(value))
                self.assertNotIn("label_scope",result)
                self.assertEqual(next(c for c in result["checks"] if c.get("source")=="database")["status"],"pass")

    def test_footer_heading_never_merges_far_blocked_or_multiple_values(self):
        heading,value="地址：","新北市土城區中興路9號"
        for lines in ([line(0,heading,width=100),line(1,value,x=350,width=220)],
                      [line(0,heading,width=100),line(1,"其他文字",y=25,width=100),line(2,value,y=50,width=220)],
                      [line(0,heading,width=100),line(1,value,y=25,width=220),line(2,value,x=10,y=50,width=220)]):
            self.assertTrue(analyze_label_scope(lines)["blocked"])
        lines=[line(0,"電話：",width=100),line(1,"0800-200-859",x=110,width=180),
               line(2,"電話：",y=100,width=100),line(3,"0800-200-859",x=110,y=100,width=180)]
        self.assertTrue(analyze_label_scope(lines)["blocked"])

    def test_date_heading_uses_close_same_row_or_wrapped_value(self):
        for lines in ([line(0,"製造日期：",width=100),line(1,"2026.11.11",x=110,width=120)],
                      [line(0,"製造日期：",width=100),line(1,"2026.11.11",y=25,width=120)],
                      [line(0,"製造日期：2026.11.",width=200),line(1,"11",y=25,width=50)]):
            result=evaluate_source(lines,None,base_date="2026-11-11")
            self.assertEqual(next(c for c in result["checks"] if c["key"]=="manufacture")["status"],"pass")
            self.assertEqual(_date_fields(lines)["manufacture"]["line_ids"],[0,1])
            self.assertEqual(extract_fields(lines)["manufacture"]["value"],"2026.11.11")

    def test_wrapped_time_preserves_same_day_reversed_hours(self):
        lines=[line(0,"製造日期：2026.11.11",width=220),line(1,"03時",y=25,width=50),
               line(2,"有效日期：2026.11.11 02時",y=60,width=240)]
        result=evaluate_source(lines,None,base_date="2026-11-11")
        self.assertEqual(next(c for c in result["checks"] if c["key"]=="date_order")["status"],"fail")

    def test_date_heading_does_not_jump_intervening_label_or_other_column(self):
        for middle in ("有效日期：","規格：200g","文字"):
            lines=[line(0,"製造日期：",width=100),line(1,middle,y=25,width=100),line(2,"2026.11.11",y=50,width=130)]
            self.assertEqual(_date_fields(lines)["manufacture"]["value"],"")
        lines=[line(0,"製造日期：",width=100),line(1,"2026.11.11",x=350,width=120)]
        self.assertEqual(_date_fields(lines)["manufacture"]["value"],"")

    def test_shared_or_competing_date_value_is_review_not_schedule_pass(self):
        lines=[line(0,"製造日期：",width=160),line(1,"有效日期：",x=40,width=160),line(2,"2026.11.11",x=20,y=25,width=160)]
        fields=_date_fields(lines)
        self.assertTrue(fields["manufacture"]["ambiguous"])
        self.assertTrue(fields["expiry"]["ambiguous"])
        result=evaluate_source(lines,None,base_date="2026-11-11")
        self.assertTrue(all(c["status"]=="review" for c in result["checks"] if c.get("source")=="date"))
        lines=[line(0,"到店日：",width=160),line(1,"2026.11.12",y=25,width=150),line(2,"2026.11.13",x=20,y=25,width=150)]
        self.assertTrue(_date_fields(lines)["arrival"]["ambiguous"])
        self.assertEqual(set(_date_fields(lines)["arrival"]["line_ids"]),{0,1,2})
        result=evaluate_source(lines,None,base_date="2026-11-11")
        self.assertFalse(any(c["status"]=="pass" for c in result["checks"]))

    def test_calendar_invalid_and_wrong_year_fail_but_scheduled_cross_year_passes(self):
        for value in ("2026.02.29","2025.11.11"):
            result=evaluate_source([line(0,"到店日："+value)],None,base_date="2026-11-11")
            self.assertEqual(result["status"],"fail")
        lines=[line(0,"製造日期：2026.12.31"),line(1,"有效日期：2027.01.03",y=30)]
        result=evaluate_source(lines,source(settings=[setting("製造日期","A"),setting("有效日期","B")],keep=3),base_date="2026-12-31")
        self.assertEqual(result["status"],"pass")

    def test_manual_scope_and_keep_days_do_not_claim_full_print_layout(self):
        selected=source("品名：蘋果",settings=[setting("製造日期","A"),setting("有效日期","A",3)],keep=3)
        selected["source_kind"]="manual"
        lines=[line(0,"品名：蘋果"),line(1,"製造日期：2026.11.11",y=30),line(2,"有效日期：2026.11.14",y=60)]
        result=evaluate_source(lines,selected,base_date="2026-11-11")
        self.assertEqual(result["status"],"pass")
        self.assertEqual(result["verified_scope"],"manual_text")
        self.assertIn("沒有完整印標版面",result["notes"][0])
        selected["keep_days"]=2
        result=evaluate_source(lines,selected,base_date="2026-11-11")
        self.assertEqual(next(c for c in result["checks"] if c["key"]=="keep_days")["status"],"fail")


if __name__=="__main__":
    unittest.main()
