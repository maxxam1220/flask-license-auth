from copy import deepcopy
import unittest

from standard_draft_quality import eligibility


def line(text, **kwargs):
    return {"id":0,"text":text,"score":.95,**kwargs}


class DraftQualityTests(unittest.TestCase):
    def test_empty_noise_and_all_blurry_are_not_useful_drafts(self):
        for rows in ([],[line("123456"),line("?? □□")],[line("品名：蘋果",score=.2)],
                     [line("品名：蘋果",uncertain=True)], [line("aaaaaaaaaaaaaaaaaa")]):
            with self.subTest(rows=rows):
                self.assertFalse(eligibility({"lines":rows})["eligible"])

    def test_partial_readability_retains_enough_content(self):
        rows=[line("品名：日本蘋果"),line("新北市土城區中興路9號",id=1)]
        rows += [line("看不清楚的文字",id=i,uncertain=True) for i in range(2,8)]
        result=eligibility({"lines":rows})
        self.assertTrue(result["eligible"])
        self.assertTrue(result["needs_review"])
        self.assertEqual(result["usable_line_count"],2)
        self.assertFalse(eligibility({"lines":[line("每份")]+rows[2:]})["eligible"])

    def test_cloud_explicit_flags_not_fake_probability_and_printed_typo_allowed(self):
        ocr={"recognition_engine":"cloud","lines":[line("品名：美國蘋菓",score=0.,score_kind="uncertainty_gate",
            ambiguous=True,uncertain=False,suspected_typo=True,ambiguity_reason="cloud_suspected_typo")]}
        self.assertTrue(eligibility(ocr)["eligible"])
        ocr["lines"][0].update(uncertain=True,ambiguity_reason="cloud_uncertain")
        self.assertFalse(eligibility(ocr)["eligible"])

    def test_failure_status_and_dynamic_dates_do_not_become_standards(self):
        self.assertFalse(eligibility({"image_status":"unreadable","lines":[line("品名：日本蘋果")]})["eligible"])
        self.assertFalse(eligibility({"lines":[line("到店日：2026.11.19")]})["eligible"])

    def test_confirmed_reading_is_usable_without_mutating_original(self):
        ocr={"lines":[line("品名：□果",score=.1,ambiguous=True)]};before=deepcopy(ocr)
        patches=[{"line_id":0,"kind":"ocr_misread","text":"品名：日本蘋果"}]
        self.assertTrue(eligibility(ocr,patches)["eligible"])
        self.assertEqual(ocr,before)
        self.assertFalse(eligibility(ocr,[{"line_id":0,"kind":"uncertain"}])["eligible"])

    def test_many_labels_require_single_label_recognition(self):
        report=eligibility({"image_status":"multiple_labels","lines":[line("品名：日本蘋果")]})
        self.assertFalse(report["eligible"])
        self.assertEqual(report["reason_code"],"multiple_labels")
        self.assertTrue(report["needs_review"])


if __name__=="__main__":unittest.main()
