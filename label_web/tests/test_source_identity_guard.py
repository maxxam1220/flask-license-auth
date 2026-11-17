"""Pinned references cannot turn another known product into a normal match."""
from copy import deepcopy
import unittest

import label_source
from source_validation import evaluate_source
import test_source_matching_independent as fixture

line=fixture.line
source=fixture.source


class SourceIdentityGuardTests(unittest.TestCase):
    resolve=fixture.IndependentSourceMatchingTests.resolve

    def test_short_bare_known_name_conflicts_without_changing_selected_identity(self):
        sources=[source("list:apple","蘋果"),source("manual:papaya","木瓜",kind="manual")]
        observed=[line("蘋果")]
        self.assertEqual(self.resolve(sources,observed)["code"],"list:apple")
        result=self.resolve(sources,observed,"manual:papaya")
        self.assertEqual(result["status"],"source_conflict")
        self.assertIsNone(result["source"])
        self.assertEqual(result["selected_source"]["code"],"manual:papaya")
        self.assertEqual(result["identity_evidence"],[{"field":"product","actual":"蘋果","expected":"木瓜","line_ids":[0]}])
        self.assertEqual([item["code"] for item in result["candidates"]],["list:apple"])

    def test_ingredient_value_is_not_a_product_name_inline_or_split(self):
        sources=[source("apple","蘋果"),source("papaya","木瓜")]
        for observed in ([line("內容物：蘋果")],[line("內容物："),line("蘋果",1)],
                [line("成分"),line("蘋果",1)]):
            with self.subTest(text=[item["text"] for item in observed]):
                self.assertEqual(self.resolve(sources,observed)["status"],"unmatched")
                self.assertEqual(self.resolve(sources,observed,"papaya")["status"],"matched")

    def test_spaced_ean13_can_conflict_with_clear_name_but_never_infer_prefix(self):
        sources=[source("apple","蘋果",["4006381333931"],barcode_kind="1"),
            source("papaya","木瓜",["2834665432436"],barcode_kind="1")]
        self.assertEqual(self.resolve(sources,[line("2 834665 432436")])["code"],"papaya")
        conflict=self.resolve(sources,[line("品名：蘋果"),line("2 834665 432436",1)])
        self.assertEqual(conflict["status"],"ambiguous")
        self.assertIsNone(conflict["source"])
        for partial in ("28346654","2 834665","2 834665 432430"):
            self.assertEqual(self.resolve(sources,[line(partial)])["status"],"unmatched")

    def test_code128_numeric_spaces_and_unknown_types_remain_literal(self):
        for kind in ("4",""):
            refs=[source("code","數字條碼",["2834665432436"],barcode_kind=kind)]
            self.assertEqual(self.resolve(refs,[line("2834665432436")])["code"],"code")
            self.assertEqual(self.resolve(refs,[line("2 834665 432436")])["status"],"unmatched")
        refs=[source("code","Code128",["條碼：AB  12"],barcode_kind="4")]
        for value in ("AB 12","AB12","ab  12"):
            self.assertEqual(self.resolve(refs,[line(value)])["status"],"unmatched")
        self.assertEqual(self.resolve(refs,[line("AB  12")])["code"],"code")

    def test_explicit_upc_and_ean8_types_allow_only_valid_complete_digits(self):
        for kind,value,spaced in (("2","036000291452","0 36000 29145 2"),("3","96385074","9 638507 4")):
            refs=[source("gtin","已知條碼",[value],barcode_kind=kind)]
            self.assertEqual(self.resolve(refs,[line(spaced)])["code"],"gtin")
            self.assertEqual(self.resolve(refs,[line(spaced[:-1]+"0")])["status"],"unmatched")

    def test_same_name_one_bad_identity_field_remains_print_error(self):
        refs=[source("a","水果盒",["貨號：A001","規格：100g/盒"]),source("b","水果盒",["貨號：B002","規格：200g/盒"])]
        observed=[line("品名：水果盒"),line("貨號：B002",1),line("規格：100g/盒",2)]
        result=self.resolve(refs,observed,"a")
        self.assertEqual(result["status"],"matched")
        self.assertEqual(evaluate_source(observed,result["source"],base_date="2026-11-17")["status"],"fail")

    def test_same_name_known_barcode_and_spec_together_identify_wrong_variant(self):
        refs=[source("a","水果盒",["4006381333931","規格：100g/盒"],barcode_kind="1"),
            source("b","水果盒",["2834665432436","規格：200g/盒"],barcode_kind="1")]
        observed=[line("品名：水果盒"),line("2 834665 432436",1),line("規格：200g/盒",2)]
        result=self.resolve(refs,observed,"a")
        self.assertEqual(result["status"],"source_conflict")
        self.assertEqual({item["field"] for item in result["identity_evidence"]},{"barcode","spec"})

    def test_historical_dynamic_hri_is_not_reused_as_fixed_product_identity(self):
        ref=source("manual:a","木瓜",["2834665432436"],kind="manual",barcode_kind="1")
        ref["web_barcode_rule"]={"version":1,"symbology":"EAN13","prefix":"28346654","day_source":"expiry","day_width":3,"suffix":"3"}
        original=deepcopy(ref)
        self.assertEqual(self.resolve([ref],[line("2834665432436")])["status"],"unmatched")
        self.assertEqual(self.resolve([ref],[line("品名：木瓜")])["code"],"manual:a")
        self.assertEqual(ref,original)

    def test_name_only_match_reason_does_not_claim_barcode_or_sku_confirmation(self):
        result=self.resolve([source("a","蘋果")],[line("品名：蘋果")])
        self.assertEqual(result["status"],"matched")
        self.assertNotIn("品名、貨號、條碼",result["reason"])


if __name__=="__main__":unittest.main()
