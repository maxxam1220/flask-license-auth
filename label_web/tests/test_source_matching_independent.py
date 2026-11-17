"""Independent regressions for selection identity, not OCR correctness.

All catalogs below are anonymous in-memory snapshots. No database or cloud
connection is opened; source resolution still runs the production algorithm.
"""
from copy import deepcopy
from contextlib import ExitStack
import unittest
from unittest.mock import patch

import label_source
from source_validation import evaluate_source


def line(value, identifier=0, score=.99, **flags):
    top = identifier * 40
    return {"id": identifier, "text": value, "score": score,
            "box": [[0, top], [500, top], [500, top + 24], [0, top + 24]], **flags}


def source(code, name, extra=(), *, kind="desktop", barcode_kind=""):
    lines = [line("品名：" + name), *(line(text, i + 1) for i, text in enumerate(extra))]
    return {"code": code, "name": name, "source_kind": kind, "revision": "source-" + code,
            "comparison_scope": "desktop_label", "lines": lines,
            "fields": {key: value["value"] for key, value in label_source.extract_fields(lines).items()},
            "barcode_values": sorted(set().union(*(label_source._fixed_barcodes(row["text"]) for row in lines))),
            "barcode_config": {"kind": barcode_kind}, "date_settings": [], "rules": {}, "keep_days": None}


class IndependentSourceMatchingTests(unittest.TestCase):
    def resolve(self, sources, observed, explicit=""):
        by_code = {item["code"]: deepcopy(item) for item in sources}
        catalog = {}
        for code, item in by_code.items():
            indexed = label_source._manual_catalog_item(item)
            indexed["source_kind"] = item["source_kind"]
            indexed["barcode_kind"] = item["barcode_config"]["kind"]
            catalog[code] = indexed
        before = deepcopy((by_code, catalog, observed))
        with ExitStack() as stack:
            stack.enter_context(patch.object(label_source, "available", return_value=True))
            stack.enter_context(patch.object(label_source, "_catalog", return_value=catalog))
            stack.enter_context(patch.object(label_source, "draft", side_effect=lambda _, code: deepcopy(by_code.get(code))))
            result = label_source.resolve(object(), observed, explicit)
        self.assertEqual((by_code, catalog, observed), before, "Matching must not rewrite OCR or source evidence")
        return result

    def assert_unselected(self, result, status="ambiguous"):
        self.assertEqual(result["status"], status)
        self.assertIsNone(result["source"])
        self.assertEqual(result["code"], "")

    def test_generic_footers_cannot_eliminate_same_name_desktop_with_missing_footer(self):
        for footer in ("福和生鮮農產股份有限公司", "新北市土城區中興路9號", "電話：0800-200-859",
                       "保存條件：0°C～7°C冷藏保存"):
            with self.subTest(footer=footer):
                sources = [source("a", "綜合水果盒", [footer]), source("b", "綜合水果盒")]
                self.assert_unselected(self.resolve(sources, [line("品名：綜合水果盒"), line(footer, 1)]))

    def test_generic_footers_cannot_choose_between_two_known_different_footers(self):
        for left, right in (("甲生鮮股份有限公司", "乙生鮮股份有限公司"),
                            ("電話：0800-111-111", "電話：0800-222-222"),
                            ("新北市土城區中興路9號", "新北市土城區中興路10號")):
            with self.subTest(left=left):
                sources = [source("a", "綜合水果盒", [left]), source("b", "綜合水果盒", [right])]
                self.assert_unselected(self.resolve(sources, [line("品名：綜合水果盒"), line(left, 1)]))

    def test_shared_footer_alone_never_identifies_product(self):
        footer = "福和生鮮農產股份有限公司"
        self.assert_unselected(self.resolve([source("a", "蘋果", [footer])], [line(footer)]), "unmatched")

    def test_known_spec_and_origin_still_distinguish_same_name_variants(self):
        sources = [source("a", "水果盒", ["規格：150g/盒", "產地：台灣"]),
                   source("b", "水果盒", ["規格：250g/盒", "產地：日本"])]
        for extra in ("規格：250g/盒", "產地：日本"):
            self.assertEqual(self.resolve(sources, [line("品名：水果盒"), line(extra, 1)])["code"], "b")
        self.assert_unselected(self.resolve(sources, [line("品名：水果盒"), line("規格：250g/盒", 1), line("產地：台灣", 2)]))

    def test_unknown_spec_remains_unknown_and_does_not_eliminate_candidate(self):
        sources = [source("a", "水果盒", ["規格：150g/盒"]), source("b", "水果盒")]
        self.assert_unselected(self.resolve(sources, [line("品名：水果盒"), line("規格：150g/盒", 1)]))

    def test_known_name_and_other_full_fixed_code_conflict_in_auto_mode(self):
        sources = [source("apple", "蘋果", ["2803993832539"]), source("papaya", "木瓜", ["2834665432436"])]
        result = self.resolve(sources, [line("品名：蘋果"), line("2834665432436", 1)])
        self.assert_unselected(result)
        self.assertEqual({item["code"] for item in result["candidates"]}, {"apple", "papaya"})

    def test_low_confidence_and_uncertain_identity_never_autoselect(self):
        sources = [source("a", "蘋果")]
        for flags in ({"score": .64}, {"ambiguous": True}, {"human_uncertain": True},
                      {"human_verified": True, "human_uncertain": True}):
            with self.subTest(flags=flags):
                self.assert_unselected(self.resolve(sources, [line("品名：蘋果", **flags)]), "unmatched")

    def test_human_confirmed_identity_retains_original_score_and_can_select(self):
        observed = [line("品名：蘋果", score=.2, ambiguous=True, human_verified=True)]
        result = self.resolve([source("a", "蘋果")], observed)
        self.assertEqual(result["code"], "a")
        self.assertEqual(observed[0]["score"], .2)

    def test_low_confidence_conflicting_sku_does_not_overrule_clear_name(self):
        sources = [source("a", "蘋果", ["貨號：APPLE-01"]), source("p", "木瓜", ["貨號：PAPAYA-01"])]
        self.assertEqual(self.resolve(sources, [line("品名：蘋果"), line("貨號：PAPAYA-01", 1, score=.1)])["code"], "a")

    def test_barcode_prefix_is_never_a_complete_fixed_code_match(self):
        sources = [source("a", "蘋果", ["2803993832539"]), source("p", "木瓜", ["2834665432436"])]
        for printed in ("28", "28039938", "28346654", "條碼：28346654"):
            with self.subTest(printed=printed):
                self.assert_unselected(self.resolve(sources, [line(printed)]), "unmatched")

    def test_code128_case_spaces_and_punctuation_are_not_normalized(self):
        sources = [source("a", "蘋果", ["條碼：AB  12:Z"], barcode_kind="4")]
        self.assertEqual(self.resolve(sources, [line("AB  12:Z")])["code"], "a")
        for printed in ("AB 12:Z", "AB12:Z", "ab  12:Z", "AB  12Z", "AB"):
            with self.subTest(printed=printed):
                self.assert_unselected(self.resolve(sources, [line(printed)]), "unmatched")

    def test_explicit_same_product_and_auto_select_same_source(self):
        sources = [source("a", "蘋果"), source("p", "木瓜")]
        observed = [line("品名：蘋果")]
        self.assertEqual(self.resolve(sources, observed)["code"], "a")
        self.assertEqual(self.resolve(sources, observed, "a")["code"], "a")

    def test_explicit_wrong_known_product_is_conflict_not_silent_auto_fallback(self):
        sources = [source("list:apple", "蘋果", kind="catalog"),
                   source("manual:papaya", "木瓜", kind="manual")]
        result = self.resolve(sources, [line("品名：蘋果")], "manual:papaya")
        self.assert_unselected(result, "source_conflict")
        self.assertEqual(result["selected_source"]["code"], "manual:papaya")
        self.assertTrue(result["identity_evidence"])
        self.assertIn("list:apple", {item["code"] for item in result["candidates"]})

    def test_explicit_standard_allows_ordinary_spelling_error_to_be_checked(self):
        sources = [source("a", "日本蘋果")]
        observed = [line("品名：日本蘋菓")]
        result = self.resolve(sources, observed, "a")
        self.assertEqual(result["code"], "a")
        evaluated = evaluate_source(observed, result["source"], base_date="2026-11-17")
        product = next(item for item in evaluated["checks"] if item["key"] == "product")
        self.assertEqual(product["status"], "fail")
        self.assertEqual(product["actual"], observed[0]["text"])

    def test_unreliable_other_name_does_not_block_explicit_standard(self):
        sources = [source("a", "蘋果"), source("p", "木瓜")]
        for flags in ({"score": .2}, {"ambiguous": True}, {"human_uncertain": True}):
            with self.subTest(flags=flags):
                self.assertEqual(self.resolve(sources, [line("品名：蘋果", **flags)], "p")["code"], "p")

    def test_missing_explicit_source_never_falls_back_to_exact_observed_name(self):
        self.assert_unselected(self.resolve([source("a", "蘋果")], [line("品名：蘋果")], "removed"), "unmatched")

    def test_explicit_same_name_single_wrong_field_remains_inspectable(self):
        sources = [source("a", "水果盒", ["貨號：AA", "規格：150g/盒"]),
                   source("b", "水果盒", ["貨號：BB", "規格：250g/盒"])]
        observed = [line("品名：水果盒"), line("規格：250g/盒", 1)]
        self.assertEqual(self.resolve(sources, observed, "a")["code"], "a")

    def test_explicit_same_name_two_identity_signals_for_other_variant_conflict(self):
        sources = [source("a", "水果盒", ["貨號：AA", "規格：150g/盒"]),
                   source("b", "水果盒", ["貨號：BB", "規格：250g/盒"])]
        observed = [line("品名：水果盒"), line("貨號：BB", 1), line("規格：250g/盒", 2)]
        self.assert_unselected(self.resolve(sources, observed, "a"), "source_conflict")


if __name__ == "__main__":
    unittest.main()
