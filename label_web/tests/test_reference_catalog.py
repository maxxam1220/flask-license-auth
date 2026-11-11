import unittest

import label_source
import reference_catalog
from source_rules import prepare_source
from source_validation import evaluate_source
from test_source_matching import FakeEngine, Result, line, rows


def entry(code="1659", name="(水果)日本空運麝香葡萄350g*2盒/禮盒", barcode="26586342", days=6):
    return {"code": code, "name": name, "barcode": barcode, "keep_days": days,
            "barcode_type": "3", "revision": "revision-" + code,
            "provenance": {"file": "20261008.xlsx", "row": 358}, "updated_at": "2026-11-11"}


class CatalogEngine(FakeEngine):
    def __init__(self, desktop=None, entries=(), desktop_available=True):
        super().__init__(desktop or {})
        self.entries = list(entries)
        self.has_desktop = desktop_available

    def execute(self, statement, params=None):
        query = str(statement)
        if "to_regclass" in query:
            self.queries.append((query, params))
            return Result(scalar=True if "public.labelcheck_catalog" in query else self.has_desktop)
        if "FROM public.labelcheck_catalog" in query:
            self.queries.append((query, params))
            values = self.entries
            if params and "code" in params:
                values = [row for row in values if row["code"] == params["code"]]
            return Result(values)
        return super().execute(statement, params)


class ReferenceCatalogTests(unittest.TestCase):
    def test_catalog_draft_contains_only_known_facts_without_layout_or_schedule(self):
        draft = reference_catalog.build_draft(entry())
        self.assertEqual(draft["code"], "list:1659")
        self.assertEqual(draft["source_kind"], "catalog")
        self.assertEqual(draft["comparison_scope"], "catalog_fields")
        self.assertEqual(draft["fields"], {"product": entry()["name"]})
        self.assertEqual(len(draft["lines"]), 1)
        self.assertEqual(draft["date_settings"], [])
        self.assertEqual(draft["keep_days"], 6)
        self.assertEqual(draft["barcode_values"], ["26586342"])
        self.assertEqual(prepare_source(draft, "2026-11-11")["barcode_values"], ["26586342"])
        self.assertNotIn("box", draft["lines"][0])

    def test_blank_barcode_and_zero_days_remain_known_as_provided(self):
        draft = reference_catalog.build_draft(entry(barcode="", days=0))
        self.assertEqual(draft["barcode_values"], [])
        self.assertEqual(draft["known_fields"], ["product", "keep_days"])
        self.assertEqual(draft["keep_days"], 0)

    def test_list_only_database_is_available_and_selectable(self):
        db = CatalogEngine(entries=[entry()], desktop_available=False)
        result = label_source.resolve(db, [line("品名：" + entry()["name"], score=.90)])
        self.assertEqual((result["status"], result["code"]), ("matched", "list:1659"))
        self.assertEqual(result["source_kind"], "catalog")
        self.assertTrue(all(query.lstrip().startswith("SELECT ") for query, _ in db.queries))

    def test_list_code_never_collides_with_existing_desktop_product(self):
        db = CatalogEngine({"1013": rows("1013", "美國櫻桃1.3kg/盒")},
                           [entry("1013", "聖女番茄200g", "2100013191363")])
        self.assertEqual(label_source.resolve(db, [], "1013")["source"]["name"], "美國櫻桃1.3kg/盒")
        self.assertEqual(label_source.resolve(db, [], "list:1013")["source"]["name"], "聖女番茄200g")
        self.assertEqual(label_source.resolve(db, [line("品名：聖女番茄200g")])["code"], "list:1013")
        self.assertEqual(label_source.resolve(db, [], "list:absent")["status"], "unmatched")

    def test_search_identifies_catalog_rows_and_supports_literal_barcode(self):
        found = label_source.search(CatalogEngine(entries=[entry()], desktop_available=False), "26586342")
        self.assertEqual(found, [{"code": "list:1659", "name": entry()["name"], "source_kind": "catalog"}])

    def test_equivalent_duplicates_use_same_known_content_without_manual_guess(self):
        db = CatalogEngine(entries=[entry("1659"), entry("1683")])
        result = label_source.resolve(db, [line("品名：" + entry()["name"]), line("26586342", 1)])
        self.assertEqual(result["status"], "matched")
        self.assertEqual({r["code"] for r in result["equivalent_sources"]}, {"list:1659", "list:1683"})
        self.assertEqual(result["source"]["keep_days"], 6)

    def test_different_days_or_barcode_are_not_equivalent(self):
        for other in (entry("1683", days=5), entry("1683", barcode="26586343")):
            db = CatalogEngine(entries=[entry(), other])
            result = label_source.resolve(db, [line("品名：" + entry()["name"])])
            self.assertEqual(result["status"], "ambiguous")
            self.assertIsNone(result["source"])

    def test_same_name_uses_exact_barcode_to_disambiguate(self):
        db = CatalogEngine(entries=[entry(), entry("1683", barcode="26586343")])
        result = label_source.resolve(db, [line("品名：" + entry()["name"]), line("26586343", 1)])
        self.assertEqual(result["code"], "list:1683")

    def test_same_name_unknown_barcode_is_not_treated_as_different(self):
        db = CatalogEngine(entries=[entry("a", name="日本葡萄350g", days=6),
                                    entry("b", name="日本葡萄350g", barcode="", days=3)])
        result = label_source.resolve(db, [line("品名：日本葡萄350g"), line("26586342", 1)])
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual({item["code"] for item in result["candidates"]}, {"list:a", "list:b"})
        self.assertEqual(label_source.resolve(db, [line("26586342")])["code"], "list:a")

    def test_name_and_barcode_for_another_product_remain_conflicting(self):
        db = CatalogEngine(entries=[entry("a", name="日本葡萄350g", barcode=""),
                                    entry("b", name="韓國葡萄350g")])
        self.assertEqual(label_source.resolve(db, [line("品名：日本葡萄350g"), line("26586342", 1)])["status"], "ambiguous")

    def test_printed_shelf_days_disambiguate_same_name_and_barcode(self):
        db = CatalogEngine(entries=[entry("a", days=6), entry("b", days=3)])
        ocr = [line("品名：" + entry()["name"]), line("26586342", 1), line("保存期限：６ 天", 2, .9)]
        self.assertEqual(label_source.resolve(db, ocr)["code"], "list:a")
        ocr[-1] = line("保存期限：3天", 2)
        self.assertEqual(label_source.resolve(db, ocr)["code"], "list:b")
        ocr[-1] = line("保存期限：0天", 2)
        self.assertEqual(label_source.resolve(db, ocr)["status"], "ambiguous")

    def test_unknown_shelf_days_cannot_be_eliminated_and_low_confidence_not_used(self):
        db = CatalogEngine(entries=[entry("a", days=6), entry("b", days=None)])
        ocr = [line("品名：" + entry()["name"]), line("保存期限：6天", 1)]
        self.assertEqual(label_source.resolve(db, ocr)["status"], "ambiguous")
        db = CatalogEngine(entries=[entry("a", days=6), entry("b", days=3)])
        ocr[-1] = line("保存期限：6天", 1, .64)
        self.assertEqual(label_source.resolve(db, ocr)["status"], "ambiguous")

    def test_conflicting_printed_shelf_days_do_not_choose_an_unknown_record(self):
        db = CatalogEngine(entries=[entry("a", days=6), entry("b", days=3), entry("c", days=None)])
        ocr = [line("品名：" + entry()["name"]), line("保存期限：6天", 1), line("保存期限：3天", 2)]
        self.assertEqual(label_source.resolve(db, ocr)["status"], "ambiguous")

    def test_exact_barcode_locates_source_then_visible_product_typo_fails(self):
        db = CatalogEngine(entries=[entry(name="日本麝香葡萄350g")])
        ocr = [line("品名：日本麝香葡萄35g"), line("26586342", 1)]
        matched = label_source.resolve(db, ocr)
        self.assertEqual(matched["code"], "list:1659")
        checks = evaluate_source(ocr, matched["source"], base_date="2026-11-11")["checks"]
        self.assertEqual(next(check for check in checks if check["key"] == "product")["status"], "fail")
        self.assertEqual(ocr[0]["text"], "品名：日本麝香葡萄35g")

    def test_no_barcode_typo_only_cannot_select_or_merge_list_source(self):
        result = label_source.resolve(CatalogEngine(entries=[entry(name="日本麝香葡萄350g")]),
                                      [line("品名：日本麝香葡萄35g")])
        self.assertEqual(result["status"], "unmatched")
        self.assertIsNone(result["source"])

    def test_unsupported_list_footer_stays_unverified(self):
        source = reference_catalog.build_draft(entry(name="日本葡萄", barcode=""))
        result = evaluate_source([line("品名：日本葡萄"), line("新北市土城區中興路9號", 1)],
                                 source, base_date="2026-11-11")
        self.assertTrue(any(c["status"] == "read" and "中興路" in c["actual"] for c in result["checks"]))
        self.assertNotEqual(result["status"], "pass")

    def test_complete_other_text_disambiguates_identical_desktop_names(self):
        db = CatalogEngine({"a": rows("a", "蘋果", [("3", "食用說明：請洗淨後食用"), ("3", "保存條件：冷藏")]),
                            "b": rows("b", "蘋果", [("3", "食用說明：請去皮後食用"), ("3", "保存條件：常溫")])})
        ocr = [line("品名：蘋果"), line("食用說明：請去皮後食用", 1, .90), line("保存條件：常温", 2)]
        self.assertEqual(label_source.resolve(db, ocr)["code"], "b")

    def test_other_correct_text_locates_source_while_misspelling_still_fails(self):
        db = CatalogEngine({"a": rows("a", "蘋果", [("3", "食用說明：請洗淨後食用"), ("3", "福和生鮮農產股份有限公司")]),
                            "b": rows("b", "蘋果", [("3", "食用說明：請去皮後食用"), ("3", "福和生鮮農產股份有限公司")])})
        ocr = [line("品名：蘋果"), line("食用說明：請去皮後食用", 1), line("福和生鮮農產股份有限公", 2)]
        result = label_source.resolve(db, ocr)
        self.assertEqual(result["code"], "b")
        self.assertEqual(evaluate_source(ocr, result["source"], base_date="2026-11-11")["status"], "fail")

    def test_conflicting_full_text_never_selects_first_candidate(self):
        db = CatalogEngine({"a": rows("a", "蘋果", [("3", "食用說明：請洗淨後食用"), ("3", "保存條件：冷藏")]),
                            "b": rows("b", "蘋果", [("3", "食用說明：請去皮後食用"), ("3", "保存條件：常溫")])})
        ocr = [line("品名：蘋果"), line("食用說明：請洗淨後食用", 1), line("保存條件：常溫", 2)]
        self.assertEqual(label_source.resolve(db, ocr)["status"], "ambiguous")

    def test_list_missing_layout_cannot_be_excluded_by_desktop_extra_text(self):
        db = CatalogEngine({"a": rows("a", "蘋果", [("3", "食用說明：請洗淨後食用")])},
                           [entry(name="蘋果", barcode="")])
        result = label_source.resolve(db, [line("品名：蘋果"), line("食用說明：請洗淨後食用", 1)])
        self.assertEqual(result["status"], "ambiguous")

    def test_low_confidence_or_ambiguous_identity_remains_unmatched(self):
        for ocr in (line("品名：" + entry()["name"], score=.64),
                    dict(line("品名：" + entry()["name"]), ambiguous=True)):
            self.assertEqual(label_source.resolve(CatalogEngine(entries=[entry()]), [ocr])["status"], "unmatched")


if __name__ == "__main__":
    unittest.main()
