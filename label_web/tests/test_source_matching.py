import unittest
from types import SimpleNamespace

from label_source import build_draft, resolve


def line(value, identifier=0, score=.99):
    top = identifier * 30
    return {"id": identifier, "text": value, "score": score,
            "box": [[0, top], [500, top], [500, top + 20], [0, top + 20]]}


def rows(code, name, contents=()):
    entries = [("2:名稱", "品名：")] + list(contents)
    return [dict(CodeNo=code, CodeName=name, KeepDays=3, Seq=str(i), Attr=attr,
                 ObjContent=value, PosX=i * 9, PosY=0, ShiftDate=1)
            for i, (attr, value) in enumerate(entries)]


class Result:
    def __init__(self, values=(), scalar=True):
        self.values, self.scalar_value = values, scalar

    def scalar(self):
        return self.scalar_value

    def mappings(self):
        return self

    def all(self):
        return self.values


class FakeEngine:
    dialect = SimpleNamespace(name="postgresql")

    def __init__(self, catalog, failure=""):
        self.catalog = catalog
        self.failure = failure
        self.queries = []

    def connect(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, statement, params=None):
        query = str(statement)
        self.queries.append((query, params))
        if self.failure and self.failure in query:
            raise RuntimeError("private database credential must not leak")
        if "to_regclass" in query:
            return Result(scalar="public.labelcheck_catalog" not in query)
        if 'WHERE m."CodeNo"=:code' in query:
            return Result(self.catalog.get(params["code"], []))
        if 'LEFT("Attr", 1)' in query:
            return Result([{"code": code, "content": row["ObjContent"]}
                           for code, entries in self.catalog.items() for row in entries
                           if str(row["Attr"]).startswith("3") and row["ObjContent"] is not None])
        if '"CodeName" AS name' in query:
            return Result([{"code": code, "name": entries[0]["CodeName"]}
                           for code, entries in self.catalog.items()])
        raise AssertionError("Unexpected query: " + query)


def engine():
    return FakeEngine({
        "1013": rows("1013", "美國櫻桃1.3kg/盒", [("3", "貨號：211300"), ("3", "產地：美國"),
                    ("3", "規格：1.3kg/盒"), ("3", "新北市土城區中興路9號"), ("0", "3150000000009")]),
        "1017": rows("1017", "日本青森蘋果3色禮盒6入(1.8kg)", [("3", "貨號：211341"), ("3", "產地：日本青森縣"),
                    ("3", "規格：1.8kg/盒"), ("3", "新北市土城區中興路9號"), ("A", "到店日：")])})


class SourceMatchingTests(unittest.TestCase):
    def test_exact_product_uses_one_latest_source_and_small_selects(self):
        db = engine()
        result = resolve(db, [line("品名：美國櫻桃1.3kg/盒")])
        self.assertEqual((result["status"], result["code"]), ("matched", "1013"))
        self.assertEqual(result["source"]["fields"]["origin"], "美國")
        self.assertNotIn("日本青森縣", str(result["source"]))
        self.assertTrue(all(query.lstrip().upper().startswith("SELECT ") for query, _ in db.queries))
        self.assertTrue(all("SELECT *" not in query.upper() for query, _ in db.queries))
        detail_query = next(query for query, _ in db.queries if 'LEFT("Attr", 1)' in query)
        self.assertIn('"ObjContent" AS content', detail_query)
        self.assertNotIn('"PosX"', detail_query)

    def test_name_normalization_only_selects_source_and_preserves_database_text(self):
        result = resolve(engine(), [line("品名： 日本青森苹果３色礼盒６入（１．８ＫＧ） ")])
        self.assertEqual(result["code"], "1017")
        self.assertEqual(result["source"]["name"], "日本青森蘋果3色禮盒6入(1.8kg)")

    def test_tai_variants_identify_same_source(self):
        db = FakeEngine({"1": rows("1", "臺灣鳳梨")})
        self.assertEqual(resolve(db, [line("品名：台湾凤梨")])["code"], "1")

    def test_typo_only_suggests_and_never_builds_source(self):
        db = engine()
        result = resolve(db, [line("品名：美國櫻挑1.3kg/盒")])
        self.assertEqual(result["status"], "unmatched")
        self.assertIsNone(result["source"])
        self.assertIn("1013", [item["code"] for item in result["candidates"]])
        self.assertFalse(any('WHERE m."CodeNo"=:code' in q for q, _ in db.queries))

    def test_low_confidence_exact_name_does_not_autoselect(self):
        result = resolve(engine(), [line("品名：美國櫻桃1.3kg/盒", score=.64)])
        self.assertEqual(result["status"], "unmatched")
        self.assertEqual(result["candidates"][0]["code"], "1013")

    def test_explicit_code_uses_latest_draft_without_catalog_or_ocr(self):
        db = engine()
        result = resolve(db, [], "1017")
        self.assertEqual((result["status"], result["code"]), ("matched", "1017"))
        self.assertEqual(len(db.queries), 2)
        self.assertTrue(result["source"]["rules"]["arrival"])
        self.assertEqual(result["source"]["date_settings"][0]["content"], "到店日：")

    def test_invalid_explicit_code_never_falls_back_to_matching_name(self):
        result = resolve(engine(), [line("品名：美國櫻桃1.3kg/盒")], "missing")
        self.assertEqual(result["status"], "unmatched")
        self.assertIsNone(result["source"])
        self.assertEqual(result["candidates"], [])

    def test_exact_sku_identifies_and_leading_zeros_are_not_discarded(self):
        self.assertEqual(resolve(engine(), [line("貨號：211341")])["code"], "1017")
        self.assertEqual(resolve(engine(), [line("貨號：0211341")])["status"], "unmatched")
        self.assertEqual(resolve(engine(), [line("1017")])["status"], "unmatched")

    def test_conflicting_name_and_sku_require_manual_choice(self):
        result = resolve(engine(), [line("品名：美國櫻桃1.3kg/盒"), line("貨號：211341", 1)])
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual({item["code"] for item in result["candidates"]}, {"1013", "1017"})
        self.assertIsNone(result["source"])

    def test_two_printed_product_names_are_not_overruled_by_one_sku(self):
        result = resolve(engine(), [line("品名：美國櫻桃1.3kg/盒"),
                                   line("品名：日本青森蘋果3色禮盒6入(1.8kg)", 1), line("貨號：211341", 2)])
        self.assertEqual(result["status"], "ambiguous")

    def test_same_name_needs_unique_variant_metadata(self):
        db = FakeEngine({"a": rows("a", "蘋果", [("3", "規格：1kg/盒"), ("3", "產地：日本")]),
                         "b": rows("b", "蘋果", [("3", "規格：2kg/盒"), ("3", "產地：美國")])})
        self.assertEqual(resolve(db, [line("品名：蘋果")])["status"], "ambiguous")
        self.assertEqual(resolve(db, [line("品名：蘋果"), line("規格：2kg/盒", 1)])["code"], "b")
        self.assertEqual(resolve(db, [line("品名：蘋果"), line("產地：日本", 1)])["code"], "a")
        conflict = resolve(db, [line("品名：蘋果"), line("規格：2kg/盒", 1), line("產地：日本", 2)])
        self.assertEqual(conflict["status"], "ambiguous")

    def test_unknown_variant_metadata_cannot_eliminate_a_candidate(self):
        db = FakeEngine({"a": rows("a", "蘋果", [("3", "規格：1kg/盒")]), "b": rows("b", "蘋果")})
        self.assertEqual(resolve(db, [line("品名：蘋果"), line("規格：1kg/盒", 1)])["status"], "ambiguous")

    def test_shared_company_address_phone_are_not_product_identifiers(self):
        result = resolve(engine(), [line("福和生鮮農產股份有限公司"), line("新北市土城區中興路9號", 1),
                                   line("免付費電話：0800-200-859", 2)])
        self.assertEqual(result["status"], "unmatched")
        self.assertIsNone(result["source"])

    def test_dynamic_barcode_detail_is_never_an_identity(self):
        self.assertEqual(resolve(engine(), [line("3150000000009")])["status"], "unmatched")
        source = resolve(engine(), [], "1013")["source"]
        self.assertEqual(source["barcode_values"], [])

    def test_true_static_barcode_is_supported_without_case_folding_code128(self):
        db = FakeEngine({"a": rows("a", "蘋果", [("3", "條碼：AB-12")]),
                         "b": rows("b", "櫻桃", [("3", "3150000000009")])})
        self.assertEqual(resolve(db, [line("條碼：AB-12")])["code"], "a")
        self.assertEqual(resolve(db, [line("條碼：ab-12")])["status"], "unmatched")
        self.assertEqual(resolve(db, [line("3150000000009")])["code"], "b")
        self.assertEqual(resolve(db, [], "a")["source"]["barcode_values"], ["AB-12"])

    def test_code128_entire_value_including_colons_is_used_not_a_shared_prefix(self):
        db = FakeEngine({"a": rows("a", "蘋果", [("3", "條碼：AB:12.5")]),
                         "b": rows("b", "櫻桃", [("3", "條碼：AB:99.0")])})
        self.assertEqual(resolve(db, [line("條碼：AB:12.5")])["code"], "a")
        self.assertEqual(resolve(db, [line("AB:99.0")])["code"], "b")
        self.assertEqual(resolve(db, [line("AB")])["status"], "unmatched")
        self.assertEqual(resolve(db, [line("AB12.5")])["status"], "unmatched")
        self.assertEqual(resolve(db, [], "a")["source"]["barcode_values"], ["AB:12.5"])

    def test_code128_internal_spaces_case_and_width_are_not_normalized(self):
        db = FakeEngine({"a": rows("a", "蘋果", [("3", "條碼：AB  12")])})
        self.assertEqual(resolve(db, [line("AB  12")])["code"], "a")
        for changed in ("AB12", "AB 12", "ab  12", "ＡＢ  12"):
            self.assertEqual(resolve(db, [line(changed)])["status"], "unmatched")
        self.assertEqual(resolve(db, [], "a")["source"]["barcode_values"], ["AB  12"])

    def test_hidden_and_dynamic_fields_cannot_add_fixed_barcodes_or_dates(self):
        source = build_draft(rows("1", "蘋果", [("0", "3150000000009"), ("1", "3150000000016"),
                            ("Z", "條碼：AB-12"), ("A", "到店日：")]), "1")
        self.assertEqual(source["barcode_values"], [])
        self.assertFalse(any("到店日" in item["text"] for item in source["lines"]))

    def test_barcode_source_save_days_override_master_and_keep_provenance(self):
        snapshot = rows("1013", "美國櫻桃1.3kg/盒", [("B", "有效日期：")])
        for row in snapshot:
            row.update(KeepDays=9, SourceSaveDays=3, Barcode=" 0000000211239 ", TypesOfBarcode="1",
                       FrontCode="01", BehindCode="99", SunDay="3", SunPos=7, PriceLen="4", SalePrice=0,
                       SourceBarcode="0000000211239", SourceFirstCode="02", SourceLastCode="", SourcePrice=89,
                       SourceProdName="來源品名")
        source = build_draft(snapshot, "1013")
        self.assertEqual((source["keep_days"], source["master_keep_days"], source["source_savedays"]), (3, 9, 3))
        self.assertEqual(source["keep_days_source"], "Barcode.SaveDays")
        self.assertEqual(source["barcode_config"], {"kind": "1", "barcode": "0000000211239",
                         "master_barcode": "0000000211239", "front": "02", "back": "99",
                         "solar": "3", "solar_pos": 7, "price_len": "4", "sale_price": 89.})
        self.assertEqual(source["fields"]["product"], "美國櫻桃1.3kg/盒")
        self.assertEqual(source["date_settings"][0], {"content": "有效日期：", "format": "B", "shift_days": 1})
        self.assertEqual(source["barcode_values"], [])

    def test_zero_source_save_days_and_master_price_are_not_overwritten(self):
        snapshot = rows("1", "蘋果")
        snapshot[0].update(KeepDays=7, SourceSaveDays=0, SalePrice=55, SourcePrice=99)
        source = build_draft(snapshot, "1")
        self.assertEqual(source["keep_days"], 0)
        self.assertEqual(source["barcode_config"]["sale_price"], 55)
        snapshot[0]["SourceSaveDays"] = None
        source = build_draft(snapshot, "1")
        self.assertEqual(source["keep_days"], 7)
        self.assertEqual(source["keep_days_source"], "BcMst.KeepDays")

    def test_draft_source_lookup_is_single_snapshot_and_skips_blank_barcode(self):
        db = engine()
        resolve(db, [], "1017")
        query = next(query for query, _ in db.queries if 'WHERE m."CodeNo"=:code' in query)
        self.assertIn("LEFT JOIN LATERAL", query)
        self.assertIn("LIMIT 1) b ON TRUE", query)
        self.assertIn('NULLIF(TRIM(m."Barcode"), \'\') IS NOT NULL', query)

    def test_database_failures_are_unavailable_without_secrets_or_defaults(self):
        for fail in ("to_regclass", '"CodeName" AS name', 'WHERE m."CodeNo"=:code'):
            db = engine()
            db.failure = fail
            result = resolve(db, [line("品名：美國櫻桃1.3kg/盒")])
            self.assertEqual(result["status"], "unavailable")
            self.assertIsNone(result["source"])
            self.assertNotIn("credential", str(result))

    def test_local_only_database_is_unavailable(self):
        db = engine()
        db.dialect = SimpleNamespace(name="sqlite")
        self.assertEqual(resolve(db, [])['status'], "unavailable")
        self.assertEqual(db.queries, [])


if __name__ == "__main__":
    unittest.main()
