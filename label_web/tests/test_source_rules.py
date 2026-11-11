import unittest
from source_rules import barcode_for_source, prepare_source


class SourceRulesTests(unittest.TestCase):
    def test_cherry_printed_ean_and_empty_apple_barcode(self):
        self.assertEqual(barcode_for_source({"kind":"1", "barcode":"0000000211239"}, "2026-11-11"), "0000000211239")
        self.assertEqual(barcode_for_source({"kind":"1", "barcode":""}, "2026-11-11"), "")

    def test_upc_and_ean8_checksums(self):
        self.assertEqual(barcode_for_source({"kind":"2", "barcode":"036000291452"}, "2026-11-11"), "036000291452")
        self.assertEqual(barcode_for_source({"kind":"3", "barcode":"96385074"}, "2026-11-11"), "96385074")

    def test_solar_day_changes_across_year_boundary(self):
        config = {"kind":"1", "barcode":"123456", "solar":"3", "solar_pos":1}
        self.assertTrue(barcode_for_source(config,"2026-12-31").startswith("365123456"))
        self.assertTrue(barcode_for_source(config,"2027-01-01").startswith("001123456"))

    def test_code128_preserves_punctuation_and_snapshot_is_immutable(self):
        source = {"barcode_config":{"kind":"4", "barcode":"A-12.5"},"barcode_values":[]}
        prepared = prepare_source(source,"2026-11-11")
        self.assertEqual(prepared["barcode_values"],["A-12.5"])
        self.assertEqual(source["barcode_values"],[])


if __name__ == "__main__":
    unittest.main()
