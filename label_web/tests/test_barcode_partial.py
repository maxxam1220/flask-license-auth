"""Partial HRI is uncertain evidence, never completed from decoded bars."""
from copy import deepcopy
import unittest

from barcode_checks import checks_for


VALUE = "2834667832333"


def row(text, identifier=1, box=None, **extra):
    return {"id":identifier, "text":text, "score":.72,
            "box":[[80,170],[240,170],[240,195],[80,195]] if box is None else box, **extra}


def evidence(lines, decoded=True, value=VALUE):
    return {"lines":lines,"barcodes":{"state":"decoded" if decoded else "not_read",
        "items":[{"text":value,"format":"EAN-13","box":[[50,50],[350,50],[350,150],[50,150]]}] if decoded else []}}


class PartialBarcodeTests(unittest.TestCase):
    def hri(self, data):
        checks = checks_for(data)
        return next((check for check in checks if check["key"] == "barcode_hri"), None)

    def test_observed_six_digits_near_decoded_bars_require_review_without_mutation(self):
        data = evidence([row("182333")])
        original = deepcopy(data)
        check = self.hri(data)
        self.assertEqual(check["status"], "review")
        self.assertEqual((check["actual"],check["expected"]), ("182333",VALUE))
        self.assertIn("一部分", check["reason"])
        self.assertEqual(check["line_ids"], [1])
        self.assertEqual(data, original)
        self.assertFalse(any(c["key"].startswith("barcode_checksum") for c in checks_for(data)))

    def test_slanted_partial_row_below_tall_real_photo_bars_is_spatially_paired(self):
        data=evidence([row("182333",7,[[251,1527],[1157,1457],[1164,1546],[258,1616]],score=.7201)])
        data["barcodes"]["items"][0]["box"]=[[327,1384],[1132,1384],[1141,1471],[335,1471]]
        check=self.hri(data)
        self.assertEqual((check["status"],check["actual"],check["expected"]),("review","182333",VALUE))

    def test_short_digits_only_are_eligible_with_one_spatially_near_decode(self):
        for text in ("2", "182333", "182 333", "條碼：182333"):
            with self.subTest(text=text):
                self.assertEqual(self.hri(evidence([row(text)]))["status"], "review")
        for data in (evidence([row("182333")],decoded=False),
                     evidence([row("182333",box=[[800,500],[900,500],[900,520],[800,520]])]),
                     evidence([row("182333",box=[])])):
            self.assertIsNone(self.hri(data))

    def test_split_digit_rows_are_not_concatenated_even_when_concatenation_would_match(self):
        rows = [row("2",1,[[20,170],[40,170],[40,195],[20,195]]),
                row("834667832333",2,[[80,170],[340,170],[340,195],[80,195]])]
        data = evidence(rows)
        original = deepcopy(data)
        check = self.hri(data)
        self.assertEqual(check["status"], "review")
        self.assertEqual(check["line_ids"], [1,2])
        self.assertEqual(check["actual"], "2；834667832333")
        self.assertIn("未自動拼接", check["reason"])
        self.assertEqual(data, original)

    def test_full_match_plus_another_numeric_row_is_not_arbitrarily_selected(self):
        check = self.hri(evidence([row(VALUE,1,score=.99),row("65",2,score=.99)]))
        self.assertEqual(check["status"], "review")
        self.assertEqual(check["line_ids"], [1,2])

    def test_ordinary_labels_dates_and_prices_are_not_numeric_hri_rows(self):
        for text in ("貨號：182333", "售價65元", "2026.11.16", "1.2kg", "電話0800-200-859", "182333元"):
            with self.subTest(text=text):
                self.assertIsNone(self.hri(evidence([row(text)])))

    def test_existing_full_row_match_and_uncertainty_semantics_remain(self):
        for changes, status in (({"score":.99},"pass"), ({"score":.4},"review"),
                ({"score":.99,"ambiguous":True},"review"),
                ({"score":.4,"ambiguous":True,"human_verified":True},"pass")):
            with self.subTest(changes=changes):
                self.assertEqual(self.hri(evidence([row(VALUE,**changes)]))["status"],status)
        self.assertEqual(self.hri(evidence([row("182333",human_verified=True)]))["status"],"fail")
        self.assertEqual(self.hri(evidence([row("182333",human_verified=True,human_uncertain=True)]))["status"],"review")

    def test_no_decode_preserves_old_full_length_candidate_rules(self):
        self.assertEqual(checks_for(evidence([row("182333")],decoded=False)), [])
        checks=checks_for(evidence([row(VALUE)],decoded=False))
        self.assertEqual([item["key"] for item in checks], ["barcode_unread"])
        self.assertEqual(checks[0]["status"], "review")

    def test_multiple_barcodes_do_not_borrow_partial_digits(self):
        data=evidence([row("182333")])
        data["barcodes"]["items"].append({"text":"12345678","format":"Code128",
            "box":[[450,50],[750,50],[750,150],[450,150]]})
        self.assertIsNone(self.hri(data))
        self.assertEqual(next(c for c in checks_for(data) if c["key"]=="barcode_multiple")["status"],"review")


if __name__ == "__main__":
    unittest.main()
