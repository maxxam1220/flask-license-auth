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

    def test_upca_human_readable_matches_zero_prefixed_ean13_only(self):
        for digits in ("400000790039","036000291452"):
            hri=" ".join((digits[:1], digits[1:6], digits[6:11], digits[-1]))
            data=evidence([row(hri)],value="0"+digits)
            checks={item["key"]:item for item in checks_for(data)}
            self.assertEqual(checks["barcode_hri"]["status"],"pass")
            self.assertEqual(checks["barcode_checksum_0"]["status"],"pass")
            self.assertEqual(checks["barcode_hri"]["expected"],"0"+digits)
            for symbology,payload in (("Code128","0"+digits),("EAN-13","1"+digits),("EAN-13","0"+digits[:-1]+"1")):
                data["barcodes"]["items"][0].update(format=symbology,text=payload)
                self.assertEqual(self.hri(data)["status"],"review")

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

    def test_traceability_qr_and_retail_bars_can_both_pass(self):
        from barcode_rule_authoring import read_observations
        from inspection_evidence import augment
        retail = "4711378333473"
        data = evidence([row("4 711378 333473", score=.99)], value=retail)
        qr = {"text":"https://trace.example.test/?t=0000000000000001", "format":"QR Code",
              "box":[[500,50],[580,50],[580,130],[500,130]]}
        data["barcodes"]["items"].insert(0, qr)
        before = deepcopy(data)
        result = augment({"checks":[]}, data)
        checks = {item["key"]:item for item in result["checks"]}
        self.assertEqual(result["status"], "pass")
        self.assertEqual(checks["barcode_hri"]["expected"], retail)
        trace = checks["barcode_traceability_0"]
        self.assertEqual((trace["status"], trace["actual"], trace["box"]), ("pass", qr["text"], qr["box"]))
        _, _, found, reason = read_observations(data, "2026-11-18")
        self.assertEqual((found, reason), (retail, ""))
        self.assertEqual(data, before)
        data["lines"][0].update(text="4711378333472", human_verified=True)
        self.assertEqual(self.hri(data)["status"], "fail")

    def test_traceability_url_does_not_replace_unread_product_bars(self):
        data = evidence([row(VALUE)], decoded=False)
        data["barcodes"]["items"].append({"text":"http://任意.example/查詢", "format":"QRCode", "box":[]})
        checks = {item["key"]:item for item in checks_for(data)}
        self.assertEqual(checks["barcode_unread"]["status"], "review")
        self.assertEqual(checks["barcode_traceability_0"]["status"], "pass")

    def test_url_exemption_requires_qr_with_a_web_address(self):
        for kind, value in (("QR Code","12345678"), ("QR Code","https://"),
                            ("QR Code","https://bad host/"), ("QR Code","https://host:abc/"),
                            ("QR Code","mailto:name@example.test"), ("Code128","https://tqr.tw/")):
            with self.subTest(kind=kind, value=value):
                data = evidence([])
                data["barcodes"]["items"].append({"text":value, "format":kind, "box":[]})
                self.assertIn("barcode_multiple", {item["key"] for item in checks_for(data)})


if __name__ == "__main__":
    unittest.main()
