"""Arrival annotations also work when storing references or checking date barcodes."""
from copy import deepcopy
from datetime import date
import unittest
from werkzeug.exceptions import BadRequest
import barcode_rule_authoring as barcode
import standard_library
import test_api
from test_validation import STANDARD,make_lines


class ArrivalMarkerReferenceTests(unittest.TestCase):
    setUp=test_api.APITests.setUp
    tearDown=test_api.APITests.tearDown
    photo=test_api.APITests.photo
    job=test_api.APITests.job
    standard=test_api.APITests.standard

    def test_create_photo_standard_preserves_marker_and_checks_date_order(self):
        rules={**STANDARD['rules'],'arrival':True}
        dates={'manufacture':'2026.11.10','expiry':'2026.11.13','arrival':'2026.11.12 ⑤'}
        response=self.standard(rules=rules,reference_dates=dates)
        self.assertEqual(response.status_code,201,response.json)
        self.assertEqual(response.json['reference_dates']['arrival'],'2026.11.12 ⑤')
        response=self.standard(rules=rules,reference_dates={**dates,'arrival':'2026.11.14 ①'})
        self.assertEqual(response.status_code,400)


class ArrivalMarkerDownstreamTests(unittest.TestCase):
    def test_photo_library_edit_accepts_different_marker_but_not_invalid_date(self):
        current=deepcopy(STANDARD)
        current.update(name='測試標準',reference_dates={'manufacture':'2026.11.10','expiry':'2026.11.13','arrival':'2026.11.12 ⑤'})
        current['rules']['arrival']=True
        updated=standard_library._photo_changes(current,{'reference_dates':{'arrival':'2026.11.12 ②'}})
        self.assertEqual(updated['reference_dates']['arrival'],'2026.11.12 ②')
        self.assertEqual(current['reference_dates']['arrival'],'2026.11.12 ⑤')
        for invalid in ('2026.02.30 ②','2026.11.14 ⑦','2026.11.12 隨意文字'):
            with self.assertRaises(BadRequest):standard_library._photo_changes(current,{'reference_dates':{'arrival':invalid}})

    def test_arrival_barcode_uses_calendar_day_not_the_circled_number(self):
        rule={'version':1,'symbology':'EAN13','prefix':'28346654','day_source':'arrival','day_width':3,'suffix':'3'}
        value=barcode.compose(rule,date(2026,11,20))
        for marker in ('①','⑤','⑦','⑳'):
            lines=make_lines({'manufacture':'','expiry':'','arrival':f'到店日：2026.11.20 {marker}','barcode':value})
            before=deepcopy(lines)
            evidence,dates,found,reason=barcode.read_observations({'lines':lines},'2026-11-17')
            self.assertEqual(dates['arrival'],date(2026,11,20));self.assertEqual(found,value)
            self.assertEqual(next(x for x in evidence['dates'] if x['kind']=='arrival')['day_of_year'],324)
            self.assertEqual(barcode.evaluate_rule(lines,rule,'2026-11-17')['status'],'pass')
            self.assertEqual(lines,before)


if __name__=='__main__':unittest.main()
