"""Main-panel scope contracts; no paid network requests."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

import cloud_vision as cloud
from tests.test_cloud_vision import line, response


def panel_document(**changes):
    document={"image_status":"readable","selection_status":"selected",
        "label_region":{"x":5,"y":5,"width":400,"height":300},
        "lines":[line("脂肪 0.1公克 0.1公克")]}
    document.update(changes)
    return document


class CloudPanelTests(unittest.TestCase):
    def parse(self,document,original=(640,480),sent=(640,480)):
        return cloud._parse_panel(document,original,sent)

    def test_coordinates_scale_to_original_and_preserve_duplicate_values(self):
        document=panel_document();before=deepcopy(document)
        lines,region=self.parse(document,(1280,960),(640,480))
        self.assertEqual(lines[0]["text"],"脂肪 0.1公克 0.1公克")
        self.assertEqual(lines[0]["box"],[[20,20],[400,20],[400,80],[20,80]])
        self.assertEqual({k:region[k] for k in ("x","y","width","height")},{"x":10,"y":10,"width":800,"height":600})
        self.assertEqual(document,before)

    def test_selected_scope_includes_all_returned_ink_and_does_not_silently_drop_footer(self):
        footer=line("包材宣傳",box=[{"x":10,"y":350},{"x":200,"y":350},{"x":200,"y":380},{"x":10,"y":380}])
        with self.assertRaises(cloud.CloudVisionError) as caught:
            self.parse(panel_document(lines=[line(),footer]))
        self.assertEqual(caught.exception.code,"scope_unclear")

    def test_uncertain_selection_is_not_a_successful_full_image_fallback(self):
        with self.assertRaises(cloud.CloudVisionError) as caught:
            self.parse(panel_document(selection_status="needs_crop"))
        self.assertEqual(caught.exception.code,"scope_unclear")

    def test_unreadable_and_multiple_labels_remain_explicit_failures(self):
        for status,code in (("unreadable","no_text"),("no_text","no_text"),("multiple_labels","multiple_labels")):
            with self.subTest(status=status), self.assertRaises(cloud.CloudVisionError) as caught:
                self.parse(panel_document(image_status=status,lines=[]))
            self.assertEqual(caught.exception.code,code)

    def test_invalid_regions_reject_nonfinite_bool_out_of_bounds_and_tiny_boxes(self):
        invalid=[None,{},dict(x=True,y=5,width=400,height=300),dict(x=float('nan'),y=5,width=400,height=300),
            dict(x=-1,y=5,width=400,height=300),dict(x=5,y=5,width=640,height=300),
            dict(x=5,y=5,width=400,height=480),dict(x=5,y=5,width=0,height=300)]
        for region in invalid:
            with self.subTest(region=region),self.assertRaises(cloud.CloudVisionError):
                self.parse(panel_document(label_region=region))

    def test_missing_region_or_unknown_fields_do_not_pass_strict_contract(self):
        document=panel_document();del document["label_region"]
        for value in (document,panel_document(extra="untrusted"),panel_document(selection_status="maybe")):
            with self.assertRaises(cloud.CloudVisionError):self.parse(value)

    def test_one_image_request_selects_scope_without_database_data_or_retry(self):
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{"OPENAI_API_KEY":"sk-test-not-a-real-key"},clear=True):
            target=Path(folder)/"image.png";Image.new("RGB",(640,480),"white").save(target)
            reply=response();reply["output"][0]["content"][0]["text"]=json.dumps(panel_document(),ensure_ascii=False)
            with patch("cloud_vision._post_response",return_value=reply) as transport:
                result=cloud.CloudVisionEngine().recognize_panel(target)
            transport.assert_called_once()
            payload=transport.call_args.args[0]
            self.assertEqual(payload["text"]["format"]["schema"],cloud.PANEL_SCHEMA)
            self.assertEqual(payload["instructions"],cloud.PANEL_INSTRUCTIONS)
            self.assertFalse(payload["store"])
            self.assertEqual(result["cloud_call_count"],1)
            self.assertEqual(result["scope_policy_version"],"main-label-v1")
            self.assertEqual(result["label_region"]["method"],"cloud_main_label_v1")

    def test_scope_rejection_retains_usage_and_does_not_make_a_second_call(self):
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{"OPENAI_API_KEY":"sk-test-not-a-real-key"},clear=True):
            target=Path(folder)/"image.png";Image.new("RGB",(640,480),"white").save(target)
            reply=response();reply["output"][0]["content"][0]["text"]=json.dumps(panel_document(selection_status="needs_crop"))
            with patch("cloud_vision._post_response",return_value=reply) as transport,self.assertRaises(cloud.CloudVisionError) as caught:
                cloud.CloudVisionEngine().recognize_panel(target)
            transport.assert_called_once()
            self.assertTrue(caught.exception.request_may_be_billed)
            self.assertEqual(caught.exception.usage["total_tokens"],3000)


if __name__=="__main__":unittest.main()
