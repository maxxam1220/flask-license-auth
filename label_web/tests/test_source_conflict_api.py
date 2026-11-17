"""A stale selection is not evidence that a different product is misprinted."""
from copy import deepcopy
from unittest.mock import patch
import unittest

from corrections import build_revision
from inspection_evidence import augment
from standard_draft_quality import eligibility
import test_api


class SourceConflictAPITests(unittest.TestCase):
    setUp = test_api.APITests.setUp
    tearDown = test_api.APITests.tearDown
    photo = test_api.APITests.photo
    job = test_api.APITests.job

    def test_conflicting_selection_blocks_standard_checks_and_rechecks_without_ocr(self):
        conflict = {"status":"source_conflict", "code":"", "name":"", "source":None,
            "reason":"照片品名與指定標準不同，請重新選擇。",
            "selected_source":{"code":"papaya", "name":"蜜香木瓜切片55元", "source_kind":"manual"},
            "identity_evidence":[{"field":"product", "actual":"雙拼水果盒89元", "expected":"蜜香木瓜切片55元", "line_ids":[0]}],
            "candidates":[]}
        with patch("server.label_source.resolve", return_value=conflict):
            job = self.job("recognition", source_code="papaya")
        identifier = job["result"]["inspection_id"]
        original = self.client.get("/api/inspections/"+identifier).json
        result = original["result"]
        self.assertIsNone(original["template_snapshot"]["source"])
        self.assertEqual(result["source_match"]["status"], "source_conflict")
        self.assertFalse(any(c.get("source")=="database" for c in result["checks"]))
        self.assertEqual(sum(c["key"]=="source_identity_conflict" for c in result["checks"]), 1)
        self.assertEqual(result["status"], "review")
        repeated=deepcopy(result);augment(repeated, original["ocr"])
        self.assertEqual(sum(c["key"]=="source_identity_conflict" for c in repeated["checks"]), 1)
        self.assertFalse(eligibility(original["ocr"], result=result)["eligible"])
        revised=build_revision(original,None,{"operation":"replace", "kind":"ocr_misread", "line_id":0,
            "text":original["ocr"]["lines"][0]["text"], "reviewer":"QA", "note":"原圖確認"}, "2026-11-17T00:00:00Z")
        self.assertTrue(any(c["key"]=="source_identity_conflict" for c in revised["result"]["checks"]))
        with patch.object(test_api.FakeOCR,"recognize",side_effect=AssertionError("must reuse OCR")), \
                patch("server.label_source.resolve",return_value={"status":"unmatched", "source":None, "candidates":[]}) as resolver:
            response=self.client.post(f"/api/inspections/{identifier}/recheck",json={"source_code":"", "base_date":"2026-11-10"},headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        self.assertEqual(resolver.call_args.args[2], "")
        fresh=self.client.get("/api/inspections/"+response.json["inspection_id"]).json
        self.assertFalse(any(c["key"]=="source_identity_conflict" for c in fresh["result"]["checks"]))
        self.assertEqual(fresh["ocr"], original["ocr"])
        self.assertEqual(self.client.get("/api/inspections/"+identifier).json["result"], result)


if __name__=="__main__":
    unittest.main()
