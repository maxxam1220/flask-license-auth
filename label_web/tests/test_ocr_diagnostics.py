from copy import deepcopy
import unittest
import numpy as np

from ocr_engine import OCREngine, recognition_diagnostics
from test_ocr_preprocessing import FakeOCR, line, result


class OCRDiagnosticsTests(unittest.TestCase):
    def test_counts_actual_original_pixel_boxes_without_mutating_evidence(self):
        lines = [line("可能錯讀但分數高", .99), line("低分原文", .64, [[0,0],[100,0],[100,8],[0,8]]),
                 dict(line("有不同候選", .65, [[0,0],[10,0],[10,80],[0,80]]), ambiguous=True),
                 line("零面積框", .7, [[0,0],[0,0],[0,0],[0,0]])]
        before = deepcopy(lines)
        metadata = recognition_diagnostics(lines, (480, 640), rotation_retry_count=1)
        self.assertEqual(metadata, {"image_width":640,"image_height":480,"line_count":4,
            "low_score_count":1,"low_score_threshold":.65,"small_text_line_count":2,
            "small_text_height_threshold_px":12,"ambiguous_line_count":1,"line_retry_count":0,"rotation_retry_count":1,
            "line_retry_failure_count":0,"line_retry_skipped_count":0})
        self.assertEqual(lines, before)
        self.assertNotIn("accuracy", metadata)
        self.assertNotIn("correct", metadata)

    def test_empty_photo_result_has_zero_counts_and_keeps_dimensions(self):
        metadata = recognition_diagnostics([], (2400, 1350))
        self.assertEqual((metadata["image_width"],metadata["image_height"]), (1350,2400))
        for key in ("line_count","low_score_count","small_text_line_count","ambiguous_line_count","line_retry_count","rotation_retry_count"):
            self.assertEqual(metadata[key],0)

    def test_engine_uses_original_size_and_records_only_ocr_work_actually_run(self):
        fake = FakeOCR(np.zeros((240,320,3),dtype=np.uint8),
            [result(["這是一段足夠完整的辨識文字"], [[[20,20],[220,20],[220,40],[20,40]]])])
        engine=OCREngine("unused-model-directory");engine.engine=fake
        observed=engine.recognize("photo.png")
        self.assertEqual(observed["diagnostics"]["image_width"],320)
        self.assertEqual(observed["diagnostics"]["small_text_line_count"],1)
        self.assertEqual(observed["diagnostics"]["line_retry_count"],0)
        self.assertEqual(observed["diagnostics"]["rotation_retry_count"],0)
        self.assertEqual(len(fake.calls),1)


if __name__=="__main__":
    unittest.main()
