from copy import deepcopy
import errno
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import numpy as np
from ocr_engine import OCREngine, retry_bold_lines
from ocr_worker import OCRMemoryLimitError
from test_ocr_preprocessing import FakeOCR, result


def line(identifier=0, text="能和脂肪", score=.89, width=145, height=57):
    y=identifier*60
    return {"id":identifier,"text":text,"score":score,"box":[[10,y],[10+width,y],[10+width,y+height],[10,y+height]]}


class OCRLineRetryTests(unittest.TestCase):
    def setUp(self):
        self.image=np.zeros((600,1200,3),dtype=np.uint8)

    def test_lower_scoring_observed_alternative_does_not_replace_original(self):
        original=[line()];before=deepcopy(original)
        engine=Mock(return_value=SimpleNamespace(txts=["飽和脂肪"],scores=[.82173]))
        observed,stats=retry_bold_lines(engine,self.image,original)
        self.assertEqual(original,before)
        self.assertEqual((observed[0]["text"],observed[0]["score"],observed[0]["box"]),(before[0]["text"],before[0]["score"],before[0]["box"]))
        self.assertTrue(observed[0]["ambiguous"])
        self.assertEqual(observed[0]["ambiguity_reason"],"line_retry_disagrees")
        self.assertEqual(observed[0]["alternatives"],[{"text":"飽和脂肪","score":.8217,"box":before[0]["box"],"method":"stroke_thin_2x2"}])
        self.assertEqual(stats["line_retry_count"],1)
        self.assertEqual(engine.call_args.kwargs,{"use_det":False,"use_cls":False,"use_rec":True})

    def test_identical_read_does_not_upgrade_score_or_create_ambiguity(self):
        engine=Mock(return_value=SimpleNamespace(txts=["能和脂肪"],scores=[.999]))
        observed,_=retry_bold_lines(engine,self.image,[line()])
        self.assertEqual(observed,[line()])

    def test_low_or_empty_alternative_is_not_added(self):
        for texts,scores in ((["其他候選"],[.64]),([""],[1.]),(None,None),(["候選"],[float("nan")])):
            observed,stats=retry_bold_lines(Mock(return_value=SimpleNamespace(txts=texts,scores=scores)),self.image,[line()])
            self.assertEqual(observed,[line()])
            self.assertEqual(stats["line_retry_count"],1)

    def test_limits_small_large_numeric_high_score_and_upscaled_crops(self):
        lines=[line(0,height=23),line(1,width=1025),line(2,width=300,height=257),line(3,text="123456789"),line(4,score=.90)]
        engine=Mock()
        observed,stats=retry_bold_lines(engine,self.image,lines)
        engine.assert_not_called();self.assertEqual(observed,lines)
        self.assertEqual(stats["line_retry_skipped_count"],3)
        retry_bold_lines(engine,self.image,[line(width=600)],scale_x=2,scale_y=2)
        engine.assert_not_called()

    def test_only_three_crops_are_processed_and_pixel_dimensions_are_bounded(self):
        engine=Mock(return_value=SimpleNamespace(txts=["能和脂肪"],scores=[.9]))
        _,stats=retry_bold_lines(engine,self.image,[line(i) for i in range(5)])
        self.assertEqual(engine.call_count,3)
        self.assertEqual(stats["line_retry_skipped_count"],2)
        for call in engine.call_args_list:
            shape=call.args[0].shape
            self.assertLessEqual(max(shape),1024);self.assertLessEqual(min(shape),256)

    def test_perspective_crop_limit_is_checked_before_allocating_pixels(self):
        original=dict(line(),box=[[0,0],[500,0],[500,400],[0,24]])
        with patch("rapidocr.utils.process_img.get_rotate_crop_image") as crop:
            _,stats=retry_bold_lines(Mock(),self.image,[original])
        crop.assert_not_called()
        self.assertEqual(stats["line_retry_skipped_count"],1)

    def test_rotation_path_and_preexisting_conflicts_are_not_reread(self):
        engine=Mock()
        _,stats=retry_bold_lines(engine,None,[line()],enabled=False)
        self.assertEqual(stats["line_retry_skipped_count"],1)
        retry_bold_lines(engine,self.image,[dict(line(),ambiguous=True)])
        engine.assert_not_called()

    def test_optional_failure_keeps_primary_but_resource_errors_propagate(self):
        engine=Mock(side_effect=RuntimeError("optional recognition failed"))
        original=[line(i) for i in range(5)]
        observed,stats=retry_bold_lines(engine,self.image,original)
        self.assertEqual(observed,original)
        self.assertEqual((stats["line_retry_count"],stats["line_retry_failure_count"],stats["line_retry_skipped_count"]),(3,3,2))
        for error in (MemoryError(),OCRMemoryLimitError("worker_budget"),OSError(errno.ENOMEM,"memory"),RuntimeError("Failed to allocate memory")):
            with self.assertRaises(type(error)):
                retry_bold_lines(Mock(side_effect=error),self.image,[line()])

    def test_engine_integration_preserves_raw_and_counts_actual_local_retry(self):
        raw=line(text="這次能和脂肪文字辨識",height=30)
        fake=FakeOCR(np.zeros((800,1600,3),dtype=np.uint8),[result([raw["text"]],[raw["box"]],[.89]),
            SimpleNamespace(txts=["這次飽和脂肪文字辨識"],scores=[.82])])
        engine=OCREngine("unused-model-directory");engine.engine=fake
        observed=engine.recognize("photo.jpg")
        self.assertEqual(len(fake.calls),2)
        self.assertEqual(observed["preprocessing"]["passes"],1)
        self.assertEqual(observed["diagnostics"]["line_retry_count"],1)
        self.assertEqual(observed["diagnostics"]["ambiguous_line_count"],1)
        self.assertEqual(observed["lines"][0]["text"],raw["text"])


if __name__=="__main__":
    unittest.main()
