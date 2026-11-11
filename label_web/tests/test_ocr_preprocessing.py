from copy import deepcopy
from types import SimpleNamespace
import unittest

import numpy as np

from ocr_engine import OCREngine, _read_lines, _needs_retry, merge_retry, prepare_small_image


def result(texts, boxes, scores=None):
    return SimpleNamespace(txts=texts, boxes=boxes, scores=scores or [.99] * len(texts))


def line(text, score=.99, box=None):
    return {"id": 0, "text": text, "score": score,
            "box": box or [[10, 10], [60, 10], [60, 30], [10, 30]]}


class FakeOCR:
    def __init__(self, image, results):
        self.image, self.results, self.calls = image, iter(results), []
        self.text_rec = SimpleNamespace(postprocess_op=SimpleNamespace(character=["±", "測", "試"]))

    def load_img(self, path):
        return self.image

    def __call__(self, image, **kwargs):
        self.calls.append((image.shape, kwargs))
        return next(self.results)


class OCRPreprocessingTests(unittest.TestCase):
    def test_small_screenshot_is_enlarged_with_bounded_resolution(self):
        original = np.zeros((480, 640, 3), dtype=np.uint8)
        image, sx, sy = prepare_small_image(original)
        self.assertEqual(image.shape, (960, 1280, 3))
        self.assertEqual((sx, sy), (2., 2.))
        self.assertEqual(original.shape, (480, 640, 3))

    def test_tiny_image_scale_is_capped_and_large_photo_is_not_copied(self):
        tiny = np.zeros((50, 200, 3), dtype=np.uint8)
        self.assertEqual(prepare_small_image(tiny)[0].shape, (100, 400, 3))
        camera = np.zeros((1800, 2400, 3), dtype=np.uint8)
        prepared, sx, sy = prepare_small_image(camera)
        self.assertIs(prepared, camera)
        self.assertEqual((sx, sy), (1., 1.))

    def test_primary_boxes_map_to_original_dimensions(self):
        raw = result(["重量200g±9g"], [[[40, 60], [240, 60], [240, 100], [40, 100]]])
        converted = _read_lines(raw, 2., 2., (480, 640))
        self.assertEqual(converted[0]["box"], [[20., 30.], [120., 30.], [120., 50.], [20., 50.]])
        self.assertEqual(converted[0]["text"], "重量200g±9g")

    def test_rotated_retry_boxes_map_back_to_original_photo(self):
        raw = result(["文字"], [[[139, 20], [179, 20], [179, 120], [139, 120]]])
        converted = _read_lines(raw, 2., 2., (100, 100), rotation=90)
        self.assertEqual(converted[0]["box"], [[10., 30.], [10., 10.], [60., 10.], [60., 30.]])

    def test_conflicting_digits_remain_visible_and_ambiguous(self):
        preferred, other = [line("200g±9g")], [line("200g+9g", .8)]
        before = deepcopy((preferred, other))
        merged = merge_retry(preferred, other)
        self.assertEqual(merged[0]["text"], "200g±9g")
        self.assertTrue(merged[0]["ambiguous"])
        self.assertEqual(merged[0]["alternatives"][0]["text"], "200g+9g")
        self.assertEqual((preferred, other), before)

    def test_retry_agreement_does_not_create_false_ambiguity(self):
        merged = merge_retry([line("日期 2026.11.12")], [line("日期2026.11.12")])
        self.assertNotIn("ambiguous", merged[0])
        self.assertEqual(merged[0]["text"], "日期 2026.11.12")

    def test_unconfirmed_new_region_is_marked_for_review(self):
        other = line("其他文字", box=[[90, 90], [130, 90], [130, 110], [90, 110]])
        merged = merge_retry([line("已辨識文字")], [other])
        self.assertEqual(len(merged), 2)
        self.assertTrue(merged[1]["ambiguous"])

    def test_retry_is_only_for_empty_sparse_or_uncertain_results(self):
        self.assertTrue(_needs_retry([]))
        self.assertTrue(_needs_retry([line("短字")]))
        self.assertTrue(_needs_retry([line("這是辨識品質不足的一段文字", .6)]))
        self.assertFalse(_needs_retry([line("這是可以直接閱讀的一段文字", .95)]))

    def test_good_primary_pass_does_not_run_extra_ocr_and_capability_is_not_warning(self):
        fake = FakeOCR(np.zeros((480, 640, 3), dtype=np.uint8),
                       [result(["這是正確可閱讀的文字"], [[[40, 60], [240, 60], [240, 100], [40, 100]]])])
        engine = OCREngine("unused-model-directory")
        engine.engine = fake
        observed = engine.recognize("photo.png")
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(observed["preprocessing"]["passes"], 1)
        self.assertEqual(observed["capabilities"]["unsupported_symbols"], ["※"])
        self.assertNotIn("warnings", observed)

    def test_sparse_retry_runs_once_and_never_copies_full_camera_size(self):
        fake = FakeOCR(np.zeros((1800, 2400, 3), dtype=np.uint8),
                       [result([], []), result(["重新辨識讀出的完整文字"], [[[10, 10], [100, 10], [100, 30], [10, 30]]])])
        engine = OCREngine("unused-model-directory")
        engine.engine = fake
        observed = engine.recognize("photo.jpg")
        self.assertEqual(len(fake.calls), 2)
        self.assertEqual(fake.calls[0][0], (1800, 2400, 3))
        self.assertEqual(fake.calls[1][0], (1280, 960, 3))
        self.assertEqual(observed["preprocessing"]["selected_rotation"], 90)
        self.assertEqual(observed["preprocessing"]["passes"], 2)
        self.assertEqual(observed["lines"][0]["text"], "重新辨識讀出的完整文字")


if __name__ == "__main__":
    unittest.main()
