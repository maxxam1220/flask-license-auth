"""Actual surface-detection regressions; fixtures contain no customer photos."""
from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from PIL import Image, ImageDraw, ImageEnhance

from sticker_scope import detect_sticker, recognize_scoped


def paper(image, box, brightness=235, rounded=False):
    draw = ImageDraw.Draw(image)
    if rounded:
        draw.rounded_rectangle(box, radius=28, fill=(brightness,)*3)
    else:
        draw.rectangle(box, fill=(brightness,)*3)
    x, y, right, bottom = box
    # Independent ink marks exercise the text-density gate without depending
    # on platform fonts, OCR models, or fixed reference answers.
    for row in range(4):
        for column in range(12):
            left = x+18+column*max(10, (right-x-50)//12)
            top = y+18+row*max(16, (bottom-y-45)//4)
            draw.rectangle((left, top, left+max(7,(right-x)//75), top+max(9,(bottom-y)//30)), fill=(15,)*3)
    return image


class StickerScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def save(self, image, name="photo.png"):
        path = self.folder/name
        image.save(path)
        self.addCleanup(image.close)
        return path

    def blank(self, size=(800,600)):
        return Image.new("RGB", size, (20,80,130))

    def test_two_distinct_stickers_are_never_selected_by_size(self):
        image = self.blank((1000,700))
        paper(image, (50,100,640,450))
        paper(image, (720,300,940,500))
        result = detect_sticker(self.save(image))
        self.assertEqual(result["status"], "multiple")
        self.assertIsNone(result["region"])
        self.assertGreaterEqual(len(result["candidates"]), 2)

    def test_closing_must_not_join_adjacent_papers_across_narrow_gap(self):
        for gap in (2, 4, 6, 30):
            with self.subTest(gap=gap):
                image = self.blank()
                paper(image, (80,150,360,420))
                paper(image, (360+gap,150,640+gap,420))
                result = detect_sticker(self.save(image, f"gap-{gap}.png"))
                self.assertEqual(result["status"], "multiple")
                self.assertIsNone(result["region"])
                self.assertGreaterEqual(len(result["candidates"]), 2)
                self.assertTrue(all(row["width"] < 400 for row in result["candidates"]), result)

    def test_two_papers_with_different_lighting_remain_multiple(self):
        image = self.blank()
        paper(image, (60,120,340,420), brightness=235)
        paper(image, (430,120,710,420), brightness=110)
        result = detect_sticker(self.save(image))
        self.assertEqual(result["status"], "multiple")
        self.assertIsNone(result["region"])

    def test_single_paper_light_changes_preserve_original_bounds(self):
        original = paper(self.blank(), (100,150,700,450), rounded=True)
        self.addCleanup(original.close)
        regions = []
        for factor in (.55, .8, 1., 1.2):
            image = ImageEnhance.Brightness(original).enhance(factor)
            result = detect_sticker(self.save(image, f"light-{factor}.png"))
            self.assertEqual(result["status"], "selected", (factor, result))
            regions.append(result["region"])
        expected = {key: regions[0][key] for key in ("x","y","width","height")}
        self.assertTrue(all({key: row[key] for key in expected} == expected for row in regions))

    def test_no_text_or_no_bright_surface_returns_no_automatic_region(self):
        blank_paper = self.blank()
        ImageDraw.Draw(blank_paper).rectangle((100,150,700,450), fill="white")
        dim_paper = paper(self.blank(), (100,150,700,450), brightness=70)
        images = [Image.new("RGB", (800,600), "white"), self.blank(), blank_paper, dim_paper]
        for index, image in enumerate(images):
            with self.subTest(index=index):
                result = detect_sticker(self.save(image, f"none-{index}.png"))
                self.assertEqual(result["status"], "no_clear_sticker")
                self.assertIsNone(result["region"])

    def test_downsampled_detection_returns_bounded_original_coordinates(self):
        path = self.save(paper(self.blank((1501,1003)), (100,120,1300,830)))
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        result = detect_sticker(path)
        self.assertEqual(result["status"], "selected")
        region = result["region"]
        self.assertLessEqual(region["x"], 105)
        self.assertLessEqual(region["y"], 125)
        self.assertGreaterEqual(region["x"]+region["width"], 1295)
        self.assertGreaterEqual(region["y"]+region["height"], 825)
        for x, y in region["polygon"]:
            self.assertTrue(0 <= x < 1501 and 0 <= y < 1003)
            self.assertTrue(region["x"] <= x < region["x"]+region["width"])
            self.assertTrue(region["y"] <= y < region["y"]+region["height"])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_actual_detected_crop_keeps_ink_and_does_not_modify_original(self):
        path = self.save(paper(self.blank(), (100,150,700,450), rounded=True))
        original_bytes = path.read_bytes()
        selected = detect_sticker(path)["region"]
        seen = {}
        def recognize(target):
            seen["path"] = Path(target)
            with Image.open(target) as crop:
                seen["size"] = crop.size
                seen["first_ink"] = crop.getpixel((120-selected["x"],170-selected["y"]))
                seen["corner"] = crop.getpixel((0,0))
            return {"lines": [], "engine": "offline fixture", "diagnostics": {}}
        recognizer = Mock()
        recognizer.recognize.side_effect = recognize
        with patch("barcode_checks.decode_barcodes", return_value={"state":"none", "items":[]}):
            result = recognize_scoped(path, recognizer)
        self.assertEqual(path.read_bytes(), original_bytes)
        self.assertFalse(seen["path"].exists())  # Transient crop is removed.
        self.assertEqual(seen["first_ink"], (15,15,15))
        self.assertEqual(seen["corner"], (255,255,255))
        self.assertEqual(result["image_size"], {"width":800, "height":600})
        self.assertEqual(seen["size"], (selected["width"],selected["height"]))

    def test_no_surface_fallback_and_explicit_full_use_unchanged_original(self):
        path = self.save(self.blank())
        original_bytes = path.read_bytes()
        observed = {"id":0, "text":"observed only", "score":.9, "box":[[10,20],[80,20],[80,40],[10,40]]}
        for mode in ("sticker", "full"):
            recognizer = Mock()
            recognizer.recognize.return_value = {"lines":[deepcopy(observed)], "engine":"offline fixture"}
            with patch("barcode_checks.decode_barcodes", return_value={"state":"none", "items":[]}):
                result = recognize_scoped(path, recognizer, mode)
            self.assertEqual(Path(recognizer.recognize.call_args.args[0]), path)
            self.assertEqual(result["lines"], [observed])
            self.assertEqual(result["label_scope"]["status"], "no_clear_sticker" if mode == "sticker" else "full")
            self.assertNotIn("label_region", result)
            self.assertEqual(path.read_bytes(), original_bytes)


class PanelRecognizer:
    """Class-level capability, unlike a dynamic Mock attribute."""
    def __init__(self, result):
        self.result = result
        self.panel_calls = []
        self.full_calls = []

    def recognize_panel(self, path):
        self.panel_calls.append(Path(path))
        return deepcopy(self.result)

    def recognize(self, path):
        self.full_calls.append(Path(path))
        return deepcopy(self.result)


class CloudPanelScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.path = self.folder/"transparent-pack.png"
        # Synthetic transparent panel, separate white barcode backing and a
        # lower advertising strip. No customer image or fixed product text.
        with Image.new("RGB", (800, 700), (150, 90, 70)) as photo:
            draw = ImageDraw.Draw(photo)
            draw.rectangle((430, 290, 690, 370), fill="white")
            draw.rectangle((0, 520, 799, 699), fill=(220, 20, 30))
            draw.rectangle((130, 150, 140, 160), fill="black")
            photo.save(self.path)
        self.region = {"x":100, "y":100, "width":600, "height":300,
                       "polygon":[[110,100],[700,100],[700,400],[100,400],[100,110]],
                       "method":"cloud_panel_v1", "auto_selected":True}
        self.observed = [
            {"id":0,"text":"營養標示","score":1.,"score_kind":"uncertainty_gate",
             "confidence":None,"box":[[120,130],[280,130],[280,160],[120,160]]},
            {"id":1,"text":"製造日期：2026.11.16","score":1.,
             "box":[[440,250],[680,250],[680,280],[440,280]],
             "alternatives":[{"text":"2026.11.18","box":[[440,250],[680,250],[680,280],[440,280]]}]},
        ]
        self.payload = {"lines":deepcopy(self.observed),"label_region":deepcopy(self.region),
                        "engine":"offline cloud fixture","usage":{"input_tokens":321},
                        "diagnostics":{"processed_width":800,"processed_height":700}}
        self.codes = {"state":"decoded","items":[{"text":"12345678","format":"Code128",
                       "box":[[340,190],[570,190],[570,270],[340,270]]}]}

    def test_panel_uses_original_once_and_keeps_nutrition_date_coordinates(self):
        recognizer = PanelRecognizer(self.payload)
        before = self.path.read_bytes()
        seen = {}
        def decode(target):
            seen["path"] = Path(target)
            with Image.open(target) as crop:
                seen["size"] = crop.size
                seen["nutrition_ink"] = crop.getpixel((35,55))
                seen["corner"] = crop.getpixel((0,0))
                self.assertNotEqual(crop.getpixel((300,299)), (220,20,30))
            return deepcopy(self.codes)
        with patch("sticker_scope.detect_sticker", side_effect=AssertionError("must not pre-crop")), \
             patch("barcode_checks.decode_barcodes", side_effect=decode) as decode_mock:
            result = recognize_scoped(self.path, recognizer)
        self.assertEqual(recognizer.panel_calls, [self.path])
        self.assertEqual(recognizer.full_calls, [])
        self.assertEqual(decode_mock.call_count, 1)
        self.assertEqual(result["lines"], self.observed)
        self.assertEqual(result["usage"], {"input_tokens":321})
        self.assertEqual(result["label_scope"], {"status":"selected","region":self.region,"candidates":[self.region]})
        self.assertEqual(result["image_size"], {"width":800,"height":700})
        self.assertEqual(result["diagnostics"]["processed_width"], 800)
        self.assertEqual(result["diagnostics"]["scope_width"], 600)
        self.assertEqual(seen["size"], (600,300))
        self.assertEqual(seen["nutrition_ink"], (0,0,0))
        self.assertEqual(seen["corner"], (255,255,255))
        self.assertEqual(result["barcodes"]["items"][0]["box"],
                         [[440,290],[670,290],[670,370],[440,370]])
        self.assertEqual(self.codes["items"][0]["box"][0], [340,190])
        self.assertFalse(seen["path"].exists())
        self.assertFalse(seen["path"].parent.exists())
        self.assertEqual(self.path.read_bytes(), before)

    def test_full_mode_uses_full_recognition_and_decodes_original(self):
        self.payload.pop("label_region")
        self.payload["lines"].append({"id":2,"text":"包材廣告","box":[[20,550],[300,550],[300,590],[20,590]]})
        recognizer = PanelRecognizer(self.payload)
        with patch("sticker_scope.detect_sticker", side_effect=AssertionError("full mode")), \
             patch("barcode_checks.decode_barcodes", return_value=deepcopy(self.codes)) as decode:
            result = recognize_scoped(self.path, recognizer, "full")
        self.assertEqual(recognizer.panel_calls, [])
        self.assertEqual(recognizer.full_calls, [self.path])
        self.assertEqual(Path(decode.call_args.args[0]), self.path)
        self.assertEqual(result["lines"], self.payload["lines"])
        self.assertEqual(result["barcodes"], self.codes)
        self.assertEqual(result["label_scope"]["status"], "full")
        self.assertNotIn("label_region", result)

    def test_cloud_failure_never_retries_with_full_or_local_crop(self):
        recognizer = PanelRecognizer(self.payload)
        error = RuntimeError("ambiguous panel")
        with patch.object(PanelRecognizer, "recognize_panel", side_effect=error) as panel, \
             patch("sticker_scope.detect_sticker") as detect, \
             patch("barcode_checks.decode_barcodes") as decode:
            with self.assertRaisesRegex(RuntimeError, "ambiguous panel"):
                recognize_scoped(self.path, recognizer)
        self.assertEqual(panel.call_count, 1)
        self.assertEqual(recognizer.full_calls, [])
        detect.assert_not_called()
        decode.assert_not_called()

    def test_barcode_failure_still_cleans_transient_crop_without_repeating_ocr(self):
        recognizer = PanelRecognizer(self.payload)
        seen = []
        def failed_decode(target):
            seen.append(Path(target))
            self.assertTrue(Path(target).is_file())
            raise RuntimeError("local decoder failure")
        with patch("barcode_checks.decode_barcodes", side_effect=failed_decode):
            with self.assertRaisesRegex(RuntimeError, "local decoder failure"):
                recognize_scoped(self.path, recognizer)
        self.assertEqual(recognizer.panel_calls, [self.path])
        self.assertEqual(recognizer.full_calls, [])
        self.assertFalse(seen[0].exists())
        self.assertFalse(seen[0].parent.exists())
        self.assertTrue(self.path.is_file())

    def test_dynamic_mock_attribute_is_not_a_panel_capability(self):
        recognizer = Mock()
        recognizer.recognize_panel.return_value = deepcopy(self.payload)
        recognizer.recognize.return_value = {"lines":[],"engine":"ordinary local"}
        with patch("sticker_scope.detect_sticker", return_value={"status":"no_clear_sticker","region":None,"candidates":[]}), \
             patch("barcode_checks.decode_barcodes", return_value={"state":"none","items":[]}):
            result = recognize_scoped(self.path, recognizer)
        recognizer.recognize_panel.assert_not_called()
        recognizer.recognize.assert_called_once_with(self.path)
        self.assertEqual(result["label_scope"]["status"], "no_clear_sticker")


if __name__ == "__main__":
    unittest.main()
