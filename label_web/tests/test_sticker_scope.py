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


if __name__ == "__main__":
    unittest.main()
