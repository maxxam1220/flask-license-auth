"""Conservative label surface detection; keep evidence in the original coordinates."""
from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path
import tempfile

from PIL import Image, ImageDraw


def _surface_candidate(contour, gray, brightness, sx, sy, width, height):
    import cv2
    import numpy as np
    small_h, small_w = gray.shape
    area = cv2.contourArea(contour)
    if not .045 <= area / (small_w * small_h) <= .84:
        return None
    polygon = cv2.approxPolyDP(contour, .025 * cv2.arcLength(contour, True), True)
    if len(polygon) != 4 or not cv2.isContourConvex(polygon):
        return None
    rw, rh = cv2.minAreaRect(polygon)[1]
    if min(rw, rh) < 50 or max(rw, rh) / min(rw, rh) > 6 or area / max(1, rw * rh) < .78:
        return None
    interior = np.zeros(gray.shape, np.uint8)
    cv2.fillConvexPoly(interior, polygon, 255)
    dark = ((gray < min(135, brightness)) & (interior > 0)).astype(np.uint8)
    density = float(dark.sum()) / max(1, int((interior > 0).sum()))
    _, _, stats, _ = cv2.connectedComponentsWithStats(dark, 8)
    ink_components = sum(1 for stat in stats[1:] if 3 <= stat[4] <= area * .1)
    if not .015 <= density <= .55 or ink_components < 8:
        return None
    # Four-point approximation is only the shape gate. Its chords can cut
    # curved sticker edges and the first text row: keep the hull instead.
    hull = cv2.convexHull(contour)
    if cv2.contourArea(hull) / max(1, area) > 1.18:
        return None
    outline = cv2.approxPolyDP(hull, .002 * cv2.arcLength(hull, True), True)
    points = [[round(float(p[0][0]) * sx), round(float(p[0][1]) * sy)] for p in outline]
    xs, ys = zip(*points)
    x, y = max(0, min(xs)-6), max(0, min(ys)-6)
    right, bottom = min(width, max(xs)+7), min(height, max(ys)+7)
    return {"x":x, "y":y, "width":right-x, "height":bottom-y,
            "polygon":points, "method":"white_surface_v1", "auto_selected":True}


def detect_sticker(path):
    import cv2
    import numpy as np
    with Image.open(path) as original:
        width, height = original.size
        thumb = original.convert("RGB")
        thumb.thumbnail((960, 960))
        rgb = np.asarray(thumb)
        hsv = cv2.cvtColor(rgb, cv2.COLOR_RGB2HSV)
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
        small_h, small_w = gray.shape
        sx, sy = width / small_w, height / small_h
        candidates = []
        for saturation, brightness in ((30, 130), (40, 155), (40, 90)):
            mask = cv2.inRange(hsv, np.array([0, 0, brightness]), np.array([179, saturation, 255]))
            # Closing fills narrow holes in a paper surface, but can also join
            # two adjacent stickers. Keep independent, plausible surfaces from
            # the unclosed mask so a later bridge cannot turn them into one.
            raw_contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            separate = [region for contour in raw_contours if (region := _surface_candidate(
                contour, gray, brightness, sx, sy, width, height)) is not None]
            mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((5, 5), np.uint8))
            contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            for contour in contours:
                region = _surface_candidate(contour, gray, brightness, sx, sy, width, height)
                if region is None:
                    continue
                contained = [prior for prior in separate if _contained(prior, region)]
                additions = contained if len(contained) > 1 else [region]
                for addition in additions:
                    overlaps=[i for i,prior in enumerate(candidates) if _iou(addition,prior)>.60]
                    if overlaps:
                        i=overlaps[0]
                        if addition["width"]*addition["height"]>candidates[i]["width"]*candidates[i]["height"]:
                            candidates[i]=addition
                        continue
                    candidates.append(addition)
        thumb.close()
    candidates.sort(key=lambda item: item["width"]*item["height"], reverse=True)
    # Never silently choose a larger sticker when more than one is plausible.
    return {"status":"selected" if len(candidates)==1 else "multiple" if candidates else "no_clear_sticker",
            "candidates":candidates[:8], "region":candidates[0] if len(candidates)==1 else None}


def _contained(inner, outer):
    return (inner["x"] >= outer["x"]-2 and inner["y"] >= outer["y"]-2
            and inner["x"]+inner["width"] <= outer["x"]+outer["width"]+2
            and inner["y"]+inner["height"] <= outer["y"]+outer["height"]+2)


def _iou(a, b):
    overlap = max(0, min(a["x"]+a["width"], b["x"]+b["width"])-max(a["x"],b["x"])) * max(
        0, min(a["y"]+a["height"], b["y"]+b["height"])-max(a["y"],b["y"]))
    return overlap / max(1, a["width"]*a["height"] + b["width"]*b["height"] - overlap)


def translate_lines(lines, x, y):
    result = deepcopy(lines)
    for line in result:
        if line.get("box"):
            line["box"] = [[p[0]+x, p[1]+y] for p in line["box"]]
        for alternative in line.get("alternatives", []):
            if alternative.get("box"):
                alternative["box"] = [[p[0]+x, p[1]+y] for p in alternative["box"]]
    return result


@contextmanager
def _masked_region_file(path, region):
    """Use one transient, polygon-masked crop without altering the source."""
    with Image.open(path) as image:
        with image.convert("RGB") as rgb:
            crop = rgb.crop((region["x"], region["y"],
                             region["x"]+region["width"], region["y"]+region["height"]))
    try:
        with Image.new("L", crop.size) as mask, Image.new("RGB", crop.size, "white") as white:
            ImageDraw.Draw(mask).polygon(
                [(p[0]-region["x"], p[1]-region["y"]) for p in region["polygon"]], fill=255)
            white.paste(crop, mask=mask)
            with tempfile.TemporaryDirectory(prefix="label-scope-") as folder:
                target = Path(folder)/"label.png"
                white.save(target)
                yield target
    finally:
        crop.close()


def recognize_scoped(path, recognizer, scope="sticker"):
    """Keep original evidence coordinates; never make an extra OCR request.

    A provider with an explicit panel capability sees the entire original once
    so transparent printed labels are not clipped to a white barcode backing.
    Its validated region is used only for local barcode decoding. Other engines
    retain the conservative local surface detector and manual/full-image path.
    """
    from barcode_checks import decode_barcodes
    path = Path(path)
    with Image.open(path) as image:
        original_size = image.size
    # Do not probe an instance's dynamic attributes: Mock and proxy objects can
    # manufacture a callable for any name without implementing this capability.
    panel_mode = scope == "sticker" and callable(getattr(type(recognizer), "recognize_panel", None))
    if panel_mode:
        result = recognizer.recognize_panel(path)
        # The provider validates the polygon and fails closed for missing or
        # ambiguous panels. There is deliberately no second-call fallback.
        region = deepcopy(result["label_region"])
        detection = {"status":"selected", "candidates":[region], "region":region}
        with _masked_region_file(path, region) as target:
            codes = decode_barcodes(target)
        codes["items"] = translate_lines(codes["items"], region["x"], region["y"])
        result["label_region"] = region
        result["label_scope"] = detection
        result["barcodes"] = codes
        result["image_size"] = {"width":original_size[0], "height":original_size[1]}
        result.setdefault("diagnostics", {}).update(
            image_width=original_size[0], image_height=original_size[1],
            scope_width=region["width"], scope_height=region["height"])
        return result
    detection = detect_sticker(path) if scope == "sticker" else {"status":"full", "candidates":[], "region":None}
    region = detection["region"]
    if region:
        with _masked_region_file(path, region) as target:
            result = recognizer.recognize(target)
            codes = decode_barcodes(target)
        result["lines"] = translate_lines(result["lines"],region["x"],region["y"])
        codes["items"] = translate_lines(codes["items"],region["x"],region["y"])
        result["label_region"] = region
    else:
        result = recognizer.recognize(path)
        codes = decode_barcodes(path)
    result["label_scope"] = detection
    result["barcodes"] = codes
    result["image_size"] = {"width":original_size[0], "height":original_size[1]}
    diagnostics=result.setdefault("diagnostics",{})
    if region:
        diagnostics.update(processed_width=region["width"],processed_height=region["height"])
    diagnostics.update(image_width=original_size[0],image_height=original_size[1])
    return result
