"""Choose isolated date crops and reconcile a blind second transcription with the first."""
from collections import Counter
from copy import deepcopy
import math
import re
from statistics import median

from label_geometry import (analyze_label_scope, bounds, date_observations, date_segments,
                            short_date_format_hint, short_date_ink)
from validation import parse_date


MISSING_INK = frozenset("□▢�？?…")
DATE_LIKE = re.compile(r"(?:民國\s*)?[0-9０-９OoIl□�]{3,4}\s*[年./．／－-]")


def _uncertain(line):
    return bool(line.get("uncertain") or line.get("ambiguous") or line.get("alternatives"))


def _complete_date(value):
    if MISSING_INK.intersection(value):
        return False
    if not DATE_LIKE.match(value):
        return short_date_ink(value) is not None
    try:
        parse_date(value)
    except (TypeError, ValueError):
        return False
    return True


def _isolated_crop(evidence, lines, size):
    width, height = size
    areas = [bounds(line) for line in evidence]
    if not all(areas):
        return None
    left = min(area[0] for area in areas)
    top = min(area[1] for area in areas)
    right = max(area[2] for area in areas)
    bottom = max(area[3] for area in areas)
    if (left < 0 or top < 0 or right > width or bottom > height
            or (right - left) * (bottom - top) > width * height * .5):
        return None
    # Use the line height rather than the photo size, including on tightly
    # spaced labels. Keep the entire target ink inside its original coordinates.
    line_height = median(area[3] - area[1] for area in areas)
    margin = max(2, line_height * .32)
    x0, y0 = max(0, left - margin), max(0, top - margin)
    x1, y1 = min(width, right + margin), min(height, bottom + margin)
    ids = {line["id"] for line in evidence}
    for other in lines:
        if other["id"] in ids or not other["text"].strip():
            continue
        area = bounds(other)
        if not area:
            continue
        x, y, r, b = area
        if r <= x0 or x >= x1 or b <= y0 or y >= y1:
            continue
        if b <= top:
            y0 = max(y0, b)
        elif y >= bottom:
            y1 = min(y1, y)
        elif r <= left:
            x0 = max(x0, r)
        elif x >= right:
            x1 = min(x1, x)
        else:
            # A different physical line intersects the box. Do not have a
            # model guess which of the visible fields was intended.
            return None
    return [math.floor(x0), math.floor(y0), math.ceil(x1), math.ceil(y1)]


def select_date_targets(lines, image_size):
    """Return up to three uniquely attributable printed dates in original-image pixels."""
    if (not lines or len(image_size) != 2 or any(type(n) is not int or n <= 0 for n in image_size)
            or not any(_uncertain(line) for line in lines) or analyze_label_scope(lines)["blocked"]):
        return []
    observations = date_observations(lines)
    kinds = Counter(item["kind"] for item in observations)
    uses = Counter(line["id"] for item in observations for line in item["lines"])
    targets = []
    for item in observations:
        evidence, kind = item["lines"], item["kind"]
        if (item["ambiguous"] or kinds[kind] != 1 or not (DATE_LIKE.match(item["value"]) or short_date_format_hint(item["value"]))
                or any(uses[line["id"]] != 1 for line in evidence)
                or not any(_uncertain(line) for line in evidence)):
            continue
        if any(line.get("human_verified") or line.get("human_uncertain") or line.get("suspected_typo")
               or line.get("typo_candidates") or line.get("date_retry") for line in evidence):
            continue
        # In particular, never crop an entire shared date/barcode row and then
        # accept a transcription of the date alone as verification of that row.
        spans = {span["line_id"]: span for span in item["evidence_spans"]}
        if any(line["text"][:spans[line["id"]]["start"]].strip()
               or line["text"][spans[line["id"]]["end"]:].strip() for line in evidence):
            continue
        crop = _isolated_crop(evidence, lines, image_size)
        if crop:
            targets.append({"target_id": f"date-{len(targets) + 1}", "kind": kind,
                            "line_ids": [line["id"] for line in evidence], "crop_box": crop})
    return targets


def crop_date_image(image, target):
    """Crop the EXIF-oriented source at native resolution, with no overlays or labels."""
    left, top, right, bottom = target["crop_box"]
    if not (0 <= left < right <= image.width and 0 <= top < bottom <= image.height):
        raise ValueError("Date crop outside source image")
    return image.crop((left, top, right, bottom))


def _ink(text):
    # OCR may reflow a heading and its value or add spaces next to punctuation.
    # A space between digits can distinguish the day from an annotation or hour.
    spaced = " ".join(text.split())
    return re.sub(r"(?<!\d) | (?!\d)", "", spaced)


def _alternatives(line, reading):
    choices = deepcopy(line.get("alternatives") or [])
    seen = {line["text"], *(choice["text"] for choice in choices)}
    for text in [reading["text"], *reading["alternatives"]]:
        if text.strip() and text not in seen:
            choices.append({"text": text, "box": deepcopy(line["box"]), "score": 0.,
                            "score_kind": "uncertainty_gate", "confidence": None, "method": "cloud_date_retry"})
            seen.add(text)
    return choices


def merge_date_readings(lines, targets, readings):
    """Return new OCR evidence. A second reading can confirm, never replace, original ink."""
    merged = deepcopy(lines)
    by_line = {line["id"]: line for line in merged}
    by_target = {reading["target_id"]: reading for reading in readings}
    if len(by_target) != len(readings) or set(by_target) != {target["target_id"] for target in targets}:
        return merged
    for target in targets:
        group = [by_line[identifier] for identifier in target["line_ids"]]
        reading = by_target[target["target_id"]]
        observed = " ".join(line["text"] for line in group)
        segments = date_segments({"text": observed})
        complete = len(segments) == 1 and _complete_date(segments[0]["value"])
        if (reading["uncertain"] or reading["alternatives"] or not reading["text"].strip()
                or MISSING_INK.intersection(reading["text"])):
            status = "uncertain"
        elif _ink(reading["text"]) == _ink(observed):
            status = "confirmed" if complete else "uncertain"
        else:
            status = "disagrees"
        for line in group:
            first = deepcopy(line)
            line["date_retry"] = {**deepcopy(target), "status": status, "first": first,
                                  "reading": deepcopy(reading)}
            if status == "confirmed":
                line.update(score=1., uncertain=False, ambiguous=False)
                line.pop("ambiguity_reason", None)
                line.pop("alternatives", None)
            else:
                line.update(score=0., uncertain=True, ambiguous=True, ambiguity_reason="cloud_date_retry_" + status)
                if len(group) == 1:
                    choices = _alternatives(first, reading)
                    if choices:
                        line["alternatives"] = choices
    return merged
