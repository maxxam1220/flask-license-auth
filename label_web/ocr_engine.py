"""Local OCR: preserve the printed characters; never spell-correct the evidence."""
from pathlib import Path
import re
import threading
import time


def prepare_small_image(image):
    """Give small printed glyphs enough detector pixels without enlarging camera photos."""
    import cv2
    height, width = image.shape[:2]
    if not height or not width:
        raise ValueError("Empty OCR image")
    scale = min(2., 1280. / max(height, width))
    if scale <= 1.:
        return image, 1., 1.
    target_width, target_height = round(width * scale), round(height * scale)
    enlarged = cv2.resize(image, (target_width, target_height), interpolation=cv2.INTER_CUBIC)
    return enlarged, target_width / width, target_height / height


def _read_lines(result, scale_x, scale_y, original_shape, rotation=0):
    """Return all boxes in the stored photo's coordinates, including a rotated retry."""
    lines = []
    original_height, original_width = original_shape
    prepared_height = round(original_height * scale_y)
    if result.txts is None or result.boxes is None:
        return lines
    for text, score, box in zip(result.txts, result.scores, result.boxes):
        points = []
        for x, y in box:
            if rotation == 90:
                x, y = y, prepared_height - 1 - x
            points.append([round(max(0., min(float(x) / scale_x, original_width)), 1),
                           round(max(0., min(float(y) / scale_y, original_height)), 1)])
        lines.append({"id": len(lines), "text": str(text), "score": round(float(score), 4), "box": points})
    return lines


def _quality(lines):
    lengths = [len(re.sub(r"\s+", "", line["text"])) for line in lines]
    count = sum(lengths)
    confident = sum(length for line, length in zip(lines, lengths) if line["score"] >= .75)
    average = sum(line["score"] * length for line, length in zip(lines, lengths)) / max(count, 1)
    return confident, average, count


def _needs_retry(lines):
    _, average, count = _quality(lines)
    return count < 8 or average < .72


def _overlap(first, second):
    def bounds(box):
        return min(p[0] for p in box), min(p[1] for p in box), max(p[0] for p in box), max(p[1] for p in box)
    ax, ay, ar, ab = bounds(first["box"])
    bx, by, br, bb = bounds(second["box"])
    area = max(0, min(ar, br) - max(ax, bx)) * max(0, min(ab, bb) - max(ay, by))
    return area / max(1., min((ar - ax) * (ab - ay), (br - bx) * (bb - by)))


def merge_retry(preferred, other):
    """Keep conflicting observed text visible instead of choosing with expected label data."""
    merged = [dict(line) for line in preferred]
    for candidate in other:
        overlaps = [(index, _overlap(line, candidate)) for index, line in enumerate(merged)]
        overlaps = [item for item in overlaps if item[1] >= .65]
        if overlaps:
            index = max(overlaps, key=lambda item: item[1])[0]
            line = merged[index]
            if re.sub(r"\s+", "", line["text"]) != re.sub(r"\s+", "", candidate["text"]):
                line["ambiguous"] = True
                line["ambiguity_reason"] = "rotation_retry_disagrees"
                line.setdefault("alternatives", []).append({key: candidate[key] for key in ("text", "score", "box")})
        elif candidate["score"] >= .85 and len(candidate["text"].strip()) >= 3:
            merged.append(dict(candidate, ambiguous=True, ambiguity_reason="unconfirmed_retry_region"))
    merged.sort(key=lambda line: (min(p[1] for p in line["box"]), min(p[0] for p in line["box"])))
    for index, line in enumerate(merged):
        line["id"] = index
    return merged


class OCREngine:
    def __init__(self, model_dir):
        self.model_dir = Path(model_dir)
        self.lock = threading.Lock()
        self.engine = None

    def recognize(self, image_path):
        with self.lock:
            if self.engine is None:
                import cv2
                from rapidocr import RapidOCR, EngineType, LangDet, LangRec, ModelType, OCRVersion
                cv2.setNumThreads(1)
                self.model_dir.mkdir(parents=True, exist_ok=True)
                self.engine = RapidOCR(params={
                    "Global.model_root_dir": str(self.model_dir),
                    "Global.text_score": 0.35,
                    "Global.max_side_len": 2400,
                    "Global.log_level": "warning",
                    "EngineConfig.onnxruntime.intra_op_num_threads": 2,
                    "EngineConfig.onnxruntime.inter_op_num_threads": 1,
                    "EngineConfig.onnxruntime.enable_cpu_mem_arena": False,
                    "Cls.cls_batch_num": 1,
                    "Det.engine_type": EngineType.ONNXRUNTIME,
                    "Det.lang_type": LangDet.CH,
                    "Det.model_type": ModelType.SMALL,
                    "Det.ocr_version": OCRVersion.PPOCRV6,
                    "Det.limit_side_len": 1280,
                    "Det.limit_type": "max",
                    "Rec.engine_type": EngineType.ONNXRUNTIME,
                    "Rec.lang_type": LangRec.CH,
                    "Rec.model_type": ModelType.MEDIUM,
                    "Rec.ocr_version": OCRVersion.PPOCRV6,
                    "Rec.rec_batch_num": 1,
                })
            import cv2
            start = time.monotonic()
            # Use RapidOCR's existing EXIF/alpha/color loader, then pass a BGR array.
            original = self.engine.load_img(str(image_path))
            original_shape = original.shape[:2]
            prepared, scale_x, scale_y = prepare_small_image(original)
            del original
            result = self.engine(prepared, use_det=True, use_cls=True, use_rec=True)
            lines = _read_lines(result, scale_x, scale_y, original_shape)
            del result
            passes, rotation = 1, 0
            if _needs_retry(lines):
                retry_source, retry_x, retry_y = prepared, scale_x, scale_y
                height, width = prepared.shape[:2]
                if max(height, width) > 1280:
                    factor = 1280. / max(height, width)
                    new_width, new_height = round(width * factor), round(height * factor)
                    retry_source = cv2.resize(prepared, (new_width, new_height), interpolation=cv2.INTER_AREA)
                    retry_x *= new_width / width
                    retry_y *= new_height / height
                rotated = cv2.rotate(retry_source, cv2.ROTATE_90_CLOCKWISE)
                del retry_source, prepared
                retry_result = self.engine(rotated, use_det=True, use_cls=True, use_rec=True)
                retry = _read_lines(retry_result, retry_x, retry_y, original_shape, rotation=90)
                del retry_result, rotated
                passes = 2
                if _quality(retry) > _quality(lines):
                    lines, rotation = merge_retry(retry, lines), 90
                else:
                    lines = merge_retry(lines, retry)
            characters = set(self.engine.text_rec.postprocess_op.character) if self.engine.text_rec is not None else set()
            return {"lines": lines, "engine": "RapidOCR 3.10 / PP-OCRv6 small-det + medium-rec",
                    "preprocessing": {"scale_x": round(scale_x, 4), "scale_y": round(scale_y, 4),
                                      "passes": passes, "selected_rotation": rotation},
                    "capabilities": {
                        "unsupported_symbols": [symbol for symbol in ("※",) if characters and symbol not in characters],
                        # A supported dictionary entry can still be missed in context.
                        # Validation uses this only for an observed matching discrepancy.
                        "known_weak_symbols": [symbol for symbol in ("※",) if symbol in characters],
                    },
                    "elapsed": round(time.monotonic() - start, 2)}


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--output")
    parser.add_argument("--model-dir", default=str(Path(__file__).parent / "models"))
    args = parser.parse_args()
    result = OCREngine(Path(args.model_dir)).recognize(args.image)
    # Operational evidence for the one-shot Linux worker, not an OCR confidence score.
    try:
        import resource
        result["worker_peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    except ImportError:
        pass
    encoded = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded)
