"""Local OCR: preserve the printed characters; never spell-correct the evidence."""
from pathlib import Path
import threading
import time


class OCREngine:
    def __init__(self, model_dir):
        self.model_dir = Path(model_dir)
        self.lock = threading.Lock()
        self.engine = None

    def recognize(self, image_path):
        with self.lock:
            if self.engine is None:
                from rapidocr import RapidOCR, EngineType, LangDet, LangRec, ModelType, OCRVersion
                self.model_dir.mkdir(parents=True, exist_ok=True)
                self.engine = RapidOCR(params={
                    "Global.model_root_dir": str(self.model_dir),
                    "Global.text_score": 0.35,
                    "Global.max_side_len": 2400,
                    "Global.log_level": "warning",
                    "EngineConfig.onnxruntime.intra_op_num_threads": 2,
                    "EngineConfig.onnxruntime.inter_op_num_threads": 1,
                    "Det.engine_type": EngineType.ONNXRUNTIME,
                    "Det.lang_type": LangDet.CH,
                    "Det.model_type": ModelType.MOBILE,
                    "Det.ocr_version": OCRVersion.PPOCRV5,
                    "Det.limit_side_len": 1280,
                    "Det.limit_type": "max",
                    "Rec.engine_type": EngineType.ONNXRUNTIME,
                    "Rec.lang_type": LangRec.CH,
                    "Rec.model_type": ModelType.SERVER,
                    "Rec.ocr_version": OCRVersion.PPOCRV5,
                })
            start = time.monotonic()
            result = self.engine(str(image_path))
            lines = []
            if result.txts is not None:
                for i, (text, score, box) in enumerate(zip(result.txts, result.scores, result.boxes)):
                    lines.append({"id": i, "text": str(text), "score": round(float(score), 4),
                                  "box": [[round(float(x), 1), round(float(y), 1)] for x, y in box]})
            return {"lines": lines, "engine": "RapidOCR 3.10 / PP-OCRv5 mobile-det + server-rec",
                    "elapsed": round(time.monotonic() - start, 2)}


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--output")
    args = parser.parse_args()
    result = OCREngine(Path(__file__).parent / "models").recognize(args.image)
    encoded = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(encoded, encoding="utf-8")
    print(encoded)
