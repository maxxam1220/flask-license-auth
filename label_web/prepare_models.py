"""Download and exercise OCR models at build time, without connecting to the database."""
from pathlib import Path
from tempfile import TemporaryDirectory
from PIL import Image, ImageDraw
from ocr_engine import OCREngine

if __name__ == "__main__":
    with TemporaryDirectory() as folder:
        path = Path(folder) / "build-check.png"
        image = Image.new("RGB", (800, 200), "white")
        ImageDraw.Draw(image).text((30, 50), "MODEL BUILD CHECK 2026", fill="black", font_size=36)
        image.save(path)
        result = OCREngine(Path(__file__).parent / "models").recognize(path)
        if not result["lines"]:
            raise SystemExit("OCR model build check did not recognize its fixture")
        print("OCR models downloaded and inference verified.")
