"""Explicit, reversible user-selected regions in the stored photo coordinates."""
import hashlib
import io
import math

from PIL import Image

import database as db


def validate_region(value, width, height):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"x", "y", "width", "height"}:
        raise ValueError("請在照片上框選單張標籤。")
    if any(type(v) not in (int, float) or isinstance(v, float) and not math.isfinite(v) for v in value.values()):
        raise ValueError("裁切範圍必須是有效數字。")
    x, y, w, h = (value[key] for key in ("x", "y", "width", "height"))
    if x < 0 or y < 0 or x > width or y > height or w < 100 or h < 100 or w > width or h > height or x + w > width or y + h > height:
        raise ValueError("請完整框選照片內的標籤，寬與高至少 100 像素。")
    left, top, right, bottom = math.floor(x), math.floor(y), math.ceil(x+w), math.ceil(y+h)
    return {"x":left, "y":top, "width":right-left, "height":bottom-top}


def save_region(data_dir, original_image, region):
    """Create a derivative; original bytes and OCR never change. Caller holds image lock."""
    source = data_dir / "images" / original_image["id"] / "image.jpg"
    with Image.open(source) as image:
        if image.size != (original_image["width"], original_image["height"]):
            raise ValueError("照片尺寸與紀錄不同，請重新上傳。")
        x, y, w, h = (region[key] for key in ("x", "y", "width", "height"))
        with image.crop((x, y, x+w, y+h)) as cropped:
            raw = io.BytesIO()
            cropped.save(raw, format="PNG")
            identifier = db.uid()
            folder = data_dir / "images" / identifier
            folder.mkdir(parents=True)
            try:
                (folder / "original").write_bytes(raw.getvalue())
                cropped.save(folder / "image.jpg", quality=95)
                with cropped.copy() as thumb:
                    thumb.thumbnail((420, 420))
                    thumb.save(folder / "thumb.jpg", quality=85)
            except Exception:
                remove_uncommitted_region(folder)
                raise
    return dict(id=identifier, created_at=db.now(), filename="裁切單張標籤.png",
                sha256=hashlib.sha256(raw.getvalue()).hexdigest(), width=w, height=h)


def remove_uncommitted_region(folder):
    """Only the three fixed files from a newly created, uncommitted derivative."""
    for name in ("original", "image.jpg", "thumb.jpg"):
        (folder / name).unlink(missing_ok=True)
    folder.rmdir()
