"""Validate and normalize private inspection photos before database storage."""
import io
import threading
import warnings

from PIL import Image, ImageOps, UnidentifiedImageError
from pillow_heif import register_heif_opener

register_heif_opener()

MAX_PHOTOS = 3
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 400 * 1024
MAX_PIXELS = 25_000_000
MAX_DIMENSION = 1600
ALLOWED_FORMATS = {"JPEG", "PNG", "WEBP", "HEIF"}
_PROCESSING_SLOT = threading.BoundedSemaphore(1)


class PhotoValidationError(ValueError):
    """A user-facing validation failure, with no partial storage."""


def process_uploads(files):
    uploads = [item for item in files if item and item.filename]
    if not uploads:
        # A no-photo check-in must not wait for somebody else's image decoding.
        return []
    # Decode one request at a time on the 512 MB service; do not let several
    # concurrent full-resolution phone images exhaust the worker's memory.
    with _PROCESSING_SLOT:
        return _process_uploads(uploads)


def _process_uploads(files):
    uploads = [item for item in files if item and item.filename]
    if len(uploads) > MAX_PHOTOS:
        raise PhotoValidationError("每次打卡最多上傳 3 張照片。")
    result = []
    for position, upload in enumerate(uploads, 1):
        prefix = f"第 {position} 張照片"
        raw = upload.stream.read(MAX_INPUT_BYTES + 1)
        if not raw or len(raw) > MAX_INPUT_BYTES:
            raise PhotoValidationError(f"{prefix}需為非空白圖片，且每張不得超過 8 MB。")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(raw)) as source:
                    if source.format not in ALLOWED_FORMATS:
                        raise PhotoValidationError(f"{prefix}請使用 JPG、PNG、WebP 或 HEIC 格式。")
                    if source.width * source.height > MAX_PIXELS:
                        raise PhotoValidationError(f"{prefix}解析度過高，請縮小至 2,500 萬畫素以下再上傳。")
                    if getattr(source, "n_frames", 1) > 1:
                        raise PhotoValidationError(f"{prefix}請使用單張靜態圖片。")
                    source.load()
                    oriented = ImageOps.exif_transpose(source)
                    # Preserve color-key transparency during resampling; RGB/L
                    # interpolation otherwise makes hidden colors opaque halos.
                    if "transparency" in oriented.info:
                        oriented = oriented.convert("RGBA")
                    oriented.thumbnail((MAX_DIMENSION, MAX_DIMENSION), Image.Resampling.LANCZOS)
                    if oriented.mode in ("RGBA", "LA") or "transparency" in oriented.info:
                        rgba = oriented.convert("RGBA")
                        image = Image.new("RGB", rgba.size, "white")
                        image.paste(rgba, mask=rgba.getchannel("A"))
                    else:
                        image = oriented.convert("RGB")
                    # Encoding into a fresh image strips EXIF/GPS and all original metadata.
                    clean = Image.new("RGB", image.size)
                    clean.paste(image)
                    for dimension in (1600, 1280, 1024):
                        clean.thumbnail((dimension, dimension), Image.Resampling.LANCZOS)
                        for quality in (82, 70, 58):
                            buffer = io.BytesIO()
                            clean.save(buffer, format="JPEG", quality=quality, optimize=True)
                            data = buffer.getvalue()
                            if len(data) <= MAX_OUTPUT_BYTES:
                                break
                        if len(data) <= MAX_OUTPUT_BYTES:
                            break
                    if len(data) > MAX_OUTPUT_BYTES:
                        raise PhotoValidationError(f"{prefix}無法壓縮至儲存限制，請先縮小圖片。")
                    result.append({"data": data, "mime_type": "image/jpeg", "size_bytes": len(data), "width": clean.width, "height": clean.height})
        except PhotoValidationError:
            raise
        except (UnidentifiedImageError, OSError, ValueError, SyntaxError, Image.DecompressionBombError, Image.DecompressionBombWarning) as error:
            raise PhotoValidationError(f"{prefix}無法讀取，請重新選擇有效的 JPG、PNG、WebP 或 HEIC 圖片。") from error
    return result
