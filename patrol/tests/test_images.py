import io

import pytest
from PIL import Image
from werkzeug.datastructures import FileStorage

from images import MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, PhotoValidationError, process_uploads


def upload(data, name="photo.jpg"):
    return FileStorage(stream=io.BytesIO(data), filename=name)


@pytest.mark.parametrize("kind", ["JPEG", "PNG", "WEBP", "HEIF"])
def test_phone_formats_normalize_to_jpeg(kind):
    image = Image.new("RGB", (40, 25), "green")
    raw = io.BytesIO()
    image.save(raw, format=kind)
    photo = process_uploads([upload(raw.getvalue(), "phone." + kind.lower())])[0]
    assert photo["mime_type"] == "image/jpeg"
    assert photo["size_bytes"] == len(photo["data"]) <= MAX_OUTPUT_BYTES
    with Image.open(io.BytesIO(photo["data"])) as decoded:
        assert decoded.format == "JPEG" and decoded.size == (40, 25)
        assert not decoded.getexif()


def test_orientation_metadata_removed_and_dimensions_bounded():
    raw = io.BytesIO()
    exif = Image.Exif()
    exif[274] = 6
    exif[270] = "Private camera metadata"
    Image.new("RGB", (2400, 1200), "blue").save(raw, format="JPEG", exif=exif)
    photo = process_uploads([upload(raw.getvalue())])[0]
    assert (photo["width"], photo["height"]) == (800, 1600)
    with Image.open(io.BytesIO(photo["data"])) as decoded:
        assert not decoded.getexif()
        assert b"Private camera metadata" not in photo["data"]


@pytest.mark.parametrize("data", [b"<svg><script>alert(1)</script></svg>", b"not a photo", b"", b"x" * (MAX_INPUT_BYTES + 1)])
def test_invalid_or_oversized_photos_rejected(data):
    with pytest.raises(PhotoValidationError):
        process_uploads([upload(data)])


def test_photo_count_and_all_or_nothing_validation():
    raw = io.BytesIO()
    Image.new("RGB", (20, 20)).save(raw, format="PNG")
    with pytest.raises(PhotoValidationError, match="3"):
        process_uploads([upload(raw.getvalue()) for _ in range(4)])
    with pytest.raises(PhotoValidationError, match="第 2"):
        process_uploads([upload(raw.getvalue()), upload(b"invalid")])


def test_transparent_image_uses_white_background():
    raw = io.BytesIO()
    Image.new("RGBA", (12, 12), (255, 0, 0, 0)).save(raw, format="PNG")
    result = process_uploads([upload(raw.getvalue())])[0]
    with Image.open(io.BytesIO(result["data"])) as decoded:
        assert min(decoded.getpixel((6, 6))) >= 250
