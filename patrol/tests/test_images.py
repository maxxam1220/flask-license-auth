import io
from concurrent.futures import ThreadPoolExecutor

import pytest
from PIL import Image
from werkzeug.datastructures import FileStorage

from images import MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, PhotoValidationError, process_uploads
import images


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


def camera_jpeg():
    """A JPEG with MPF auxiliary data, delivered by a camera as image/jpeg."""
    raw = io.BytesIO()
    exif = Image.Exif()
    exif[274] = 6
    exif[270] = "Private camera metadata"
    primary = Image.new("RGB", (80, 40), "green")
    primary.save(raw, format="MPO", save_all=True,
                 append_images=[Image.new("RGB", (16, 16), "red")], exif=exif)
    return raw.getvalue()


def test_camera_mpf_jpeg_uses_primary_photo_and_strips_auxiliary_metadata():
    raw = camera_jpeg()
    with Image.open(io.BytesIO(raw)) as source:
        assert source.format == "MPO" and source.n_frames == 2
    result = process_uploads([FileStorage(stream=io.BytesIO(raw), filename="IMG_0001.JPG", content_type="image/jpeg")])[0]
    assert result["mime_type"] == "image/jpeg" and result["size_bytes"] <= MAX_OUTPUT_BYTES
    with Image.open(io.BytesIO(result["data"])) as photo:
        assert photo.format == "JPEG" and photo.size == (40, 80)
        assert getattr(photo, "n_frames", 1) == 1
        assert not photo.getexif() and "mp" not in photo.info
        r, g, b = photo.getpixel((20, 40))
        assert g > r + 50 and g > b + 50  # The primary photo, never the red auxiliary.
    assert b"Private camera metadata" not in result["data"] and b"MPF\0" not in result["data"]


def test_camera_mpf_jpeg_does_not_bypass_pixel_limit(monkeypatch):
    monkeypatch.setattr(images, "MAX_PIXELS", 1000)
    with pytest.raises(PhotoValidationError, match="解析度過高"):
        process_uploads([upload(camera_jpeg())])


def test_camera_mpf_jpeg_never_decodes_auxiliary_frames(monkeypatch):
    from PIL.MpoImagePlugin import MpoImageFile
    original = MpoImageFile.seek
    def primary_only(self, frame):
        assert frame == 0, "Auxiliary camera frames must not be decoded"
        return original(self, frame)
    monkeypatch.setattr(MpoImageFile, "seek", primary_only)
    assert len(process_uploads([upload(camera_jpeg())])) == 1


@pytest.mark.parametrize("kind", ["PNG", "WEBP", "HEIF"])
def test_camera_compatibility_does_not_enable_other_multiframe_uploads(kind):
    raw = io.BytesIO()
    Image.new("RGB", (30, 20), "blue").save(raw, format=kind, save_all=True,
        append_images=[Image.new("RGB", (30, 20), "red")])
    with pytest.raises(PhotoValidationError, match="單張靜態圖片"):
        process_uploads([upload(raw.getvalue(), "renamed.jpg")])


@pytest.mark.parametrize("kind", ["GIF", "BMP", "TIFF", "AVIF"])
def test_renaming_other_formats_as_jpeg_does_not_bypass_validation(kind, caplog):
    raw = io.BytesIO()
    Image.new("RGB", (20, 20)).save(raw, format=kind)
    with pytest.raises(PhotoValidationError, match="請使用 JPG"):
        process_uploads([upload(raw.getvalue(), "private-name.jpg")])
    assert f"photo_format_rejected format={kind} position=1" in caplog.text
    assert "private-name" not in caplog.text


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


@pytest.mark.parametrize("mode,color,transparent", [("RGB", (255, 0, 0), (255, 0, 0)), ("L", 0, 0)])
def test_png_color_key_transparency_uses_white_background(mode, color, transparent):
    raw = io.BytesIO()
    source = Image.new(mode, (40, 20), color)
    source.paste((0, 0, 255) if mode == "RGB" else 100, (20, 0, 40, 20))
    source.save(raw, format="PNG", transparency=transparent)
    result = process_uploads([upload(raw.getvalue(), name="transparent.png")])[0]
    with Image.open(io.BytesIO(result["data"])) as decoded:
        assert min(decoded.getpixel((10, 10))) >= 250
        opaque = decoded.getpixel((30, 10))
        if mode == "RGB":
            assert opaque[2] >= 245 and max(opaque[:2]) <= 10
        else:
            assert all(95 <= value <= 105 for value in opaque)


def test_resized_png_transparent_color_does_not_bleed_into_edges():
    raw = io.BytesIO()
    source = Image.new("RGB", (3200, 1200), (255, 0, 0))
    source.paste((0, 0, 255), (1600, 0, 3200, 1200))
    source.save(raw, format="PNG", transparency=(255, 0, 0))
    result = process_uploads([upload(raw.getvalue(), name="large-transparent.png")])[0]
    with Image.open(io.BytesIO(result["data"])) as decoded:
        assert decoded.size == (1600, 600)
        assert min(decoded.getpixel((700, 300))) >= 250
        # Blue blended over white has equal red/green channels. The invisible
        # red source must not become a red or purple fringe during thumbnailing.
        edge = [decoded.getpixel((x, 300)) for x in range(790, 810)]
        assert max(abs(red - green) for red, green, _ in edge) <= 10


@pytest.mark.parametrize("placeholder", [False, True])
def test_no_photo_checkin_does_not_wait_for_other_image_processing(placeholder):
    files = [upload(b"", name="")] if placeholder else []
    with ThreadPoolExecutor(max_workers=1) as workers:
        images._PROCESSING_SLOT.acquire()
        try:
            result = workers.submit(process_uploads, files)
            assert result.result(timeout=1) == []
        finally:
            images._PROCESSING_SLOT.release()
