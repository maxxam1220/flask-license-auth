"""Versioned checklist definitions; no database access or implicit live edits.

The submitted profile and item IDs are stable identifiers. Display translations
may improve, but a saved receipt must retain its own definition/answer snapshot.
Source text is preserved separately from corrected, concise display labels.
"""
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path


SOURCE_FILENAME = "總務巡檢表-附越文版.xlsx"
SOURCE_SHA256 = "443e8472451a79034902f0571ad4afb727eda7a47448b1986f8c7c169843ca8e"
SOURCE_SHEET = "4M餐廳&廚房巡檢表"
CATALOG_VERSION = 1
PROFILE_CHOICES = {
    "toilet_v1": "廁所點檢",
    "dining_v1": "餐廳點檢",
    "kitchen_v1": "廚房點檢",
}
PROFILE_KEYS = tuple(PROFILE_CHOICES)


# id, Chinese display label, source cell, original printed code, source stars,
# exact original bilingual cell value (including original whitespace/typos).
_ITEMS = {
    "toilet_v1": (
        ("toilet.mirror", "鏡面乾淨", "B6", "", 0, "鏡面乾淨\ngương vệ sinh sạch"),
        ("toilet.sink", "洗手台乾淨", "C6", "", 0, "洗手台乾淨bồn rửa Tay vệ sinh sạch"),
        ("toilet.soap", "洗手乳充足", "D6", "", 0, "洗手乳充足\nnước rửa tay đủ"),
        ("toilet.hand_dryer", "烘手機乾淨", "E6", "", 0, "烘手機乾淨\nmáy sấy tay sạch xẽ"),
        ("toilet.toilet_fixtures", "大小便器乾淨", "F6", "", 0, "大小便器乾淨bồn cầu bồn tiểu sạch xẽ"),
        ("toilet.paper", "衛生紙充足", "G6", "", 0, "衛生紙充足\ngiấy vệ sinh đầy đủ"),
        ("toilet.floor", "地面清潔", "H6", "", 0, "地面清潔\nĐồ lau sàn"),
    ),
    "dining_v1": (
        ("dining.a1", "洗手槽(廚餘)", "C2", "A1", 3,
         "★★★ A1/餐廳\n洗手槽(廚餘)\nbồn rửa tay nhà ăn (đồ ăn thừa)"),
        ("dining.a2", "廚餘箱", "D2", "A2", 3,
         "★★★ A2/餐廳\n廚餘箱\nnhà ăn \nthùng đồ ăn thừa "),
        ("dining.a3", "出餐檯區", "E2", "A3", 3,
         "★★★ A3/餐廳\n出餐檯區\nnhà ăn khu vực \nquầy xuất đồ ăn "),
        ("dining.a4", "用餐座位區", "F2", "A4", 3,
         "★★★ A4/餐廳\n用餐座位區\nnhà ăn\nkhu vực ngồi ăn "),
        ("dining.a5", "洗手槽", "G2", "A5", 3,
         "★★★ A5/餐廳\n洗手槽\nnhà ăn khu vực \nbồn rửa tay "),
    ),
    "kitchen_v1": (
        ("kitchen.b1", "洗碗區", "H2", "B1", 2, "★★ B1/廚房\n洗碗區\nnhà bếp\n khu rửa bát"),
        ("kitchen.b2", "前置作業區", "I2", "B2", 3,
         "★★★ B2/廚房\n前置作業區\nnhà bếp \nkhu vực làm việc phía trước"),
        ("kitchen.b3", "排油煙機區", "J2", "B3", 1,
         "★ B3/廚房\n排油煙機區\n nhà bếp \nkhu vực máy hút khói dầu"),
        ("kitchen.b4", "團膳工作檯", "K2", "B4", 3,
         "★★★ B4/廚房\n團膳工作檯\nnhà bếp \nkhu vực quầy nấu ăn "),
        ("kitchen.b5", "餐具烘乾櫃", "L2", "B5", 1,
         "★ B5/廚房\n餐具烘乾櫃\nnhà bếp \ntủ sấy dụng cụ ăn "),
    ),
}


class ChecklistValidationError(ValueError):
    pass


@lru_cache(maxsize=1)
def _translations():
    return json.loads((Path(__file__).parent / "locales" / "checklists.json").read_text(encoding="utf-8"))


def _labels(text):
    translated = _translations()[text]
    return {"zh-Hant": text, "id": translated["id"], "vi": translated["vi"]}


def checklist_definition(profile_key, *, include_source=False):
    """Return a detached JSON-safe definition; invalid nonempty keys fail closed."""
    if profile_key in (None, ""):
        return None
    if not isinstance(profile_key, str) or profile_key not in _ITEMS:
        raise ChecklistValidationError("點檢項目設定不正確，請重新開啟此點。")
    result = {"key": profile_key, "version": CATALOG_VERSION,
              "title": _labels(PROFILE_CHOICES[profile_key]), "items": []}
    for identifier, label, cell, code, stars, raw in _ITEMS[profile_key]:
        item = {"id": identifier, "label": _labels(label)}
        if code:
            item["source_code"] = code
        if include_source:
            item["source"] = {"sheet": SOURCE_SHEET, "cell": cell, "raw": raw, "stars": stars}
        result["items"].append(item)
    if include_source:
        result["source"] = {"filename": SOURCE_FILENAME, "sha256": SOURCE_SHA256, "sheet": SOURCE_SHEET}
    return result


def checklist_for_point(point):
    """Apply the authorized name rules to general points, including future additions."""
    if point is None or getattr(point, "category", None) != "general":
        return None
    name = getattr(point, "name", "")
    if not isinstance(name, str):
        return None
    name = name.strip()
    if "廁" in name:
        return checklist_definition("toilet_v1")
    # Dining/kitchen checklists are retired from new check-ins. Keep their
    # definitions above so original records and offline snapshots remain readable.
    return None


def checklist_revision(point):
    """Stable content digest used to invalidate stale online/offline definitions."""
    definition = checklist_for_point(point)
    if definition is None:
        return ""
    canonical = json.dumps(definition, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def retired_checklist_for_point(point):
    """Historical food checklist, only for validating previously signed drafts."""
    if (point is None or getattr(point, "category", None) != "general"
            or getattr(point, "floor", None) != 14):
        return None
    name = getattr(point, "name", "")
    if not isinstance(name, str):
        return None
    name = name.strip()
    if name in ("員工餐廳", "餐廳"):
        return checklist_definition("dining_v1")
    if name == "廚房":
        return checklist_definition("kitchen_v1")
    return None


def validate_checklist(point, selected):
    """Require at least one checked item; this is not a per-item pass/fail form."""
    return validate_checklist_definition(checklist_for_point(point), selected)


def validate_checklist_definition(definition, selected):
    """Validate answers against a trusted current or historical definition."""
    if not isinstance(selected, list) or any(not isinstance(value, str) for value in selected):
        raise ChecklistValidationError("點檢項目資料不正確，請重新確認。")
    if definition is None:
        if selected:
            raise ChecklistValidationError("此巡檢點沒有適用的點檢項目，請重新開啟此點。")
        return None
    allowed = tuple(item["id"] for item in definition["items"])
    if len(selected) != len(set(selected)) or any(value not in allowed for value in selected):
        raise ChecklistValidationError("點檢項目資料不正確，請重新確認。")
    if not selected:
        raise ChecklistValidationError("請至少勾選 1 項已完成的點檢項目。")
    chosen = set(selected)
    snapshot = deepcopy(definition)
    snapshot["selected"] = [identifier for identifier in allowed if identifier in chosen]
    return snapshot
