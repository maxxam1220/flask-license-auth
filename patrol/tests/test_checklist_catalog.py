"""Checklist source fidelity, translated labels and strict checkbox snapshots."""
from copy import deepcopy
import hashlib
import json
import re
from types import SimpleNamespace
import unicodedata

import pytest

import checklist_catalog as catalog


def point(name="1F女廁所", *, category="general", floor=1, code="FUTURE-POINT"):
    return SimpleNamespace(name=name, category=category, floor=floor, code=code)


@pytest.mark.parametrize("name,floor,key,count", [
    ("1F女廁所", 1, "toilet_v1", 7), ("1.2客梯廁所", -2, "toilet_v1", 7),
    ("新增無障礙廁", 5, "toilet_v1", 7), ("  新設廁所  ", 3, "toilet_v1", 7),
])
def test_existing_and_future_general_points_receive_correct_profile(name, floor, key, count):
    definition = catalog.checklist_for_point(point(name, floor=floor))
    assert definition["key"] == key and definition["version"] == 1
    assert len(definition["items"]) == count
    assert set(definition) == {"key", "version", "title", "items"}
    assert "source" not in definition


@pytest.mark.parametrize("category", ["safety", "uncategorized", "", None])
@pytest.mark.parametrize("name,floor", [("1F女廁所", 1), ("員工餐廳", 14), ("廚房", 14)])
def test_same_name_points_outside_general_never_receive_or_accept_checklist(category, name, floor):
    target = point(name, category=category, floor=floor)
    assert catalog.checklist_for_point(target) is None
    assert catalog.checklist_revision(target) == ""
    assert catalog.validate_checklist(target, []) is None
    with pytest.raises(ValueError, match="沒有適用的點檢項目"):
        catalog.validate_checklist(target, ["toilet.mirror"])


@pytest.mark.parametrize("target", [None, point("停車場"), point("廚餘室"), point("廚房", floor=4),
    point("餐廳", floor=4), point("員工餐廳", floor="14"), point("員工餐廳", floor=14),
    point("餐廳", floor=14), point("廚房", floor=14), point(None), point(123),
    SimpleNamespace(category="general")])
def test_unrelated_or_incomplete_points_have_no_checklist(target):
    assert catalog.checklist_for_point(target) is None
    assert catalog.checklist_revision(target) == ""
    assert catalog.validate_checklist(target, []) is None


@pytest.mark.parametrize("name,key,item", [
    ("員工餐廳", "dining_v1", "dining.a1"), ("餐廳", "dining_v1", "dining.a1"),
    ("廚房", "kitchen_v1", "kitchen.b1"),
])
def test_retired_food_definitions_only_validate_previously_signed_snapshots(name, key, item):
    target = point(name, floor=14)
    assert catalog.checklist_for_point(target) is None
    historical = catalog.retired_checklist_for_point(target)
    assert historical["key"] == key and len(historical["items"]) == 5
    assert catalog.validate_checklist_definition(historical, [item])["selected"] == [item]
    assert "selected" not in historical
    with pytest.raises(ValueError, match="沒有適用的點檢項目"):
        catalog.validate_checklist(target, [item])
    for alternative in (point(name, category="safety", floor=14), point(name, floor=4),
                        point("4M女廁所", floor=14), None):
        assert catalog.retired_checklist_for_point(alternative) is None


@pytest.mark.parametrize("key,expected_ids,expected_codes", [
    ("toilet_v1", ["toilet.mirror", "toilet.sink", "toilet.soap", "toilet.hand_dryer",
                   "toilet.toilet_fixtures", "toilet.paper", "toilet.floor"], []),
    ("dining_v1", [f"dining.a{i}" for i in range(1, 6)], [f"A{i}" for i in range(1, 6)]),
    ("kitchen_v1", [f"kitchen.b{i}" for i in range(1, 6)], [f"B{i}" for i in range(1, 6)]),
])
def test_stable_identifiers_and_source_printed_codes_are_language_independent(key, expected_ids, expected_codes):
    definition = catalog.checklist_definition(key)
    assert [item["id"] for item in definition["items"]] == expected_ids
    assert [item["source_code"] for item in definition["items"] if "source_code" in item] == expected_codes
    for label in [definition["title"], *(item["label"] for item in definition["items"])]:
        assert set(label) == {"zh-Hant", "id", "vi"}
        for language, text in label.items():
            assert isinstance(text, str) and text and text == text.strip()
            assert "\n" not in text and "\r" not in text and "\x00" not in text
            assert unicodedata.is_normalized("NFC", text)
            if language != "zh-Hant":
                assert not re.search(r"[\u3400-\u9fff]", text)


def test_source_cell_text_is_retained_with_whitespace_typos_and_corrected_display():
    toilet = catalog.checklist_definition("toilet_v1", include_source=True)
    dining = catalog.checklist_definition("dining_v1", include_source=True)
    kitchen = catalog.checklist_definition("kitchen_v1", include_source=True)
    assert toilet["source"] == {
        "filename": "總務巡檢表-附越文版.xlsx", "sheet": "4M餐廳&廚房巡檢表",
        "sha256": "443e8472451a79034902f0571ad4afb727eda7a47448b1986f8c7c169843ca8e",
    }
    assert [item["source"]["cell"] for item in toilet["items"]] == ["B6", "C6", "D6", "E6", "F6", "G6", "H6"]
    assert [item["source"]["cell"] for item in dining["items"]] == ["C2", "D2", "E2", "F2", "G2"]
    assert [item["source"]["cell"] for item in kitchen["items"]] == ["H2", "I2", "J2", "K2", "L2"]
    assert toilet["items"][1]["source"]["raw"] == "洗手台乾淨bồn rửa Tay vệ sinh sạch"
    assert toilet["items"][3]["source"]["raw"].endswith("sạch xẽ")
    assert toilet["items"][-1]["source"]["raw"] == "地面清潔\nĐồ lau sàn"
    assert toilet["items"][-1]["label"]["vi"] == "Sàn nhà sạch"
    assert dining["items"][1]["source"]["raw"] == "★★★ A2/餐廳\n廚餘箱\nnhà ăn \nthùng đồ ăn thừa "
    assert [item["source"]["stars"] for item in kitchen["items"]] == [2, 3, 1, 3, 1]
    # The original stars are provenance only and never scheduling rules.
    assert all("frequency" not in item and "stars" not in item for item in kitchen["items"])


def test_one_checked_item_is_sufficient_and_multiselect_is_canonical_without_mutating_input():
    target = point()
    selected = ["toilet.floor", "toilet.mirror"]
    snapshot = catalog.validate_checklist(target, selected)
    assert selected == ["toilet.floor", "toilet.mirror"]
    assert snapshot["selected"] == ["toilet.mirror", "toilet.floor"]
    assert len(snapshot["items"]) == 7
    assert catalog.validate_checklist(target, ["toilet.paper"])["selected"] == ["toilet.paper"]
    assert "selected" not in catalog.checklist_for_point(target)


@pytest.mark.parametrize("selected", [
    None, "toilet.mirror", ("toilet.mirror",), {"toilet.mirror": True}, {"toilet.mirror"},
    [True], [1], [None], [["toilet.mirror"]], [""], [" toilet.mirror"], ["TOILET.MIRROR"],
    ["toilet.mirror", "toilet.mirror"], ["dining.a1"], ["unknown"], ["toilet.mirror", "<script>"],
])
def test_malformed_unknown_duplicate_or_other_profile_answers_fail_closed(selected):
    with pytest.raises(ValueError, match="點檢項目資料不正確"):
        catalog.validate_checklist(point(), selected)


def test_empty_selection_requires_at_least_one_not_all_items():
    with pytest.raises(ValueError, match="請至少勾選 1 項已完成的點檢項目。"):
        catalog.validate_checklist(point(), [])
    for item in catalog.checklist_for_point(point())["items"]:
        assert catalog.validate_checklist(point(), [item["id"]])["selected"] == [item["id"]]


@pytest.mark.parametrize("selected", [None, "", {}, (), False, 0])
def test_even_unrelated_points_require_an_explicit_list(selected):
    with pytest.raises(ValueError, match="點檢項目資料不正確"):
        catalog.validate_checklist(point("停車場"), selected)


def test_returned_payloads_are_detached_and_json_serializable():
    target = point("4M女廁所", floor=14)
    original = catalog.checklist_for_point(target)
    modified = catalog.checklist_for_point(target)
    modified["title"]["vi"] = "changed"
    modified["items"][0]["label"]["id"] = "changed"
    modified["items"].clear()
    assert catalog.checklist_for_point(target) == original
    snapshot = catalog.validate_checklist(target, ["toilet.soap"])
    assert json.loads(json.dumps(snapshot, ensure_ascii=False)) == snapshot
    snapshot["items"][0]["label"]["zh-Hant"] = "changed snapshot"
    assert catalog.checklist_for_point(target) == original


def test_revision_is_deterministic_content_hash_and_tracks_changed_definition(monkeypatch):
    target = point("4M女廁所", floor=14)
    definition = catalog.checklist_for_point(target)
    expected = hashlib.sha256(json.dumps(definition, ensure_ascii=False, sort_keys=True,
                                         separators=(",", ":")).encode("utf-8")).hexdigest()
    assert catalog.checklist_revision(target) == expected
    assert catalog.checklist_revision(point("4M男廁所", floor=14, code="OTHER")) == expected
    assert catalog.checklist_revision(point("廚房", floor=14)) != expected
    snapshot = catalog.validate_checklist(target, ["toilet.mirror"])
    old_label = snapshot["items"][0]["label"]["vi"]
    translations = deepcopy(catalog._translations())
    translations["鏡面乾淨"]["vi"] = "Nhãn đã cập nhật"
    monkeypatch.setattr(catalog, "_translations", lambda: translations)
    assert catalog.checklist_revision(target) != expected
    assert snapshot["items"][0]["label"]["vi"] == old_label


@pytest.mark.parametrize("key", ["wrong", "toilet_v2", [], {}, 1, True])
def test_unknown_profile_definitions_fail_closed(key):
    with pytest.raises(ValueError, match="點檢項目設定不正確"):
        catalog.checklist_definition(key)
