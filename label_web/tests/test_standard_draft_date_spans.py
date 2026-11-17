"""Drafts retain fixed content sharing an OCR box with a variable date."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from sqlalchemy import func, select

import database as db
import manual_reference
import standard_reference
import test_manual_reference as manual_fixture
import test_source_fulltext_upgrade as source_fixture


class DraftDateSpanTests(unittest.TestCase):
    setUp = manual_fixture.ManualReferenceTests.setUp
    add_inspection = manual_fixture.ManualReferenceTests.add_inspection

    def draft(self, lines, identifier="mixed"):
        original = self.add_inspection(identifier, lines)
        response = self.client.get(f"/api/inspections/{identifier}/manual-standard")
        self.assertEqual(response.status_code, 200, response.json)
        with self.engine.connect() as conn:
            self.assertEqual(dict(conn.execute(select(db.inspections).where(
                db.inspections.c.id == identifier)).mappings().one()), original)
        return response.json

    def test_combined_arrival_storage_keeps_only_observed_fixed_text(self):
        for index, marker in enumerate(("①", "⑤", "⑳")):
            with self.subTest(marker=marker):
                lines = [manual_fixture.line(0, "品名：履歷香蕉1KG(常溫原果)"),
                         manual_fixture.line(1, f"到店日：2026.11.20 {marker} 保存條件：18℃")]
                draft = self.draft(lines, f"mixed-{index}")
                self.assertTrue(draft["can_create"])
                self.assertEqual([row["text"] for row in draft["draft_lines"]],
                                 [lines[0]["text"], "保存條件：18℃"])
                self.assertEqual(draft["draft_lines"][1]["source_line_ids"], [1])
                self.assertEqual(draft["ocr_lines"], lines)
                source, _ = manual_reference.definition({"name": "履歷香蕉1KG(常溫原果)",
                    "lines": [{"text": row["text"]} for row in draft["draft_lines"]]})
                self.assertEqual(source["fields"]["storage"], "18℃")
                self.assertFalse(source["date_settings"])

    def test_multiple_dates_and_fixed_prefix_do_not_lose_company_text(self):
        lines = [manual_fixture.line(0, "品名：日本蘋果"),
                 manual_fixture.line(1, "公司名稱：福和生鮮農產股份有限公司 製造日期：2026.11.17 有效日期：2026.11.20")]
        draft = self.draft(lines)
        self.assertEqual(draft["draft_lines"][1]["text"], "公司名稱：福和生鮮農產股份有限公司")
        self.assertNotIn("2026", "\n".join(row["text"] for row in draft["draft_lines"]))

    def test_unrecognized_date_remainder_and_plain_date_never_become_fixed_text(self):
        lines = [manual_fixture.line(0, "品名：日本蘋果"),
                 manual_fixture.line(1, "到店日：2026.11.20 ⑤ 未知尾字"),
                 manual_fixture.line(2, "製造日期：2026.11.17"),
                 manual_fixture.line(3, "到店日：2026.11.20⑥ 保存條件：有效日期2026.12.01")]
        draft = self.draft(lines)
        self.assertEqual([row["text"] for row in draft["draft_lines"]], ["品名：日本蘋果"])

    def test_uncertain_recovered_text_stays_uncertain_and_is_not_filled_from_standard(self):
        lines = [manual_fixture.line(0, "品名：日本蘋果"),
                 dict(manual_fixture.line(1, "到店日：2026.11.20⑤ 保存條件：1B℃"),
                      uncertain=True, ambiguous=True)]
        draft = self.draft(lines)
        self.assertTrue(draft["manual_standard_eligibility"]["needs_review"])
        self.assertEqual(draft["draft_lines"][1]["text"], "保存條件：1B℃")
        self.assertTrue(draft["draft_lines"][1]["ambiguous"])
        self.assertFalse(draft["draft_lines"][1]["confidence_ok"])


class ExistingSourceDraftDateSpanTests(unittest.TestCase):
    setUp = source_fixture.SourceFulltextUpgradeTests.setUp
    tearDown = source_fixture.SourceFulltextUpgradeTests.tearDown
    raw_catalog = source_fixture.SourceFulltextUpgradeTests.raw_catalog
    seed = source_fixture.SourceFulltextUpgradeTests.seed
    payload = source_fixture.SourceFulltextUpgradeTests.payload
    body = source_fixture.SourceFulltextUpgradeTests.body
    save = source_fixture.SourceFulltextUpgradeTests.save

    def test_desktop_and_catalog_approve_same_code_photo_and_observed_storage(self):
        for number, code in enumerate((source_fixture.CODE, "1017")):
            with self.subTest(code=code):
                name = self.sources[code]["name"]
                original_source = deepcopy(self.sources[code])
                identifier = f"date-span-{number}"
                original = self.seed(identifier, code, {"lines": [
                    source_fixture.line(0, "品名：" + name),
                    source_fixture.line(1, "到店日：2026.11.20⑤ 保存條件：18℃")]})
                data = self.payload(identifier)
                self.assertTrue(data["editable"])
                self.assertTrue(data["regrouped_can_apply"])
                self.assertEqual(data["regrouped_draft_lines"][1]["text"], "保存條件：18℃")
                with patch("cloud_vision._post_response", side_effect=AssertionError("No OCR on draft approval")):
                    preview = self.save(identifier=identifier, preview=True)
                    self.assertEqual(preview.status_code, 200, preview.json)
                    saved = self.save(identifier=identifier)
                self.assertEqual(saved.status_code, 201, saved.json)
                self.assertEqual(saved.json["code"], code)
                self.assertEqual(saved.json["source"]["fields"]["storage"], "18℃")
                self.assertEqual(saved.json["source"]["reference_image_id"], identifier + "-image")
                self.assertEqual(saved.json["source"]["date_settings"], original_source["date_settings"])
                self.assertEqual(saved.json["source"]["barcode_config"], original_source["barcode_config"])
                self.assertEqual(self.sources[code], original_source)
                with self.engine.connect() as conn:
                    self.assertEqual(dict(conn.execute(select(db.inspections).where(
                        db.inspections.c.id == identifier)).mappings().one()), original)
                    self.assertEqual(conn.scalar(select(func.count()).select_from(db.manual_sources)), 0)


if __name__ == "__main__":
    unittest.main()
