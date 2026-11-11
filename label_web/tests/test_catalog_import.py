import unittest
from sqlalchemy import create_engine, select
import database as db
from import_catalog import prepare_rows, write_rows


class CatalogImportTests(unittest.TestCase):
    def record(self, **extra):
        return {"CodeNo": "1683", "CodeName": "日本空運麝香葡萄350g*2盒/禮盒", "Barcode": "26586342",
                "KeepDays": 6, "TypesOfBarcode": "3", "latest_source_since_20261008": True,
                "source_file": "test.xlsx", "source_sheet": "清單", "source_row": 2, "source_date": "20261008", **extra}

    def test_import_is_idempotent_and_preserves_unrelated_catalog_entries(self):
        engine = create_engine("sqlite://")
        db.catalog.create(engine)
        rows = prepare_rows([self.record()], {"1683"})
        other = prepare_rows([self.record(CodeNo="OTHER")], {"OTHER"})
        with engine.begin() as conn:
            self.assertEqual(write_rows(conn, other)["inserted"], 1)
            self.assertEqual(write_rows(conn, rows)["inserted"], 1)
            self.assertEqual(write_rows(conn, rows)["unchanged"], 1)
            actual = conn.execute(select(db.catalog)).mappings().all()
            self.assertEqual(len(actual), 2)
            self.assertTrue(all(row["keep_days"] == 6 for row in actual))
        engine.dispose()

    def test_duplicate_missing_historical_and_invalid_days_rejected(self):
        for records, selected in (([self.record(), self.record()], {"1683"}),
            ([], {"1683"}), ([self.record(latest_source_since_20261008=False)], {"1683"}),
            ([self.record(KeepDays=-1)], {"1683"})):
            with self.subTest(records=records), self.assertRaises(ValueError):
                prepare_rows(records, selected)

