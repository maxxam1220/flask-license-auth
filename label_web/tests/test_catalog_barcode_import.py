"""Import metadata enriches evidence without replacing approved label identity."""
from copy import deepcopy
import hashlib
import json
import unittest

from sqlalchemy import create_engine, insert, select
import database as db
import import_catalog
import reference_catalog
from source_rules import prepare_source


def record():
    return {"CodeNo":"1623","CodeName":"測試單顆蘋果","Barcode":"28039938","TypesOfBarcode":"1","KeepDays":9,
        "source_file":"list-20261008.xlsx","source_sheet":"Sheet1","source_row":325,"source_date":"20261008",
        "latest_source_since_20261008":True,
        "fields":{"FrontCode":"","BehindCode":"3","SunDay":"3","SunPos":9,"PriceLen":"1"}}


class CatalogBarcodeImportTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine("sqlite:///:memory:")
        db.catalog.create(self.engine)

    def tearDown(self):self.engine.dispose()

    def prepared(self,value=None):return import_catalog.prepare_rows([value or record()],{"1623"})[0]

    def test_import_evidence_preserves_original_identity_hash_and_date_unknown(self):
        row=self.prepared()
        prior=deepcopy(row);prior.pop("revision");prior["provenance"].pop("barcode_config")
        self.assertEqual(row["revision"],hashlib.sha256(json.dumps(prior,ensure_ascii=False,sort_keys=True).encode()).hexdigest())
        source=reference_catalog.build_draft(row)
        self.assertEqual(reference_catalog.barcode_structure(source),{"prefix":"28039938","day_width":3,"suffix":"3"})
        self.assertEqual(prepare_source(source,"2026-11-12")["barcode_values"],["28039938"])
        self.assertEqual(source["date_settings"],[])

    def test_metadata_only_enrichment_retains_revision_and_is_idempotent(self):
        fresh=self.prepared();old=deepcopy(fresh)
        old["provenance"].pop("barcode_config");old["revision"]="existing-revision"
        with self.engine.begin() as conn:
            conn.execute(insert(db.catalog).values(**old,updated_at=db.now()))
            self.assertEqual(import_catalog.write_rows(conn,[fresh]),{"inserted":0,"updated":1,"unchanged":0})
        with self.engine.begin() as conn:
            self.assertEqual(import_catalog.write_rows(conn,[fresh]),{"inserted":0,"updated":0,"unchanged":1})
            actual=dict(conn.execute(select(db.catalog)).mappings().one())
        self.assertEqual(actual["revision"],old["revision"])
        for key in ("code","name","barcode","barcode_type","keep_days","active"):
            self.assertEqual(actual[key],old[key])

    def test_older_list_and_same_date_identity_conflict_cannot_overwrite(self):
        fresh=self.prepared()
        with self.engine.begin() as conn:import_catalog.write_rows(conn,[fresh])
        for changes in ({"source_date":"20260901"},{"CodeName":"另一款商品"},{"KeepDays":0}):
            candidate=self.prepared(dict(record(),**changes))
            with self.assertRaises(ValueError):
                with self.engine.begin() as conn:import_catalog.write_rows(conn,[candidate])
        with self.engine.connect() as conn:
            self.assertEqual(dict(conn.execute(select(db.catalog)).mappings().one())["name"],fresh["name"])

    def test_missing_fields_do_not_remove_existing_same_source_evidence(self):
        fresh=self.prepared()
        with self.engine.begin() as conn:import_catalog.write_rows(conn,[fresh])
        absent=self.prepared(dict(record(),fields={}))
        self.assertNotIn("barcode_config",absent["provenance"])
        with self.engine.begin() as conn:
            self.assertEqual(import_catalog.write_rows(conn,[absent])["unchanged"],1)
            self.assertEqual(conn.execute(select(db.catalog.c.provenance)).scalar()["barcode_config"],fresh["provenance"]["barcode_config"])

    def test_exact_position_front_and_back_are_preserved_without_padding(self):
        item=record();item["Barcode"]="1234567"
        item["fields"].update(FrontCode="9",BehindCode="3",SunDay="3",SunPos=9)
        source=reference_catalog.build_draft(self.prepared(item))
        self.assertEqual(reference_catalog.barcode_structure(source),{"prefix":"91234567","day_width":3,"suffix":"3"})
        source["catalog_barcode_config"]["solar_pos"]=4
        self.assertEqual(reference_catalog.barcode_structure(source),{"prefix":"912","day_width":3,"suffix":"345673"})

    def test_incomplete_overflow_price_and_code128_are_not_invented(self):
        source=reference_catalog.build_draft(self.prepared())
        for changes in ({"back":""},{"back":"33"},{"solar_pos":99},{"solar_pos":True},
                {"front":"ABC"},{"price_len":"4"},{"kind":"4"},{"solar":"1"}):
            candidate=deepcopy(source);candidate["catalog_barcode_config"].update(changes)
            with self.assertRaises(ValueError):reference_catalog.barcode_structure(candidate)

    def test_different_composition_or_approved_versions_are_not_equivalent(self):
        first=self.prepared();second=deepcopy(first)
        second["code"]="another"
        a={"catalog_record":first};b={"catalog_record":second}
        self.assertEqual(reference_catalog.equivalence_key(a),reference_catalog.equivalence_key(b))
        second["provenance"]["barcode_config"]["back"]="4"
        self.assertNotEqual(reference_catalog.equivalence_key(a),reference_catalog.equivalence_key(b))
        second["provenance"]=deepcopy(first["provenance"])
        a.update(code="list:1623",_standard_revision=1,_source_revision="rule1")
        b.update(code="list:another",_standard_revision=1,_source_revision="rule2")
        self.assertNotEqual(reference_catalog.equivalence_key(a),reference_catalog.equivalence_key(b))


if __name__=="__main__":unittest.main()
