"""Observed-date hypotheses prefill a form; they do not approve a barcode rule."""
from copy import deepcopy
from datetime import date
import unittest

from sqlalchemy import func, select, update
from werkzeug.exceptions import Conflict

import barcode_rule_authoring as rules
import database as db
import standard_library
import standard_reference as standards
import test_manual_barcode_rule as manual_fixture

RULE=manual_fixture.RULE
CODE=manual_fixture.CODE


def entry(value="2834665432436",expiry="2026-11-20",base_date="2026-11-17"):
    return {"available":True,"observed_value":value,"base_date":base_date,"fixed_barcode_reference":False,
        "dates":[{"kind":"expiry","iso":expiry,"uncertain":False}]}


class AutoBarcodeMathTests(unittest.TestCase):
    def test_qmc_meal_examples_use_the_printed_expiry_time_and_original_code(self):
        # Printed and decoded examples on pages 5 and 8 of QMC001 B.
        examples = (("2764706633938", "2020-12-04", "03時", "3.1.4"),
                    ("2013101013242", "2021-11-09", "24時", "4.1.3"))
        for value, expiry, time, clause in examples:
            with self.subTest(clause=clause):
                data = entry(value, expiry=expiry, base_date="")
                data["dates"][0]["value"] = expiry + " " + time
                candidates, recommended = rules.auto_hypotheses(data)
                selected = next(item for item in candidates if item["id"] == recommended)
                self.assertEqual(selected["sop_reference"], {"document":"QMC001", "edition":"B", "clause":clause})
                self.assertEqual(selected["composed_value"], value)
                data["fixed_barcode_reference"] = True
                self.assertIsNone(rules.auto_hypotheses(data)[1])
                data["dates"][0]["value"] = expiry + " 17時"
                candidates, _ = rules.auto_hypotheses(data)
                self.assertFalse(any("sop_reference" in item for item in candidates))

    def test_unique_three_digit_suggests_but_retains_two_digit_alternative(self):
        candidates,recommended=rules.auto_hypotheses(entry())
        best=next(item for item in candidates if item["id"]==recommended)
        self.assertEqual(best["rule"],RULE)
        self.assertEqual(best["evidence"]["kind"],"observed_hypothesis")
        self.assertEqual(best["evidence"]["insertion_position"],9)
        self.assertTrue(best["evidence"]["components_inferred"])
        self.assertTrue(any(item["rule"]["day_width"]==2 for item in candidates))
        self.assertTrue(all(item["composed_value"]=="2834665432436" for item in candidates))
        self.assertTrue(any("尚未證實" in text for text in best["warnings"]))

    def test_same_calendar_day_with_different_meanings_is_not_one_candidate(self):
        data=entry(base_date="2026-11-20")
        data["dates"].append({"kind":"manufacture","iso":"2026-11-20","uncertain":False})
        candidates,recommended=rules.auto_hypotheses(data)
        self.assertIsNone(recommended)
        self.assertEqual({item["rule"]["day_source"] for item in candidates if item["rule"]["day_width"]==3},
            {"base_date","manufacture","expiry"})

    def test_repeated_date_token_positions_are_not_silently_discarded(self):
        repeated=dict(RULE,prefix="1",suffix="32456789")
        value=rules.compose(repeated,date(2026,11,20))
        candidates,recommended=rules.auto_hypotheses(entry(value,base_date=""))
        self.assertIsNone(recommended)
        self.assertEqual({item["evidence"]["insertion_position"] for item in candidates if item["rule"]["day_width"]==3},{2,5})

    def test_leap_year_uses_real_calendar_and_short_dates_are_not_invented(self):
        value=rules.compose(RULE,date(2028,2,29))
        candidates,recommended=rules.auto_hypotheses(entry(value,expiry="2028-02-29",base_date=""))
        best=next(item for item in candidates if item["id"]==recommended)
        self.assertEqual(best["evidence"]["day_token"],"060")
        for invalid in ("02/29","2027-02-29","2028.02.29"):
            self.assertEqual(rules.auto_hypotheses(entry(value,expiry=invalid,base_date="")),([],None))

    def test_existing_fixed_code_does_not_get_an_auto_recommendation(self):
        data=entry();data["fixed_barcode_reference"]=True
        candidates,recommended=rules.auto_hypotheses(data)
        self.assertTrue(candidates)
        self.assertIsNone(recommended)
        self.assertTrue(all(any("巧合" in warning for warning in item["warnings"]) for item in candidates))
        preferred=dict(RULE,prefix="283466543",day_width=2)
        candidates,recommended=rules.auto_hypotheses(data,preferred)
        best=next(item for item in candidates if item["id"]==recommended)
        self.assertEqual(best["rule"],preferred)
        self.assertEqual(best["evidence"]["kind"],"approved_rule")

    def test_no_three_digit_match_does_not_recommend_two_digit_guess(self):
        two_digit=dict(RULE,prefix="91234567",day_width=2,suffix="89")
        value=rules.compose(two_digit,date(2026,11,20))
        candidates,recommended=rules.auto_hypotheses(entry(value,base_date=""))
        self.assertTrue(candidates)
        self.assertTrue(all(item["rule"]["day_width"]==2 for item in candidates))
        self.assertIsNone(recommended)

    def test_nonmatching_approved_rule_never_recommends_replacement_to_fit_photo(self):
        current=dict(RULE,day_source="base_date")
        candidates,recommended=rules.auto_hypotheses(entry(),current)
        self.assertTrue(any(item["rule"]==RULE for item in candidates))
        self.assertTrue(all(item["evidence"]["kind"]=="observed_hypothesis" for item in candidates))
        self.assertIsNone(recommended)
        self.assertEqual(current["day_source"],"base_date")

    def test_unavailable_uncertain_or_invalid_checksum_never_bypasses_gate(self):
        data=entry();data["available"]=False
        self.assertEqual(rules.auto_hypotheses(data),([],None))
        data=entry(base_date="");data["dates"][0]["uncertain"]=True
        self.assertEqual(rules.auto_hypotheses(data),([],None))
        self.assertEqual(rules.auto_hypotheses(entry("2834665432430")),([],None))


class AutoBarcodeWorkflowTests(unittest.TestCase):
    setUp=manual_fixture.ManualBarcodeRuleTests.setUp
    tearDown=manual_fixture.ManualBarcodeRuleTests.tearDown
    body=manual_fixture.ManualBarcodeRuleTests.body
    save_body=manual_fixture.ManualBarcodeRuleTests.save_body

    def test_upca_is_carried_into_legacy_library_suggestion_save_and_recheck(self):
        from label_source import _manual_catalog_item, _barcode_matches
        from source_validation import evaluate_source
        printed="4 00000 79003 9"
        value="400000790039"
        original=deepcopy(self.original)
        source=deepcopy(self.source)
        source["name"]="B8 高山甜柿2.5kg"
        source["fields"]["product"]=source["name"]
        source["lines"][0]["text"]="品名："+source["name"]
        source["lines"][1]["text"]=printed
        source["barcode_values"]=[]
        source["barcode_config"]={}
        original["ocr"]["lines"][0]["text"]=source["lines"][0]["text"]
        original["ocr"]["lines"][1]["text"]=printed
        original["ocr"]["barcodes"]={"items":[{"text":"0"+value,"format":"EAN-13","box":[]}]}
        with self.engine.begin() as conn:
            conn.execute(update(db.manual_sources).where(db.manual_sources.c.code==CODE).values(snapshot=source))
            conn.execute(update(standards.versions).where(standards.versions.c.code==CODE).values(snapshot=source))
            conn.execute(update(db.inspections).where(db.inspections.c.id=="scan").values(ocr=original["ocr"]))
        display=standard_library.detail(self.engine,"manual",CODE,lambda _:None)
        self.assertEqual(display["identity"]["barcode"],value)
        self.assertTrue(_barcode_matches(_manual_catalog_item(source),value))
        self.assertTrue(_barcode_matches(_manual_catalog_item(source),"0"+value))
        result=rules.suggest(self.engine,"scan")
        self.assertTrue(result["can_write"])
        self.assertFalse(result["manual_entry"]["available"])
        self.assertEqual(result["manual_entry"]["auto_candidates"],[])
        candidate,=result["candidates"]
        self.assertEqual(candidate["rule"],{"version":1,"symbology":"UPCA","value":value})
        body={key:result[key] for key in ("base_revision","source_revision","manual_revision")}
        body.update(candidate_id=candidate["id"],fill_keep_days=False)
        preview=rules.preview(self.engine,"scan",body)
        self.assertEqual(preview["after"]["rule"],candidate["rule"])
        saved=rules.save(self.engine,"scan",dict(body,preview_hash=preview["preview_hash"],confirmed=True,reviewer="QA",note="核對柿子條碼"))
        self.assertEqual(saved["rule"],candidate["rule"])
        reopened=rules.suggest(self.engine,"scan")
        self.assertEqual(reopened["current_rule"],candidate["rule"])
        display=standard_library.detail(self.engine,"manual",CODE,lambda _:None)
        self.assertNotIn("web_barcode_rule", display["source"])
        self.assertEqual(display["source"]["lines"],source["lines"])
        for text,status in ((printed,"pass"),(value,"pass"),("0"+value,"pass"),("036000291452","review")):
            original["ocr"]["lines"][1]["text"]=text
            result=evaluate_source(original["ocr"]["lines"],display["source"],base_date="2026-11-17")
            checks=[check for check in result["checks"] if check["label"]=="條碼"]
            self.assertEqual([item["status"] for item in checks],[status],checks)

    def test_new_fixed_code_is_saved_when_manual_standard_lacks_any_barcode(self):
        from source_validation import evaluate_source
        printed="4 00000 79003 9"
        ocr=deepcopy(self.original["ocr"]);ocr["lines"][1]["text"]=printed
        source=deepcopy(self.source);source["lines"].pop(1)
        with self.engine.begin() as conn:
            conn.execute(update(standards.versions).where(standards.versions.c.code==CODE).values(snapshot=source))
            conn.execute(update(db.inspections).where(db.inspections.c.id=="scan").values(ocr=ocr))
        result=rules.suggest(self.engine,"scan")
        self.assertIsNone(result["current_rule"])
        candidate,=result["candidates"]
        self.assertEqual(candidate["evidence"]["type_verification"],"printed_checksum")
        body={key:result[key] for key in ("base_revision","source_revision","manual_revision")}
        body.update(candidate_id=candidate["id"],fill_keep_days=False)
        preview=rules.preview(self.engine,"scan",body)
        rules.save(self.engine,"scan",dict(body,preview_hash=preview["preview_hash"],confirmed=True,reviewer="QA",note="核對固定商品碼"))
        final=standard_library.detail(self.engine,"manual",CODE,lambda _:None)["source"]
        updated=standards.changed_snapshot(source,final,{"keep_days":source["keep_days"]})
        self.assertEqual(updated["barcode_values"],["400000790039"])
        result=evaluate_source(ocr["lines"],updated,base_date="2026-11-17")
        self.assertEqual(next(check for check in result["checks"] if check["label"]=="條碼")["status"],"pass")

    def test_upca_blocks_an_existing_different_or_dynamic_barcode(self):
        for source in (dict(deepcopy(self.source),barcode_values=["036000291452"]),dict(deepcopy(self.source),web_barcode_rule=RULE)):
            ocr=deepcopy(self.original["ocr"]);ocr["lines"][1]["text"]="4 00000 79003 9"
            with self.engine.begin() as conn:
                conn.execute(update(standards.versions).where(standards.versions.c.code==CODE).values(snapshot=source))
                conn.execute(update(db.inspections).where(db.inspections.c.id=="scan").values(ocr=ocr))
            payload=rules.suggest(self.engine,"scan")
            self.assertFalse(payload["can_write"])
            self.assertEqual(payload["candidates"],[])
            self.assertIn("現行標準",payload["reason"])

    def test_get_proposals_and_preview_are_read_only_and_preserve_raw(self):
        before=deepcopy(self.original)
        payload=rules.suggest(self.engine,"scan")
        # The preserved spaced HRI is historical text, not a declared fixed
        # barcode_values/config entry. An explicit field is tested separately.
        self.assertIn("2 834665 432436",[item["text"] for item in self.source["lines"]])
        self.assertEqual(self.source["barcode_values"],[])
        self.assertFalse(payload["manual_entry"]["fixed_barcode_reference"])
        choices=payload["manual_entry"]["auto_candidates"]
        best=next(item for item in choices if item["id"]==payload["manual_entry"]["recommended_id"])
        self.assertEqual(best["rule"],RULE)
        self.assertIsNone(payload["current_rule"])
        preview=rules.preview(self.engine,"scan",self.body(best["rule"]))
        evidence=preview["candidate"]["evidence"]
        self.assertEqual(payload["manual_entry"]["type_verification"],"assumed")
        self.assertEqual(evidence["type_verification"],"assumed")
        self.assertTrue(evidence["ean13_assumption_accepted"])
        self.assertNotIn("confirmed_ean13",evidence)
        self.assertEqual(evidence["photo_date_hypothesis"]["method"],"date_token_match")
        self.assertNotIn("entered_rule",evidence)
        self.assertFalse(any("人工輸入" in part["label"] for part in preview["candidate"]["parts"]))
        with self.engine.connect() as conn:
            self.assertEqual(conn.execute(select(func.count()).select_from(standards.versions)).scalar(),1)
            self.assertEqual(dict(conn.execute(select(db.inspections)).mappings().one()),before)

    def test_auto_selection_uses_existing_ack_hash_and_save_guards(self):
        body=self.save_body()
        alternative=dict(RULE,prefix="283466543",day_width=2)
        with self.assertRaises(Conflict):rules.save(self.engine,"scan",dict(body,manual_rule=alternative))
        saved=rules.save(self.engine,"scan",body)
        self.assertEqual(saved["base_revision"],3)
        with self.engine.connect() as conn:
            snapshot=conn.execute(select(standards.versions.c.snapshot).where(standards.versions.c.revision==3)).scalar()
        self.assertEqual(snapshot["web_barcode_rule"],RULE)
        self.assertEqual(snapshot["web_barcode_rule_evidence"]["manual_entry"]["photo_date_hypothesis"]["kind"],"observed_hypothesis")

    def test_current_explicit_fixed_value_disables_recommendation(self):
        snapshot=deepcopy(self.source);snapshot["barcode_values"]=["2834665432436"]
        with self.engine.begin() as conn:
            conn.execute(update(standards.versions).where(standards.versions.c.code==CODE).values(snapshot=snapshot))
        entry=rules.suggest(self.engine,"scan")["manual_entry"]
        self.assertTrue(entry["fixed_barcode_reference"])
        self.assertTrue(entry["auto_candidates"])
        self.assertIsNone(entry["recommended_id"])

    def test_multi_label_and_ocr_conflict_never_expose_auto_candidates(self):
        for changes in ({"image_status":"multiple_labels"},{"barcodes":{"items":[{"format":"EAN13","text":"4006381333931","box":[]}]}}):
            ocr=dict(deepcopy(self.original["ocr"]),**changes)
            with self.engine.begin() as conn:conn.execute(update(db.inspections).where(db.inspections.c.id=="scan").values(ocr=ocr))
            entry=rules.suggest(self.engine,"scan")["manual_entry"]
            self.assertFalse(entry["available"])
            self.assertEqual(entry["auto_candidates"],[])
            self.assertIsNone(entry["recommended_id"])

    def test_declared_or_decoded_type_is_distinct_from_accepting_an_assumption(self):
        decoded=dict(deepcopy(self.original["ocr"]),barcodes={"items":[
            {"text":"2834665432436","format":"EAN13","box":[]}]})
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id=="scan").values(ocr=decoded))
        payload=rules.suggest(self.engine,"scan")
        self.assertEqual(payload["manual_entry"]["type_verification"],"decoded")
        self.assertFalse(payload["manual_entry"]["requires_ean13_confirmation"])
        body=dict(self.body(),confirmed_ean13=False)
        preview=rules.preview(self.engine,"scan",body)
        self.assertEqual(preview["candidate"]["evidence"]["type_verification"],"decoded")
        self.assertFalse(preview["candidate"]["evidence"]["ean13_assumption_accepted"])
        source=deepcopy(self.source);source["barcode_config"]={"kind":"1"}
        with self.engine.begin() as conn:
            conn.execute(update(db.manual_sources).where(db.manual_sources.c.code==CODE).values(snapshot=source))
            conn.execute(update(db.inspections).where(db.inspections.c.id=="scan").values(ocr=self.original["ocr"]))
        payload=rules.suggest(self.engine,"scan")
        self.assertEqual(payload["manual_entry"]["type_verification"],"source_config")
        self.assertFalse(payload["manual_entry"]["requires_ean13_confirmation"])
        preview=rules.preview(self.engine,"scan",dict(self.body(),confirmed_ean13=False))
        self.assertEqual(preview["candidate"]["evidence"]["type_verification"],"source_config")


if __name__=="__main__":unittest.main()
