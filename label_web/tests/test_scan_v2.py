"""Offline integration checks for paid-call limits and physical label evidence."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import io
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from PIL import Image
from sqlalchemy import func, insert, select
from sqlalchemy.exc import IntegrityError

import barcode_checks
import cloud_budget
from cloud_vision import CloudVisionError
import corrections
import database as db
from inspection_evidence import augment
from server import create_app
from sticker_scope import recognize_scoped
from test_validation import make_lines, STANDARD
from validation import evaluate


def numeric_line(text="2004486115249", **changes):
    row={"id":9,"text":text,"score":.99,"box":[[30,100],[230,100],[230,125],[30,125]]}
    row.update(changes)
    return row


def decoded(text="2004486115249", format="Code128"):
    return {"state":"decoded","items":[{"text":text,"format":format,
            "box":[[30,40],[230,40],[230,95],[30,95]]}]}


class BarcodeEvidenceTests(unittest.TestCase):
    def test_code128_numeric_payload_does_not_inherit_ean_checksum(self):
        value="12345678"  # Deliberately not a valid GTIN-8; valid Code128 payload.
        checks=barcode_checks.checks_for({"lines":[numeric_line(value)],"barcodes":decoded(value)})
        self.assertFalse(any(c["key"].startswith("barcode_checksum") for c in checks))
        self.assertEqual(next(c for c in checks if c["key"]=="barcode_hri")["status"],"pass")

    def test_explicit_gtin_wrong_check_digit_fails_but_uncertain_read_is_review(self):
        for extra,status in (({},"fail"),({"ambiguous":True},"review")):
            checks=barcode_checks.checks_for({"lines":[numeric_line("GTIN:12345678",**extra)],"barcodes":{"items":[]}})
            self.assertEqual(next(c for c in checks if c["key"].startswith("barcode_checksum"))["status"],status)

    def test_unlabelled_eight_digits_alone_never_prove_ean(self):
        checks=barcode_checks.checks_for({"lines":[numeric_line("20261116")],"barcodes":{"items":[]}})
        self.assertFalse(any(c["key"].startswith("barcode_checksum") for c in checks))
        self.assertFalse(any(c["status"]=="pass" for c in checks))

    def test_far_standalone_date_is_not_assigned_to_the_only_barcode(self):
        date_line=numeric_line("20261116",box=[[600,450],[760,450],[760,480],[600,480]])
        checks=barcode_checks.checks_for({"lines":[date_line],"barcodes":decoded()})
        self.assertFalse(any(c["key"]=="barcode_hri" for c in checks),checks)

    def test_human_verified_hri_can_resolve_original_low_confidence(self):
        row=numeric_line(score=.2,ambiguous=True,human_verified=True,human_uncertain=False)
        checks=barcode_checks.checks_for({"lines":[row],"barcodes":decoded()})
        self.assertEqual(next(c for c in checks if c["key"]=="barcode_hri")["status"],"pass")

    def test_ocr_hri_disagreement_needs_review_until_human_confirms_the_print(self):
        for extra,expected in (({},"review"),({"human_verified":True},"fail"),
                               ({"human_verified":True,"human_uncertain":True},"review")):
            with self.subTest(extra=extra):
                checks=barcode_checks.checks_for({"lines":[numeric_line("2004486115248",**extra)],"barcodes":decoded()})
                self.assertEqual(next(c for c in checks if c["key"]=="barcode_hri")["status"],expected)

    def test_upce_uses_expansion_not_gtin8_formula(self):
        # UPC-A 042100005264 compresses to valid UPC-E 04252614.
        checks=barcode_checks.checks_for({"lines":[numeric_line("04252614")],"barcodes":decoded("04252614","UPC-E")})
        self.assertFalse(any(c["status"]=="fail" for c in checks),checks)

    def test_multiple_decoded_barcodes_require_scope_review(self):
        codes=decoded();codes["items"].append(decoded("12345678")["items"][0])
        checks=barcode_checks.checks_for({"lines":[],"barcodes":codes})
        self.assertEqual(next(c for c in checks if c["key"]=="barcode_multiple")["status"],"review")


class ScopeAndCorrectionTests(unittest.TestCase):
    def original(self,ocr):
        result=evaluate(ocr["lines"],STANDARD,"2026-11-10")
        result["inputs"]={"base_date":"2026-11-10","batch_date":"2026-11-10","arrival_date":"","source_code":""}
        augment(result,ocr)
        return {"id":"a"*32,"status":result["status"],"result":result,"ocr":deepcopy(ocr),
                "template_snapshot":deepcopy(STANDARD)}

    def correction(self,original,line_id,text):
        action={"operation":"replace","kind":"ocr_misread","line_id":line_id,"text":text,
                "reviewer":"QA","note":"原圖逐字核對"}
        return corrections.build_revision(original,None,action,"2026-11-16T00:00:00+00:00")

    def test_multiple_surfaces_demote_all_passes_and_repeat_augmentation_is_idempotent(self):
        result={"checks":[{"key":"product","status":"pass","reason":"match"}],"status":"pass"}
        ocr={"lines":[],"label_scope":{"status":"multiple"},"barcodes":decoded()}
        augment(result,ocr)
        first=deepcopy(result)
        augment(result,ocr)
        self.assertEqual(result,first)
        self.assertEqual(result["status"],"review")
        self.assertFalse(any(c["status"]=="pass" for c in result["checks"]))

    def test_correction_cannot_remove_multiple_label_scope_or_barcode_evidence(self):
        ocr={"lines":make_lines(),"label_scope":{"status":"multiple","candidates":[{},{}]},"barcodes":decoded(),"engine":"test"}
        original=self.original(ocr);before=deepcopy(original)
        revised=self.correction(original,0,ocr["lines"][0]["text"])
        self.assertEqual(original,before)
        self.assertEqual(revised["ocr"]["barcodes"],ocr["barcodes"])
        self.assertEqual(revised["ocr"]["label_scope"],ocr["label_scope"])
        self.assertEqual(revised["result"]["inputs"],original["result"]["inputs"])
        self.assertEqual(revised["status"],"review")
        self.assertTrue(any(c["key"]=="photo_scope" for c in revised["result"]["checks"]))
        self.assertFalse(any(c["status"]=="pass" for c in revised["result"]["checks"]))

    def test_confirmed_cloud_typo_suggestion_no_longer_overrides_human_observation(self):
        lines=make_lines()
        lines[0].update(suspected_typo=True,typo_candidates=["品名：雙拚水果盒"],ambiguous=True,
                        score=0.,score_kind="uncertainty_gate",confidence=None)
        ocr={"lines":lines,"provider":"openai","engine":"mock cloud"}
        original=self.original(ocr)
        revised=self.correction(original,0,lines[0]["text"])
        self.assertFalse(any(c["key"].startswith("cloud_word_") for c in revised["result"]["checks"]),revised["result"]["checks"])
        self.assertTrue(original["ocr"]["lines"][0]["suspected_typo"])

    def test_scoped_crop_translates_lines_alternatives_and_bars_without_changing_photo(self):
        region={"x":100,"y":50,"width":300,"height":200,"polygon":[[100,50],[400,50],[400,250],[100,250]],
                "method":"test","auto_selected":True}
        observed=numeric_line();observed["alternatives"]=[deepcopy(observed)]
        recognizer=Mock();recognizer.recognize.return_value={"lines":[observed],"engine":"mock","elapsed":.01}
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"photo.png";Image.new("RGB",(640,480),"gray").save(path);before=path.read_bytes()
            with patch("sticker_scope.detect_sticker",return_value={"status":"selected","region":region,"candidates":[region]}), \
                 patch("barcode_checks.decode_barcodes",return_value=decoded()):
                result=recognize_scoped(path,recognizer)
            self.assertEqual(path.read_bytes(),before)
        self.assertEqual(result["lines"][0]["box"][0],[130,150])
        self.assertEqual(result["lines"][0]["alternatives"][0]["box"][0],[130,150])
        self.assertEqual(result["barcodes"]["items"][0]["box"][0],[130,90])
        self.assertEqual(observed["box"][0],[30,100])
        self.assertEqual(result["image_size"],{"width":640,"height":480})

    def test_multiple_surfaces_are_not_silently_cropped_to_the_largest(self):
        recognizer=Mock();recognizer.recognize.return_value={"lines":[],"engine":"mock","elapsed":.01}
        detection={"status":"multiple","region":None,"candidates":[{"x":0},{"x":200}]}
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"photo.png";Image.new("RGB",(640,480),"white").save(path)
            with patch("sticker_scope.detect_sticker",return_value=detection),patch("barcode_checks.decode_barcodes",return_value={"items":[]}):
                result=recognize_scoped(path,recognizer)
            self.assertEqual(Path(recognizer.recognize.call_args.args[0]),path)
        self.assertEqual(result["label_scope"],detection)


class PersistentBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.engine=db.open_database("",self.root);cloud_budget.initialize(self.engine)

    def tearDown(self):
        self.engine.dispose();self.temp.cleanup()

    def count(self):
        with self.engine.connect() as conn:
            return conn.scalar(select(func.count()).select_from(cloud_budget.calls))

    def test_limit_twenty_is_atomic_under_concurrent_attempts(self):
        def attempt(index):
            try:
                cloud_budget.reserve(self.engine,f"{index:032x}","mock",20)
                return True
            except RuntimeError:
                return False
        with ThreadPoolExecutor(max_workers=8) as workers:
            results=list(workers.map(attempt,range(32)))
        self.assertEqual(sum(results),20)
        self.assertEqual(self.count(),20)
        self.assertEqual(cloud_budget.remaining(self.engine,20),0)

    def test_failed_and_unknown_calls_still_count_after_reopen(self):
        cloud_budget.reserve(self.engine,"a"*32,"mock",20)
        cloud_budget.finish(self.engine,"a"*32,"failed",error_code="timeout")
        cloud_budget.reserve(self.engine,"b"*32,"mock",20)  # Simulate process death after reservation.
        self.engine.dispose();self.engine=db.open_database("",self.root);cloud_budget.initialize(self.engine)
        self.assertEqual(cloud_budget.remaining(self.engine,20),18)
        self.assertEqual(self.count(),2)

    def test_duplicate_job_reservation_rolls_back_counter_increment(self):
        cloud_budget.reserve(self.engine,"a"*32,"mock",20)
        with self.assertRaises(IntegrityError):
            cloud_budget.reserve(self.engine,"a"*32,"mock",20)
        self.assertEqual(cloud_budget.remaining(self.engine,20),19)
        self.assertEqual(self.count(),1)


class CountingCloud:
    def __init__(self):
        self.calls=0;self.error=None

    def recognize(self,path):
        self.calls+=1
        if self.error:raise self.error
        return {"lines":make_lines(),"engine":"mock cloud","provider":"openai","elapsed":.01,
                "usage":{"input_tokens":30,"output_tokens":10,"total_tokens":40}}


class PaidScanAPITests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.cloud=CountingCloud()
        self.local=CountingCloud()
        self.app=create_app({"TESTING":True,"DATA_DIR":self.root,"DATABASE_URL":"","APP_PASSWORD":"",
            "CLOUD_OCR":self.cloud,"CLOUD_TRIAL_LIMIT":20},ocr=self.local)
        self.engine=self.app.extensions["label_engine"]
        self.client=self.app.test_client()
        self.headers={"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}
        self.app.logger.disabled=True

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True);self.engine.dispose();self.temp.cleanup()
        self.app.logger.disabled=False

    def photo(self):
        image=io.BytesIO();Image.new("RGB",(640,480),"white").save(image,"PNG");image.seek(0);return image

    def upload(self,request_id="a"*32,**changes):
        return self.client.post("/api/jobs",data={"kind":"recognition","recognition_engine":"cloud",
            "label_scope":"full","base_date":"2026-11-10","request_id":request_id,"photo":(self.photo(),"photo.png"),**changes},headers=self.headers)

    def wait(self,identifier):
        for _ in range(200):
            job=self.client.get("/api/jobs/"+identifier).json
            if job["state"] in ("done","failed"):return job
            time.sleep(.01)
        self.fail("Job did not finish")

    def test_initial_upload_same_request_id_does_not_pay_twice(self):
        first=self.upload();self.assertEqual(first.status_code,202,first.json);self.wait(first.json["id"])
        second=self.upload();self.assertEqual(second.status_code,202,second.json);self.wait(second.json["id"])
        self.assertEqual(first.json["id"],second.json["id"])
        self.assertEqual(self.cloud.calls,1)
        self.assertEqual(cloud_budget.remaining(self.engine,20),19)

    def test_initial_upload_replay_at_exhausted_limit_returns_existing_job(self):
        self.app.config["CLOUD_TRIAL_LIMIT"]=1
        first=self.upload();self.assertEqual(first.status_code,202,first.json);self.wait(first.json["id"])
        second=self.upload()
        self.assertEqual(second.status_code,202,second.json)
        self.assertEqual(first.json["id"],second.json["id"])
        self.assertEqual(self.cloud.calls,1)

    def test_initial_upload_same_id_cannot_change_scope_date_or_photo(self):
        first=self.upload();self.assertEqual(first.status_code,202,first.json);self.wait(first.json["id"])
        for changes in ({"base_date":"2026-11-11"},{"label_scope":"sticker"},{"recognition_engine":"local"}):
            changed=self.upload(**changes)
            self.assertEqual(changed.status_code,409,changed.json)
        photo=io.BytesIO();Image.new("RGB",(640,480),"black").save(photo,"PNG");photo.seek(0)
        changed=self.upload(photo=(photo,"photo.png"))
        self.assertEqual(changed.status_code,409,changed.json)
        self.assertEqual(self.cloud.calls,1)

    def test_failed_initial_upload_replay_does_not_charge_another_call(self):
        self.cloud.error=CloudVisionError("timeout",request_may_be_billed=True)
        first=self.upload();self.assertEqual(first.status_code,202,first.json)
        self.assertEqual(self.wait(first.json["id"])["state"],"failed")
        second=self.upload();self.assertEqual(second.status_code,202,second.json)
        self.assertEqual(first.json["id"],second.json["id"])
        self.assertEqual(self.cloud.calls,1)

    def test_successful_re_recognition_replay_stays_idempotent_even_after_budget_exhausted(self):
        first=self.upload();job=self.wait(first.json["id"])
        identifier=job["result"]["inspection_id"]
        self.app.config["CLOUD_TRIAL_LIMIT"]=2
        body={"request_id":"b"*32,"recognition_engine":"cloud","label_scope":"full"}
        url=f"/api/inspections/{identifier}/recognize"
        second=self.client.post(url,json=body,headers=self.headers)
        done=self.wait(second.json["id"])
        again=self.client.post(url,json=body,headers=self.headers)
        self.assertEqual(again.status_code,202,again.json)
        self.assertEqual(again.json,second.json)
        self.assertEqual(self.cloud.calls,2)
        self.assertEqual(done["result"]["request"]["base_date"],"2026-11-10")
        changed=self.client.post(url,json={**body,"label_scope":"sticker"},headers=self.headers)
        self.assertEqual(changed.status_code,409)
        self.assertEqual(self.cloud.calls,2)

    def test_failed_cloud_request_counts_once_and_failed_re_recognition_replay_does_not_retry(self):
        first=self.upload();job=self.wait(first.json["id"])
        identifier=job["result"]["inspection_id"]
        self.cloud.error=CloudVisionError("timeout",request_may_be_billed=True)
        body={"request_id":"c"*32,"recognition_engine":"cloud","label_scope":"full"}
        url=f"/api/inspections/{identifier}/recognize"
        second=self.client.post(url,json=body,headers=self.headers);failed=self.wait(second.json["id"])
        self.assertEqual(failed["state"],"failed")
        self.assertIn("逾時",failed["error"])
        again=self.client.post(url,json=body,headers=self.headers)
        self.assertEqual(again.json,second.json)
        self.assertEqual(self.cloud.calls,2)
        self.assertEqual(cloud_budget.remaining(self.engine,20),18)
        with self.engine.connect() as conn:
            call=conn.execute(select(cloud_budget.calls).where(cloud_budget.calls.c.job_id==second.json["id"])).mappings().one()
        self.assertEqual((call["state"],call["error_code"]),("failed","timeout"))

    def test_paid_token_usage_survives_a_later_validation_failure(self):
        with patch("server.augment",side_effect=RuntimeError("offline validation failure")):
            submitted=self.upload()
            self.assertEqual(submitted.status_code,202,submitted.json)
            failed=self.wait(submitted.json["id"])
        self.assertEqual(failed["state"],"failed")
        self.assertEqual(self.cloud.calls,1)
        self.assertEqual(cloud_budget.remaining(self.engine,20),19)
        with self.engine.connect() as conn:
            call=conn.execute(select(cloud_budget.calls).where(cloud_budget.calls.c.job_id==submitted.json["id"])).mappings().one()
        self.assertEqual(call["usage"],{"input_tokens":30,"output_tokens":10,"total_tokens":40})

    def test_retry_of_same_failed_parent_is_idempotent_even_when_child_also_failed(self):
        self.cloud.error=CloudVisionError("timeout",request_may_be_billed=True)
        original=self.upload();self.assertEqual(original.status_code,202,original.json)
        self.assertEqual(self.wait(original.json["id"])["state"],"failed")
        url=f"/api/jobs/{original.json['id']}/retry"
        retry=self.client.post(url,headers=self.headers)
        self.assertEqual(retry.status_code,202,retry.json)
        self.assertEqual(self.wait(retry.json["id"])["state"],"failed")
        replay=self.client.post(url,headers=self.headers)
        self.assertEqual(replay.status_code,202,replay.json)
        self.assertEqual(replay.json["id"],retry.json["id"])
        self.assertEqual(self.cloud.calls,2)
        # An intentional further retry targets the newest failed attempt.
        next_try=self.client.post(f"/api/jobs/{retry.json['id']}/retry",headers=self.headers)
        self.assertEqual(next_try.status_code,202,next_try.json)
        self.assertNotEqual(next_try.json["id"],retry.json["id"])
        self.wait(next_try.json["id"])
        self.assertEqual(self.cloud.calls,3)

    def test_failed_cloud_can_explicitly_retry_locally_without_key_or_budget(self):
        self.cloud.error=CloudVisionError("quota",request_may_be_billed=True)
        submitted=self.upload(batch_date="2026-11-09",arrival_date="2026-11-11")
        failed=self.wait(submitted.json["id"])
        self.assertEqual(failed["state"],"failed")
        self.app.config.update(CLOUD_OCR=None,CLOUD_TRIAL_LIMIT=0)
        url=f"/api/jobs/{failed['id']}/retry"
        with patch.dict(os.environ,{"OPENAI_API_KEY":""}):
            retried=self.client.post(url,json={"recognition_engine":"local"},headers=self.headers)
            self.assertEqual(retried.status_code,202,retried.json)
            completed=self.wait(retried.json["id"])
            replay=self.client.post(url,json={"recognition_engine":"local"},headers=self.headers)
        self.assertEqual(completed["state"],"done",completed.get("error"))
        self.assertEqual(replay.status_code,202,replay.json)
        self.assertEqual(replay.json["id"],completed["id"])
        self.assertEqual(completed["result"]["request"],{**failed["result"]["request"],"recognition_engine":"local"})
        self.assertEqual(completed["image_id"],failed["image_id"])
        self.assertEqual(completed["batch_date"],failed["batch_date"])
        self.assertEqual(completed["result"]["retry_of"],failed["id"])
        self.assertEqual((self.cloud.calls,self.local.calls),(1,1))
        self.assertEqual(cloud_budget.remaining(self.engine,20),19)
        self.assertEqual(self.client.get(f"/api/jobs/{failed['id']}").json["result"],failed["result"])

    def test_retry_engine_change_conflicts_with_existing_child_in_both_directions(self):
        self.cloud.error=CloudVisionError("timeout",request_may_be_billed=True)
        self.local.error=RuntimeError("offline local failure")
        for index,first_engine,changed_engine in ((1,"cloud","local"),(2,"local","cloud")):
            with self.subTest(first_engine=first_engine):
                original=self.upload(request_id=f"{index:032x}")
                failed=self.wait(original.json["id"])
                url=f"/api/jobs/{failed['id']}/retry"
                child=self.client.post(url,json={"recognition_engine":first_engine},headers=self.headers)
                self.assertEqual(child.status_code,202,child.json)
                self.assertEqual(self.wait(child.json["id"])["state"],"failed")
                before=(self.cloud.calls,self.local.calls)
                changed=self.client.post(url,json={"recognition_engine":changed_engine},headers=self.headers)
                self.assertEqual(changed.status_code,409,changed.json)
                self.assertIn("最新工作",changed.json["error"])
                replay=self.client.post(url,json={"recognition_engine":first_engine},headers=self.headers)
                self.assertEqual(replay.status_code,202,replay.json)
                self.assertEqual(replay.json["id"],child.json["id"])
                self.assertEqual((self.cloud.calls,self.local.calls),before)
                if first_engine=="cloud":
                    latest=self.client.post(f"/api/jobs/{child.json['id']}/retry",json={"recognition_engine":"local"},headers=self.headers)
                    self.assertEqual(latest.status_code,202,latest.json)
                    self.wait(latest.json["id"])
                else:
                    omitted=self.client.post(url,headers=self.headers)
                    self.assertEqual(omitted.status_code,409,omitted.json)

    def test_local_retry_cannot_upgrade_to_cloud_or_change_original_settings(self):
        self.local.error=RuntimeError("offline local failure")
        original=self.upload(recognition_engine="local")
        failed=self.wait(original.json["id"])
        url=f"/api/jobs/{failed['id']}/retry"
        for body in ({"recognition_engine":"cloud"},{"recognition_engine":"unknown"},
                     {"recognition_engine":None},{"recognition_engine":[]},
                     {"recognition_engine":"local","label_scope":"sticker"},
                     {"base_date":"2026-11-12"},[]):
            with self.subTest(body=body):
                response=self.client.post(url,json=body,headers=self.headers)
                self.assertEqual(response.status_code,400,response.json)
        malformed=self.client.post(url,data="{",content_type="application/json",headers=self.headers)
        self.assertEqual(malformed.status_code,400,malformed.json)
        self.assertEqual((self.cloud.calls,self.local.calls),(0,1))
        # No request body preserves the existing legacy local retry contract.
        legacy=self.client.post(url,headers=self.headers)
        self.assertEqual(legacy.status_code,202,legacy.json)
        self.assertEqual(self.wait(legacy.json["id"])["state"],"failed")
        same=self.client.post(url,json={"recognition_engine":"local"},headers=self.headers)
        self.assertEqual(same.json["id"],legacy.json["id"])
        self.assertEqual((self.cloud.calls,self.local.calls),(0,2))

    def test_manual_crop_does_not_relocate_or_replace_historical_date(self):
        first=self.upload();job=self.wait(first.json["id"]);identifier=job["result"]["inspection_id"]
        response=self.client.post(f"/api/inspections/{identifier}/recognize",json={"request_id":"d"*32,
            "recognition_engine":"cloud","label_scope":"sticker","crop":{"x":100,"y":80,"width":300,"height":200}},headers=self.headers)
        done=self.wait(response.json["id"])
        self.assertEqual(done["result"]["request"]["label_scope"],"full")
        self.assertEqual(done["result"]["request"]["base_date"],"2026-11-10")
        self.assertEqual(done["result"]["ocr"]["image_size"],{"width":300,"height":200})


if __name__=="__main__":
    unittest.main()
