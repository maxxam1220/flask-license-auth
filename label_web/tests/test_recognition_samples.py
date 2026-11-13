from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from flask import Flask, abort, jsonify, session
from sqlalchemy import insert, select, update
from werkzeug.exceptions import HTTPException

import database as db
import history_cleanup
import recognition_samples as samples


class RecognitionSampleTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.engine = db.open_database("", self.root)
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, SECRET_KEY="candidate-test-only")
        @self.app.errorhandler(HTTPException)
        def error(exc):
            return jsonify(error=exc.description), exc.code
        def require_admin():
            if not session.get("authenticated"):
                abort(401)
            if session.get("role") != "admin":
                abort(403)
        samples.register_routes(self.app, self.engine, require_admin, self.root)
        self.client = self.app.test_client()
        with self.client.session_transaction() as saved:
            saved.update(authenticated=True, role="admin")
        self.add("first")

    def tearDown(self):
        self.engine.dispose()
        self.temp.cleanup()

    def add(self, identifier, target="實際印字", kind="ocr_misread", image_id=None,
            image_hash="a" * 64, box=None, present=True):
        image_id = image_id or "image-" + identifier
        box = box if box is not None else [[10, 10], [160, 10], [160, 40], [10, 40]]
        with self.engine.begin() as conn:
            if not conn.execute(select(db.images.c.id).where(db.images.c.id == image_id)).first():
                conn.execute(insert(db.images).values(id=image_id, created_at=db.now(), filename="private-photo.jpg",
                    sha256=image_hash, width=200, height=100))
            conn.execute(insert(db.inspections).values(id=identifier, image_id=image_id, template_id="",
                template_snapshot={"name":"標準名稱", "source":{"code":"manual:one", "lines":[{"text":"不可用作訓練答案"}]}},
                status="fail", result={"checks":[]}, created_at=db.now(),
                ocr={"engine":"RapidOCR / PP-OCRv6 medium-rec", "preprocessing":{"det_limit":1600},
                     "lines":[{"id":0, "text":"OCR原字", "score":0.8, "box":box}]}))
        if present:
            folder = self.root / "images" / image_id
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "image.jpg").write_bytes(b"unchanged photo bytes; never decode")
        self.revision(identifier, 1, target, kind)

    def revision(self, identifier, revision, target="實際印字", kind="ocr_misread", empty=False):
        with self.engine.begin() as conn:
            conn.execute(insert(db.corrections).values(id=db.uid(), inspection_id=identifier, revision=revision,
                change={"operation":"revoke" if empty else "replace", "line_id":0},
                patches=[] if empty else [{"line_id":0,"kind":kind,"text":target,"reviewer":"確認人","note":"逐字確認","created_at":db.now()}],
                ocr={}, result={}, status="review", reviewer="確認人", note="理由", created_at=db.now()))

    def get(self, suffix=""):
        return self.client.get("/api/admin/recognition-samples" + suffix)

    def exported(self):
        response = self.get("/export")
        self.assertEqual(response.status_code, 200, response.data)
        return [json.loads(line) for line in response.data.decode().splitlines()]

    def test_candidate_has_exact_human_text_raw_box_provenance_but_no_standard_truth(self):
        before = {}
        with self.engine.connect() as conn:
            for table in (db.inspections, db.images, db.corrections):
                before[table.name] = [dict(row) for row in conn.execute(select(table)).mappings()]
        response = self.get()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["counts"]["candidates"], 1)
        self.assertFalse(response.json["training_ready"])
        self.assertTrue(response.json["requires_review"])
        record = self.exported()[0]
        self.assertEqual(record["raw_text"], "OCR原字")
        self.assertEqual(record["corrected_text"], "實際印字")
        self.assertEqual(record["coordinate_space"], "normalized_image.jpg")
        self.assertEqual(record["image"]["url"], "/media/image-first/image.jpg")
        self.assertEqual(record["provenance"][0]["correction_revision"], 1)
        self.assertNotIn("不可用作訓練答案", json.dumps(record, ensure_ascii=False))
        self.assertNotIn(str(self.root), json.dumps(record))
        self.assertEqual(self.get("/export").headers["Cache-Control"], "no-store")
        self.assertIn("attachment", self.get("/export").headers["Content-Disposition"])
        with self.engine.connect() as conn:
            for table in (db.inspections, db.images, db.corrections):
                self.assertEqual([dict(row) for row in conn.execute(select(table)).mappings()], before[table.name])
        self.assertEqual((self.root / "images/image-first/image.jpg").read_bytes(), b"unchanged photo bytes; never decode")

    def test_only_latest_effective_revision_is_used_and_revoke_removes_sample(self):
        self.revision("first", 2, target="新版實印字")
        self.assertEqual(self.exported()[0]["corrected_text"], "新版實印字")
        self.revision("first", 3, empty=True)
        self.assertEqual(self.get().json["counts"]["candidates"], 0)
        self.assertEqual(self.get("/export").status_code, 409)

    def test_uncertain_and_label_misprint_are_never_training_targets(self):
        for kind in ("uncertain", "label_misprint"):
            with self.subTest(kind=kind):
                self.revision("first", 2 if kind == "uncertain" else 3, target="應印標準", kind=kind)
                result = self.get().json
                self.assertEqual(result["counts"]["candidates"], 0)
                self.assertEqual(result["counts"]["excluded_kind"], 1)

    def test_same_photo_hash_and_box_dedupes_rechecks_and_vertex_rotation(self):
        self.add("second", box=[[160,10],[160,40],[10,40],[10,10]])
        result = self.get().json
        self.assertEqual(result["counts"]["eligible_observations"], 2)
        self.assertEqual(result["counts"]["candidates"], 1)
        self.assertEqual(result["counts"]["duplicate_observations"], 1)
        self.assertEqual(len(self.exported()[0]["provenance"]), 2)

    def test_conflicting_human_answers_exclude_entire_crop_without_normalizing(self):
        self.add("second", target="实际印字")
        result = self.get().json
        self.assertEqual(result["counts"]["conflict_groups"], 1)
        self.assertEqual(result["counts"]["candidates"], 0)
        self.assertEqual(self.get("/export").status_code, 409)

    def test_duplicate_marked_uncertain_blocks_another_auto_candidate(self):
        self.add("second", kind="uncertain")
        self.assertEqual(self.get().json["counts"]["conflict_groups"], 1)
        self.assertEqual(self.get().json["counts"]["candidates"], 0)

    def test_archived_inspection_is_excluded_but_active_duplicate_remains(self):
        self.add("second")
        with self.engine.begin() as conn:
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="first", batch_id="batch",
                archived=True, revision=1, updated_at=db.now()))
        result = self.get().json
        self.assertEqual(result["counts"]["excluded_archived"], 1)
        self.assertEqual(result["counts"]["candidates"], 1)
        self.assertEqual([p["inspection_id"] for p in self.exported()[0]["provenance"]], ["second"])

    def test_invalid_and_out_of_bounds_boxes_are_not_exported(self):
        for index, box in enumerate(([], [[0,0]]*4, [[-1,0],[10,0],[10,10],[0,10]],
            [[0,0],[201,0],[201,10],[0,10]], [[True,0],[10,0],[10,10],[0,10]])):
            self.add("bad"+str(index), box=box, image_hash=str(index)*64)
        result = self.get().json
        self.assertEqual(result["counts"]["excluded_invalid"], 5)
        self.assertEqual(result["counts"]["candidates"], 1)
        self.assertIsNone(samples._box([[0,0],[float("nan"),0],[10,10],[0,10]],200,100))
        self.assertIsNone(samples._box([[0,0],[10**400,0],[10,10],[0,10]],200,100))

    def test_optional_nonfinite_metadata_cannot_break_streamed_jsonl(self):
        summary, records = samples.collect(self.engine, self.root)
        records[0]["raw_score"] = float("nan")
        records[0]["provenance"][0]["raw_score"] = float("inf")
        with patch.object(samples, "collect", return_value=(summary, records)):
            result = self.exported()[0]
        self.assertIsNone(result["raw_score"])
        self.assertIsNone(result["provenance"][0]["raw_score"])

    def test_derivative_origin_is_preserved_for_grouped_train_test_split(self):
        origin = {"inspection_id":"parent", "image_id":"original-image",
                  "crop":{"x":20,"y":30,"width":200,"height":100}}
        with self.engine.begin() as conn:
            conn.execute(update(db.inspections).where(db.inspections.c.id == "first").values(
                result={"checks":[], "recognition_of":origin}))
        self.assertEqual(self.exported()[0]["provenance"][0]["recognition_of"], origin)
        self.assertIn("衍生裁切不可跨", self.get().json["notice"])

    def test_missing_photo_and_path_escape_do_not_become_candidates(self):
        self.add("missing", present=False, image_hash="b"*64)
        self.assertFalse(samples._image_available(self.root, "../elsewhere"))
        self.assertEqual(self.get().json["counts"]["excluded_missing_image"], 1)
        self.assertEqual(self.get().json["counts"]["candidates"], 1)

    def test_limits_never_export_partial_pool_that_might_hide_later_conflict(self):
        self.add("second", target="矛盾文字")
        for name in ("MAX_INSPECTIONS", "MAX_OBSERVATIONS"):
            with self.subTest(name=name), patch.object(samples, name, 1):
                result = self.get().json
                self.assertTrue(result["truncated"])
                self.assertFalse(result["download_available"])
                self.assertEqual(self.get("/export").status_code, 409)

    def test_both_endpoints_require_admin_and_reject_arbitrary_filters(self):
        for suffix in ("", "/export"):
            self.assertEqual(self.get(suffix+"?path=anything").status_code, 400)
        with self.client.session_transaction() as saved:
            saved["role"] = "operator"
        for suffix in ("", "/export"):
            self.assertEqual(self.get(suffix).status_code, 403)
        with self.client.session_transaction() as saved:
            saved.clear()
        for suffix in ("", "/export"):
            self.assertEqual(self.get(suffix).status_code, 401)


if __name__ == "__main__":
    unittest.main()
