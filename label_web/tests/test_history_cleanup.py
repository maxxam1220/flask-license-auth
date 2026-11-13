from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from flask import Flask, abort, jsonify, session
from sqlalchemy import select, insert, update, func
from werkzeug.exceptions import HTTPException

import database as db
import history_cleanup as cleanup


class HistoryCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.root=Path(self.temp.name)
        self.engine=db.open_database("",self.root)
        self.app=Flask(__name__);self.app.config.update(TESTING=True,SECRET_KEY="isolated-test-only")
        @self.app.errorhandler(HTTPException)
        def error(exc):
            return jsonify(error=exc.description),exc.code
        def require_admin():
            if not session.get("authenticated"):
                abort(401)
            if session.get("role")!="admin":
                abort(403)
        cleanup.register_routes(self.app,self.engine,require_admin)
        @self.app.get("/api/inspections/<identifier>")
        def inspection(identifier):
            return jsonify(id=identifier)
        @self.app.post("/api/inspections/<identifier>/corrections")
        def correction(identifier):
            return jsonify(id=identifier)
        self.client=self.app.test_client()
        with self.client.session_transaction() as saved:
            saved.update(authenticated=True,role="admin",csrf="test-csrf")
        self.headers={"X-CSRF-Token":"test-csrf"}
        self.photo=self.root/"photo.jpg";self.photo.write_bytes(b"original photo bytes")
        self.seed("first","pass","2026-11-12T16:00:00+00:00")
        self.seed("second","fail","2026-11-13T15:59:59+00:00")
        self.seed("outside","review","2026-11-13T16:00:00+00:00")

    def tearDown(self):
        self.engine.dispose();self.temp.cleanup()

    def seed(self,identifier,status="pass",created="2026-11-13T00:00:00+00:00"):
        with self.engine.begin() as conn:
            conn.execute(insert(db.inspections).values(id=identifier,image_id="shared-image",template_id="template",
                template_snapshot={"name":"label "+identifier,"fields":{"company":"unchanged"}},status=status,
                result={"checks":[{"status":status}]},ocr={"lines":[{"text":"raw original"}]},created_at=created))

    def post(self,path,body,client=None,headers=None):
        return (client or self.client).post("/api/admin/history/"+path,json=body,headers=headers or self.headers)

    def preview(self,filters=None):
        response=self.post("preview",{"filters":filters or {"ids":["first","second"]}})
        self.assertEqual(response.status_code,200,response.json)
        return response.json

    def archive(self,preview=None,**changes):
        preview=preview or self.preview()
        return self.post("archive",{"preview_id":preview["preview_id"],"preview_hash":preview["preview_hash"],
            "confirmed":True,"reviewer":"Test operator","note":"Reviewable test cleanup",**changes})

    def restore(self,batch,**changes):
        return self.post(f"batches/{batch}/restore",{"base_revision":1,"confirmed":True,"reviewer":"Restore reviewer",
            "note":"Restore requested records",**changes})

    def rows(self,table):
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(select(table)).mappings()]

    def active(self):
        with self.engine.connect() as conn:
            return conn.execute(select(db.inspections.c.id).where(cleanup.active_filter()).order_by(db.inspections.c.id)).scalars().all()

    def test_roundtrip_is_reversible_and_never_changes_original_records_or_photos(self):
        original=deepcopy(self.rows(db.inspections));photo=self.photo.read_bytes()
        preview=self.preview();response=self.archive(preview)
        self.assertEqual(response.status_code,201,response.json)
        batch=response.json["batch_id"]
        self.assertEqual(self.active(),["outside"])
        self.assertEqual(self.rows(db.inspections),original)
        self.assertEqual(self.photo.read_bytes(),photo)
        self.assertEqual(self.client.get("/api/inspections/first").status_code,404)
        self.assertEqual(self.client.post("/api/inspections/first/corrections").status_code,404)
        detail=self.client.get(f"/api/admin/history/batches/{batch}").json
        self.assertEqual(len(detail["items"]),2)
        self.assertEqual(detail["audit"][0]["operation"],"archive")
        restored=self.restore(batch)
        self.assertEqual(restored.status_code,200,restored.json)
        self.assertEqual(self.active(),["first","outside","second"])
        self.assertEqual(self.client.get("/api/inspections/first").status_code,200)
        self.assertEqual(self.rows(db.inspections),original)
        self.assertEqual(self.photo.read_bytes(),photo)
        self.assertEqual([row["operation"] for row in self.rows(cleanup.audit)],["archive","restore"])
        self.assertEqual(self.rows(cleanup.batches)[0]["revision"],2)

    def test_taiwan_date_range_is_inclusive_and_status_uses_original_result(self):
        preview=self.preview({"date_from":"2026-11-13","date_to":"2026-11-13"})
        self.assertEqual([x["id"] for x in preview["items"]],["first","second"])
        self.assertEqual(self.preview({"date_from":"2026-11-13","date_to":"2026-11-13","status":"fail"})["count"],1)
        self.assertEqual(preview["status_basis"],"original")

    def test_old_preview_never_adds_new_matching_records(self):
        preview=self.preview({"status":"pass"})
        self.seed("new-pass")
        response=self.archive(preview)
        self.assertEqual(response.status_code,201)
        self.assertIn("new-pass",self.active())
        self.assertEqual(response.json["count"],1)

    def test_changed_review_or_correction_invalidates_whole_preview(self):
        for change in ("review","correction"):
            preview=self.preview()
            with self.engine.begin() as conn:
                if change=="review":
                    conn.execute(insert(db.reviews).values(id=db.uid(),inspection_id="first",decision="confirmed_bad",
                        reviewer="new reviewer",note="changed",created_at=db.now()))
                else:
                    conn.execute(insert(db.corrections).values(id=db.uid(),inspection_id="first",revision=1,change={},patches=[],ocr={},
                        result={},status="fail",reviewer="new reviewer",note="changed",created_at=db.now()))
            response=self.archive(preview)
            self.assertEqual(response.status_code,409,response.json)
            self.assertEqual(len(self.active()),3)
            self.assertEqual(self.rows(cleanup.batches),[])
            self.assertTrue(all(row["state"]=="ready" for row in self.rows(cleanup.previews)))

    def test_previews_expire_hash_mismatch_and_reuse_are_rejected(self):
        preview=self.preview()
        self.assertEqual(self.archive(preview,preview_hash="0"*64).status_code,409)
        self.assertEqual(self.archive(preview,preview_hash="錯").status_code,400)
        with self.engine.begin() as conn:
            conn.execute(update(cleanup.previews).where(cleanup.previews.c.id==preview["preview_id"]).values(
                expires_at=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()))
        self.assertEqual(self.archive(preview).status_code,409)
        fresh=self.preview();self.assertEqual(self.archive(fresh).status_code,201)
        self.assertEqual(self.archive(fresh).status_code,409)

    def test_previews_are_bound_to_admin_session_and_permissions_fail_closed(self):
        preview=self.preview()
        other=self.app.test_client()
        self.assertEqual(other.get("/api/admin/history/batches").status_code,401)
        with other.session_transaction() as saved:
            saved.update(authenticated=True,role="operator",csrf="other")
        self.assertEqual(other.get("/api/admin/history/batches").status_code,403)
        self.assertEqual(self.post("preview",{"filters":{"status":"pass"}},other,{"X-CSRF-Token":"other"}).status_code,403)
        with other.session_transaction() as saved:
            saved["role"]="admin"
        response=self.post("archive",{"preview_id":preview["preview_id"],"preview_hash":preview["preview_hash"],
            "confirmed":True,"reviewer":"other","note":"other"},other,{"X-CSRF-Token":"other"})
        self.assertEqual(response.status_code,404)
        self.assertEqual(len(self.active()),3)

    def test_csrf_confirmation_and_cross_site_fail_without_mutation(self):
        body={"filters":{"status":"pass"}}
        self.assertEqual(self.client.post("/api/admin/history/preview",json=body).status_code,403)
        self.assertEqual(self.post("preview",body,headers={**self.headers,"Sec-Fetch-Site":"cross-site"}).status_code,403)
        self.assertEqual(self.archive(confirmed=False).status_code,400)
        self.assertEqual(self.archive(reviewer="").status_code,400)
        self.assertEqual(self.rows(cleanup.audit),[])

    def test_stale_restore_or_changed_tombstone_rolls_back_entire_batch(self):
        batch=self.archive().json["batch_id"]
        self.assertEqual(self.restore(batch,base_revision=2).status_code,409)
        with self.engine.begin() as conn:
            conn.execute(update(cleanup.tombstones).where(cleanup.tombstones.c.inspection_id=="second").values(revision=99))
        self.assertEqual(self.restore(batch).status_code,409)
        self.assertEqual(self.active(),["outside"])
        self.assertEqual(self.rows(cleanup.batches)[0]["status"],"archived")
        self.assertEqual(len(self.rows(cleanup.audit)),1)

    def test_rearchiving_after_restore_keeps_old_batch_immutable(self):
        first=self.archive().json["batch_id"]
        self.assertEqual(self.restore(first).status_code,200)
        second=self.archive().json["batch_id"]
        self.assertNotEqual(first,second)
        self.assertEqual(self.restore(first).status_code,409)
        self.assertEqual(self.active(),["outside"])
        self.assertEqual(self.restore(second).status_code,200)
        self.assertEqual(len(self.rows(cleanup.audit)),4)

    def test_invalid_filters_and_selection_are_rejected(self):
        for filters in ({},{"ids":[]},{"ids":["first","first"]},{"ids":["first"],"status":"pass"},
                        {"ids":[{}]},{"ids":["x"]*501},{"status":[]},{"date_from":"2026-02-30"},
                        {"date_from":"2026-11-14","date_to":"2026-11-13"},{"table":"images"}):
            self.assertEqual(self.post("preview",{"filters":filters}).status_code,400,filters)
        self.assertEqual(self.post("preview",{"filters":{"ids":["absent"]}}).status_code,409)
        empty=self.preview({"date_to":"2000-01-01"})
        self.assertEqual(empty["count"],0)
        self.assertEqual(self.archive(empty).status_code,400)

    def test_expired_preview_cache_is_pruned_without_removing_batches_or_active_previews(self):
        used=self.preview();batch=self.archive(used).json["batch_id"]
        self.assertEqual(next(row for row in self.rows(cleanup.previews) if row["id"]==used["preview_id"])["entries"],[])
        expired=self.preview({"ids":["outside"]})
        active=self.preview({"ids":["outside"]})
        before=self.rows(db.inspections)
        with self.engine.begin() as conn:
            conn.execute(update(cleanup.previews).where(cleanup.previews.c.id.in_([used["preview_id"],expired["preview_id"]]))
                .values(expires_at=(datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()))
        self.preview({"ids":["outside"]})
        remaining={row["id"] for row in self.rows(cleanup.previews)}
        self.assertIn(active["preview_id"],remaining)
        self.assertNotIn(expired["preview_id"],remaining)
        self.assertNotIn(used["preview_id"],remaining)
        self.assertEqual(self.rows(db.inspections),before)
        self.assertEqual(len(self.rows(cleanup.audit)),1)
        self.assertEqual(len(self.rows(cleanup.batches)),1)
        self.assertEqual(self.restore(batch).status_code,200)
        self.assertEqual(self.photo.read_bytes(),b"original photo bytes")

    def test_more_than_500_is_rejected_and_batch_listing_is_bounded(self):
        with self.engine.begin() as conn:
            conn.execute(insert(db.inspections),[dict(id=f"bulk-{i}",image_id="shared-image",template_id="template",
                template_snapshot={"name":"bulk"},status="pass",result={},ocr={},created_at=db.now()) for i in range(500)])
        self.assertEqual(self.post("preview",{"filters":{"status":"pass"}}).status_code,400)
        listed=self.client.get("/api/admin/history/batches").json
        self.assertEqual(listed,{"items":[],"page":1,"has_more":False})
        self.assertEqual(self.client.get("/api/admin/history/batches?page=0").status_code,400)


if __name__=="__main__":
    unittest.main()
