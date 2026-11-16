from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from sqlalchemy import insert,select,func

import database as db
import pending_drafts
from server import create_app
import test_pending_standards as fixture


class PendingDraftStateTests(unittest.TestCase):
    setUp=fixture.PendingStandardTests.setUp
    tearDown=fixture.PendingStandardTests.tearDown
    login=fixture.PendingStandardTests.login
    add=fixture.PendingStandardTests.add
    get=fixture.PendingStandardTests.get

    def selection(self,row):
        return {"inspection_id":row["inspection_id"],"image_id":row["image_id"],"base_revision":row["pending_revision"]}

    def action(self,operation,rows,**extra):
        return self.client.post("/api/manual-standards/pending/state",headers=self.headers,
            json={"operation":operation,"items":[self.selection(row) for row in rows],**extra})

    def events(self):
        with self.engine.connect() as conn:
            return [dict(row) for row in conn.execute(select(pending_drafts.events)).mappings()]

    def test_admin_and_csrf_are_required_for_state_writes_and_removed_listing(self):
        self.add("one")
        body={"operation":"remove","items":[{"inspection_id":"one","image_id":"image-one","base_revision":0}]}
        self.assertEqual(self.client.post("/api/manual-standards/pending/state",json=body,headers=self.headers).status_code,401)
        self.login(False)
        self.assertEqual(self.client.post("/api/manual-standards/pending/state",json=body,headers=self.headers).status_code,403)
        self.assertEqual(self.client.get("/api/manual-standards/pending?state=removed").status_code,403)
        self.login()
        self.assertEqual(self.client.post("/api/manual-standards/pending/state",json=body).status_code,403)
        self.assertEqual(self.client.post("/api/manual-standards/pending/state",json=body,
            headers={**self.headers,"Sec-Fetch-Site":"cross-site"}).status_code,403)
        self.assertEqual(self.events(),[])

    def test_remove_restore_versions_are_append_only_and_repeat_is_conflict(self):
        self.login();self.add("one");first=self.get()["items"][0]
        response=self.action("remove",[first],note="同款重複照片")
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(response.json["items"],[{"image_id":"image-one","revision":1,"removed":True}])
        self.assertEqual(self.get()["total"],0)
        removed=self.get(range="all",state="removed")["items"][0]
        self.assertEqual((removed["pending_revision"],removed["pending_note"]),(1,"同款重複照片"))
        self.assertEqual(self.action("remove",[first]).status_code,409)
        self.assertEqual(self.action("restore",[removed]).status_code,200)
        active=self.get()["items"][0]
        self.assertEqual(active["pending_revision"],2)
        self.assertEqual(self.action("restore",[removed]).status_code,409)
        self.assertEqual(self.action("remove",[active]).status_code,200)
        self.assertEqual([row["revision"] for row in self.events()],[1,2,3])

    def test_same_image_new_inspection_stays_removed_until_restore(self):
        self.login();self.add("first","shared")
        self.assertEqual(self.action("remove",self.get()["items"]).status_code,200)
        self.add("second","shared",created="2026-11-16T05:00:00+00:00")
        self.assertEqual(self.get()["total"],0)
        removed=self.get(range="all",state="removed")["items"]
        self.assertEqual(len(removed),1)
        self.assertEqual(removed[0]["inspection_id"],"second")
        self.assertEqual(self.action("restore",removed).status_code,200)
        self.assertEqual(self.get()["items"][0]["inspection_id"],"second")

    def test_stale_batch_rolls_back_all_images(self):
        self.login();self.add("one");self.add("two")
        rows=self.get()["items"]
        self.assertEqual(self.action("remove",[rows[0]]).status_code,200)
        self.assertEqual(self.action("remove",rows).status_code,409)
        self.assertEqual(len(self.events()),1)
        self.assertEqual(self.get()["total"],1)

    def test_batch_success_and_removed_today_use_decision_date(self):
        self.login()
        self.add("old-one",created="2026-11-14T00:00:00+00:00")
        self.add("old-two",created="2026-11-14T01:00:00+00:00")
        rows=self.get(range="all")["items"]
        self.assertEqual(self.get()["total"],0)
        with patch("pending_drafts.db.now",return_value="2026-11-16T04:00:00+00:00"):
            response=self.action("remove",rows)
        self.assertEqual(response.status_code,200,response.json)
        self.assertEqual(response.json["count"],2)
        removed=self.get(state="removed")
        self.assertEqual(removed["total"],2)
        self.assertTrue(all(row["pending_updated_at"]=="2026-11-16T04:00:00+00:00" for row in removed["items"]))
        self.assertEqual(self.action("restore",removed["items"]).status_code,200)
        self.assertEqual(self.get(range="all")["total"],2)
        self.assertEqual(self.get(state="removed",range="all")["total"],0)

    def test_invalid_batch_and_identity_rejected_without_writes(self):
        self.login();self.add("one");row=self.get()["items"][0]
        self.assertEqual(self.action("remove",[row,row]).status_code,400)
        self.assertEqual(self.action("remove",[row]*25).status_code,400)
        self.assertEqual(self.action("remove",[row],note="bad\x00note").status_code,400)
        body={"operation":"remove","items":[dict(self.selection(row),base_revision=True)]}
        self.assertEqual(self.client.post("/api/manual-standards/pending/state",json=body,headers=self.headers).status_code,400)
        self.add("another")
        wrong=dict(row,image_id="image-another")
        self.assertEqual(self.action("remove",[wrong]).status_code,404)
        self.assertEqual(self.events(),[])

    def test_photo_and_all_original_inspection_data_remain_untouched_after_restart(self):
        self.login();original=self.add("one")
        folder=Path(self.temp.name)/"images"/"image-one";folder.mkdir(parents=True)
        photo=folder/"image.jpg";photo.write_bytes(b"original-photo-test-evidence")
        with self.engine.connect() as conn:
            image_before=dict(conn.execute(select(db.images)).mappings().one())
        self.assertEqual(self.action("remove",self.get()["items"]).status_code,200)
        with self.engine.connect() as conn:
            self.assertEqual(dict(conn.execute(select(db.inspections)).mappings().one()),original)
            self.assertEqual(dict(conn.execute(select(db.images)).mappings().one()),image_before)
            for table in (db.templates,db.manual_sources,db.corrections):
                self.assertEqual(conn.scalar(select(func.count()).select_from(table)),0)
        self.assertEqual(photo.read_bytes(),b"original-photo-test-evidence")
        second=create_app({"TESTING":True,"DATA_DIR":Path(self.temp.name),"DATABASE_URL":"",
            "APP_PASSWORD":"operator-secret","ADMIN_PASSWORD":"manager-secret"},ocr=object())
        try:
            client=second.test_client();token=client.get("/api/session").json["csrf"]
            client.post("/api/login",json={"password":"manager-secret"},headers={"X-CSRF-Token":token})
            self.assertEqual(client.get("/api/manual-standards/pending?range=all").json["total"],0)
            self.assertEqual(client.get("/api/manual-standards/pending?range=all&state=removed").json["total"],1)
        finally:
            second.extensions["label_worker"].shutdown(wait=True);second.extensions["label_engine"].dispose()

    def test_restore_does_not_remove_or_change_a_later_approved_standard(self):
        self.login();self.add("one");self.action("remove",self.get()["items"])
        body={"name":"待確認蘋果","lines":[{"text":"品名：待確認蘋果"}]}
        preview=self.client.post("/api/inspections/one/manual-standard/preview",json=body,headers=self.headers)
        response=self.client.post("/api/inspections/one/manual-standard",json=dict(body,preview_hash=preview.json["preview_hash"],
            reviewer="QA",note="核准完整文字",confirmed=True),headers=self.headers)
        self.assertEqual(response.status_code,201,response.json)
        with self.engine.connect() as conn:approved=deepcopy(dict(conn.execute(select(db.manual_sources)).mappings().one()))
        removed=self.get(range="all",state="removed")["items"]
        self.assertEqual(self.action("restore",removed).status_code,200)
        self.assertEqual(self.get(range="all")["total"],0)
        with self.engine.connect() as conn:self.assertEqual(dict(conn.execute(select(db.manual_sources)).mappings().one()),approved)


if __name__=="__main__":unittest.main()
