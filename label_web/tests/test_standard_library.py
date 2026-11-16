from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from sqlalchemy import insert,select,func,update

import database as db
import history_cleanup
import label_source
import manual_reference
import reference_photos
import standard_library as library
import standard_reference as standards
from server import create_app


CODE="manual:3a35c12f00112233445566778899aabb"
FAMILY="f1234567890123456789012345678901"


class StandardLibraryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.app=create_app({"TESTING":True,"DATA_DIR":Path(self.temp.name),"DATABASE_URL":"",
            "APP_PASSWORD":"qa-operator-2026","ADMIN_PASSWORD":"qa-manager-2026"},ocr=object())
        self.engine=self.app.extensions["label_engine"];self.client=self.app.test_client()
        self.headers={"X-CSRF-Token":self.client.get("/api/session").json["csrf"]}
        with self.app.app_context():
            self.base,_=manual_reference.definition({"name":"測試蘋果","sku":"ABC-123","lines":[
                {"text":"品名：測試蘋果"},{"text":"規格：120g/盒"},{"text":"營養標示"},
                {"text":"每一份量120公克"},{"text":"每份 每100公克"},{"text":"脂肪 0.1公克 0.1公克"},
                {"text":"電話：0800-200-859"}],"keep_days":3})
        self.base["code"]=CODE
        self.original={"id":"original","image_id":"manual-image","template_id":"","template_snapshot":{"id":"","image_id":"",
            "source":deepcopy(self.base),"name":"人工標準","version":0},"status":"review","ocr":{"lines":[]},
            "result":{"checks":[],"inputs":{}},"created_at":db.now()}
        with self.engine.begin() as conn:
            for identifier in ("manual-image","photo-image","extra-image"):
                conn.execute(insert(db.images).values(id=identifier,filename=identifier+".jpg",width=640,height=480,created_at=db.now()))
            conn.execute(insert(db.inspections).values(**self.original))
            conn.execute(insert(db.manual_sources).values(code=CODE,name=self.base["name"],inspection_id="original",
                reference_hash=self.base["revision"],snapshot=self.base,active=True,reviewer="QA",note="建立",created_at=db.now()))
            conn.execute(insert(standards.heads).values(code=CODE,revision=1))
            conn.execute(insert(standards.versions).values(id="version-one",code=CODE,revision=1,source_revision=self.base["revision"],
                operation="create",snapshot=self.base,changes={},inspection_id="original",reviewer="QA",note="建立",created_at=db.now()))
            for version in (1,2):
                conn.execute(insert(db.templates).values(id=f"photo-v{version}",family_id=FAMILY,version=version,active=version==2,
                    name="照片蘋果",image_id="photo-image",fields={"product":"照片蘋果","address":"新北市土城區中興路9號","origin":"台灣"},
                    rules={"dates":False,"arrival":False,"keep_days":3},reference_dates={},approved_by="QA",created_at=db.now()))

    def tearDown(self):
        self.app.extensions["label_worker"].shutdown(wait=True);self.engine.dispose();self.temp.cleanup()

    def login(self,admin=True):
        response=self.client.post("/api/login",json={"password":"qa-manager-2026" if admin else "qa-operator-2026"},headers=self.headers)
        self.assertEqual(response.status_code,200,response.json);self.headers["X-CSRF-Token"]=response.json["csrf"]

    def url(self,kind="manual",key=CODE):return f"/api/standard-library/{kind}/{key}"

    def detail(self,kind="manual",key=CODE):
        response=self.client.get(self.url(kind,key));self.assertEqual(response.status_code,200,response.json);return response.json

    def post(self,url,body):return self.client.post(url,json=body,headers=self.headers)

    def preview_body(self,changes,kind="manual",key=CODE):
        current=self.detail(kind,key)
        return {field:current[field] for field in ("item_revision","base_revision","source_revision")}|{"changes":changes}

    def save_body(self,changes,kind="manual",key=CODE):
        body=self.preview_body(changes,kind,key)
        preview=self.post(self.url(kind,key)+"/preview",body)
        self.assertEqual(preview.status_code,200,preview.json)
        return body|{"preview_hash":preview.json["preview_hash"],"reviewer":"QA","note":"逐字核對標準","confirmed":True}

    def state_body(self,operation,kind="manual",key=CODE):
        value=self.detail(kind,key)
        return {"operation":operation,"item_revision":value["item_revision"],"base_revision":value["base_revision"]}

    def test_all_library_routes_require_admin_and_write_csrf(self):
        self.assertEqual(self.client.get("/api/standard-library").status_code,401)
        self.login(False)
        for url in ("/api/standard-library","/api/standard-library/categories",self.url()):
            self.assertEqual(self.client.get(url).status_code,403)
        self.assertEqual(self.post("/api/standard-library/categories",{"name":"水果"}).status_code,403)
        self.login()
        self.assertEqual(self.client.post("/api/standard-library/categories",json={"name":"水果"}).status_code,403)
        self.assertEqual(self.client.post("/api/standard-library/categories",json={"name":"水果"},
            headers={**self.headers,"Sec-Fetch-Site":"cross-site"}).status_code,403)

    def test_unified_list_search_short_codes_and_superseded_photo_not_in_trash(self):
        self.login()
        result=self.client.get("/api/standard-library").json
        self.assertEqual(result["total"],2)
        self.assertEqual({row["kind"] for row in result["items"]},{"manual","photo"})
        manual=next(row for row in result["items"] if row["kind"]=="manual")
        self.assertEqual(manual["identity"],{"spec":"120g/盒","barcode":"","sku":"ABC-123"})
        for query in ("M-3a35c12f","ABC-123","120g/盒"):
            response=self.client.get("/api/standard-library",query_string={"q":query})
            self.assertEqual(response.json["total"],1,response.json)
        self.assertEqual(self.client.get("/api/standard-library?q=P-f1234567").json["total"],1)
        self.assertEqual(self.client.get("/api/standard-library?state=removed").json["total"],0)
        self.assertEqual(self.client.get("/api/standard-library?limit=1&page=2").json["total"],2)
        self.assertEqual(len(self.client.get("/api/standard-library?limit=1&page=2").json["items"]),1)

    def test_preview_is_read_only_and_save_updates_matching_without_inspection(self):
        self.login();before=self.detail()
        replacement=[{"text":row["text"].replace("測試蘋果","新版蘋果")} for row in before["source"]["lines"]]
        body=self.save_body({"name":"新版蘋果","replace_lines":replacement})
        with self.engine.connect() as conn:self.assertEqual(conn.scalar(select(func.count()).select_from(standards.versions)),1)
        saved=self.post(self.url()+"/save",body)
        self.assertEqual(saved.status_code,201,saved.json)
        self.assertEqual((saved.json["base_revision"],saved.json["item_revision"]),(2,1))
        self.assertEqual(label_source.draft(self.engine,CODE)["name"],"新版蘋果")
        self.assertEqual(self.post(self.url()+"/save",body).status_code,409)
        with self.engine.connect() as conn:
            self.assertEqual(conn.scalar(select(db.manual_sources.c.snapshot)),self.base)
            self.assertEqual(dict(conn.execute(select(db.inspections)).mappings().one()),self.original)
            latest=conn.execute(select(standards.versions).where(standards.versions.c.revision==2)).mappings().one()
            self.assertEqual(latest["inspection_id"],"")
            self.assertEqual(conn.scalar(select(func.count()).select_from(db.inspections)),1)

    def test_preview_hash_and_source_revision_prevent_unreviewed_overwrite(self):
        self.login();body=self.save_body({"keep_days":4})
        bad=deepcopy(body);bad["changes"]["keep_days"]=5
        self.assertEqual(self.post(self.url()+"/save",bad).status_code,409)
        bad=deepcopy(body);bad["source_revision"]="wrong"
        self.assertEqual(self.post(self.url()+"/save",bad).status_code,409)
        self.assertEqual(self.detail()["base_revision"],1)

    def test_archived_creation_inspection_does_not_block_library_photos_or_edit(self):
        self.login()
        with self.engine.begin() as conn:
            conn.execute(insert(history_cleanup.tombstones).values(inspection_id="original",batch_id="qa",archived=True,revision=1,updated_at=db.now()))
        detail=self.detail();self.assertEqual(detail["current_image"]["id"],"manual-image")
        body=self.save_body({"keep_days":4})
        self.assertEqual(self.post(self.url()+"/save",body).status_code,201)
        self.assertEqual(self.client.get("/api/inspections/original").status_code,404)

    def test_manual_remove_restore_preserves_versions_and_blocks_old_editor(self):
        self.login();prepared=self.save_body({"keep_days":4});remove=self.state_body("remove")
        response=self.post(self.url()+"/state",remove)
        self.assertEqual(response.status_code,200,response.json);self.assertTrue(response.json["removed"])
        self.assertIsNone(label_source.draft(self.engine,CODE))
        self.assertFalse(any(row["code"]==CODE for row in label_source.search(self.engine,"蘋果")))
        self.assertEqual(self.post(self.url()+"/save",prepared).status_code,409)
        old_editor=self.client.get("/api/inspections/original/standard")
        self.assertEqual(old_editor.status_code,200,old_editor.json);self.assertFalse(old_editor.json["editable"])
        self.assertIn("source",old_editor.json)
        restored=self.post(self.url()+"/state",self.state_body("restore"))
        self.assertEqual(restored.status_code,200,restored.json)
        self.assertEqual(restored.json["base_revision"],1)
        self.assertEqual(restored.json["item_revision"],2)
        self.assertEqual(self.post(self.url()+"/save",prepared).status_code,409)
        self.assertEqual(label_source.draft(self.engine,CODE)["name"],self.base["name"])

    def test_photo_save_new_version_then_restore_only_latest(self):
        self.login();url=self.url("photo",FAMILY)
        before=self.detail("photo",FAMILY);self.assertEqual(before["template"]["id"],"photo-v2")
        body=self.save_body({"name":"照片新版","fields":{"spec":"120g/盒"}},"photo",FAMILY)
        saved=self.post(url+"/save",body)
        self.assertEqual(saved.status_code,201,saved.json)
        latest_id=saved.json["template"]["id"]
        self.assertEqual(saved.json["base_revision"],3)
        self.assertEqual(self.post(url+"/state",self.state_body("remove","photo",FAMILY)).status_code,200)
        self.assertEqual(self.client.get("/api/standard-library?state=removed").json["total"],1)
        self.assertEqual(self.post(url+"/state",self.state_body("restore","photo",FAMILY)).status_code,200)
        with self.engine.connect() as conn:
            rows=conn.execute(select(db.templates).where(db.templates.c.family_id==FAMILY)).mappings().all()
            self.assertEqual(len(rows),3)
            self.assertEqual([row["id"] for row in rows if row["active"]],[latest_id])
            self.assertEqual(next(row for row in rows if row["id"]=="photo-v2")["fields"]["product"],"照片蘋果")

    def test_photo_dates_validate_order_and_keep_days(self):
        self.login()
        body=self.preview_body({"rules":{"dates":True,"keep_days":3},"reference_dates":{"manufacture":"2026.11.16","expiry":"2026.11.15"}},"photo",FAMILY)
        self.assertEqual(self.post(self.url("photo",FAMILY)+"/preview",body).status_code,400)
        body["changes"]["reference_dates"]["expiry"]="2026.11.19"
        self.assertEqual(self.post(self.url("photo",FAMILY)+"/preview",body).status_code,200)

    def test_categories_create_rename_remove_returns_items_to_uncategorized(self):
        self.login()
        category=self.post("/api/standard-library/categories",{"name":"水果"})
        self.assertEqual(category.status_code,201,category.json);category=category.json
        item=self.detail()
        assignment={"item_revision":item["item_revision"],"category_id":category["id"],"category_revision":category["revision"]}
        self.assertEqual(self.post(self.url()+"/category",dict(assignment,category_revision=True)).status_code,400)
        assigned=self.post(self.url()+"/category",assignment)
        self.assertEqual(assigned.status_code,200,assigned.json)
        self.assertEqual(assigned.json["base_revision"],1)
        self.assertEqual(self.client.get("/api/standard-library",query_string={"category_id":category["id"]}).json["total"],1)
        self.assertEqual(self.post("/api/standard-library/categories",{"name":"水果"}).status_code,409)
        renamed=self.post("/api/standard-library/categories/"+category["id"],{"base_revision":1,"operation":"rename","name":"鮮果"})
        self.assertEqual(renamed.status_code,200,renamed.json)
        self.assertEqual(self.detail()["category_name"],"鮮果")
        prepared=self.save_body({"keep_days":4})
        deleted=self.post("/api/standard-library/categories/"+category["id"],{"base_revision":2,"operation":"remove"})
        self.assertEqual(deleted.status_code,200,deleted.json)
        self.assertIsNone(self.detail()["category_id"])
        self.assertEqual(self.detail()["base_revision"],1)
        self.assertEqual(self.post(self.url()+"/save",prepared).status_code,409)
        self.assertEqual(self.client.get("/api/standard-library/categories").json["items"],[])
        self.assertEqual(self.post(self.url()+"/category",assignment).status_code,409)

    def test_list_materializes_only_one_thumbnail_per_item(self):
        self.login()
        with self.engine.begin() as conn:
            conn.execute(insert(reference_photos.photos).values(id="extra",image_id="extra-image",inspection_id="original",source_code=CODE,
                source_revision=self.base["revision"],standard_revision=1,reviewer="QA",note="多張光線參考",created_at=db.now()))
        image_payload=Mock(side_effect=lambda identifier:{"id":identifier})
        result=library.listing(self.engine,image_payload,kind="manual")
        self.assertEqual(result["items"][0]["photo_count"],2)
        image_payload.assert_called_once_with("manual-image")
        detailed=library.detail(self.engine,"manual",CODE,image_payload)
        self.assertEqual(len(detailed["photos"]),2)

    def test_untracked_inactive_photo_is_not_misreported_as_removed(self):
        self.login()
        with self.engine.begin() as conn:conn.execute(update(db.templates).where(db.templates.c.family_id==FAMILY).values(active=False))
        self.assertEqual(self.client.get("/api/standard-library?state=removed").json["total"],0)


if __name__=="__main__":unittest.main()
