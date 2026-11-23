from copy import deepcopy
import unittest

from flask import Flask, jsonify
from sqlalchemy import create_engine, insert, select, func
from werkzeug.exceptions import HTTPException

import database as db
import label_source
import manual_reference as manual
import standard_reference as standards
from source_validation import evaluate_source
from text_rows import group_observed_rows


def cell(identifier,text,x,y,width=80,score=.99,**extra):
    return {"id":identifier,"text":text,"score":score,"box":[[x,y],[x+width,y],[x+width,y+22],[x,y+22]],**extra}


def table_lines():
    rows=[cell(0,"營養標示",20,0,200),cell(1,"每一份量120公克",0,35,200),
          cell(2,"每份 每100公克",100,70,210)]
    for index,(name,a,b) in enumerate((("熱量","68.5大卡","57.3大卡"),("蛋白質","0.2公克","0.2公克"),
                                      ("脂肪","0.1公克","0.1公克"))):
        y=110+index*40; identifier=3+index*3
        rows.extend([cell(identifier,name,0,y),cell(identifier+1,a,110,y),cell(identifier+2,b,220,y)])
    rows.extend([cell(12,"1.4毫克",110,230),cell(13,"1.2毫克",220,230),
                 cell(14,"品名：測試蘋果",410,110,250),cell(15,"製造日期：2026.11.16",410,150,280)])
    return rows


def definition_for(lines):
    rows=group_observed_rows(lines)
    return {"name":"測試蘋果","lines":[{"text":row["text"]} for row in rows if not row["text"].startswith("製造日期")],
            "keep_days":None,"date_settings":[]}


class NutritionRowTests(unittest.TestCase):
    def test_liquid_table_and_full_fatty_acid_labels_keep_their_cells(self):
        lines=table_lines()
        lines[1]['text']='每一份量120毫升'
        lines[2]['text']='每份 每100毫升'
        lines[6]['text']='飽和脂肪酸'
        lines[9]['text']='反式脂肪酸'
        rows=group_observed_rows(lines)
        self.assertIn('飽和脂肪酸 0.2公克 0.2公克',[row['text'] for row in rows])
        self.assertIn('反式脂肪酸 0.1公克 0.1公克',[row['text'] for row in rows])

    def source(self,lines):
        with Flask(__name__).app_context():
            source,_=manual.definition(definition_for(lines))
        return dict(source,code="manual:test")

    def checks(self,lines,source):
        return [check for check in evaluate_source(lines,source,base_date="2026-11-16")["checks"]
                if check.get("source")=="database"]

    def test_rows_keep_duplicate_columns_literal_cells_and_original_metadata(self):
        lines=table_lines();before=deepcopy(lines)
        grouped=group_observed_rows(lines)
        fat=next(row for row in grouped if row["text"].startswith("脂肪"))
        self.assertEqual(fat["text"],"脂肪 0.1公克 0.1公克")
        self.assertEqual(fat["source_line_ids"],[9,10,11])
        self.assertEqual(fat["cell_texts"],["脂肪","0.1公克","0.1公克"])
        self.assertEqual(lines,before)
        self.assertEqual(sorted(identifier for row in grouped for identifier in row["source_line_ids"]),list(range(16)))

    def test_dates_other_column_and_missing_nutrient_label_are_not_filled(self):
        grouped=group_observed_rows(table_lines())
        self.assertEqual(next(row for row in grouped if row["id"]==15)["source_line_ids"],[15])
        self.assertEqual(next(row for row in grouped if row["id"]==14)["source_line_ids"],[14])
        orphan=next(row for row in grouped if row["row_type"]=="nutrition_values")
        self.assertEqual(orphan["text"],"1.4毫克 1.2毫克")
        self.assertNotIn("鈉",orphan["text"])

    def test_missing_swapped_or_uncertain_nutrition_cells_do_not_affect_product(self):
        original=table_lines();source=self.source(original)
        baseline=self.checks(original,source)
        self.assertEqual([check["expected"] for check in baseline],["品名：測試蘋果"])
        for extra in ({"text":"57.3大卡"},{"score":.3},{"ambiguous":True},{"human_uncertain":True}):
            lines=deepcopy(original);lines[4].update(extra)
            self.assertEqual(self.checks(lines,source),baseline)
        reduced=[row for row in original if row["id"]!=11]
        self.assertEqual(self.checks(reduced,source),baseline)

    def test_no_title_or_two_tables_do_not_generate_cross_table_rows(self):
        lines=table_lines()[1:]
        self.assertTrue(all(len(row["source_line_ids"])==1 for row in group_observed_rows(lines)))
        lines=table_lines()+[cell(99,"營養標示",500,0,200)]
        self.assertTrue(all(len(row["source_line_ids"])==1 for row in group_observed_rows(lines)))

    def test_millilitre_header_keeps_same_row_evidence(self):
        lines=table_lines();lines[2]["text"]="每份 每100毫升"
        self.assertIn("脂肪 0.1公克 0.1公克",[row["text"] for row in group_observed_rows(lines)])

    def test_overlapping_full_rows_preserve_geometry_without_reporting_an_anomaly(self):
        lines=[cell(0,"營養標示",0,0,200),cell(1,"每一份量100公克",0,35,200),
            cell(2,"每份 每100公克",100,70,210),cell(3,"蛋白質 0.2公克 0.2公克",0,110,280),
            cell(4,"脂肪 0.1公克 0.1公克",120,110,280),cell(5,"品名：測試蘋果",450,110,250)]
        source=self.source(lines)
        grouped=group_observed_rows(lines)
        self.assertTrue(all(row["ambiguous"] for row in grouped if row["id"] in (3,4)))
        checks=[check for check in self.checks(lines,source) if check["expected"].startswith(("蛋白質","脂肪"))]
        self.assertEqual(checks,[])

    def test_augmentation_preserves_all_eight_nutrition_rows_for_reading(self):
        from inspection_evidence import augment
        names=("熱量","蛋白質","脂肪","飽和脂肪","反式脂肪","碳水化合物","糖","鈉")
        values=("50大卡","0.2公克","0.1公克","0公克","0公克","10公克","5公克","1.4毫克")
        lines=[cell(0,"營養標示",0,0,200),cell(1,"每一份量100公克",0,35,200),cell(2,"每份 每100公克",100,70,210)]
        for index,(name,value) in enumerate(zip(names,values)):
            lines.append(cell(index+3,f"{name} {value} {value}",0,110+index*40,300))
        lines.append(cell(99,"品名：測試蘋果",450,110,220))
        source=self.source(lines)
        result=evaluate_source(lines,source,base_date="2026-11-16")
        self.assertEqual([check["key"] for check in result["checks"]],["product"])
        augment(result,{"lines":lines})
        only_text=[row["text"] for row in result["display_rows"] if row["nutrition_display_only"]]
        self.assertTrue(all(f"{name} {value} {value}" in only_text for name,value in zip(names,values)))
        self.assertEqual([check["key"] for check in result["checks"]],["product"])
        self.assertEqual(result["counts"],{"pass":1,"fail":0,"review":0,"read":0})
        once=deepcopy(result);augment(result,{"lines":lines})
        self.assertEqual(result,once)


class CompleteStandardAuthoringTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine("sqlite:///:memory:");db.metadata.create_all(self.engine)
        self.app=Flask(__name__);self.app.config["TESTING"]=True
        @self.app.errorhandler(HTTPException)
        def error(exception):return jsonify(error=exception.description),exception.code
        standards.register_routes(self.app,self.engine);self.client=self.app.test_client()
        self.original=self.add("original",table_lines())
        self.addCleanup(self.engine.dispose)

    def add(self,identifier,lines,source=None):
        row={"id":identifier,"image_id":"image","template_id":"","status":"review",
            "template_snapshot":{"mode":"system_label","source":source},"ocr":{"lines":deepcopy(lines)},
            "result":{"inputs":{"base_date":"2026-11-16"}},"created_at":db.now()}
        with self.engine.begin() as conn:conn.execute(insert(db.inspections).values(**row))
        return row

    def create(self):
        # Preserve a deliberately fragmented existing standard, including
        # duplicate cells, to exercise the real replacement migration.
        body={"name":"測試蘋果","lines":[{"text":row["text"]} for row in table_lines() if row["id"]!=15]}
        preview=self.client.post("/api/inspections/original/manual-standard/preview",json=body)
        self.assertEqual(preview.status_code,200,preview.json)
        response=self.client.post("/api/inspections/original/manual-standard",json=dict(body,
            preview_hash=preview.json["preview_hash"],reviewer="核對員",note="建立原版",confirmed=True))
        self.assertEqual(response.status_code,201,response.json)
        source=label_source.draft(self.engine,response.json["code"])
        self.add("edit",table_lines(),source)
        return source

    def edit_body(self,changes):
        current=self.client.get("/api/inspections/edit/standard").json
        return {"base_revision":current["base_revision"],"source_revision":current["source_revision"],
                "changes":changes,"reviewer":"核對員","note":"完整列人工確認","confirmed":True}

    def test_create_preserves_repeated_values_and_grouped_draft_has_no_dates(self):
        source=self.create()
        self.assertEqual([row["text"] for row in source["lines"]].count("0.1公克"),2)
        payload=self.client.get("/api/inspections/edit/standard").json
        self.assertTrue(payload["supports_line_replacement"])
        draft=payload["regrouped_draft_lines"]
        self.assertIn("脂肪 0.1公克 0.1公克",[row["text"] for row in draft])
        self.assertFalse(any("2026" in row["text"] for row in draft))
        self.assertEqual(payload["source"]["lines"],source["lines"])

    def test_replace_and_subsequent_edit_do_not_restore_deleted_fragments(self):
        source=self.create();before=deepcopy(source)
        replacement=definition_for(table_lines())["lines"]
        body=self.edit_body({"replace_lines":replacement})
        preview_body={key:body[key] for key in ("base_revision","source_revision","changes")}
        preview=self.client.post("/api/inspections/edit/standard/preview",json=preview_body)
        self.assertEqual(preview.status_code,200,preview.json)
        self.assertEqual(preview.json["nutrition_checks"], [])
        with self.engine.connect() as conn:self.assertEqual(conn.scalar(select(func.count()).select_from(standards.versions)),1)
        saved=self.client.post("/api/inspections/edit/standard",json=body)
        self.assertEqual(saved.status_code,201,saved.json)
        self.assertEqual([row["text"] for row in saved.json["source"]["lines"]],[row["text"] for row in replacement])
        self.assertTrue(saved.json["focus_ids_stale"])
        self.assertFalse(any(row["text"]=="0.1公克" for row in saved.json["source"]["lines"]))
        followup=self.client.post("/api/inspections/edit/standard",json=self.edit_body({"keep_days":3}))
        self.assertEqual(followup.status_code,201,followup.json)
        self.assertEqual(followup.json["source"]["lines"],saved.json["source"]["lines"])
        self.assertEqual(self.client.post("/api/inspections/edit/standard",json=body).status_code,409)
        with self.engine.connect() as conn:
            original=dict(conn.execute(select(db.inspections).where(db.inspections.c.id=="original")).mappings().one())
            raw=conn.execute(select(db.manual_sources.c.snapshot)).scalar_one()
        self.assertEqual(original,self.original)
        self.assertEqual(raw["lines"],before["lines"])

    def test_blank_patch_really_deletes_and_empty_or_dynamic_replacement_is_rejected(self):
        self.create();current=self.client.get("/api/inspections/edit/standard").json
        target=next(row for row in current["source"]["lines"] if row["text"]=="0.1公克")
        saved=self.client.post("/api/inspections/edit/standard",json=self.edit_body({"lines":[{"id":target["id"],"text":""}]}))
        self.assertEqual(saved.status_code,201,saved.json)
        self.assertNotIn(target["id"],[row["id"] for row in saved.json["source"]["lines"]])
        for replacement in ([],[{"text":""}],[{"text":"製造日期：2026.11.16"}]):
            response=self.client.post("/api/inspections/edit/standard",json=self.edit_body({"replace_lines":replacement}))
            self.assertEqual(response.status_code,400,response.json)

    def test_replacement_name_and_retained_bare_product_must_agree(self):
        self.create()
        bare=[{"text":"測試蘋果"},{"text":"脂肪 0.1公克 0.1公克"}]
        first=self.client.post("/api/inspections/edit/standard",json=self.edit_body({"replace_lines":bare}))
        self.assertEqual(first.status_code,201,first.json)
        bad=self.edit_body({"name":"新鮮蘋果","replace_lines":bare})
        preview={key:bad[key] for key in ("base_revision","source_revision","changes")}
        self.assertEqual(self.client.post("/api/inspections/edit/standard/preview",json=preview).status_code,400)
        self.assertEqual(self.client.post("/api/inspections/edit/standard",json=bad).status_code,400)
        current=self.client.get("/api/inspections/edit/standard").json
        self.assertEqual(current["source"]["name"],"測試蘋果")
        self.assertEqual([row["text"] for row in current["source"]["lines"]],[row["text"] for row in bare])
        good=self.edit_body({"name":"新鮮蘋果","replace_lines":[{"text":"新鮮蘋果"},bare[1]]})
        saved=self.client.post("/api/inspections/edit/standard",json=good)
        self.assertEqual(saved.status_code,201,saved.json)
        self.assertEqual(saved.json["source"]["fields"]["product"],"新鮮蘋果")

    def test_replacement_ids_are_unique_and_old_rows_do_not_point_at_new_text(self):
        self.create();prior=self.client.get("/api/inspections/edit/standard").json["source"]["lines"]
        replacement=[{"text":"品名：測試蘋果"},{"text":"0.1公克"},{"text":"0.1公克"},{"text":"新增加的說明"}]
        response=self.client.post("/api/inspections/edit/standard",json=self.edit_body({"replace_lines":replacement}))
        self.assertEqual(response.status_code,201,response.json)
        rows=response.json["source"]["lines"]
        self.assertEqual(len(rows),len({str(row["id"]) for row in rows}))
        old={str(row["id"]):row["text"] for row in prior}
        for row in rows:
            if str(row["id"]) in old:self.assertEqual(row["text"],old[str(row["id"])])

    def test_split_short_date_tail_is_not_saved_as_a_static_day(self):
        lines=[cell(0,"品名：測試蘋果",0,0,200),cell(1,"到店日",10,40,90),
               cell(2,"11/",110,40,40),cell(3,"19",160,40,30),cell(4,"19公克",300,40,80)]
        self.add("short-date",lines)
        payload=self.client.get("/api/inspections/short-date/manual-standard").json
        self.assertEqual({row["id"] for row in payload["excluded_date_lines"]},{1,2,3})
        self.assertIn("19公克",[row["text"] for row in payload["draft_lines"]])
