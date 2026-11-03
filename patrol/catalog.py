"""User-provided occupational safety catalogue; explicit, idempotent import."""
from datetime import datetime
from zoneinfo import ZoneInfo

import click
from sqlalchemy import select

from domain import floor_label
from models import AuditLog, Point, PointSchedule, db

# Source numbering is retained in the S001–S042 suffix. Existing points are
# never renamed, repurposed, or removed by this import.
SAFETY_POINTS = [
    (-2, 1, "停車場", "daily"),
    (-2, 2, "包材區", "daily"),
    (-2, 3, "消防泵浦室", "daily"),
    (-1, 4, "壓紙區及垃圾區", "daily2"),
    (-1, 5, "發電機室", "daily"),
    (-1, 6, "空調機房", "daily"),
    (-1, 7, "香蕉庫/冷凍庫", "daily2"),
    (1, 8, "大碼頭", "daily2"),
    (1, 9, "小碼頭", "daily2"),
    (1, 10, "理貨區", "daily2"),
    (1, 11, "充電區", "daily2"),
    (1, 12, "警衛室", "daily"),
    (1, 13, "停車場", "daily"),
    (1, 14, "機車棚", "daily"),
    (1, 15, "防火巷", "daily"),
    (11, 16, "參觀走道", "daily"),
    (11, 17, "工務工作區", "daily"),
    (2, 18, "原果生產區", "daily2"),
    (2, 19, "充電區", "daily2"),
    (3, 20, "品質控制室", "daily"),
    (3, 21, "包裝區", "daily2"),
    (3, 22, "備料區", "daily2"),
    (3, 23, "洗果區", "daily2"),
    (3, 24, "充電區", "daily2"),
    (3, 25, "烘衣室", "daily2"),
    (3, 26, "食品添加室/化學室", "daily"),
    (3, 27, "參觀走道", "daily"),
    (4, 28, "IQF生產線", "daily2"),
    (4, 29, "IQF機房", "daily2"),
    (4, 30, "洗籃區", "daily2"),
    (4, 31, "女員工宿舍", "daily"),
    (14, 32, "包材區", "daily2"),
    (14, 33, "男員工宿舍", "daily"),
    (14, 34, "員工餐廳", "daily2"),
    (14, 35, "廚房", "daily2"),
    (14, 36, "熱泵機室", "daily"),
    (5, 37, "棧板/空籃放置區", "daily"),
    (5, 38, "抽風機/冷卻水塔/桶槽區", "daily"),
    (15, 39, "1、2號客梯機房", "daily"),
    (15, 40, "3、4號客梯機房", "daily"),
    (15, 41, "5、6號貨梯機房", "daily"),
    (15, 42, "7、8號貨梯機房", "daily"),
]
IMPORT_ACTION = "safety_catalog_20261103"


def catalogue_rows():
    return [dict(floor=floor, number=number, code=f"{floor_label(floor)}-S{number:03d}",
                 name=name, frequency=frequency, category="safety")
            for floor, number, name, frequency in SAFETY_POINTS]


def import_safety_catalog(apply=False):
    """All rows commit together. A completed import never resets admin edits."""
    if apply and db.engine.dialect.name == "postgresql":
        db.session.execute(db.text("SELECT pg_advisory_xact_lock(714032610304)"))
    if db.session.scalar(select(AuditLog.id).where(AuditLog.action == IMPORT_ACTION).limit(1)):
        db.session.rollback()
        return {"created": 0, "existing": 42, "already_imported": True}
    rows = catalogue_rows()
    found = {p.code: p for p in db.session.scalars(select(Point).where(Point.code.in_([r["code"] for r in rows])))}
    missing = []
    for row in rows:
        point = found.get(row["code"])
        if point:
            if any(getattr(point, key) != row[key] for key in ("floor", "name", "frequency", "category")):
                db.session.rollback()
                raise ValueError(f"點位 {row['code']} 已存在且設定不同，請先確認；未匯入任何點位。")
        else:
            missing.append(row)
    result = {"created": len(missing), "existing": len(found), "already_imported": False}
    if not apply:
        db.session.rollback()
        return result
    today = datetime.now(ZoneInfo("Asia/Taipei")).date()
    try:
        for row in missing:
            point = Point(**{k: v for k, v in row.items() if k != "number"}, active=True, schedule_start=today)
            point.schedules.append(PointSchedule(effective_date=today, frequency=point.frequency,
                                                active=True, category="safety"))
            db.session.add(point)
        db.session.add(AuditLog(action=IMPORT_ACTION, target="42 safety points",
                               detail=f"Created {len(missing)}; existing {len(found)}. Daily=23; AM/PM=19."))
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    return result


def register_catalog_commands(app):
    @app.cli.command("import-safety-points")
    @click.option("--apply", is_flag=True, help="Commit the supplied 42-point safety catalogue; default is preview only.")
    def import_safety_points(apply):
        try:
            result = import_safety_catalog(apply=apply)
        except ValueError as error:
            raise click.ClickException(str(error)) from error
        click.echo(f"{'Imported' if apply else 'Preview'}: new={result['created']}, existing={result['existing']}, "
                   f"already_imported={result['already_imported']}; 42 points / 61 daily check-ins.")
