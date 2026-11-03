import pytest

from app import create_app
from catalog import catalogue_rows, import_safety_catalog
from models import AuditLog, Point, db


@pytest.fixture
def catalogue_app():
    app = create_app({"TESTING": True, "SECRET_KEY": "test", "SQLALCHEMY_DATABASE_URI": "sqlite://"})
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_catalogue_matches_supplied_counts_and_floor_order():
    rows = catalogue_rows()
    assert len(rows) == 42
    assert [r["number"] for r in rows] == list(range(1, 43))
    assert len({r["code"] for r in rows}) == 42
    assert sum(r["frequency"] == "daily2" for r in rows) == 19
    assert sum(2 if r["frequency"] == "daily2" else 1 for r in rows) == 61
    assert [(r["code"], r["name"]) for r in rows if r["number"] in (1, 16, 32, 42)] == [
        ("B2-S001", "停車場"), ("1M-S016", "參觀走道"), ("4M-S032", "包材區"), ("5M-S042", "7、8號貨梯機房")]


def test_import_is_explicit_atomic_and_preserves_previous_points(catalogue_app):
    old = Point(code="1F-A01", name="大門", floor=1, qr_token="original-qr", category="uncategorized")
    db.session.add(old)
    db.session.commit()
    assert import_safety_catalog()["created"] == 42
    assert db.session.query(Point).count() == 1
    assert import_safety_catalog(apply=True)["created"] == 42
    assert db.session.query(Point).count() == 43
    imported = db.session.query(Point).filter_by(code="B2-S001").one()
    imported.name = "管理員後來調整的名稱"
    db.session.commit()
    assert import_safety_catalog(apply=True)["already_imported"]
    assert db.session.query(Point).count() == 43
    assert db.session.query(Point).filter_by(code="1F-A01").one().qr_token == "original-qr"
    assert db.session.query(Point).filter_by(code="B2-S001").one().name == "管理員後來調整的名稱"


def test_conflicting_catalogue_does_not_partially_import(catalogue_app):
    db.session.add(Point(code="1F-S010", name="另一個地點", floor=1, category="general"))
    db.session.commit()
    with pytest.raises(ValueError, match="1F-S010"):
        import_safety_catalog(apply=True)
    assert db.session.query(Point).count() == 1
    assert db.session.query(AuditLog).count() == 0
