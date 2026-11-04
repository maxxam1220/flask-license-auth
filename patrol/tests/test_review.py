"""Independent regression cases from the production-readiness review.

Uses the existing isolated SQLite fixtures; never contacts a live service.
"""
from datetime import date, datetime, timedelta

from sqlalchemy import event
from sqlalchemy.dialects import postgresql

from test_app import (  # noqa: F401: imported pytest fixtures
    application, seeded, app_module, db, login, rendered_contexts,
)
from models import DeviceBinding, Inspection, Point, PointSchedule, User


def test_legacy_record_location_matches_csv_without_queries_per_point(application, seeded):
    import csv
    import io
    author = seeded["inspector"]
    author_name = author.display_name
    for index in range(24):
        item = Point(code=f"LEGACY-{index}", name=f"舊點位 {index}", floor=1, category="safety", frequency="daily")
        db.session.add(item)
        db.session.flush()
        db.session.add(Inspection(point_id=item.id, point_code="", point_name="", point_floor=1,
            category="safety", frequency="daily", period_key="2026-11-02", created_at=datetime(2026,11,2,3),
            user_id=author.id, user_name="", slot="any"))
    db.session.commit()
    client = application.test_client()
    login(client)
    for path in ("/records", "/records/export"):
        # A new session gives each request a cold identity map, as in production.
        db.session.remove()
        reads = []
        def capture(conn, cursor, statement, *args):
            if statement.startswith("SELECT"):
                reads.append(statement)
        event.listen(db.engine, "before_cursor_execute", capture)
        try:
            response = client.get(path + "?date_from=2026-11-02&date_to=2026-11-02")
            assert response.status_code == 200
            if path == "/records":
                assert "LEGACY-23" in response.text and "舊點位 23" in response.text
            else:
                rows = list(csv.reader(io.StringIO(response.data.decode("utf-8-sig"))))
                assert len(rows) == 25 and rows[1][:4] == [author_name, "1F", "LEGACY-23", "舊點位 23"]
        finally:
            event.remove(db.engine, "before_cursor_execute", capture)
        assert not any("WHERE patrol_points.id = " in query for query in reads)
        assert len(reads) < 12


def test_large_csv_is_served_in_chunks_and_closes_on_early_disconnect(application, seeded, monkeypatch):
    files = []
    spool = app_module.SpooledTemporaryFile
    def track_file(**options):
        file = spool(**options)
        files.append(file)
        return file
    monkeypatch.setattr(app_module, "SpooledTemporaryFile", track_file)
    point, author = seeded["daily"], seeded["inspector"]
    for offset in range(100):
        when = datetime(2026,1,1,3) + timedelta(days=offset)
        db.session.add(Inspection(point_id=point.id, point_code=point.code, point_name=point.name, point_floor=point.floor,
            category="safety", frequency="daily", period_key=when.date().isoformat(), slot="any", created_at=when,
            user_id=author.id, user_name=author.display_name, note="巡" * 2000))
    db.session.commit()
    client = application.test_client()
    login(client)
    response = client.get("/records/export?date_from=2026-01-01&date_to=2026-04-10", buffered=False)
    try:
        assert response.status_code == 200 and response.content_length > 512 * 1024
        assert "patrol-2026-01-01-2026-04-10.csv" in response.headers["Content-Disposition"]
        first = next(iter(response.response))
        assert first.startswith(b"\xef\xbb\xbf") and len(first) < response.content_length
    finally:
        response.close()
    assert len(files) == 1 and files[0].closed


def test_current_week_is_due_when_selected_date_is_later_in_same_week(application, seeded):
    client = application.test_client()
    login(client, "manager")
    # Fixture clock is Tuesday, November 3. Sunday still selects the current week.
    with rendered_contexts(application) as contexts:
        response = client.get("/dashboard?view=weekly&date=2026-11-08")
    assert response.status_code == 200
    context = contexts[-1][1]
    card = next(card for card in context["cards"] if card["point"].id == seeded["weekly"].id)
    assert card["status"] == "pending"
    assert context["totals"]["total"] == 1
    assert context["totals"]["pending"] == 1


def test_next_week_is_not_due_before_monday(application, seeded):
    client = application.test_client()
    login(client, "manager")
    with rendered_contexts(application) as contexts:
        response = client.get("/dashboard?view=weekly&date=2026-11-09")
    assert response.status_code == 200
    context = contexts[-1][1]
    card = next(card for card in context["cards"] if card["point"].id == seeded["weekly"].id)
    assert card["status"] == "not_due"
    assert context["totals"]["total"] == 0


def test_non_ascii_csrf_is_rejected_as_a_bad_request(application, seeded):
    application.config["CSRF_ENABLED"] = True
    client = application.test_client()
    client.get("/login")
    response = client.post("/login", data={
        "username": "inspector",
        "password": "not-used-because-csrf-must-fail",
        "csrf_token": "\u4e0d\u662f\u6709\u6548\u6b0a\u6756",
    })
    assert response.status_code == 400


def test_dashboard_query_count_does_not_grow_once_per_point(application, seeded):
    client = application.test_client()
    login(client, "manager")

    def count_reads():
        statements = []

        def capture(conn, cursor, statement, params, context, executemany):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement)

        db.session.expire_all()
        event.listen(db.engine, "before_cursor_execute", capture)
        try:
            response = client.get("/dashboard?view=daily&date=2026-11-03")
            assert response.status_code == 200
        finally:
            event.remove(db.engine, "before_cursor_execute", capture)
        return len(statements)

    small_reads = count_reads()
    for number in range(30):
        point = Point(code=f"3F-R{number:02}", name=f"Review point {number}", floor=3,
                      frequency="daily", active=True, schedule_start=date(2026, 1, 1))
        point.schedules.append(PointSchedule(effective_date=date(2026, 1, 1),
                                             frequency="daily", active=True))
        db.session.add(point)
    db.session.commit()
    large_reads = count_reads()
    assert large_reads <= small_reads + 2, (
        f"Adding 30 points grew SELECTs from {small_reads} to {large_reads}; "
        "dashboard must load schedule history in batches."
    )


def test_device_review_query_count_does_not_grow_once_per_employee(application, seeded):
    client = application.test_client()
    login(client, "manager")

    def count_reads():
        statements = []

        def capture(conn, cursor, statement, params, context, executemany):
            if statement.lstrip().upper().startswith("SELECT"):
                statements.append(statement)

        # Ensure previous fixture and request identity-map entries do not hide loads.
        db.session.expunge_all()
        event.listen(db.engine, "before_cursor_execute", capture)
        try:
            response = client.get("/admin/devices")
            assert response.status_code == 200
        finally:
            event.remove(db.engine, "before_cursor_execute", capture)
        return len(statements)

    small_reads = count_reads()
    for number in range(30):
        user = User(username=f"review_{number}", display_name=f"Review employee {number}",
                    password_hash="unused-review-fixture", role="inspector", active=True)
        db.session.add(user)
        db.session.flush()
        db.session.add(DeviceBinding(user_id=user.id, token_hash=f"review-token-{number}",
                                     label="Review browser", status="pending"))
    db.session.commit()
    large_reads = count_reads()
    assert large_reads <= small_reads + 2, (
        f"Adding 30 employees grew SELECTs from {small_reads} to {large_reads}; "
        "device review must load employee details in batches."
    )


def test_user_lock_compiles_to_postgres_no_key_update(application, seeded):
    """Exercise the actual request query; PostgreSQL compilation needs no DB."""
    client = application.test_client()
    login(client, "inspector")
    locks = []

    def capture(conn, statement, multiparams, params, execution_options):
        if getattr(statement, "_for_update_arg", None) is not None:
            sql = str(statement.compile(dialect=postgresql.dialect()))
            if "FROM patrol_users" in sql:
                locks.append(sql)

    event.listen(db.engine, "before_execute", capture)
    try:
        response = client.post("/devices/request", data={"label": "Review phone"})
        assert response.status_code == 302
    finally:
        event.remove(db.engine, "before_execute", capture)
    assert locks, "The user must be locked before checking the pending request quota."
    assert all(sql.rstrip().endswith("FOR NO KEY UPDATE") for sql in locks)
