"""Weekly and monthly handoffs through QR confirmation forms and saved receipts."""
from datetime import datetime, timedelta, timezone

import pytest

from receipt_urls import without_voice_feedback

import app as patrol
from models import Inspection, PatrolExecution, Point, User, db
from test_app import application, rendered_contexts  # noqa: F401
from test_postgres_features import postgres_app  # noqa: F401
from test_workflow_checkin import payload, team


@pytest.mark.parametrize("database", ["application", "postgres_app"])
@pytest.mark.parametrize("frequency,boundary,old_key,new_key", [
    ("weekly", datetime(2027, 1, 3, 16, tzinfo=timezone.utc), "2026-12-28", "2027-01-04"),
    ("monthly", datetime(2028, 2, 29, 16, tzinfo=timezone.utc), "2028-02-01", "2028-03-01"),
])
def test_cross_day_personal_reviews_use_period_execution(request, monkeypatch, database, frequency, boundary, old_key, new_key):
    app = request.getfixturevalue(database)
    now = boundary - timedelta(days=2, minutes=1)
    monkeypatch.setattr(patrol, "now_utc", lambda: now)
    with app.app_context():
        executor, inspector, colleague, other_executor, url, _, _ = team(app)
        second_actor = db.session.scalar(db.select(User).where(User.username == "admin"))
        second_actor.role, second_actor.patrol_category = "executor", "general"
        point = db.session.scalar(db.select(Point).where(Point.qr_token == url[3:]))
        point.frequency = point.schedules[0].frequency = frequency
        db.session.commit()
        post = url + "/confirm"

        assert 'id="inspection-form"' not in inspector.get(url).text
        now -= timedelta(days=1)
        never_submitted = payload(executor, url)
        now += timedelta(days=1)
        assert executor.post(post, data=never_submitted).status_code == 409
        assert db.session.query(PatrolExecution).count() == 0
        first_form = payload(executor, url)
        first = executor.post(post, data=first_form)
        assert first.status_code == 302 and first.location.startswith("/executions/")
        assert first_form["period_key"] == old_key
        first_id = db.session.scalar(db.select(PatrolExecution.id))
        old_form = payload(inspector, url)
        first_created_at = now.replace(tzinfo=None)

        # Taipei midnight within the same period. A retry of a saved execution
        # reads that receipt; yesterday's unsaved inspection cannot be posted.
        now += timedelta(minutes=2)
        assert without_voice_feedback(executor.post(post, data=first_form).location) == without_voice_feedback(first.location)
        assert other_executor.post(post, data=first_form).status_code == 409
        assert other_executor.get(first.location).status_code == 403
        assert executor.post(post, data=first_form | {"personal_day": "2001-01-01"}).status_code == 409
        with rendered_contexts(app) as contexts:
            assert 'id="inspection-form"' not in executor.get(url).text
        assert contexts[-1][1]["stage_notice"] == "本週期已登記執行，不需重複簽到。"
        assert inspector.post(post, data=old_form).status_code == 409
        assert db.session.query(Inspection).count() == 0
        day_one = patrol.local_dt(now).date()
        receipt_ids = []
        for actor in (inspector, colleague):
            fields = payload(actor, url)
            assert fields["stage"] == "inspect" and fields["period_key"] == old_key
            receipt = actor.post(post, data=fields)
            assert receipt.status_code == 302 and receipt.location.startswith("/checkins/")
            assert actor.get(receipt.location).status_code == 200
            assert without_voice_feedback(actor.post(post, data=fields).location) == without_voice_feedback(receipt.location)
            receipt_ids.append(int(without_voice_feedback(receipt.location).rsplit("/", 1)[1]))
        assert len(set(receipt_ids)) == 2
        with rendered_contexts(app) as contexts:
            assert executor.get(first.location).status_code == 200
        assert contexts[-1][1]["finalized"] is True
        assert 'id="inspection-form"' not in inspector.get(url).text

        now = boundary - timedelta(minutes=1)
        day_two = patrol.local_dt(now).date()
        assert day_two != day_one
        next_day = inspector.post(post, data=payload(inspector, url))
        assert next_day.status_code == 302
        assert int(without_voice_feedback(next_day.location).rsplit("/", 1)[1]) not in receipt_ids
        rows = db.session.scalars(db.select(Inspection).order_by(Inspection.id)).all()
        assert [(r.period_key, r.personal_day, r.execution_id, r.execution.created_at) for r in rows] == [
            (old_key, d, first_id, first_created_at) for d in (day_one, day_one, day_two)]
        stale = payload(colleague, url)

        # The new period cannot inherit the old stage, even at precisely 00:00.
        now = boundary
        assert executor.post(post, data=first_form).status_code == 409
        assert colleague.post(post, data=stale).status_code == 409
        assert "尚未執行" in inspector.get(url).text
        stage_one_fields = payload(executor, url)
        assert stage_one_fields["period_key"] == new_key
        assert inspector.post(post, data=stage_one_fields | {"stage": "inspect"}).status_code == 409
        assert (db.session.query(PatrolExecution).count(), db.session.query(Inspection).count()) == (1, 3)
        second_execution = executor.post(post, data=stage_one_fields)
        assert second_execution.status_code == 302 and without_voice_feedback(second_execution.location) != without_voice_feedback(first.location)
        assert inspector.post(post, data=payload(inspector, url)).status_code == 302
        last = db.session.scalar(db.select(Inspection).order_by(Inspection.id.desc()))
        assert last.period_key == last.execution.period_key == new_key and last.execution_id != first_id
        assert last.personal_day.isoformat() == new_key
        assert (db.session.query(PatrolExecution).count(), db.session.query(Inspection).count()) == (2, 4)
