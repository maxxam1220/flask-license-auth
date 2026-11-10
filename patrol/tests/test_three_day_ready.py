"""Today's actionable stops share the same fixed three-day team obligation."""
from datetime import date, datetime

import pytest

from missed import TAIPEI
from models import Inspection, Point, PointSchedule, User, db
from ready_patrol import ready_patrol_points
from test_app import application


@pytest.fixture
def fixture_point(application):
    users = [User(username=name, display_name=name, role="inspector", patrol_category="general",
                  password_hash="unused", active=True, must_change_password=False)
             for name in ("first", "second")]
    point = Point(code="1F-3DAY", name="Three-day test", floor=1, category="general", inspection_team="general",
                  workflow_mode="spot", frequency="three_day", active=True, schedule_start=date(2026, 11, 10),
                  created_at=datetime(2026, 11, 9))
    point.schedules.append(PointSchedule(effective_date=point.schedule_start, category="general", floor=1,
        point_code=point.code, point_name=point.name, frequency="three_day", workflow_mode="spot", active=True))
    db.session.add_all([point, *users])
    db.session.commit()
    return point, users


def ready(point, user, day):
    instant = datetime.combine(date.fromisoformat(day), datetime.min.time(), TAIPEI).replace(hour=10)
    return ready_patrol_points([point], user, instant, "", "")


def record(point, user, day="2026-11-11", frequency="three_day", period="2026-11-10"):
    db.session.add(Inspection(point_id=point.id, user_id=user.id, frequency=frequency, period_key=period, slot="any",
        category="general", workflow_mode="spot", personal_day=date.fromisoformat(day), spot_request_id="test:" + day,
        created_at=datetime.fromisoformat(day + "T01:00:00"), point_code=point.code, point_name=point.name,
        point_floor=point.floor, user_name=user.display_name))
    db.session.commit()


def test_uncompleted_stop_remains_ready_for_all_three_days_and_disappears_before_start(fixture_point):
    point, users = fixture_point
    assert ready(point, users[0], "2026-11-09") == []
    for day in ("2026-11-10", "2026-11-11", "2026-11-12"):
        row, = ready(point, users[0], day)
        assert row["code"] == point.code and row["status_key"] == "inspect"
        assert row["frequency"] == "three_day" and row["period_end"] == date(2026, 11, 12)


def test_team_completion_stays_done_next_day_then_next_period_reappears(fixture_point):
    point, users = fixture_point
    record(point, users[0])
    assert ready(point, users[1], "2026-11-11") == []
    assert ready(point, users[1], "2026-11-12") == []
    row, = ready(point, users[1], "2026-11-13")
    assert row["period_end"] == date(2026, 11, 15)


def test_old_optional_record_does_not_fulfill_new_cycle_but_personal_daily_gate_remains(fixture_point):
    point, users = fixture_point
    record(point, users[0], frequency="irregular", period="2026-11-11")
    assert ready(point, users[0], "2026-11-11") == []
    assert len(ready(point, users[1], "2026-11-11")) == 1
    assert len(ready(point, users[0], "2026-11-12")) == 1


def test_responsibility_filter_never_exposes_three_day_stop_to_engineering_or_safety(fixture_point):
    point, users = fixture_point
    users[1].engineering_inspector_title = True
    db.session.commit()
    assert ready(point, users[1], "2026-11-10") == []
    users[1].engineering_inspector_title = False
    users[1].patrol_category = "safety"
    db.session.commit()
    assert ready(point, users[1], "2026-11-10") == []
