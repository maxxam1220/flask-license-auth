"""Explicit QR selection prints only the chosen, currently authorized active points."""
from datetime import date, datetime
from html.parser import HTMLParser
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit
import re

import pytest

import app as patrol
from models import AuditLog, Point, User, db
from test_app import application, rendered_contexts


PRINT = "/admin/points/print"


class Inputs(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.inputs = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag == "input": self.inputs.append(dict(attrs))


@pytest.fixture
def selection(application):
    clients, users = {}, {}
    for name, role, category, manager, engineer in (
        ("admin", "admin", None, False, False),
        ("inspector", "inspector", "general", False, False),
        ("safety", "inspector", "safety", False, False),
        ("executor", "executor", "general", False, False),
        ("general_manager", "inspector", "general", True, False),
        ("engineering", "inspector", "general", False, True),
    ):
        user = User(username=f"qr-{name}", display_name=name, role=role, patrol_category=category,
                    password_hash="unused-fixture", active=True, must_change_password=False,
                    general_manager_title=manager, engineering_inspector_title=engineer)
        db.session.add(user)
        db.session.flush()
        client = application.test_client()
        with client.session_transaction() as session:
            session.update(user_id=user.id, auth_version=user.auth_version, csrf_token=f"qr-{name}-csrf")
        clients[name], users[name] = client, user
    specs = [
        (201, "1M-G014", "201會議室", 11, "general", "general", True, False),
        (202, "1M-G015", "202會議室", 11, "general", "general", True, False),
        (203, "1M-G016", "203會議室", 11, "general", "general", True, False),
        (204, "1M-G100", "停用會議室", 11, "general", "general", False, False),
        (205, "1M-G101", "已刪除會議室", 11, "general", "general", True, True),
        (301, "1M-E001", "工務機房", 11, "general", "engineering", True, False),
        (401, "1M-S001", "職安機房", 11, "safety", "general", True, False),
        (501, "2F-G019", "1.2客梯梯廳", 2, "general", "general", True, False),
        (601, "AB1m-W01", "MixÉD廁所", -1, "general", "general", True, False),
    ]
    points = {}
    for pid, code, name, floor, category, team, active, deleted in specs:
        point = Point(id=pid, code=code, name=name, floor=floor, category=category, inspection_team=team,
            workflow_mode="standard" if category == "safety" else "spot", frequency="daily", active=active,
            deleted_at=datetime(2026, 10, 1) if deleted else None, qr_token=f"unchanged-qr-{pid}",
            schedule_start=date(2026, 1, 1), created_at=datetime(2026, 1, 1))
        db.session.add(point)
        points[pid] = point
    db.session.commit()
    return SimpleNamespace(app=application, admin=clients["admin"], clients=clients, users=users, points=points)


def page(env, query, *, client=None, template="print_qr.html"):
    with rendered_contexts(env.app) as rendered:
        response = (client or env.admin).get(PRINT, query_string=query)
    assert response.status_code == 200, response.text
    assert rendered[-1][0] == template
    return rendered[-1][1], response


def point_ids(context):
    return {point.id for point in context["points"]}


def forbid_qr_generation(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("The selector or rejected request must not generate QR graphics.")
    monkeypatch.setattr(patrol.qrcode, "make", fail)


def test_repeated_nonadjacent_selection_prints_only_201_and_203_on_one_sheet(selection):
    env = selection
    original = {pid: point.qr_token for pid, point in env.points.items()}
    result, response = page(env, [("selected", "1"), ("ids", "201"), ("ids", "203")])
    assert [point.id for point in result["points"]] == [201, 203]
    assert set(result["qr_images"]) == {201, 203}
    assert response.text.count('<section class="qr-print-page"') == 1
    labels = re.findall(r'<article class="qr-label[^>]*>(.*?)</article>', response.text, re.S)
    assert len(labels) == 2 and "201會議室" in labels[0] and "203會議室" in labels[1]
    assert "202會議室" not in response.text
    assert {pid: point.qr_token for pid, point in env.points.items()} == original
    assert db.session.query(AuditLog).count() == 0


@pytest.mark.parametrize("query,expected", [
    ({"ids": "201,203,201"}, {201, 203}),
    ([("ids", "201,203"), ("ids", "203"), ("ids", "201")], {201, 203}),
    ({"ids": "201"}, {201}),
])
def test_comma_single_and_repeated_ids_are_compatible_and_deduplicated(selection, query, expected):
    result, response = page(selection, query)
    assert point_ids(result) == expected and len(result["points"]) == len(expected)
    assert len(re.findall(r'<article class="qr-label', response.text)) == len(expected)


@pytest.mark.parametrize("query", [
    {"selected": "1"}, {"selected": "1", "ids": ""},
    [("selected", "1"), ("ids", ""), ("ids", "")],
])
def test_empty_explicit_selection_redirects_with_message_instead_of_printing_all(selection, monkeypatch, query):
    forbid_qr_generation(monkeypatch)
    response = selection.admin.get(PRINT, query_string=query)
    assert response.status_code == 302 and urlsplit(response.location).path == PRINT
    assert parse_qs(urlsplit(response.location).query)["select"] == ["1"]
    with selection.admin.session_transaction() as session:
        assert any("勾選" in message and "至少" in message for _, message in session.get("_flashes", []))
    followed = selection.admin.get(response.location)
    assert followed.status_code == 200 and 'class="qr-print-page"' not in followed.text
    assert "data:image/png;base64," not in followed.text


@pytest.mark.parametrize("value", ["0", "-1", "abc", "1.5", "2147483648", "201,,203", "201, 203", "２０１", "1 OR 1=1"])
@pytest.mark.parametrize("select_mode", [False, True])
def test_invalid_ids_are_rejected_before_generation(selection, monkeypatch, value, select_mode):
    forbid_qr_generation(monkeypatch)
    query = [("ids", "201"), ("ids", value)] + ([("select", "1")] if select_mode else [])
    assert selection.admin.get(PRINT, query_string=query).status_code == 400


@pytest.mark.parametrize("query,expected", [
    ({"ids": "201,204,205,999999"}, {201}),
    ({"ids": "204,205,999999"}, set()),
])
def test_disabled_deleted_and_unknown_ids_cannot_print_or_expand_to_all(selection, query, expected):
    result, response = page(selection, query)
    assert point_ids(result) == expected
    assert "停用會議室" not in response.text and "已刪除會議室" not in response.text
    assert "202會議室" not in response.text


@pytest.mark.parametrize("filters,expected", [
    ({}, {201, 202, 203, 301, 401, 501, 601}),
    ({"category": "general", "floor": "11", "inspection_team": "general"}, {201, 202, 203}),
    ({"category": "general", "floor": "11", "inspection_team": "engineering"}, {301}),
    ({"category": "safety", "floor": "11"}, {401}),
    ({"q": "203"}, {203}),
    ({"q": "  ab1M-w01  "}, {601}),
    ({"q": "mixéd"}, {601}),
    ({"q": "not-found"}, set()),
])
def test_selector_filters_visible_choices_and_does_not_generate_graphics(selection, monkeypatch, filters, expected):
    forbid_qr_generation(monkeypatch)
    result, response = page(selection, {"select": "1", **filters}, template="qr_select.html")
    assert point_ids(result) == expected
    assert "data:image/png;base64," not in response.text and 'class="qr-print-page"' not in response.text
    inputs = Inputs(response.text).inputs
    assert any(item.get("name") == "selected" and item.get("value") == "1" and item.get("type") == "hidden"
               for item in inputs)
    choices = {int(item["value"]) for item in inputs if item.get("name") == "ids" and item.get("type") == "checkbox"}
    assert choices == expected


def test_selector_preselection_intersects_visible_choices_and_preserves_repeated_comma_ids(selection, monkeypatch):
    forbid_qr_generation(monkeypatch)
    result, response = page(selection, [("select", "1"), ("floor", "11"), ("category", "general"),
        ("inspection_team", "general"), ("ids", "201,203"), ("ids", "203"), ("ids", "204,205,301,401,501,99999")],
        template="qr_select.html")
    assert set(result["selected_ids"]) == {201, 203}
    checked = {int(item["value"]) for item in Inputs(response.text).inputs
               if item.get("name") == "ids" and item.get("type") == "checkbox" and "checked" in item}
    assert checked == {201, 203}


@pytest.mark.parametrize("filters,expected", [
    ({"category": "safety", "floor": "11"}, {401}),
    ({"category": "general", "inspection_team": "engineering"}, {301}),
    ({"category": "general", "inspection_team": "general", "floor": "11"}, {201, 203}),
    ({"floor": "2"}, {501}),
    ({"category": "safety", "floor": "2"}, set()),
])
def test_forged_selected_ids_cannot_escape_category_team_or_floor_filters(selection, filters, expected):
    result, _ = page(selection, {"selected": "1", "ids": "201,203,204,205,301,401,501", **filters})
    assert point_ids(result) == expected


def test_confirmed_id_selection_is_not_silently_dropped_when_search_name_changes(selection):
    selection.points[201].name = "Renamed meeting room"
    db.session.commit()
    result, _ = page(selection, {"selected": "1", "ids": "201", "q": "201會議室"})
    assert point_ids(result) == {201} and result["points"][0].name == "Renamed meeting room"


@pytest.mark.parametrize("filters", [{"category": "bogus"}, {"floor": "99"}, {"inspection_team": "safety"}])
def test_invalid_scope_filters_are_rejected(selection, monkeypatch, filters):
    forbid_qr_generation(monkeypatch)
    for mode in ({"select": "1"}, {"selected": "1", "ids": "201"}):
        assert selection.admin.get(PRINT, query_string={**mode, **filters}).status_code == 400


@pytest.mark.parametrize("actor", ["inspector", "safety", "executor", "general_manager", "engineering"])
def test_selector_and_print_remain_system_admin_only(selection, monkeypatch, actor):
    forbid_qr_generation(monkeypatch)
    for query in ({"select": "1"}, {"selected": "1", "ids": "201,203"}, {"ids": "201"}):
        assert selection.clients[actor].get(PRINT, query_string=query).status_code == 403
    anonymous = selection.app.test_client().get(PRINT + "?select=1")
    assert anonymous.status_code == 302 and urlsplit(anonymous.location).path == "/login"
