from test_app import application, db, login, seeded
from test_inspector_issues import make_case


def test_two_rounds_of_multiline_issue_actions_and_recently_closed_order(application, seeded):
    user = seeded["inspector"]
    earliest = make_case(user, seeded["daily"], 1)
    recent = [make_case(user, seeded["daily"], day, resolved=True) for day in range(2, 53)]
    db.session.commit()
    owner, admin = application.test_client(), application.test_client()
    login(owner)
    login(admin, "manager")
    # HTML form submission encodes each textarea newline as CRLF even though
    # the 2,000-character DOM value contains only a single LF at that position.
    note = ("現場已完成查核\n" * 250)[:1999] + "。"
    assert len(note) == 2000
    submitted = note.replace("\n", "\r\n")
    endpoint = f"/issues/{earliest.id}/resolve"
    close = owner.post(endpoint, data={"expected_event_id": "0", "note": submitted})
    assert close.status_code == 302
    db.session.refresh(earliest)
    assert earliest.issue.resolution_note == note
    assert earliest.issue.events[-1].note == note
    first = owner.get("/issues?status=resolved&date_from=&date_to=").text
    assert first.index(f'href="/records/{earliest.id}?') < first.index(f'href="/records/{recent[-1].id}?')
    reopen = admin.post(f"/admin/issues/{earliest.id}/reopen", data={
        "expected_event_id": earliest.issue.events[-1].id, "note": submitted,
    })
    assert reopen.status_code == 302
    db.session.refresh(earliest)
    assert earliest.issue.events[-1].note == note
    retry = owner.post(endpoint, data={"expected_event_id": earliest.issue.events[-1].id, "note": "再次確認"})
    assert retry.status_code == 302
    db.session.refresh(earliest)
    assert [e.action for e in earliest.issue.events] == ["resolved", "reopened", "resolved"]
