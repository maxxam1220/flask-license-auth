"""A second review tab cannot silently change the phone approved by the first."""
from html.parser import HTMLParser

from models import AuditLog, DeviceBinding, db
from test_app import application, login, seeded


class ReviewForms(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.fields = {}
        self.current = None
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = self.fields.setdefault(attrs.get("action"), {})
        elif self.current is not None and tag == "input" and attrs.get("name"):
            self.current[attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None


def test_two_admin_tabs_require_a_fresh_review_before_replacing_another_approval(application, seeded):
    viewer = application.test_client()
    login(viewer, "manager")
    owner = seeded["inspector"].id
    old, first, second = [
        DeviceBinding(user_id=owner, token_hash=f"test-device-{name}", label=name, status=status)
        for name, status in [("Old phone", "approved"), ("New phone A", "pending"), ("New phone B", "pending")]
    ]
    db.session.add_all([old, first, second])
    db.session.commit()
    approve = lambda row: f"/admin/devices/{row.id}/approve"
    forms = ReviewForms(viewer.get("/admin/devices").text).fields
    assert viewer.post(approve(first), data=forms[approve(first)]).status_code == 302
    blocked = viewer.post(approve(second), data=forms[approve(second)])
    assert blocked.status_code == 409 and 'href="/admin/devices"' in blocked.text
    assert viewer.post(approve(second)).status_code == 409
    assert first.status == "approved" and second.status == "pending"
    assert db.session.query(AuditLog).filter_by(action="device_approved").count() == 1
    # New form explicitly identifies the phone the administrator now intends to replace.
    updated = ReviewForms(viewer.get("/admin/devices").text).fields[approve(second)]
    assert updated["reviewed_approved_id"] == str(first.id)
    assert viewer.post(approve(second), data=updated).status_code == 302
    assert second.status == "approved" and first.status == old.status == "revoked"


def test_retrying_revoke_never_overwrites_device_history(application, seeded):
    viewer = application.test_client()
    login(viewer, "manager")
    phone = DeviceBinding(user_id=seeded["inspector"].id, token_hash="attempt-again", status="pending")
    db.session.add(phone)
    db.session.commit()
    base = f"/admin/devices/{phone.id}/"
    assert viewer.post(base + "reject").status_code == 302
    for action in ("revoke", "reject", "approve"):
        stale = viewer.post(base + action)
        assert stale.status_code == 409 and 'href="/admin/devices"' in stale.text
    assert phone.status == "rejected"
    assert db.session.query(AuditLog).filter_by(target=str(phone.id), action="device_revoked").count() == 0
