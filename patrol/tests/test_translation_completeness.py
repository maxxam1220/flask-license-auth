"""Rendered executor translations keep numeric rules and recovery semantics intact."""
import pytest

from i18n import translate
from models import DeviceBinding, User, db
from test_app import PASSWORD, application
from test_daily2_anytime import anytime
from test_executor_localized_workflows import visible_text


@pytest.mark.parametrize("locale", ["id", "vi"])
def test_short_password_error_renders_actual_limits_without_placeholder_leak(application, anytime, locale):
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    actor.ui_language, actor.simple_executor_ui = locale, True
    actor.set_password(PASSWORD)
    db.session.commit()
    version, original_hash = actor.auth_version, actor.password_hash
    response = anytime.executor.post("/change-password", data={"current_password": PASSWORD,
        "new_password": "12345", "confirm_password": "12345"})
    assert response.status_code == 200
    text = visible_text(response)
    assert "{minimum}" not in text and "{maximum}" not in text
    expected = ("Gunakan 6–256 karakter untuk kata sandi baru." if locale == "id"
                else "Mật khẩu mới phải có 6–256 ký tự.")
    assert expected in text
    assert actor.auth_version == version and actor.password_hash == original_hash


@pytest.mark.parametrize("locale", ["id", "vi"])
def test_password_error_template_and_existing_formatted_source_translate_identically(locale):
    parameterized = translate("新密碼請使用 {minimum} 至 {maximum} 個字元。", locale, minimum=6, maximum=256)
    formatted = translate("新密碼請使用 6 至 256 個字元。", locale)
    assert parameterized == formatted and "{" not in parameterized


@pytest.mark.parametrize("locale", ["id", "vi"])
def test_bound_inspector_device_guidance_uses_selected_language(application, anytime, locale):
    actor = db.session.scalar(db.select(User).where(User.username == "inspect"))
    actor.ui_language = locale
    db.session.commit()
    response = anytime.inspector.get("/devices")
    text = visible_text(response)
    source = "到巡檢點掃描現場 QR Code，再核對點位並確認打卡。"
    expected = translate(source, locale)
    assert expected != source and expected in text and source not in text


@pytest.mark.parametrize("locale, expected, misleading", [
    ("id", "Buka pendaftaran browser", "Buka pengaturan ponsel"),
    ("vi", "Mở trang liên kết trình duyệt", "Mở cài đặt điện thoại"),
])
def test_pending_executor_binding_action_names_the_website_destination(application, anytime, locale, expected, misleading):
    """Recovery goes to this site's browser binding, not OS phone settings."""
    actor = db.session.scalar(db.select(User).where(User.username == "exec"))
    actor.ui_language, actor.simple_executor_ui = locale, True
    binding = db.session.scalar(db.select(DeviceBinding).where(DeviceBinding.user_id == actor.id))
    binding.status = "pending"
    db.session.commit()
    response = anytime.executor.get(anytime.paired)
    assert response.status_code == 200
    text = visible_text(response)
    assert expected in text and misleading not in text
    assert f'href="/devices?next={anytime.paired}"' in response.text
    assert binding.status == "pending"
