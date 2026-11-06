"""Language choice is presentation only; private values are not public catalogs."""
import json
from pathlib import Path
import re
from types import SimpleNamespace

from flask import Flask, g, session

from i18n import catalog, client_catalog, get_locale, t, translate


def test_account_language_overrides_old_browser_session():
    app = Flask(__name__)
    app.secret_key = "test"
    with app.test_request_context():
        session["ui_language"] = "vi"
        g.user = SimpleNamespace(ui_language="id")
        assert get_locale() == "id"
        assert t("待簽到") == catalog()["待簽到"]["id"]
        g.user = SimpleNamespace(ui_language="zh-Hant")
        assert get_locale() == "zh-Hant"
        assert t("待簽到") == "待簽到"
        assert client_catalog()["messages"] == {}
        assert client_catalog("zh-Hant")["messages"]
        g.user = SimpleNamespace(ui_language="invalid")
        assert get_locale() == "zh-Hant"
        g.user = None
        assert get_locale() == "vi"


def test_translation_formats_named_values_without_format_code_execution():
    result = translate("第 {round} 次 · 待簽到", "vi", round=2)
    assert "2" in result and "待簽到" not in result
    assert translate("第 2 次 · 待簽到", "vi") == result
    assert translate("{person.__class__}", "vi", person="test") == "{person.__class__}"
    assert translate("unknown entered note", "id") == "unknown entered note"
    assert translate(None, "id") == ""
    assert translate("{count} 筆", "zh-Hant", count=3) == "3 筆"


def test_public_catalog_excludes_location_dictionary():
    public = client_catalog("zh-Hant")
    assert public["locale"] == "zh-Hant"
    assert "抽風機/冷卻水塔/桶槽區" in catalog()
    assert "抽風機/冷卻水塔/桶槽區" not in public["messages"]
    assert "1M男廁所-甲" not in public["messages"]


def test_each_catalog_translation_preserves_placeholders_and_has_both_languages():
    field = re.compile(r"\{([A-Za-z_][A-Za-z_0-9]*)\}")
    for path in (Path(__file__).parents[1] / "locales").glob("*.json"):
        for source, translations in json.loads(path.read_text(encoding="utf-8")).items():
            assert set(translations) == {"id", "vi"}, (path.name, source)
            for locale, text in translations.items():
                assert isinstance(text, str) and text.strip(), (path.name, source, locale)
                assert set(field.findall(source)) == set(field.findall(text)), (path.name, source, locale)


def test_csp_catalog_is_data_not_inline_executable_script():
    for name in ("base.html", "offline.html"):
        source = (Path(__file__).parents[1] / "templates" / name).read_text(encoding="utf-8")
        assert 'type="application/json"' in source
        assert "window.PATROL_I18N =" not in source
