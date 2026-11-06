"""Small, explicit UI catalog. User content and stored business values stay intact."""
from functools import lru_cache
import json
from pathlib import Path
import re

from flask import g, has_request_context, session

LANGUAGES = {"zh-Hant": "繁體中文", "id": "Bahasa Indonesia", "vi": "Tiếng Việt"}
_FIELD = re.compile(r"\{([A-Za-z_][A-Za-z_0-9]*)\}")


def get_locale():
    if not has_request_context():
        return "zh-Hant"
    if g.get("patrol_ui_locale") in LANGUAGES:
        return g.patrol_ui_locale
    user = g.get("user")
    value = getattr(user, "ui_language", "zh-Hant") if user is not None else session.get("ui_language", "zh-Hant")
    return value if value in LANGUAGES else "zh-Hant"


@lru_cache(maxsize=1)
def catalog():
    messages = {}
    for path in sorted((Path(__file__).parent / "locales").glob("*.json")):
        for source, values in json.loads(path.read_text(encoding="utf-8")).items():
            messages.setdefault(source, {}).update(values)
    return messages


@lru_cache(maxsize=1)
def patterns():
    result = []
    for source in catalog():
        fields = list(_FIELD.finditer(source))
        if not fields:
            continue
        parts, names, offset = [], [], 0
        for field in fields:
            parts.extend((re.escape(source[offset:field.start()]), r"(.+?)"))
            names.append(field.group(1))
            offset = field.end()
        parts.append(re.escape(source[offset:]))
        result.append((re.compile("^" + "".join(parts) + "$", re.DOTALL), source, names))
    return result


def translate(source, locale, **values):
    if source is None:
        return ""
    text = str(source)
    key = text
    if locale != "zh-Hant" and key not in catalog():
        for pattern, candidate, names in patterns():
            matched = pattern.fullmatch(text)
            if matched:
                key = candidate
                values = dict(zip(names, matched.groups())) | values
                break
    translated = catalog().get(key, {}).get(locale, key) if locale != "zh-Hant" else key
    # Substitute only named placeholders; never execute format expressions.
    return _FIELD.sub(lambda match: str(values.get(match.group(1), match.group(0))), translated)


def t(source, **values):
    return translate(source, get_locale(), **values)


def point_name(source):
    """Call only for known point names; never apply to names or entered notes."""
    return t(source)


@lru_cache(maxsize=1)
def public_messages():
    # The cacheable offline shell is public. Location names come only from the
    # authenticated point manifest, never from its shared UI catalog.
    messages = {}
    for path in sorted((Path(__file__).parent / "locales").glob("*.json")):
        if path.name == "points.json":
            continue
        for source, values in json.loads(path.read_text(encoding="utf-8")).items():
            messages.setdefault(source, {}).update(values)
    return messages


def client_catalog(locale=None):
    selected = locale or get_locale()
    # Default-language pages use the source strings already in the scripts.
    # Only the explicit public offline shell needs both languages for later IDB
    # restoration. Avoid sending all translations with every Chinese report.
    messages = {} if locale is None and selected == "zh-Hant" else public_messages()
    return {"locale": selected, "messages": messages}
