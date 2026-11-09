"""Historical checklist snapshots are read from the record, never today's catalog."""
import json


def encode_checklist(snapshot):
    return json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")) if snapshot else ""


def checklist_snapshot(record):
    raw = getattr(record, "checklist_data", "")
    if not raw:
        return None
    try:
        value = json.loads(raw)
        if (not isinstance(value, dict) or not isinstance(value.get("items"), list)
                or not isinstance(value.get("selected"), list) or not isinstance(value.get("title"), dict)):
            return None
        if any(not isinstance(item, dict) or not isinstance(item.get("id"), str)
               or not isinstance(item.get("label"), dict) for item in value["items"]):
            return None
        if any(not isinstance(item, str) for item in value["selected"]):
            return None
        items = value["items"]
        labels = [value["title"], *(item["label"] for item in items)]
        if any(not isinstance(label.get("zh-Hant"), str) or not label["zh-Hant"]
               or any(not isinstance(text, str) for text in label.values()) for label in labels):
            return None
        identifiers = [item["id"] for item in items]
        if (len(set(identifiers)) != len(identifiers) or len(set(value["selected"])) != len(value["selected"])
                or not set(value["selected"]) <= set(identifiers)
                or any("source_code" in item and not isinstance(item["source_code"], str) for item in items)):
            return None
        return value
    except (ValueError, TypeError):
        return None


def checklist_text(record, locale="zh-Hant"):
    snapshot = checklist_snapshot(record)
    if not snapshot:
        return ""
    selected = set(snapshot["selected"])
    return "\n".join(("☑ " if item["id"] in selected else "☐ ")
                     + (item["source_code"] + " " if item.get("source_code") else "")
                     + item["label"].get(locale, item["label"].get("zh-Hant", item["id"]))
                     for item in snapshot["items"])
