"""Pure rules shared with the desktop label printer's barcode composition."""
from copy import deepcopy
from datetime import date


def _digits(value):
    return "".join(c for c in str(value or "") if c.isascii() and c.isdigit())


def barcode_for_source(config, base_date):
    """Return a checkable printed value, never invent an empty barcode's value.

    Mirrors app/services/label_renderer.py compose_barcode_raw and the EAN/UPC
    display checksum. The web process does not import Qt or the desktop app.
    """
    kind = str(config.get("kind", "")).strip()
    direct = str(config.get("barcode", "") or "").strip()
    if not direct:
        return ""
    if kind not in {"1", "2", "3"}:
        return direct
    length = {"1": 12, "2": 11, "3": 7}[kind]
    front, back = _digits(config.get("front")), _digits(config.get("back"))
    solar = str(config.get("solar", "")).strip()
    custom = bool(front or back or solar in {"2", "3"} or str(config.get("price_len", "")).strip() == "4")
    digits = _digits(direct)
    if len(digits) >= length + 1 and not custom:
        raw = digits[:length]
    else:
        core = _digits(config.get("master_barcode")) or digits[:length]
        raw = front + core + back
        if solar in {"2", "3"}:
            day = date.fromisoformat(base_date).timetuple().tm_yday
            inserted = f"{day % 100:02d}" if solar == "2" else f"{day:03d}"
            pos = min(max(0, int(config.get("solar_pos") or 1) - 1), len(raw))
            raw = raw[:pos] + inserted + raw[pos:]
        price = float(config.get("sale_price") or 0)
        if str(config.get("price_len", "")).strip() == "4" and price > 0 and len(raw) < length:
            raw += f"{int(round(price)) % 10000:04d}"
        raw = raw.ljust(length, "0")[:length]
    if len(raw) != length or not raw.isascii() or not raw.isdigit():
        return ""
    checksum = (10 - sum(int(d) * (3 if index % 2 == 0 else 1) for index, d in enumerate(reversed(raw))) % 10) % 10
    return raw + str(checksum)


def prepare_source(source, base_date):
    if source is None:
        return None
    result = deepcopy(source)
    result["base_date"] = base_date
    value = barcode_for_source(result.get("barcode_config", {}), base_date)
    if value:
        result["barcode_values"] = list(dict.fromkeys([*result.get("barcode_values", []), value]))
    return result
