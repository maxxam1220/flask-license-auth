"""Validate backup payloads before opening a database connection.

These helpers accept decoded JSON and never access the database.  They return
copies with the fields consumed by the existing importers normalized, retaining
extra metadata and columns for compatibility with exported backups.
"""

import json
import re
from datetime import datetime


AUTH_DATASETS = ("licenses", "bindings", "accounts", "rbac_tabs", "rbac_modules")
BARCODE_DATASETS = ("BcMst", "BcDtl", "BcLog", "Barcode")


def _object(value, path):
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be a JSON object")
    return dict(value)


def _rows(data, key, *, path="backup", allow_empty=True):
    label = f"{path}.{key}"
    if key not in data or not isinstance(data[key], list):
        raise ValueError(f"{label} is required and must be a list")
    if not allow_empty and not data[key]:
        raise ValueError(f"{label} must not be empty for a full restore")
    rows = []
    for index, value in enumerate(data[key]):
        row_path = f"{label}[{index}]"
        row = _object(value, row_path)
        if not row:
            raise ValueError(f"{row_path} must not be an empty object")
        if any(not isinstance(key, str) or not key for key in row):
            raise ValueError(f"{row_path} contains an invalid field name")
        rows.append(row)
    return rows


def _text(row, key, path, *, optional=False, strip=False):
    value = row.get(key)
    if optional and value is None:
        return None
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError(f"{path}.{key} must be a string" + (" or null" if optional else ""))
    if not optional and not value.strip():
        raise ValueError(f"{path}.{key} must not be blank")
    return value.strip() if strip else value


def _date(value, path, *, optional=False):
    if optional and value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a valid date" + (" or null" if optional else ""))
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return datetime.strptime(value, "%Y-%m-%d").date().isoformat()
        # /export_licenses passes DATE values directly to Flask's JSON provider,
        # which serializes them as HTTP dates.  /export_auth_backup uses ISO.
        if re.fullmatch(r"[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} 00:00:00 GMT", value):
            return datetime.strptime(value, "%a, %d %b %Y %H:%M:%S GMT").date().isoformat()
    except ValueError:
        pass
    raise ValueError(f"{path} must be a valid ISO date or exported HTTP date")


def _unique(rows, key, path):
    seen = set()
    for index, row in enumerate(rows):
        value = row[key]
        if value in seen:
            # Never include field values, password hashes, or license codes in
            # a validation error that may be displayed or logged by the caller.
            raise ValueError(f"{path}[{index}].{key} is duplicated")
        seen.add(value)
    return seen


def _validate_license_datasets(data, *, full_restore):
    licenses = _rows(data, "licenses", allow_empty=not full_restore)
    bindings = _rows(data, "bindings")
    for index, row in enumerate(licenses):
        path = f"backup.licenses[{index}]"
        row["auth_code"] = _text(row, "auth_code", path)
        row["expiry"] = _date(row.get("expiry"), f"{path}.expiry")
        remaining = row.get("remaining")
        if type(remaining) is not int or not 0 <= remaining <= 2147483647:
            raise ValueError(f"{path}.remaining must be an integer from 0 to 2147483647")
        row["mac"] = _text(row, "mac", path, optional=True)
    codes = _unique(licenses, "auth_code", "backup.licenses")
    for index, row in enumerate(bindings):
        path = f"backup.bindings[{index}]"
        row["mac"] = _text(row, "mac", path)
        row["auth_code"] = _text(row, "auth_code", path)
        if row["auth_code"] not in codes:
            raise ValueError(f"{path}.auth_code does not reference a license in this backup")
    _unique(bindings, "mac", "backup.bindings")
    data["licenses"] = licenses
    data["bindings"] = bindings


def _aliased_text(row, key, aliases, path, *, strip=False):
    # Legacy imports accept role/name and module/name aliases.  An explicitly
    # present malformed canonical field must not be hidden by a valid alias.
    selected = key
    if key not in row:
        selected = next((alias for alias in aliases if alias in row), key)
    return _text(row, selected, path, strip=strip)


def _validate_rbac(data, dataset, name_key, aliases):
    rows = _rows(data, dataset, allow_empty=False)
    for index, row in enumerate(rows):
        path = f"backup.{dataset}[{index}]"
        row[name_key] = _aliased_text(row, name_key, aliases, path)
        tabs = row.get("tabs")
        if isinstance(tabs, str):
            try:
                tabs = json.loads(tabs)
            except (ValueError, TypeError):
                raise ValueError(f"{path}.tabs must contain a valid JSON list") from None
        if not isinstance(tabs, list) or any(
            not isinstance(tab, str) or not tab.strip() or "\x00" in tab for tab in tabs
        ):
            raise ValueError(f"{path}.tabs must be a list of nonblank strings")
        row["tabs"] = list(tabs)
    _unique(rows, name_key, f"backup.{dataset}")
    data[dataset] = rows


def validate_auth_backup(data):
    """Validate a complete destructive auth restore; empty bindings are valid."""
    result = _object(data, "backup")
    _validate_license_datasets(result, full_restore=True)
    accounts = _rows(result, "accounts", allow_empty=False)
    for index, row in enumerate(accounts):
        path = f"backup.accounts[{index}]"
        row["username"] = _text(row, "username", path, strip=True)
        row["password_hash"] = _text(row, "password_hash", path)
        row["role"] = _aliased_text(row, "role", ("role_name",), path, strip=True)
        row["module"] = _aliased_text(row, "module", ("module_name",), path, strip=True)
        if type(row.get("active")) is not bool:
            raise ValueError(f"{path}.active is required and must be a boolean")
        row["expires_at"] = _date(row.get("expires_at"), f"{path}.expires_at", optional=True)
        row["expires_enc"] = _text(row, "expires_enc", path, optional=True)
    _unique(accounts, "username", "backup.accounts")
    result["accounts"] = accounts
    _validate_rbac(result, "rbac_tabs", "role_name", ("role", "name"))
    _validate_rbac(result, "rbac_modules", "module_name", ("module", "name"))
    return result


def validate_licenses_backup(data):
    """Validate the complete license/binding payload used by the merge importer."""
    result = _object(data, "backup")
    _validate_license_datasets(result, full_restore=False)
    return result


def validate_barcode_backup(data):
    """Check the full barcode backup's shape without freezing dynamic columns.

    BcLog is required as an exported dataset but is restored through separate
    endpoints.  It cannot make an otherwise empty destructive restore valid.
    Column compatibility must still be checked inside the import transaction.
    """
    result = _object(data, "backup")
    payload = _object(result.get("barcode53"), "backup.barcode53")
    for dataset in BARCODE_DATASETS:
        payload[dataset] = _rows(payload, dataset, path="backup.barcode53")
    if not any(payload[name] for name in ("BcMst", "BcDtl", "Barcode")):
        raise ValueError("backup.barcode53 must contain data in a table restored by this endpoint")
    result["barcode53"] = payload
    return result
