import copy
import importlib.util
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "flask-license-auth" / "backup_validation.py"
SPEC = importlib.util.spec_from_file_location("backup_validation", MODULE_PATH)
validation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validation)


def auth_backup():
    return {
        "schema_version": 1,
        "licenses": [{"auth_code": "license-1", "expiry": "2030-12-31", "remaining": 2, "mac": None}],
        "bindings": [{"mac": "device-1", "auth_code": "license-1"}],
        "accounts": [{
            "username": "operator", "password_hash": "opaque-existing-password-hash",
            "role": "staff", "module": "sales", "active": False,
            "expires_at": None, "expires_enc": None,
        }],
        "rbac_tabs": [{"role_name": "staff", "tabs": ["orders"]}],
        "rbac_modules": [{"module_name": "sales", "tabs": ["orders"]}],
    }


def barcode_backup():
    return {"barcode53": {
        "BcMst": [{"CodeNo": "label-1", "KeepDays": 3, "ExtensionColumn": "preserved"}],
        "BcDtl": [], "BcLog": [], "Barcode": [],
    }}


class AuthBackupValidationTests(unittest.TestCase):
    def test_current_export_round_trip_preserves_values_and_input(self):
        source = auth_backup()
        original = copy.deepcopy(source)
        result = validation.validate_auth_backup(source)
        self.assertEqual(result, original)
        self.assertIsNot(result, source)
        result["licenses"][0]["remaining"] = 100
        result["rbac_tabs"][0]["tabs"].append("extra")
        self.assertEqual(source, original)

    def test_rejects_missing_or_nonobject_json(self):
        for value in (None, [], "", 0, False):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validation.validate_auth_backup(value)

    def test_all_datasets_required_even_when_bindings_can_be_empty(self):
        for name in validation.AUTH_DATASETS:
            source = auth_backup()
            del source[name]
            with self.subTest(dataset=name), self.assertRaises(ValueError):
                validation.validate_auth_backup(source)
        source = auth_backup()
        source["bindings"] = []
        self.assertEqual(validation.validate_auth_backup(source)["bindings"], [])

    def test_rejects_empty_destructive_datasets(self):
        for name in ("licenses", "accounts", "rbac_tabs", "rbac_modules"):
            source = auth_backup()
            source[name] = []
            with self.subTest(dataset=name), self.assertRaises(ValueError):
                validation.validate_auth_backup(source)

    def test_rejects_bad_dataset_and_row_shapes(self):
        for name in validation.AUTH_DATASETS:
            for value in (None, {}, "[]", [None], ["row"], [{}]):
                source = auth_backup()
                source[name] = value
                with self.subTest(dataset=name, value=value), self.assertRaises(ValueError):
                    validation.validate_auth_backup(source)

    def test_rejects_duplicate_primary_keys(self):
        for name in validation.AUTH_DATASETS:
            source = auth_backup()
            source[name].append(copy.deepcopy(source[name][0]))
            with self.subTest(dataset=name), self.assertRaises(ValueError):
                validation.validate_auth_backup(source)

    def test_rejects_usernames_that_collide_after_importer_trims_them(self):
        source = auth_backup()
        source["accounts"].append(dict(source["accounts"][0], username=" operator "))
        with self.assertRaises(ValueError):
            validation.validate_auth_backup(source)

    def test_rejects_malformed_or_missing_required_fields(self):
        cases = {
            "licenses": ("auth_code", "expiry", "remaining"),
            "bindings": ("mac", "auth_code"),
            "accounts": ("username", "password_hash", "role", "module", "active"),
            "rbac_tabs": ("role_name", "tabs"),
            "rbac_modules": ("module_name", "tabs"),
        }
        for name, keys in cases.items():
            for key in keys:
                source = auth_backup()
                del source[name][0][key]
                with self.subTest(dataset=name, field=key), self.assertRaises(ValueError):
                    validation.validate_auth_backup(source)

    def test_integer_range_and_type_are_checked_without_coercion(self):
        for value in (-1, 2147483648, True, False, 2.5, "2", None):
            source = auth_backup()
            source["licenses"][0]["remaining"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validation.validate_auth_backup(source)
        for value in (0, 2147483647):
            source = auth_backup()
            source["licenses"][0]["remaining"] = value
            self.assertEqual(validation.validate_auth_backup(source)["licenses"][0]["remaining"], value)

    def test_rejects_invalid_dates_including_optional_account_expiry(self):
        for dataset, key in (("licenses", "expiry"), ("accounts", "expires_at")):
            for value in ("", "2030-02-30", "2030-1-2", "20301231", "2030-12-31T12:00:00Z", 123, False):
                source = auth_backup()
                source[dataset][0][key] = value
                with self.subTest(dataset=dataset, value=value), self.assertRaises(ValueError):
                    validation.validate_auth_backup(source)

    def test_optional_expiry_fields_and_metadata_need_not_be_present(self):
        source = auth_backup()
        del source["schema_version"]
        del source["accounts"][0]["expires_at"]
        del source["accounts"][0]["expires_enc"]
        result = validation.validate_auth_backup(source)
        self.assertIsNone(result["accounts"][0]["expires_at"])
        self.assertIsNone(result["accounts"][0]["expires_enc"])

    def test_rejects_nonboolean_active_without_enabling_account(self):
        for value in ("false", "true", 0, 1, None):
            source = auth_backup()
            source["accounts"][0]["active"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validation.validate_auth_backup(source)

    def test_rejects_invalid_text_and_does_not_leak_value_in_error(self):
        for value in ("", " ", 7, False, ["secret"], {"secret": "value"}, "secret\x00value"):
            source = auth_backup()
            source["accounts"][0]["password_hash"] = value
            with self.subTest(value=value), self.assertRaises(ValueError) as error:
                validation.validate_auth_backup(source)
            self.assertNotIn("secret", str(error.exception))

    def test_rejects_broken_binding_references(self):
        source = auth_backup()
        source["bindings"][0]["auth_code"] = "missing-license-secret"
        with self.assertRaises(ValueError) as error:
            validation.validate_auth_backup(source)
        self.assertNotIn("missing-license-secret", str(error.exception))

    def test_legacy_aliases_and_encoded_tabs_are_normalized(self):
        source = auth_backup()
        account = source["accounts"][0]
        account["role_name"] = account.pop("role")
        account["module_name"] = account.pop("module")
        source["rbac_tabs"] = [{"role": "staff", "tabs": '["orders"]'}]
        source["rbac_modules"] = [{"name": "sales", "tabs": "[]"}]
        result = validation.validate_auth_backup(source)
        self.assertEqual(result["accounts"][0]["role"], "staff")
        self.assertEqual(result["accounts"][0]["module"], "sales")
        self.assertEqual(result["rbac_tabs"][0]["role_name"], "staff")
        self.assertEqual(result["rbac_tabs"][0]["tabs"], ["orders"])
        self.assertEqual(result["rbac_modules"][0]["tabs"], [])

    def test_rejects_invalid_tabs_instead_of_discarding_them(self):
        for value in (None, {}, "not-json", '{}', '[1]', [None], [1], [""], ["x\x00y"]):
            source = auth_backup()
            source["rbac_tabs"][0]["tabs"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validation.validate_auth_backup(source)


class LicenseBackupValidationTests(unittest.TestCase):
    def test_accepts_http_dates_from_license_export(self):
        source = auth_backup()
        source["licenses"][0]["expiry"] = "Tue, 31 Dec 2030 00:00:00 GMT"
        payload = {key: source[key] for key in ("licenses", "bindings")}
        result = validation.validate_licenses_backup(payload)
        self.assertEqual(result["licenses"][0]["expiry"], "2030-12-31")

    def test_requires_both_datasets(self):
        for payload in ({}, {"licenses": []}, {"bindings": []}, None):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                validation.validate_licenses_backup(payload)

    def test_empty_merge_is_a_valid_no_op(self):
        payload = {"licenses": [], "bindings": []}
        self.assertEqual(validation.validate_licenses_backup(payload), payload)

    def test_rejects_broken_binding_reference_before_database_access(self):
        payload = {"licenses": [], "bindings": [{"mac": "device", "auth_code": "missing"}]}
        with self.assertRaises(ValueError):
            validation.validate_licenses_backup(payload)

    def test_missing_optional_mac_is_normalized_for_merge_importer(self):
        payload = {"licenses": [{"auth_code": "code", "expiry": "2030-12-31", "remaining": 0}], "bindings": []}
        self.assertIsNone(validation.validate_licenses_backup(payload)["licenses"][0]["mac"])


class BarcodeBackupValidationTests(unittest.TestCase):
    def test_preserves_dynamic_columns_and_allows_individual_empty_groups(self):
        source = barcode_backup()
        original = copy.deepcopy(source)
        result = validation.validate_barcode_backup(source)
        self.assertEqual(result, original)
        result["barcode53"]["BcMst"][0]["CodeNo"] = "changed"
        self.assertEqual(source, original)

    def test_requires_object_and_all_exported_groups(self):
        for value in (None, [], {}, {"barcode53": None}, {"barcode53": []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validation.validate_barcode_backup(value)
        for name in validation.BARCODE_DATASETS:
            source = barcode_backup()
            del source["barcode53"][name]
            with self.subTest(dataset=name), self.assertRaises(ValueError):
                validation.validate_barcode_backup(source)

    def test_rejects_bad_group_and_row_shapes(self):
        for name in validation.BARCODE_DATASETS:
            for value in (None, {}, "[]", [None], ["row"], [{}]):
                source = barcode_backup()
                source["barcode53"][name] = value
                with self.subTest(dataset=name, value=value), self.assertRaises(ValueError):
                    validation.validate_barcode_backup(source)

    def test_rejects_all_empty_restore_and_log_only_restore(self):
        source = {"barcode53": {name: [] for name in validation.BARCODE_DATASETS}}
        with self.assertRaises(ValueError):
            validation.validate_barcode_backup(source)
        source["barcode53"]["BcLog"] = [{"UsrNo": "operator"}]
        with self.assertRaises(ValueError):
            validation.validate_barcode_backup(source)

    def test_does_not_invent_uniqueness_for_log_or_dynamic_tables(self):
        source = barcode_backup()
        source["barcode53"]["BcLog"] = [{"UsrNo": "operator"}, {"UsrNo": "operator"}]
        self.assertEqual(len(validation.validate_barcode_backup(source)["barcode53"]["BcLog"]), 2)


if __name__ == "__main__":
    unittest.main()
