from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tcc_analyzer.api_catalog import ApiCatalog


class ApiCatalogTests(unittest.TestCase):
    def test_loads_default_catalog_and_matches_smali_invocation(self) -> None:
        catalog = ApiCatalog()
        instruction = (
            "invoke-virtual {v0}, Landroid/widget/EditText;"
            "->getText()Landroid/text/Editable;"
        )

        invocation, rules = catalog.match_instruction(instruction)

        self.assertIsNotNone(invocation)
        self.assertEqual(invocation.owner, "Landroid/widget/EditText;")
        self.assertEqual([rule.api for rule in rules], ["TextView.getText"])
        self.assertEqual(rules[0].source_kind, "user_input")
        self.assertGreater(catalog.metadata()["rule_count"], 90)

    def test_recognizes_third_party_network_sink(self) -> None:
        catalog = ApiCatalog()
        instruction = (
            "invoke-virtual {v0, v1, v2}, "
            "Lcom/loopj/android/http/AsyncHttpClient;"
            "->post(Ljava/lang/String;Ljava/lang/Object;)V"
        )

        _, rules = catalog.match_instruction(instruction)

        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].api, "AsyncHttpClient.request")
        self.assertEqual(rules[0].operation_kind, "network_request")
        self.assertTrue(rules[0].risk_relevant)

    def test_reportable_filter_hides_semantic_propagators(self) -> None:
        catalog = ApiCatalog()
        instruction = (
            "invoke-virtual {v0}, Landroid/text/Editable;"
            "->toString()Ljava/lang/String;"
        )

        _, all_rules = catalog.match_instruction(instruction)
        _, reportable = catalog.match_instruction(
            instruction,
            reportable_only=True,
        )

        self.assertEqual(all_rules[0].category, "propagator")
        self.assertEqual(reportable, [])

    def test_later_file_can_override_or_disable_rules(self) -> None:
        base = {
            "schema_version": "1.0",
            "catalog_version": "test",
            "rules": [
                {
                    "id": "TEST-RULE",
                    "api": "Old.api",
                    "owners": ["Lexample/Test;"],
                    "methods": ["read"],
                    "descriptors": ["()Ljava/lang/String;"],
                    "category": "external_source",
                    "taint_behavior": "return"
                },
                {
                    "id": "DISABLED-RULE",
                    "api": "Disabled.api",
                    "owners": ["Lexample/Test;"],
                    "methods": ["write"],
                    "category": "sensitive_operation",
                    "taint_behavior": "sink"
                }
            ]
        }
        override = {
            "schema_version": "1.0",
            "disabled_rule_ids": ["DISABLED-RULE"],
            "rules": [
                {
                    "id": "TEST-RULE",
                    "api": "New.api",
                    "owners": ["Lexample/Test;"],
                    "methods": ["read"],
                    "descriptors": ["()Ljava/lang/String;"],
                    "category": "external_source",
                    "source_kind": "untrusted_input",
                    "taint_behavior": "return"
                }
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            base_path = Path(directory) / "base.json"
            override_path = Path(directory) / "override.json"
            base_path.write_text(json.dumps(base), encoding="utf-8")
            override_path.write_text(json.dumps(override), encoding="utf-8")

            catalog = ApiCatalog(base_path, [override_path])

        self.assertEqual([rule.api for rule in catalog.rules], ["New.api"])

    def test_rejects_duplicate_ids_in_same_document(self) -> None:
        rule = {
            "id": "DUPLICATE",
            "api": "Example.api",
            "owners": ["Lexample/Test;"],
            "methods": ["run"],
            "category": "external_source",
            "taint_behavior": "return"
        }
        document = {
            "schema_version": "1.0",
            "catalog_version": "test",
            "rules": [rule, rule]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(json.dumps(document), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicado"):
                ApiCatalog(path)

    def test_content_resolver_rules_are_method_specific(self) -> None:
        catalog = ApiCatalog()
        _, insert_rules = catalog.match_instruction(
            "invoke-virtual {v0, v1, v2}, Landroid/content/ContentResolver;"
            "->insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;"
        )
        _, notify_rules = catalog.match_instruction(
            "invoke-virtual {v0, v1, v2}, Landroid/content/ContentResolver;"
            "->notifyChange(Landroid/net/Uri;Landroid/database/ContentObserver;)V"
        )

        self.assertEqual([rule.api for rule in insert_rules], ["ContentResolver.insert"])
        self.assertEqual(insert_rules[0].sensitive_arguments, (1, 2))
        self.assertNotIn(0, insert_rules[0].sensitive_arguments)
        self.assertEqual(notify_rules[0].api, "ContentResolver.notifyChange")
        self.assertEqual(notify_rules[0].severity, "low")
        self.assertEqual(notify_rules[0].sensitive_arguments, (1,))

    def test_sqlite_rules_exclude_receiver_from_critical_arguments(self) -> None:
        catalog = ApiCatalog()
        sqlite_rules = [
            rule
            for rule in catalog.rules
            if rule.owners == ("Landroid/database/sqlite/SQLiteDatabase;",)
            and rule.category == "sensitive_operation"
        ]

        self.assertGreaterEqual(len(sqlite_rules), 7)
        self.assertTrue(
            all(0 not in rule.sensitive_arguments for rule in sqlite_rules)
        )
        self.assertTrue(
            all("*" not in rule.sensitive_arguments for rule in sqlite_rules)
        )

    def test_catalog_version_is_frozen_for_smaliris_v1(self) -> None:
        metadata = ApiCatalog().metadata()

        self.assertEqual(metadata["catalog_version"], "1.0.0")


if __name__ == "__main__":
    unittest.main()
