from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tcc_analyzer.manifest_analyzer import ManifestAnalyzer


FIXTURE = Path(__file__).parent / "fixtures" / "sample_manifest.xml"


class ManifestAnalyzerTests(unittest.TestCase):
    def test_extracts_components_and_expected_findings(self) -> None:
        result = ManifestAnalyzer(FIXTURE).analyze()

        self.assertEqual(result["package"], "owasp.sat.agoat")
        self.assertEqual(result["sdk"]["target"], 30)
        self.assertEqual(result["summary"]["component_count"], 5)
        self.assertEqual(result["summary"]["exported_component_count"], 5)
        self.assertEqual(result["summary"]["deep_link_filter_count"], 1)
        self.assertEqual(result["summary"]["uri_intent_filter_count"], 1)
        self.assertEqual(result["summary"]["browsable_deep_link_count"], 1)

        rule_ids = {finding["rule_id"] for finding in result["findings"]}
        self.assertIn("DEEPLINK-001", rule_ids)
        self.assertIn("COMPONENT-001", rule_ids)
        self.assertIn("PROVIDER-001", rule_ids)
        self.assertIn("COMPONENT-INFO-001", rule_ids)
        self.assertIn("COMPONENT-INFO-002", rule_ids)

    def test_target_31_requires_explicit_exported(self) -> None:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.target31">
            <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="31" />
            <application>
                <activity android:name=".DeepLinkActivity">
                    <intent-filter>
                        <action android:name="android.intent.action.VIEW" />
                        <category android:name="android.intent.category.DEFAULT" />
                        <category android:name="android.intent.category.BROWSABLE" />
                        <data android:scheme="https" android:host="example.com" />
                    </intent-filter>
                </activity>
            </application>
        </manifest>
        """

        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "AndroidManifest.xml"
            manifest_path.write_text(manifest, encoding="utf-8")
            result = ManifestAnalyzer(manifest_path).analyze()

        component = result["components"][0]
        self.assertIsNone(component["exported"])
        self.assertEqual(
            component["exported_source"],
            "invalid-missing-exported-for-target-31+",
        )
        self.assertIn(
            "MANIFEST-001",
            {finding["rule_id"] for finding in result["findings"]},
        )

    def test_multiple_data_values_generate_cross_product_warning(self) -> None:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.links">
            <uses-sdk android:targetSdkVersion="30" />
            <application>
                <activity android:name=".Links" android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.VIEW" />
                        <category android:name="android.intent.category.DEFAULT" />
                        <category android:name="android.intent.category.BROWSABLE" />
                        <data android:scheme="https" android:host="example.com" />
                        <data android:scheme="demo" android:host="open.example.com" />
                    </intent-filter>
                </activity>
            </application>
        </manifest>
        """

        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "AndroidManifest.xml"
            manifest_path.write_text(manifest, encoding="utf-8")
            result = ManifestAnalyzer(manifest_path).analyze()

        intent_filter = result["components"][0]["intent_filters"][0]
        self.assertEqual(len(intent_filter["uri_patterns"]), 4)
        self.assertIn(
            "DEEPLINK-005",
            {finding["rule_id"] for finding in result["findings"]},
        )

    def test_uri_handler_without_browsable_is_not_lost(self) -> None:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="owasp.sat.agoat">
            <uses-sdk android:targetSdkVersion="27" />
            <application>
                <activity android:name=".AccessControl1ViewActivity">
                    <intent-filter>
                        <action android:name="android.intent.action.VIEW" />
                        <category android:name="android.intent.category.DEFAULT" />
                        <data android:scheme="androgoat" android:host="vulnapp" />
                    </intent-filter>
                </activity>
            </application>
        </manifest>
        """

        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "AndroidManifest.xml"
            manifest_path.write_text(manifest, encoding="utf-8")
            result = ManifestAnalyzer(manifest_path).analyze()

        intent_filter = result["components"][0]["intent_filters"][0]
        self.assertTrue(intent_filter["is_uri_intent"])
        self.assertFalse(intent_filter["is_browsable_deep_link"])
        self.assertEqual(result["summary"]["uri_intent_filter_count"], 1)
        self.assertEqual(result["summary"]["browsable_deep_link_count"], 0)
        self.assertIn(
            "URI-INFO-001",
            {finding["rule_id"] for finding in result["findings"]},
        )

    def test_sdk_falls_back_to_apktool_yml(self) -> None:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="owasp.sat.agoat">
            <application />
        </manifest>
        """
        apktool_yml = """version: 2.9.3
sdkInfo:
  minSdkVersion: '23'
  targetSdkVersion: '27'
"""

        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "AndroidManifest.xml"
            yml_path = Path(directory) / "apktool.yml"
            manifest_path.write_text(manifest, encoding="utf-8")
            yml_path.write_text(apktool_yml, encoding="utf-8")
            result = ManifestAnalyzer(
                manifest_path,
                apktool_yml_path=yml_path,
            ).analyze()

        self.assertEqual(result["sdk"]["min"], 23)
        self.assertEqual(result["sdk"]["target"], 27)
        self.assertEqual(result["sdk"]["source"]["min"], "apktool.yml")
        self.assertEqual(result["sdk"]["source"]["target"], "apktool.yml")

    def test_reports_explicitly_debuggable_application(self) -> None:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.debuggable">
            <application android:debuggable="true" />
        </manifest>
        """

        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "AndroidManifest.xml"
            manifest_path.write_text(manifest, encoding="utf-8")
            result = ManifestAnalyzer(manifest_path).analyze()

        self.assertTrue(result["application"]["debuggable"])
        finding = next(
            item
            for item in result["findings"]
            if item["rule_id"] == "APP-DEBUG-001"
        )
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["confidence"], "high")
        self.assertEqual(finding["component_type"], "application")
        self.assertEqual(result["summary"]["findings_by_severity"]["high"], 1)

    def test_does_not_infer_debuggable_when_attribute_is_absent(self) -> None:
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.release">
            <application />
        </manifest>
        """

        with tempfile.TemporaryDirectory() as directory:
            manifest_path = Path(directory) / "AndroidManifest.xml"
            manifest_path.write_text(manifest, encoding="utf-8")
            result = ManifestAnalyzer(manifest_path).analyze()

        self.assertIsNone(result["application"]["debuggable"])
        self.assertNotIn(
            "APP-DEBUG-001",
            {finding["rule_id"] for finding in result["findings"]},
        )


if __name__ == "__main__":
    unittest.main()
