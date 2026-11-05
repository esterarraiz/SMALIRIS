from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tcc_analyzer.code_analyzer import CodeAnalyzer


SERVICE_SMALI = """.class public Lowasp/sat/agoat/DownloadInvoiceService;
.super Landroid/app/Service;

.method public constructor <init>()V
    .locals 0
    return-void
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 1
    const/4 v0, 0x1
    return v0
.end method

.method private validateInvoice(Ljava/lang/String;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
"""

EVIDENCE_SMALI = """.class public Lowasp/sat/agoat/DownloadInvoiceService;
.super Landroid/app/Service;

.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 4
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    invoke-virtual {p1, v0, v1}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;
    invoke-virtual {v0, v1}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    invoke-virtual {v0, v1}, Ljava/lang/String;->matches(Ljava/lang/String;)Z
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z
    invoke-virtual {v0}, Landroid/net/Uri;->getScheme()Ljava/lang/String;
    invoke-virtual {v0}, Landroid/net/Uri;->getHost()Ljava/lang/String;
    invoke-virtual {p0, v0}, Landroid/app/Service;->checkCallingPermission(Ljava/lang/String;)I
    invoke-virtual {p0, v0, v1}, Landroid/app/Service;->enforceCallingPermission(Ljava/lang/String;Ljava/lang/String;)V
    invoke-static {}, Landroid/os/Binder;->getCallingUid()I
    invoke-virtual {v0, v1}, Ljava/io/FileOutputStream;->write([B)V
    invoke-virtual {v0, v1}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;)Landroid/database/Cursor;
    invoke-virtual {v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;)I
    invoke-virtual {v0}, Ljava/net/HttpURLConnection;->connect()V
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-virtual {p0, v0}, Landroid/app/Service;->startActivity(Landroid/content/Intent;)V
    invoke-virtual {p0, v0}, Landroid/app/Service;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    invoke-virtual {p0, v0}, Landroid/app/Service;->sendBroadcast(Landroid/content/Intent;)V
    const/4 v0, 0x1
    return v0
.end method

.method private helperOutsideEntryPoint(Landroid/content/Intent;)V
    .locals 1
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""


class CodeAnalyzerTests(unittest.TestCase):
    def test_extracts_methods_and_service_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decompiled_dir = Path(directory)
            smali_file = (
                decompiled_dir
                / "smali"
                / "owasp"
                / "sat"
                / "agoat"
                / "DownloadInvoiceService.smali"
            )
            smali_file.parent.mkdir(parents=True)
            smali_file.write_text(SERVICE_SMALI, encoding="utf-8")
            component = {
                "type": "service",
                "smali": {
                    "attempted": True,
                    "found": True,
                    "path": (
                        "smali/owasp/sat/agoat/"
                        "DownloadInvoiceService.smali"
                    ),
                    "reason": None,
                },
            }

            result = CodeAnalyzer(decompiled_dir).analyze_component(component)

        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["method_count"], 3)
        self.assertEqual(result["entry_point_count"], 1)
        self.assertEqual(result["entry_points"][0]["name"], "onStartCommand")
        self.assertEqual(
            result["entry_points"][0]["signature"],
            "onStartCommand(Landroid/content/Intent;II)I",
        )
        self.assertEqual(result["entry_points"][0]["start_line"], 9)
        self.assertEqual(result["entry_points"][0]["end_line"], 13)
        self.assertFalse(result["methods"][0]["is_entry_point"])
        self.assertEqual(
            result["methods"][0]["modifiers"],
            ["public", "constructor"],
        )

    def test_returns_unavailable_when_smali_was_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            component = {
                "type": "receiver",
                "smali": {
                    "attempted": True,
                    "found": False,
                    "path": None,
                    "reason": "class-not-found",
                },
            }

            result = CodeAnalyzer(directory).analyze_component(component)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["reason"], "class-not-found")
        self.assertEqual(result["methods"], [])

    def test_detects_all_requested_apis_only_inside_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decompiled_dir = Path(directory)
            smali_file = decompiled_dir / "smali" / "DownloadInvoiceService.smali"
            smali_file.parent.mkdir(parents=True)
            smali_file.write_text(EVIDENCE_SMALI, encoding="utf-8")
            component = {
                "name": "owasp.sat.agoat.DownloadInvoiceService",
                "type": "service",
                "smali": {
                    "attempted": True,
                    "found": True,
                    "path": "smali/DownloadInvoiceService.smali",
                    "reason": None,
                },
            }

            result = CodeAnalyzer(decompiled_dir).analyze_component(component)

        entry_point = result["entry_points"][0]
        evidence = entry_point["evidence"]
        apis = {item["api"] for item in evidence}

        self.assertEqual(entry_point["analysis_priority"], 1)
        self.assertEqual(entry_point["evidence_count"], 23)
        self.assertEqual(entry_point["evidence_summary"]["external_source_count"], 7)
        self.assertEqual(
            entry_point["evidence_summary"]["possible_validation_count"],
            8,
        )
        self.assertEqual(
            entry_point["evidence_summary"]["sensitive_operation_count"],
            8,
        )
        self.assertEqual(len(apis), 23)
        self.assertNotIn(31, {item["line"] for item in evidence})
        self.assertTrue(
            all(
                {
                    "api",
                    "line",
                    "instruction",
                    "category",
                    "origin",
                    "depth",
                    "class_name",
                    "method_signature",
                    "smali_path",
                    "call_chain",
                }.issubset(item)
                for item in evidence
            )
        )
        self.assertTrue(all(item["origin"] == "direct" for item in evidence))
        self.assertTrue(all(item["depth"] == 0 for item in evidence))
        self.assertEqual(result["evidence_summary"], entry_point["evidence_summary"])

    def test_does_not_scan_non_entry_point_methods(self) -> None:
        helper_only_smali = """.class public Lexample/Receiver;
.method private helper(Landroid/content/Intent;)V
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    return-void
.end method
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 0
    return-void
.end method
"""
        with tempfile.TemporaryDirectory() as directory:
            decompiled_dir = Path(directory)
            smali_file = decompiled_dir / "smali" / "example" / "Receiver.smali"
            smali_file.parent.mkdir(parents=True)
            smali_file.write_text(helper_only_smali, encoding="utf-8")
            component = {
                "name": "example.Receiver",
                "type": "receiver",
                "smali": {
                    "attempted": True,
                    "found": True,
                    "path": "smali/example/Receiver.smali",
                    "reason": None,
                },
            }

            result = CodeAnalyzer(decompiled_dir).analyze_component(component)

        self.assertEqual(result["entry_point_count"], 1)
        self.assertEqual(result["evidence_count"], 0)
        self.assertEqual(result["entry_points"][0]["evidence"], [])

    def test_detects_additional_androgoat_sensitive_apis(self) -> None:
        smali = """.class public Lexample/DownloadService;
.method public onStartCommand(Landroid/content/Intent;II)I
    invoke-direct {v0, v1}, Landroid/app/DownloadManager$Request;-><init>(Landroid/net/Uri;)V
    invoke-virtual {v0, v1, v2}, Landroid/app/DownloadManager$Request;->setDestinationInExternalPublicDir(Ljava/lang/String;Ljava/lang/String;)Landroid/app/DownloadManager$Request;
    invoke-virtual {v0, v1}, Landroid/app/DownloadManager;->enqueue(Landroid/app/DownloadManager$Request;)J
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V
    invoke-static {v0, v1, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    const/4 v0, 0x1
    return v0
.end method
"""
        with tempfile.TemporaryDirectory() as directory:
            decompiled_dir = Path(directory)
            smali_file = decompiled_dir / "smali" / "example" / "DownloadService.smali"
            smali_file.parent.mkdir(parents=True)
            smali_file.write_text(smali, encoding="utf-8")
            component = {
                "name": "example.DownloadService",
                "type": "service",
                "smali": {
                    "attempted": True,
                    "found": True,
                    "path": "smali/example/DownloadService.smali",
                    "reason": None,
                },
            }

            result = CodeAnalyzer(decompiled_dir).analyze_component(component)

        evidence = result["entry_points"][0]["direct_evidence"]
        self.assertEqual(len(evidence), 6)
        self.assertEqual(
            {item["api"] for item in evidence},
            {
                "DownloadManager.Request.<init>",
                "DownloadManager.Request.setDestinationInExternalPublicDir",
                "DownloadManager.enqueue",
                "Thread.start",
                "Toast.makeText",
                "Log.i",
            },
        )
        self.assertTrue(
            all(item["category"] == "sensitive_operation" for item in evidence)
        )

    def test_applies_requested_androgoat_priority(self) -> None:
        expected = [
            ("owasp.sat.agoat.DownloadInvoiceService", "onStartCommand", 1),
            ("owasp.sat.agoat.DownloadInvoiceService", "onBind", 2),
            ("owasp.sat.agoat.AccessControl1ViewActivity", "onCreate", 3),
            ("owasp.sat.agoat.ShowDataReceiver", "onReceive", 4),
            ("owasp.sat.agoat.SplashActivity", "onCreate", 5),
        ]

        for component, method, priority in expected:
            with self.subTest(component=component, method=method):
                self.assertEqual(
                    CodeAnalyzer.entry_point_priority(component, method),
                    priority,
                )

        self.assertIsNone(
            CodeAnalyzer.entry_point_priority("example.OtherActivity", "onCreate")
        )

    def test_reports_unclosed_method_without_stopping(self) -> None:
        malformed_smali = """.class public Lexample/BrokenReceiver;
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 0
    return-void
"""
        with tempfile.TemporaryDirectory() as directory:
            decompiled_dir = Path(directory)
            smali_file = decompiled_dir / "smali" / "example" / "BrokenReceiver.smali"
            smali_file.parent.mkdir(parents=True)
            smali_file.write_text(malformed_smali, encoding="utf-8")
            component = {
                "type": "receiver",
                "smali": {
                    "attempted": True,
                    "found": True,
                    "path": "smali/example/BrokenReceiver.smali",
                    "reason": None,
                },
            }

            result = CodeAnalyzer(decompiled_dir).analyze_component(component)

        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["entry_point_count"], 1)
        self.assertTrue(result["warnings"])

    def test_rejects_path_outside_decompiled_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            component = {
                "type": "activity",
                "smali": {
                    "attempted": True,
                    "found": True,
                    "path": "../outside.smali",
                    "reason": None,
                },
            }

            result = CodeAnalyzer(directory).analyze_component(component)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "invalid-smali-path")

    def test_separates_external_and_interface_input_metrics(self) -> None:
        summary = CodeAnalyzer.summarize_evidence(
            [
                {
                    "category": "external_source",
                    "source_kind": "untrusted_input",
                },
                {
                    "category": "external_source",
                    "source_kind": "user_input",
                },
                {
                    "category": "external_source",
                    "source_kind": "interface_input",
                },
                {"category": "sensitive_operation"},
            ]
        )

        self.assertEqual(summary["input_source_count"], 3)
        self.assertEqual(summary["external_source_count"], 1)
        self.assertEqual(summary["interface_source_count"], 2)


if __name__ == "__main__":
    unittest.main()
