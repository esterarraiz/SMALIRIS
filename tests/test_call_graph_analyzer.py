from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tcc_analyzer.code_analyzer import CodeAnalyzer


ENTRY_ACTIVITY_SMALI = """.class public Lexample/EntryActivity;
.super Landroid/app/Activity;

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 2
    invoke-direct {p0, v0}, Lexample/EntryActivity;->helper(Landroid/content/Intent;)V
    sget-object v1, Lexample/EntryActivity$onCreate$1;->INSTANCE:Lexample/EntryActivity$onCreate$1;
    return-void
.end method

.method private helper(Landroid/content/Intent;)V
    .locals 1
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    invoke-static {}, Lexample/EntryActivity;->loop()V
    invoke-virtual {p0, p1}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    return-void
.end method

.method private static loop()V
    .locals 1
    invoke-direct {v0, v1}, Lexample/EntryActivity;->helper(Landroid/content/Intent;)V
    return-void
.end method
"""

SYNTHETIC_CALLBACK_SMALI = """.class final Lexample/EntryActivity$onCreate$1;
.super Ljava/lang/Object;

.method public final run()V
    .locals 2
    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""

DEPTH_SMALI = """.class public Lexample/DepthActivity;
.super Landroid/app/Activity;

.method protected onCreate(Landroid/os/Bundle;)V
    invoke-direct {p0}, Lexample/DepthActivity;->first()V
    return-void
.end method

.method private first()V
    invoke-direct {p0}, Lexample/DepthActivity;->second()V
    return-void
.end method

.method private second()V
    invoke-static {v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method
"""


class CallGraphAnalyzerTests(unittest.TestCase):
    def test_follows_internal_methods_and_kotlin_synthetic_callback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decompiled_dir = Path(directory)
            entry_file = decompiled_dir / "smali" / "example" / "EntryActivity.smali"
            callback_file = (
                decompiled_dir
                / "smali"
                / "example"
                / "EntryActivity$onCreate$1.smali"
            )
            entry_file.parent.mkdir(parents=True)
            entry_file.write_text(ENTRY_ACTIVITY_SMALI, encoding="utf-8")
            callback_file.write_text(SYNTHETIC_CALLBACK_SMALI, encoding="utf-8")
            component = {
                "name": "example.EntryActivity",
                "type": "activity",
                "smali": {
                    "attempted": True,
                    "class_name": "example.EntryActivity",
                    "descriptor": "Lexample/EntryActivity;",
                    "found": True,
                    "path": "smali/example/EntryActivity.smali",
                    "reason": None,
                },
            }

            result = CodeAnalyzer(
                decompiled_dir,
                application_package="example",
            ).analyze_component(component)

        entry_point = result["entry_points"][0]
        call_graph = entry_point["call_graph"]
        reached = {
            (method["class_name"], method["signature"], method["depth"])
            for method in call_graph["reachable_methods"]
        }

        self.assertIn(("example.EntryActivity", "helper(Landroid/content/Intent;)V", 1), reached)
        self.assertIn(("example.EntryActivity", "loop()V", 2), reached)
        self.assertIn(("example.EntryActivity$onCreate$1", "run()V", 1), reached)
        self.assertEqual(call_graph["reachable_method_count"], 3)
        self.assertEqual(call_graph["cycle_count"], 1)
        self.assertEqual(call_graph["unresolved_call_count"], 0)
        self.assertEqual(entry_point["direct_evidence_count"], 0)
        self.assertEqual(entry_point["indirect_evidence_count"], 3)
        self.assertEqual(
            {item["api"] for item in entry_point["indirect_evidence"]},
            {"Intent.getStringExtra", "startService", "WebView.loadUrl"},
        )
        self.assertTrue(
            all(
                item["origin"] == "indirect" and item["depth"] > 0
                for item in entry_point["indirect_evidence"]
            )
        )
        self.assertTrue(
            all(len(item["call_chain"]) > 1 for item in entry_point["indirect_evidence"])
        )

    def test_respects_configured_depth_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decompiled_dir = Path(directory)
            smali_file = decompiled_dir / "smali" / "example" / "DepthActivity.smali"
            smali_file.parent.mkdir(parents=True)
            smali_file.write_text(DEPTH_SMALI, encoding="utf-8")
            component = {
                "name": "example.DepthActivity",
                "type": "activity",
                "smali": {
                    "attempted": True,
                    "class_name": "example.DepthActivity",
                    "descriptor": "Lexample/DepthActivity;",
                    "found": True,
                    "path": "smali/example/DepthActivity.smali",
                    "reason": None,
                },
            }

            result = CodeAnalyzer(
                decompiled_dir,
                application_package="example",
                max_call_depth=1,
            ).analyze_component(component)

        call_graph = result["entry_points"][0]["call_graph"]
        self.assertEqual(call_graph["max_depth"], 1)
        self.assertEqual(call_graph["reachable_method_count"], 1)
        self.assertEqual(call_graph["truncated_call_count"], 1)
        self.assertEqual(call_graph["indirect_evidence_count"], 0)
        self.assertEqual(
            call_graph["truncated_calls"][0]["target_signature"],
            "second()V",
        )


if __name__ == "__main__":
    unittest.main()
