from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from tcc_analyzer.code_analyzer import CodeAnalyzer
from tcc_analyzer.data_flow_analyzer import DataFlowAnalyzer


class DataFlowAnalyzerTests(unittest.TestCase):
    def analyze_smali(
        self,
        smali: str,
        *,
        extra_files: dict[str, str] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        smali_file = root / "smali" / "example" / "ExportedService.smali"
        smali_file.parent.mkdir(parents=True)
        smali_file.write_text(smali, encoding="utf-8")
        for relative_path, content in (extra_files or {}).items():
            extra_file = root / relative_path
            extra_file.parent.mkdir(parents=True, exist_ok=True)
            extra_file.write_text(content, encoding="utf-8")
        component = {
            "name": "example.ExportedService",
            "type": "service",
            "enabled": True,
            "exported": True,
            "smali": {
                "attempted": True,
                "found": True,
                "class_name": "example.ExportedService",
                "descriptor": "Lexample/ExportedService;",
                "path": "smali/example/ExportedService.smali",
            },
        }
        component["code_analysis"] = CodeAnalyzer(
            root,
            application_package="example",
        ).analyze_component(component)
        analysis = {
            "package": "example",
            "application": {"permission": None},
            "components": [component],
            "summary": {},
        }

        summary = DataFlowAnalyzer(root).analyze(analysis)
        entry_point = component["code_analysis"]["entry_points"][0]
        return summary, entry_point["data_flow_analysis"]

    def test_tracks_api_result_and_move_into_sensitive_operation(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 4
    const-string v0, "url"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    move-object v2, v1
    invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method
"""

        summary, result = self.analyze_smali(smali)

        self.assertEqual(summary["confirmed_flow_count"], 1)
        self.assertEqual(result["data_flow_status"], "confirmed-unvalidated")
        flow = result["flows"][0]
        self.assertEqual(flow["flow_id"], "FLOW-0001")
        self.assertEqual(flow["status"], "confirmed-unvalidated")
        self.assertEqual(flow["sink"]["api"], "WebView.loadUrl")
        self.assertEqual(flow["tainted_registers_at_sink"], ["v2"])
        self.assertIn(
            "Intent.getStringExtra",
            {source["api"] for source in flow["sources"]},
        )
        self.assertIn(
            "move",
            {step["kind"] for step in flow["trace"]},
        )

    def test_records_possible_validation_touching_tainted_register(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 4
    const-string v0, "url"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z
    move-result v2
    invoke-virtual {v3, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method
"""

        summary, result = self.analyze_smali(smali)

        self.assertEqual(summary["validated_flow_count"], 1)
        self.assertEqual(
            result["data_flow_status"],
            "confirmed-with-possible-validation",
        )
        flow = result["flows"][0]
        self.assertEqual(
            [item["api"] for item in flow["possible_validations"]],
            ["TextUtils.isEmpty"],
        )
        self.assertEqual(flow["confidence"], "medium")

    def test_overwrite_removes_taint_before_sensitive_operation(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 3
    const-string v0, "url"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    const-string v1, "https://safe.example"
    invoke-virtual {v2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method
"""

        summary, result = self.analyze_smali(smali)

        self.assertEqual(summary["confirmed_flow_count"], 0)
        self.assertEqual(
            result["data_flow_status"],
            "source-and-sink-unconfirmed",
        )
        assessment = result["sensitive_argument_assessments"][0]
        self.assertEqual(assessment["classification"], "constant")
        self.assertEqual(
            assessment["arguments"][0]["constant_values"],
            ['"https://safe.example"'],
        )

    def test_propagates_taint_through_internal_argument_and_return(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 4
    const-string v0, "url"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-static {v1}, Lexample/ExportedService;->identity(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method
.method private static identity(Ljava/lang/String;)Ljava/lang/String;
    .locals 0
    return-object p0
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 1)
        flow = result["flows"][0]
        trace_kinds = [step["kind"] for step in flow["trace"]]
        self.assertIn("method-argument", trace_kinds)
        self.assertIn("return", trace_kinds)
        self.assertEqual(result["analyzed_method_count"], 2)

    def test_entry_point_intent_parameter_is_an_external_source(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 1
    invoke-virtual {p0, p1}, Landroid/app/Service;->startActivity(Landroid/content/Intent;)V
    const/4 v0, 0x1
    return v0
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 1)
        flow = result["flows"][0]
        self.assertEqual(
            flow["sources"][0]["kind"],
            "entry_point_parameter",
        )
        self.assertEqual(
            flow["sources"][0]["source_kind"],
            "untrusted_input",
        )
        self.assertEqual(flow["sources"][0]["register"], "p1")

    def test_catalog_propagates_user_input_into_loopj_request(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 6
    invoke-virtual {v0}, Landroid/widget/EditText;->getText()Landroid/text/Editable;
    move-result-object v1
    invoke-interface {v1}, Landroid/text/Editable;->toString()Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v3, v4, v2}, Lcom/loopj/android/http/AsyncHttpClient;->post(Ljava/lang/String;Ljava/lang/Object;)V
    const/4 v0, 0x1
    return v0
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 1)
        flow = result["flows"][0]
        self.assertEqual(flow["sink"]["api"], "AsyncHttpClient.request")
        self.assertEqual(flow["sink"]["operation_kind"], "network_request")
        self.assertEqual(flow["tainted_registers_at_sink"], ["v2"])
        self.assertEqual(flow["sources"][0]["source_kind"], "user_input")
        self.assertIn(
            "catalog-propagation",
            {step["kind"] for step in flow["trace"]},
        )

    def test_sink_ignores_taint_outside_sensitive_argument_positions(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 3
    const-string v0, "value"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    const-string v2, "https://safe.example"
    invoke-virtual {v1, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 0)
        self.assertEqual(
            result["data_flow_status"],
            "source-and-sink-unconfirmed",
        )

    def test_tracks_external_value_through_instance_field_into_runtime_exec(
        self,
    ) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.field private command:Ljava/lang/String;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 4
    const-string v0, "command"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    iput-object v1, p0, Lexample/ExportedService;->command:Ljava/lang/String;
    invoke-direct {p0}, Lexample/ExportedService;->execute()V
    const/4 v0, 0x1
    return v0
.end method
.method private execute()V
    .locals 3
    iget-object v0, p0, Lexample/ExportedService;->command:Ljava/lang/String;
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v1
    invoke-virtual {v1, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    return-void
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 1)
        flow = result["flows"][0]
        self.assertEqual(flow["sink"]["api"], "Runtime.exec")
        self.assertEqual(flow["argument_classification"], "external-tainted")
        self.assertEqual(flow["tracking_precision"], "field-or-array-dependency")
        self.assertIn("instance-field-write", flow["storage_propagation"])
        self.assertIn("instance-field-read", flow["storage_propagation"])

    def test_tracks_external_value_through_static_field_between_methods(
        self,
    ) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.field private static url:Ljava/lang/String;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 3
    const-string v0, "url"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    sput-object v1, Lexample/ExportedService;->url:Ljava/lang/String;
    invoke-static {}, Lexample/ExportedService;->open()V
    const/4 v0, 0x1
    return v0
.end method
.method private static open()V
    .locals 2
    sget-object v0, Lexample/ExportedService;->url:Ljava/lang/String;
    invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 1)
        flow = result["flows"][0]
        self.assertEqual(flow["sink"]["api"], "WebView.loadUrl")
        self.assertEqual(flow["argument_classification"], "external-tainted")
        self.assertIn("static-field-write", flow["storage_propagation"])
        self.assertIn("static-field-read", flow["storage_propagation"])

    def test_tracks_array_element_across_internal_method(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 6
    const-string v0, "url"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    const/4 v2, 0x1
    new-array v3, v2, [Ljava/lang/String;
    const/4 v4, 0x0
    aput-object v1, v3, v4
    invoke-static {v3}, Lexample/ExportedService;->open([Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method
.method private static open([Ljava/lang/String;)V
    .locals 3
    const/4 v0, 0x0
    aget-object v1, p0, v0
    invoke-virtual {v2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 1)
        flow = result["flows"][0]
        self.assertEqual(flow["argument_classification"], "external-tainted")
        self.assertIn("array-write", flow["storage_propagation"])
        self.assertIn("array-read", flow["storage_propagation"])

    def test_classifies_interface_and_unknown_sensitive_arguments(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 6
    invoke-virtual {v0}, Landroid/widget/EditText;->getText()Landroid/text/Editable;
    move-result-object v1
    invoke-interface {v1}, Landroid/text/Editable;->toString()Ljava/lang/String;
    move-result-object v2
    invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-virtual {v4, v5}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    const/4 v0, 0x1
    return v0
.end method
"""

        _, result = self.analyze_smali(smali)

        assessments = {
            item["api"]: item["classification"]
            for item in result["sensitive_argument_assessments"]
        }
        self.assertEqual(assessments["WebView.loadUrl"], "interface-tainted")
        self.assertEqual(assessments["Runtime.exec"], "unknown")
        self.assertEqual(result["argument_classification_counts"]["interface-tainted"], 1)
        self.assertEqual(result["argument_classification_counts"]["unknown"], 1)

    def test_tracks_captured_instance_field_into_synthetic_callback(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 4
    const-string v0, "url"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Lexample/ExportedService$Callback;
    invoke-direct {v2, v1}, Lexample/ExportedService$Callback;-><init>(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method
"""
        callback = """.class final Lexample/ExportedService$Callback;
.super Ljava/lang/Object;
.field url:Ljava/lang/String;
.method public constructor <init>(Ljava/lang/String;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lexample/ExportedService$Callback;->url:Ljava/lang/String;
    return-void
.end method
.method public final run()V
    .locals 2
    iget-object v0, p0, Lexample/ExportedService$Callback;->url:Ljava/lang/String;
    invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""

        _, result = self.analyze_smali(
            smali,
            extra_files={
                "smali/example/ExportedService$Callback.smali": callback,
            },
        )

        self.assertEqual(result["flow_count"], 1)
        flow = result["flows"][0]
        self.assertEqual(flow["sink"]["api"], "WebView.loadUrl")
        self.assertEqual(flow["argument_classification"], "external-tainted")
        self.assertEqual(
            flow["tracking_precision"],
            "approximate-object-propagation",
        )
        self.assertIn("instance-field-read", flow["storage_propagation"])
        self.assertIn("constructor-capture", flow["storage_propagation"])
        self.assertTrue(
            any(
                step["kind"] == "callback-receiver"
                for step in flow["trace"]
            )
        )

    def test_tracks_intent_contents_into_ipc_sinks_between_methods(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 5
    const-string v0, "payload"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Landroid/content/Intent;
    invoke-direct {v2}, Landroid/content/Intent;-><init>()V
    invoke-virtual {v2, v0, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    move-result-object v2
    invoke-static {p0, v2}, Lexample/ExportedService;->dispatch(Landroid/app/Service;Landroid/content/Intent;)V
    const/4 v0, 0x1
    return v0
.end method
.method private static dispatch(Landroid/app/Service;Landroid/content/Intent;)V
    .locals 3
    const-string v0, "payload"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-virtual {p0, p1}, Landroid/app/Service;->sendBroadcast(Landroid/content/Intent;)V
    invoke-virtual {p0, p1}, Landroid/app/Service;->startActivity(Landroid/content/Intent;)V
    invoke-virtual {p0, p1}, Landroid/app/Service;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    return-void
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 4)
        self.assertEqual(
            {flow["sink"]["api"] for flow in result["flows"]},
            {
                "WebView.loadUrl",
                "sendBroadcast",
                "startActivity",
                "startService",
            },
        )
        for flow in result["flows"]:
            self.assertEqual(
                flow["argument_classification"],
                "external-tainted",
            )
            self.assertIn(
                "container-write",
                {step["kind"] for step in flow["trace"]},
            )
        web_flow = next(
            flow
            for flow in result["flows"]
            if flow["sink"]["api"] == "WebView.loadUrl"
        )
        self.assertIn(
            "container-read",
            {step["kind"] for step in web_flow["trace"]},
        )

    def test_bundle_reads_preserve_key_specific_classification(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 10
    const-string v0, "input"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Landroid/os/Bundle;
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V
    const-string v3, "safe"
    const-string v4, "https://safe.example"
    invoke-virtual {v2, v3, v4}, Landroid/os/Bundle;->putString(Ljava/lang/String;Ljava/lang/String;)V
    const-string v5, "unsafe"
    invoke-virtual {v2, v5, v1}, Landroid/os/Bundle;->putString(Ljava/lang/String;Ljava/lang/String;)V
    invoke-virtual {v2, v3}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v6
    invoke-virtual {v9, v6}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    invoke-virtual {v2, v5}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v7
    invoke-virtual {v9, v7}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    const/4 v0, 0x1
    return v0
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 1)
        assessments = result["sensitive_argument_assessments"]
        self.assertEqual(
            [item["classification"] for item in assessments],
            ["constant", "external-tainted"],
        )
        self.assertEqual(
            assessments[0]["arguments"][0]["constant_values"],
            ['"https://safe.example"'],
        )

    def test_content_values_preserve_interface_taint_between_methods(
        self,
    ) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 6
    invoke-virtual {v0}, Landroid/widget/EditText;->getText()Landroid/text/Editable;
    move-result-object v1
    new-instance v2, Landroid/content/ContentValues;
    invoke-direct {v2}, Landroid/content/ContentValues;-><init>()V
    const-string v3, "url"
    invoke-virtual {v2, v3, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V
    invoke-static {v2}, Lexample/ExportedService;->open(Landroid/content/ContentValues;)V
    const/4 v0, 0x1
    return v0
.end method
.method private static open(Landroid/content/ContentValues;)V
    .locals 3
    const-string v0, "url"
    invoke-virtual {p0, v0}, Landroid/content/ContentValues;->getAsString(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 1)
        flow = result["flows"][0]
        self.assertEqual(flow["argument_classification"], "interface-tainted")
        self.assertEqual(flow["tracking_precision"], "container-dependency")
        self.assertIn("container-read", flow["storage_propagation"])
        self.assertIn("container-write", flow["storage_propagation"])

    def test_constant_container_content_does_not_create_taint(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 5
    new-instance v0, Landroid/content/Intent;
    invoke-direct {v0}, Landroid/content/Intent;-><init>()V
    const-string v1, "payload"
    const-string v2, "fixed"
    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {p0, v0}, Landroid/app/Service;->sendBroadcast(Landroid/content/Intent;)V
    const/4 v3, 0x1
    return v3
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 0)
        assessment = result["sensitive_argument_assessments"][0]
        self.assertEqual(assessment["classification"], "constant")
        self.assertEqual(
            assessment["arguments"][0]["constant_values"],
            ['"fixed"'],
        )

    def test_filled_new_array_classifies_runtime_exec_arguments(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 8
    const-string v0, "command"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    const-string v2, "/system/bin/echo"
    filled-new-array {v2, v1}, [Ljava/lang/String;
    move-result-object v3
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v4
    invoke-virtual {v4, v3}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    const-string v5, "/system/bin/which"
    const-string v6, "su"
    filled-new-array {v5, v6}, [Ljava/lang/String;
    move-result-object v7
    invoke-virtual {v4, v7}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    const/4 v0, 0x1
    return v0
.end method
"""

        _, result = self.analyze_smali(smali)

        self.assertEqual(result["flow_count"], 1)
        assessments = result["sensitive_argument_assessments"]
        self.assertEqual(
            [item["classification"] for item in assessments],
            ["external-tainted", "constant"],
        )
        self.assertEqual(
            assessments[1]["arguments"][0]["constant_values"],
            ['"/system/bin/which"', '"su"'],
        )
        flow = result["flows"][0]
        self.assertEqual(flow["sink"]["api"], "Runtime.exec")
        self.assertIn("array-write", flow["storage_propagation"])

    def test_classifies_explicit_internal_intent_from_constructor(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 4
    new-instance v0, Landroid/content/Intent;
    const-class v1, Lexample/InternalActivity;
    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    invoke-virtual {p0, v0}, Landroid/app/Service;->startActivity(Landroid/content/Intent;)V
    const/4 v2, 0x1
    return v2
.end method
"""

        summary, result = self.analyze_smali(smali)

        self.assertEqual(summary["ipc_transition_count"], 1)
        transition = result["ipc_transitions"][0]
        self.assertEqual(transition["intent_kind"], "explicit")
        self.assertEqual(transition["selector_classification"], "constant")
        self.assertTrue(transition["destination_internal"])
        self.assertTrue(transition["explicit_internal_constant"])
        self.assertIn(
            "example.InternalActivity",
            transition["destination_candidates"],
        )

    def test_classifies_implicit_intent_with_external_action_and_data(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 7
    const-string v0, "selector"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Landroid/content/Intent;
    invoke-direct {v2}, Landroid/content/Intent;-><init>()V
    invoke-virtual {v2, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;
    move-result-object v2
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v3
    invoke-virtual {v2, v3}, Landroid/content/Intent;->setData(Landroid/net/Uri;)Landroid/content/Intent;
    move-result-object v2
    invoke-virtual {p0, v2}, Landroid/app/Service;->sendBroadcast(Landroid/content/Intent;)V
    const/4 v4, 0x1
    return v4
.end method
"""

        _, result = self.analyze_smali(smali)

        transition = result["ipc_transitions"][0]
        self.assertEqual(transition["intent_kind"], "implicit")
        self.assertEqual(
            transition["selector_classification"],
            "external-tainted",
        )
        self.assertTrue(transition["selector_controllable"])
        self.assertEqual(
            transition["attributes"]["action"]["classification"],
            "external-tainted",
        )
        self.assertEqual(
            transition["attributes"]["data"]["classification"],
            "external-tainted",
        )

    def test_tracks_set_class_name_and_set_component_destinations(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 10
    new-instance v0, Landroid/content/Intent;
    invoke-direct {v0}, Landroid/content/Intent;-><init>()V
    const-string v1, "example"
    const-string v2, "InternalService"
    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    invoke-virtual {p0, v0}, Landroid/app/Service;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;
    new-instance v3, Landroid/content/ComponentName;
    const-class v4, Lexample/InternalReceiver;
    invoke-direct {v3, p0, v4}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    new-instance v5, Landroid/content/Intent;
    invoke-direct {v5}, Landroid/content/Intent;-><init>()V
    invoke-virtual {v5, v3}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;
    invoke-virtual {p0, v5}, Landroid/app/Service;->sendBroadcast(Landroid/content/Intent;)V
    const/4 v6, 0x1
    return v6
.end method
"""

        _, result = self.analyze_smali(smali)

        transitions = {item["api"]: item for item in result["ipc_transitions"]}
        self.assertEqual(transitions["startService"]["intent_kind"], "explicit")
        self.assertIn(
            "example.InternalService",
            transitions["startService"]["destination_candidates"],
        )
        self.assertEqual(transitions["sendBroadcast"]["intent_kind"], "explicit")
        self.assertIn(
            "example.InternalReceiver",
            transitions["sendBroadcast"]["destination_candidates"],
        )

    def test_tracks_set_class_destination(self) -> None:
        smali = """.class public Lexample/ExportedService;
.super Landroid/app/Service;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 5
    new-instance v0, Landroid/content/Intent;
    invoke-direct {v0}, Landroid/content/Intent;-><init>()V
    const-class v1, Lexample/InternalActivity;
    invoke-virtual {v0, p0, v1}, Landroid/content/Intent;->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {p0, v0}, Landroid/app/Service;->startActivity(Landroid/content/Intent;)V
    const/4 v2, 0x1
    return v2
.end method
"""

        _, result = self.analyze_smali(smali)

        transition = result["ipc_transitions"][0]
        self.assertEqual(transition["intent_kind"], "explicit")
        self.assertEqual(transition["selector_classification"], "constant")
        self.assertTrue(transition["explicit_internal_constant"])
        self.assertIn(
            "example.InternalActivity",
            transition["destination_candidates"],
        )
        self.assertTrue(transition["destination_internal"])

    def test_destination_overrides_unknown_intent_hint(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        analyzer = DataFlowAnalyzer(temporary.name)
        analyzer.application_package = "example"
        analyzer.known_components = {"example.InternalActivity"}
        object_id = "intent-with-merged-alias"
        destination = analyzer._constant_state(
            "Lexample/InternalActivity;",
            {
                "kind": "test-constant",
                "line": 10,
                "instruction": "const-class v1, Lexample/InternalActivity;",
            },
        )
        intent_state = {
            "classification": "unknown",
            "constant_values": [],
            "sources": [],
            "validations": [],
            "trace": [],
            "object_ids": [object_id],
            "object_descriptors": ["Landroid/content/Intent;"],
            "array_ids": [],
        }

        transition = analyzer._ipc_transition(
            evidence={
                "api": "startActivity",
                "operation_kind": "ipc_activity",
                "line": 12,
            },
            component={"name": "example.ExportedService"},
            entry_point={"signature": "onStartCommand()I"},
            intent_state=intent_state,
            intent_profiles={
                object_id: {
                    "__kind_hint__": "unknown",
                    "destination": destination,
                }
            },
        )

        self.assertEqual(transition["intent_kind"], "explicit")
        self.assertTrue(transition["destination_internal"])
        self.assertTrue(transition["explicit_internal_constant"])


if __name__ == "__main__":
    unittest.main()
