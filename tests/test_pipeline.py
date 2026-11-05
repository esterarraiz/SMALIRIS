from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tcc_analyzer.pipeline import AnalysisPipeline
from tcc_analyzer.report_schema import validate_report


FIXTURE = Path(__file__).parent / "fixtures" / "sample_manifest.xml"


class FakeReverseEngineer:
    def __init__(self, decompiled_dir: Path) -> None:
        self.decompiled_dir = decompiled_dir
        self.output_base = decompiled_dir.parent
        self.apktool_path = "apktool-test"

    def decompile(self, apk_path: Path, force: bool = True) -> Path:
        return self.decompiled_dir

    @staticmethod
    def get_manifest_path(decompiled_dir: Path) -> Path:
        return decompiled_dir / "AndroidManifest.xml"

    @staticmethod
    def version() -> str:
        return "3.0.2-test"


class AnalysisPipelineTests(unittest.TestCase):
    def test_attaches_smali_paths_to_exported_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decompiled_dir = Path(directory)
            manifest_path = decompiled_dir / "AndroidManifest.xml"
            manifest_path.write_text(
                FIXTURE.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            apk_path = decompiled_dir / "AndroGoat.apk"
            apk_content = b"deterministic-test-apk"
            apk_path.write_bytes(apk_content)

            main_activity = (
                decompiled_dir
                / "smali"
                / "owasp"
                / "sat"
                / "agoat"
                / "MainActivity.smali"
            )
            main_activity.parent.mkdir(parents=True)
            main_activity.write_text(
                """.class public Lowasp/sat/agoat/MainActivity;
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 0
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    return-void
.end method
""",
                encoding="utf-8",
            )

            service = (
                decompiled_dir
                / "smali_classes2"
                / "owasp"
                / "sat"
                / "agoat"
                / "DownloadInvoiceService.smali"
            )
            service.parent.mkdir(parents=True)
            service.write_text(
                """.class public Lowasp/sat/agoat/DownloadInvoiceService;
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 1
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    invoke-virtual {p0, p1}, Landroid/app/Service;->startActivity(Landroid/content/Intent;)V
    const/4 v0, 0x1
    return v0
.end method
""",
                encoding="utf-8",
            )

            pipeline = AnalysisPipeline.__new__(AnalysisPipeline)
            pipeline.reverse_engineer = FakeReverseEngineer(decompiled_dir)
            pipeline.max_call_depth = 7
            pipeline.catalog_path = None
            result = pipeline.analyze_apk(apk_path)

            components = {
                component["name"]: component
                for component in result.analysis["components"]
            }
            summary = result.analysis["summary"]

            self.assertEqual(summary["smali_component_count"], 5)
            self.assertEqual(summary["smali_found_count"], 2)
            self.assertEqual(summary["smali_missing_count"], 3)
            self.assertEqual(summary["code_component_count"], 5)
            self.assertEqual(summary["code_analyzed_count"], 2)
            self.assertEqual(summary["code_unavailable_count"], 3)
            self.assertEqual(summary["code_error_count"], 0)
            self.assertEqual(summary["code_entry_point_count"], 2)
            self.assertEqual(summary["code_reachable_method_count"], 0)
            self.assertEqual(summary["code_direct_evidence_count"], 3)
            self.assertEqual(summary["code_indirect_evidence_count"], 0)
            self.assertEqual(summary["code_evidence_count"], 3)
            self.assertEqual(summary["code_external_source_count"], 2)
            self.assertEqual(summary["code_possible_validation_count"], 0)
            self.assertEqual(summary["code_sensitive_operation_count"], 1)
            self.assertEqual(summary["data_flow_component_count"], 2)
            self.assertEqual(summary["data_flow_entry_point_count"], 2)
            self.assertEqual(summary["data_flow_method_count"], 2)
            self.assertEqual(summary["data_flow_confirmed_count"], 1)
            self.assertEqual(summary["data_flow_unvalidated_count"], 1)
            self.assertEqual(summary["data_flow_validated_count"], 0)
            self.assertEqual(summary["data_flow_error_count"], 0)
            self.assertEqual(summary["risk_candidate_count"], 1)
            self.assertEqual(summary["risk_candidate_proposal_count"], 2)
            self.assertEqual(summary["risk_candidate_absorbed_count"], 1)
            self.assertEqual(
                summary["risk_candidates_by_severity"],
                {"high": 0, "medium": 1, "low": 0, "info": 0},
            )
            self.assertEqual(
                components["owasp.sat.agoat.MainActivity"]["smali"]["path"],
                "smali/owasp/sat/agoat/MainActivity.smali",
            )
            self.assertEqual(
                components["owasp.sat.agoat.DownloadInvoiceService"]
                ["smali"]["dex_directory"],
                "smali_classes2",
            )
            self.assertFalse(
                components["owasp.sat.agoat.ShowDataReceiver"]
                ["smali"]["found"]
            )
            self.assertEqual(
                components["owasp.sat.agoat.MainActivity"]
                ["code_analysis"]["entry_points"][0]["name"],
                "onCreate",
            )
            self.assertEqual(
                components["owasp.sat.agoat.DownloadInvoiceService"]
                ["code_analysis"]["entry_points"][0]["name"],
                "onStartCommand",
            )

            saved_report = json.loads(
                result.report_path.read_text(encoding="utf-8")
            )
            self.assertEqual(saved_report["schema_version"], "2.0")
            self.assertEqual(
                saved_report["api_catalog"]["catalog_version"],
                "1.0.0",
            )
            self.assertGreater(saved_report["api_catalog"]["rule_count"], 90)
            self.assertEqual(saved_report["summary"], summary)
            self.assertEqual(
                saved_report["smali_lookup"]["missing_component_count"],
                3,
            )
            self.assertFalse(
                saved_report["code_analysis_summary"]
                ["security_verdicts_generated"]
            )
            self.assertEqual(
                saved_report["code_analysis_summary"]["phase"],
                "bounded-call-graph-evidence-detection",
            )
            self.assertEqual(
                saved_report["code_analysis_summary"]
                ["prioritized_entry_points"][0]["method"],
                "onStartCommand",
            )
            self.assertFalse(
                saved_report["risk_analysis"]
                ["definitive_security_verdicts_generated"]
            )
            self.assertEqual(
                {
                    candidate["rule_id"]
                    for candidate in saved_report["risk_analysis"]["candidates"]
                },
                {"RISK-FLOW-001"},
            )
            self.assertFalse(
                saved_report["data_flow_analysis"]
                ["definitive_security_verdicts_generated"]
            )
            flow_candidate = next(
                candidate
                for candidate in saved_report["risk_analysis"]["candidates"]
                if candidate["rule_id"] == "RISK-FLOW-001"
            )
            self.assertEqual(
                flow_candidate["data_flow_status"],
                "confirmed-unvalidated",
            )
            self.assertEqual(flow_candidate["data_flow_count"], 1)
            self.assertEqual(
                flow_candidate["contributing_rule_ids"],
                ["RISK-FLOW-001", "RISK-CODE-001"],
            )
            self.assertTrue(result.html_report_path.is_file())
            self.assertEqual(
                saved_report["reports"]["html"],
                str(result.html_report_path),
            )
            html_report = result.html_report_path.read_text(encoding="utf-8")
            self.assertIn("Relatório de análise estática", html_report)
            self.assertIn("SMALIRIS", html_report)
            self.assertIn("RISK-FLOW-001", html_report)
            self.assertEqual(saved_report["tool"]["version"], "1.0.0")
            self.assertEqual(
                saved_report["reproducibility"]["apk_sha256"],
                hashlib.sha256(apk_content).hexdigest(),
            )
            self.assertEqual(
                saved_report["reproducibility"]["max_call_depth"],
                7,
            )
            self.assertEqual(
                saved_report["reproducibility"]["apktool_version"],
                "3.0.2-test",
            )
            self.assertEqual(
                saved_report["reproducibility"]["truncated_call_count"],
                summary["code_truncated_call_count"],
            )
            self.assertEqual(summary["code_input_source_count"], 2)
            self.assertEqual(summary["code_interface_source_count"], 0)
            validate_report(saved_report)

    def test_repeated_analysis_is_equivalent_except_for_durations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            decompiled_dir = Path(directory)
            (decompiled_dir / "AndroidManifest.xml").write_text(
                FIXTURE.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            apk_path = decompiled_dir / "sample.apk"
            apk_path.write_bytes(b"same-input")

            pipeline = AnalysisPipeline.__new__(AnalysisPipeline)
            pipeline.reverse_engineer = FakeReverseEngineer(decompiled_dir)
            pipeline.max_call_depth = 7
            pipeline.catalog_path = None

            first = copy.deepcopy(pipeline.analyze_apk(apk_path).analysis)
            second = copy.deepcopy(pipeline.analyze_apk(apk_path).analysis)

            for report in (first, second):
                reproducibility = report["reproducibility"]
                reproducibility.pop("decompilation_duration_seconds")
                reproducibility.pop("analysis_duration_seconds")

            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
