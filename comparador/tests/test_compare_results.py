from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import compare_results as comparator


SHA = "a" * 64


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def smaliris_report() -> dict:
    return {
        "package": "com.example.app",
        "apk_path": "corpus/apps_vulneraveis/example.apk",
        "application": {"debuggable": True, "uses_cleartext_traffic": False},
        "components": [
            {"type": "activity", "name": ".MainActivity", "exported": True},
            {"type": "service", "name": ".InternalService", "exported": False},
        ],
        "findings": [
            {
                "rule_id": "APP-DEBUG-001",
                "title": "Aplicação com depuração habilitada",
                "severity": "high",
                "component": "application",
                "evidence": "android:debuggable=true",
            }
        ],
        "summary": {
            "browsable_deep_link_count": 0,
            "risk_candidate_count": 1,
            "data_flow_confirmed_count": 1,
        },
        "risk_analysis": {
            "candidates": [
                {
                    "rule_id": "RISK-FLOW-001",
                    "title": "Fonte externa e operação sensível",
                    "severity": "high",
                    "component": ".MainActivity",
                    "reasons": ["Fluxo externo confirmado"],
                    "sensitive_apis": ["Runtime.exec"],
                    "critical_argument_classification": "external-tainted",
                }
            ]
        },
        "tool": {"version": "1.0.0"},
        "reproducibility": {
            "apk_sha256": SHA,
            "decompilation_duration_seconds": 2,
            "analysis_duration_seconds": 3,
        },
    }


def mobsf_report() -> dict:
    return {
        "sha256": SHA,
        "file_name": "example.apk",
        "package_name": "com.example.app",
        "debuggable": True,
        "activities": ["com.example.app.MainActivity"],
        "services": ["com.example.app.InternalService"],
        "receivers": [],
        "providers": [],
        "exported_activities": ["com.example.app.MainActivity"],
        "exported_services": [],
        "exported_receivers": [],
        "exported_providers": [],
        "browsable_activities": [],
        "security_score": 40,
        "appsec": {
            "high": [
                {
                    "title": "Application is debuggable [android:debuggable=true]",
                    "description": "Debugging is enabled.",
                    "section": "manifest",
                },
                {
                    "title": "Runtime.exec may lead to command execution",
                    "description": "OS command execution",
                    "section": "code",
                },
            ],
            "warning": [],
            "info": [],
            "hotspot": [],
        },
    }


class ComparatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.smaliris = self.root / "smaliris"
        self.mobsf = self.root / "mobsf"
        self.output = self.root / "comparison"
        write_json(
            self.smaliris / "apps_vulneraveis" / "example" / "manifest_analysis.json",
            smaliris_report(),
        )
        write_json(
            self.mobsf / "apps_vulneraveis" / "example" / "report.json",
            mobsf_report(),
        )
        write_json(
            self.mobsf / "apps_vulneraveis" / "example" / "metadata.json",
            {"sha256": SHA, "categoria": "apps_vulneraveis", "duracao_segundos": 8},
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_comparison(self):
        return comparator.run_comparison(
            self.smaliris,
            self.mobsf,
            self.output,
            Path(comparator.__file__).with_name("comparison_catalog.json"),
        )

    def test_pairs_reports_by_sha256(self) -> None:
        report = self.run_comparison()
        self.assertEqual(report["summary"]["paired_apks"], 1)
        self.assertEqual(report["summary"]["paired_by_sha256"], 1)

    def test_exported_activity_and_debuggable_agree(self) -> None:
        report = self.run_comparison()
        rows = {row["categoria_id"]: row for row in report["comparisons"]}
        self.assertEqual(rows["APP_DEBUGGABLE"]["resultado"], "concordancia")
        self.assertEqual(rows["EXPORTED_ACTIVITY"]["resultado"], "concordancia")
        self.assertEqual(rows["EXPORTED_ACTIVITY"]["smaliris_valor"], 1)
        self.assertEqual(rows["EXPORTED_ACTIVITY"]["mobsf_valor"], 1)

    def test_tool_specific_flow_is_not_false_negative(self) -> None:
        report = self.run_comparison()
        row = next(
            item
            for item in report["comparisons"]
            if item["categoria_id"] == "EXTERNAL_TO_SENSITIVE_FLOW"
        )
        self.assertEqual(row["resultado"], "nao_comparavel")

    def test_command_execution_is_compared(self) -> None:
        report = self.run_comparison()
        row = next(
            item
            for item in report["comparisons"]
            if item["categoria_id"] == "COMMAND_EXECUTION"
        )
        self.assertEqual(row["resultado"], "concordancia")

    def test_outputs_are_created(self) -> None:
        self.run_comparison()
        for name in (
            "comparacao_apks.csv",
            "comparacao_categorias.csv",
            "divergencias.csv",
            "comparison_report.json",
            "comparison_report.html",
            "metricas_gabarito.csv",
            "revisao_manual.csv",
            "ground_truth_template.json",
        ):
            self.assertTrue((self.output / name).is_file(), name)

    def test_inferred_launcher_is_not_compared_as_explicit_export(self) -> None:
        report = smaliris_report()
        report["components"] = [
            {
                "type": "activity",
                "name": ".LauncherActivity",
                "exported": True,
                "exported_source": "inferred-from-intent-filter",
                "intent_filters": [
                    {
                        "actions": ["android.intent.action.MAIN"],
                        "categories": ["android.intent.category.LAUNCHER"],
                    }
                ],
            },
            {
                "type": "activity",
                "name": ".AdminActivity",
                "exported": True,
                "exported_source": "explicit",
                "intent_filters": [],
            },
        ]
        write_json(
            self.smaliris / "apps_vulneraveis" / "example" / "manifest_analysis.json",
            report,
        )
        mobsf = mobsf_report()
        mobsf["activities"] = [
            "com.example.app.LauncherActivity",
            "com.example.app.AdminActivity",
        ]
        mobsf["exported_activities"] = ["com.example.app.AdminActivity"]
        write_json(
            self.mobsf / "apps_vulneraveis" / "example" / "report.json",
            mobsf,
        )
        result = self.run_comparison()
        row = next(item for item in result["comparisons"] if item["categoria_id"] == "EXPORTED_ACTIVITY")
        self.assertEqual(row["resultado"], "concordancia")
        self.assertEqual(row["smaliris_valor"], 1)
        self.assertEqual(row["mobsf_valor"], 1)
        self.assertEqual(row["base_comparacao"], "nomes")
        self.assertEqual(row["componentes_comuns"], ["com.example.app.adminactivity"])

    def test_same_component_count_with_different_names_is_divergent(self) -> None:
        report = smaliris_report()
        report["components"][0]["name"] = ".FirstActivity"
        report["components"][0]["exported_source"] = "explicit"
        write_json(
            self.smaliris / "apps_vulneraveis" / "example" / "manifest_analysis.json",
            report,
        )
        mobsf = mobsf_report()
        mobsf["exported_activities"] = ["com.example.app.SecondActivity"]
        write_json(
            self.mobsf / "apps_vulneraveis" / "example" / "report.json",
            mobsf,
        )
        result = self.run_comparison()
        row = next(item for item in result["comparisons"] if item["categoria_id"] == "EXPORTED_ACTIVITY")
        self.assertEqual(row["resultado"], "componentes_divergentes")
        self.assertEqual(row["somente_smaliris_componentes"], ["com.example.app.firstactivity"])
        self.assertEqual(row["somente_mobsf_componentes"], ["com.example.app.secondactivity"])

    def test_smaliris_cleartext_default_uses_target_sdk(self) -> None:
        report = smaliris_report()
        report["application"]["uses_cleartext_traffic"] = None
        report["sdk"] = {"target": 26}
        record = comparator.ReportFile(
            "smaliris", Path("manifest_analysis.json"), report, {}, SHA, "example.apk", "test"
        )
        normalized = comparator.normalize_smaliris(record)
        self.assertTrue(normalized["facts"]["cleartext_traffic"])
        report["sdk"]["target"] = 34
        normalized = comparator.normalize_smaliris(record)
        self.assertFalse(normalized["facts"]["cleartext_traffic"])

    def test_mobsf_reads_manifest_finding_and_nested_security_score(self) -> None:
        report = mobsf_report()
        report.pop("debuggable")
        report.pop("security_score")
        report["manifest_analysis"] = [
            {
                "rule": "debuggable",
                "title": "Application is debuggable",
                "description": "android:debuggable=\"true\"",
                "severity": "high",
            }
        ]
        report["appsec"]["security_score"] = 28
        record = comparator.ReportFile(
            "mobsf", Path("report.json"), report, {}, SHA, "example.apk", "test"
        )
        normalized = comparator.normalize_mobsf(record, {"warning": "medium"})
        self.assertTrue(normalized["facts"]["debuggable"])
        self.assertEqual(normalized["security_score"], 28.0)

    def test_finding_presence_ignores_different_evidence_counts(self) -> None:
        report = smaliris_report()
        report["risk_analysis"]["candidates"].append(
            {
                "rule_id": "RISK-FLOW-002",
                "title": "Outro fluxo de comando",
                "severity": "high",
                "reasons": ["Runtime.exec com dado externo"],
                "sensitive_apis": ["Runtime.exec"],
            }
        )
        write_json(
            self.smaliris / "apps_vulneraveis" / "example" / "manifest_analysis.json",
            report,
        )
        result = self.run_comparison()
        row = next(item for item in result["comparisons"] if item["categoria_id"] == "COMMAND_EXECUTION")
        self.assertEqual(row["resultado"], "concordancia")
        self.assertGreater(row["smaliris_evidence_count"], row["mobsf_evidence_count"])

    def test_mobsf_case_sensitive_duplicate_keys_are_preserved(self) -> None:
        path = self.mobsf / "case" / "report.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            '{"sha256":"' + ("b" * 64) + '","file_name":"case.apk",'
            '"okio/Buffer.java":1,"okio/buffer.java":2,"appsec":{}}',
            encoding="utf-8",
        )
        loaded = comparator.load_json(path)
        self.assertIn("okio/Buffer.java", loaded)
        self.assertIn("okio/buffer.java", loaded)

    def test_ground_truth_metrics(self) -> None:
        ground_truth = self.root / "ground_truth.json"
        write_json(
            ground_truth,
            {
                "apps": [
                    {
                        "sha256": SHA,
                        "categories": {
                            "APP_DEBUGGABLE": True,
                            "BROWSABLE_DEEP_LINK": False,
                        },
                    }
                ]
            },
        )
        report = comparator.run_comparison(
            self.smaliris,
            self.mobsf,
            self.output,
            Path(comparator.__file__).with_name("comparison_catalog.json"),
            ground_truth,
        )
        metrics = {
            (item["ferramenta"], item["categoria_id"]): item
            for item in report["ground_truth_metrics"]
        }
        self.assertEqual(metrics[("SMALIRIS", "APP_DEBUGGABLE")]["vp"], 1)
        self.assertEqual(metrics[("MobSF", "BROWSABLE_DEEP_LINK")]["vn"], 1)
        self.assertEqual(metrics[("SMALIRIS", "TOTAL")]["amostras"], 2)

    def test_ground_truth_ignores_pending_values_and_parses_false(self) -> None:
        ground_truth = self.root / "ground_truth.json"
        write_json(
            ground_truth,
            {
                "apps": [
                    {
                        "sha256": SHA,
                        "categories": {
                            "APP_DEBUGGABLE": {"expected": None},
                            "BROWSABLE_DEEP_LINK": {"expected": "false"},
                        },
                    }
                ]
            },
        )
        loaded = comparator.load_ground_truth(ground_truth)
        self.assertNotIn("APP_DEBUGGABLE", loaded[SHA])
        self.assertFalse(loaded[SHA]["BROWSABLE_DEEP_LINK"])


if __name__ == "__main__":
    unittest.main()
