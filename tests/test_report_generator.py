from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tcc_analyzer.report_generator import ReportGenerator


class ReportGeneratorTests(unittest.TestCase):
    def sample_analysis(self) -> dict:
        evidence = {
            "api": "WebView.loadUrl",
            "category": "sensitive_operation",
            "origin": "direct",
            "depth": 0,
            "smali_path": "smali/example/Activity.smali",
            "line": 42,
            "instruction": "invoke-virtual {v0, v1}, <unsafe>",
        }
        return {
            "schema_version": "2.0",
            "apk_path": "example.apk",
            "manifest_path": "output/example/AndroidManifest.xml",
            "package": "example.<unsafe>",
            "sdk": {
                "min": 23,
                "target": 35,
                "source": {"min": "manifest", "target": "apktool.yml"},
            },
            "summary": {
                "component_count": 2,
                "exported_component_count": 1,
                "finding_count": 1,
                "risk_candidate_count": 1,
                "code_evidence_count": 1,
                "data_flow_confirmed_count": 1,
                "code_input_source_count": 1,
                "ipc_transition_count": 1,
                "risk_candidates_by_severity": {
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                "findings_by_severity": {
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                },
            },
            "code_analysis_summary": {"max_call_depth": 3},
            "reproducibility": {
                "tool_version": "1.0.0",
                "apk_sha256": "a" * 64,
                "max_call_depth": 7,
                "apktool_version": "3.0.2",
                "decompilation_duration_seconds": 1.25,
                "analysis_duration_seconds": 0.5,
                "truncated_call_count": 0,
            },
            "findings": [
                {
                    "rule_id": "COMPONENT-001",
                    "title": "Componente exportado sem permissão",
                    "severity": "medium",
                    "confidence": "high",
                    "component": "example.ExportedActivity",
                    "component_type": "activity",
                    "evidence": "Componente exportado e sem permission.",
                    "recommendation": "Restringir o acesso.",
                }
            ],
            "components": [
                {
                    "name": "example.ExportedActivity",
                    "type": "activity",
                    "exported": True,
                    "exported_source": "explicit",
                    "permission": None,
                    "read_permission": None,
                    "write_permission": None,
                    "intent_filters": [],
                    "smali": {"found": True},
                    "code_analysis": {
                        "status": "analyzed",
                        "entry_points": [
                            {
                                "signature": "onCreate(Landroid/os/Bundle;)V",
                                "data_flow_analysis": {
                                    "data_flow_status": "confirmed-unvalidated",
                                    "source_count": 1,
                                    "touched_validation_count": 0,
                                    "flow_count": 1,
                                    "argument_classification_counts": {
                                        "external-tainted": 1,
                                        "interface-tainted": 0,
                                        "constant": 0,
                                        "unknown": 0,
                                    },
                                },
                            }
                        ],
                    },
                }
            ],
            "data_flow_analysis": {
                "analyzed_method_count": 1,
                "confirmed_flow_count": 1,
                "unvalidated_flow_count": 1,
                "validated_flow_count": 0,
                "ipc_transition_count": 1,
                "ipc_transitions": [
                    {
                        "transition_id": "IPC-0001",
                        "source_component": "example.ExportedActivity",
                        "api": "startActivity",
                        "intent_kind": "implicit",
                        "selector_classification": "external-tainted",
                        "destination_candidates": [],
                        "destination_internal": None,
                    }
                ],
                "limitations": ["Fluxo estático."],
            },
            "risk_analysis": {
                "candidates": [
                    {
                        "candidate_id": "RISK-0001",
                        "rule_id": "RISK-FLOW-001",
                        "title": "Dado externo alcança operação sensível",
                        "severity": "high",
                        "confidence": "high",
                        "component": "example.ExportedActivity",
                        "component_type": "activity",
                        "entry_point": "onCreate(Landroid/os/Bundle;)V",
                        "data_flow_status": "confirmed-unvalidated",
                        "data_flow_count": 1,
                        "data_flow_ids": ["FLOW-0001"],
                        "critical_argument_classification": (
                            "external-tainted"
                        ),
                        "reasons": ["Dependência entre registradores confirmada."],
                        "evidence": [evidence],
                        "recommendation": "Validar a entrada.",
                        "limitations": ["Não comprova exploração."],
                    }
                ],
                "limitations": ["Correlação estática."],
            },
            "limitations": ["Manifesto não comprova exploração."],
        }

    def test_renders_sections_mappings_and_escaped_values(self) -> None:
        generator = ReportGenerator(
            generated_at=datetime(2026, 9, 12, 15, 30, tzinfo=timezone.utc)
        )

        html = generator.render(self.sample_analysis())

        self.assertIn("Relatório de análise estática", html)
        self.assertIn("Resumo executivo", html)
        self.assertIn("Candidatos de risco", html)
        self.assertIn("Achados do Manifesto", html)
        self.assertIn("Componentes exportados", html)
        self.assertIn("Fluxo de dados", html)
        self.assertIn("Transições IPC", html)
        self.assertIn("IPC-0001", html)
        self.assertIn("Versão da SMALIRIS", html)
        self.assertIn("3.0.2", html)
        self.assertIn("RISK-0001", html)
        self.assertIn("FLOW-0001", html)
        self.assertIn("CWE-20", html)
        self.assertIn("OWASP MASVS-CODE", html)
        self.assertIn("Contaminado externamente", html)
        self.assertIn("example.&lt;unsafe&gt;", html)
        self.assertIn("&lt;unsafe&gt;", html)
        self.assertNotIn("example.<unsafe>", html)
        self.assertIn("12/09/2026 15:30 UTC", html)

    def test_writes_standalone_html_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "analysis_report.html"

            result = ReportGenerator().generate(
                self.sample_analysis(),
                output,
            )

            self.assertEqual(result, output)
            self.assertTrue(output.is_file())
            content = output.read_text(encoding="utf-8")
            self.assertTrue(content.startswith("<!doctype html>"))
            self.assertIn("<style>", content)
            self.assertNotIn("<script", content)

    def test_renders_debuggable_application_mapping(self) -> None:
        analysis = self.sample_analysis()
        analysis["findings"][0].update(
            {
                "rule_id": "APP-DEBUG-001",
                "title": "Aplicação com depuração habilitada",
                "component": "example.app",
                "component_type": "application",
            }
        )

        html = ReportGenerator().render(analysis)

        self.assertIn("CWE-489", html)
        self.assertIn("OWASP MASVS-RESILIENCE", html)


if __name__ == "__main__":
    unittest.main()
