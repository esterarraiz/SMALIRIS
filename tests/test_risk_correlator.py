from __future__ import annotations

import unittest
from typing import Any

from tcc_analyzer.risk_correlator import RiskCorrelator


def evidence(
    api: str,
    category: str,
    *,
    origin: str = "direct",
    depth: int = 0,
    source_kind: str | None = None,
    operation_kind: str | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    result = {
        "api": api,
        "category": category,
        "origin": origin,
        "depth": depth,
        "class_name": "example.ExportedComponent",
        "method_signature": "onStartCommand(Landroid/content/Intent;II)I",
        "smali_path": "smali/example/ExportedComponent.smali",
        "line": 12,
        "instruction": f"invoke-* ... {api}",
        "call_chain": [
            "example.ExportedComponent->onStartCommand(Landroid/content/Intent;II)I"
        ],
    }
    if source_kind is not None:
        result["source_kind"] = source_kind
    if operation_kind is not None:
        result["operation_kind"] = operation_kind
    if severity is not None:
        result["severity"] = severity
    return result


def entry_point(
    items: list[dict[str, Any]],
    *,
    priority: int = 1,
) -> dict[str, Any]:
    return {
        "signature": "onStartCommand(Landroid/content/Intent;II)I",
        "analysis_priority": priority,
        "evidence": items,
        "call_graph": {
            "unresolved_call_count": 0,
            "cycle_count": 0,
            "truncated_call_count": 0,
        },
    }


def component(
    items: list[dict[str, Any]],
    *,
    component_type: str = "service",
    permission: str | None = None,
    intent_filters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "name": "example.ExportedComponent",
        "type": component_type,
        "enabled": True,
        "exported": True,
        "exported_source": "explicit",
        "permission": permission,
        "read_permission": None,
        "write_permission": None,
        "permission_assessment": {
            "status": "absent" if permission is None else "strong",
            "protection_level": None if permission is None else "signature",
        },
        "intent_filters": intent_filters or [],
        "code_analysis": {
            "status": "analyzed",
            "entry_points": [entry_point(items)],
        },
    }


def analysis_for(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "application": {"permission": None},
        "components": [item],
        "summary": {},
    }


class RiskCorrelatorTests(unittest.TestCase):
    def test_unconfirmed_high_impact_api_is_capped_at_medium_severity(
        self,
    ) -> None:
        item = component(
            [evidence("DownloadManager.enqueue", "sensitive_operation")]
        )
        analysis = analysis_for(item)

        result = RiskCorrelator().analyze(analysis)

        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["candidate_id"], "RISK-0001")
        self.assertEqual(candidate["rule_id"], "RISK-CODE-001")
        self.assertEqual(candidate["severity"], "medium")
        self.assertEqual(candidate["confidence"], "high")
        self.assertFalse(candidate["definitive_verdict"])
        self.assertIs(item["risk_candidates"][0], candidate)
        self.assertEqual(analysis["summary"]["risk_candidate_count"], 1)

    def test_caller_validation_suppresses_unprotected_component_rule(self) -> None:
        item = component(
            [
                evidence("checkCallingPermission", "possible_validation"),
                evidence("DownloadManager.enqueue", "sensitive_operation"),
            ]
        )

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 0)

    def test_signature_permission_suppresses_unprotected_component_rule(
        self,
    ) -> None:
        item = component(
            [evidence("DownloadManager.enqueue", "sensitive_operation")],
            permission="example.permission.INTERNAL",
        )

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 0)

    def test_launcher_navigation_is_not_reported_as_risk_candidate(self) -> None:
        item = component(
            [evidence("startActivity", "sensitive_operation")],
            component_type="activity",
            intent_filters=[
                {
                    "actions": ["android.intent.action.MAIN"],
                    "categories": ["android.intent.category.LAUNCHER"],
                    "is_uri_intent": False,
                }
            ],
        )

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 0)

    def test_uri_filter_without_uri_validation_gets_specific_candidate(
        self,
    ) -> None:
        item = component(
            [evidence("startService", "sensitive_operation")],
            component_type="activity",
            intent_filters=[
                {
                    "actions": ["android.intent.action.VIEW"],
                    "categories": [],
                    "is_uri_intent": True,
                    "uri_patterns": ["example://open"],
                }
            ],
        )

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 1)
        uri_candidate = result["candidates"][0]
        self.assertEqual(uri_candidate["rule_id"], "RISK-URI-001")
        self.assertEqual(
            uri_candidate["contributing_rule_ids"],
            ["RISK-URI-001", "RISK-CODE-001"],
        )
        self.assertEqual(uri_candidate["uri_patterns"], ["example://open"])

    def test_uri_validation_suppresses_only_uri_specific_candidate(self) -> None:
        item = component(
            [
                evidence("Uri.getHost", "possible_validation"),
                evidence("startService", "sensitive_operation"),
            ],
            component_type="activity",
            intent_filters=[
                {
                    "actions": ["android.intent.action.VIEW"],
                    "categories": [],
                    "is_uri_intent": True,
                    "uri_patterns": ["example://open"],
                }
            ],
        )

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(
            [candidate["rule_id"] for candidate in result["candidates"]],
            ["RISK-CODE-001"],
        )

    def test_correlates_source_and_sink_without_claiming_data_flow(self) -> None:
        item = component(
            [
                evidence("Intent.getStringExtra", "external_source"),
                evidence("startActivity", "sensitive_operation"),
            ]
        )

        result = RiskCorrelator().analyze(analysis_for(item))

        flow_candidate = next(
            candidate
            for candidate in result["candidates"]
            if candidate["rule_id"] == "RISK-FLOW-001"
        )
        self.assertEqual(flow_candidate["confidence"], "low")
        self.assertEqual(
            flow_candidate["source_apis"],
            ["Intent.getStringExtra"],
        )
        self.assertIn(
            "O fluxo entre fonte e operação ainda não foi confirmado.",
            flow_candidate["limitations"],
        )
        self.assertFalse(result["definitive_security_verdicts_generated"])

    def test_uses_confirmed_register_flow_even_without_source_evidence(self) -> None:
        item = component(
            [evidence("startActivity", "sensitive_operation")]
        )
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "flows": [
                {
                    "flow_id": "FLOW-0001",
                    "status": "confirmed-unvalidated",
                    "sources": [
                        {
                            "api": "Android entry point parameter",
                            "kind": "entry_point_parameter",
                        }
                    ],
                    "sink": {"api": "startActivity"},
                    "tainted_registers_at_sink": ["p1"],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        flow_candidate = next(
            candidate
            for candidate in result["candidates"]
            if candidate["rule_id"] == "RISK-FLOW-001"
        )
        self.assertEqual(
            flow_candidate["data_flow_status"],
            "confirmed-unvalidated",
        )
        self.assertEqual(flow_candidate["data_flow_ids"], ["FLOW-0001"])
        self.assertEqual(flow_candidate["confirmed_flow_count"], 1)
        self.assertEqual(flow_candidate["confidence"], "high")
        self.assertEqual(flow_candidate["source_profile"]["external_count"], 1)
        self.assertEqual(
            flow_candidate["source_profile"]["external_kinds"],
            ["entry_point_parameter"],
        )

    def test_confirmed_flow_supersedes_generic_and_uri_candidates(self) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        sink = evidence(
            "WebView.loadUrl",
            "sensitive_operation",
            operation_kind="web_content_loading",
            severity="high",
        )
        item = component(
            [source, sink],
            component_type="activity",
            intent_filters=[
                {
                    "actions": ["android.intent.action.VIEW"],
                    "categories": ["android.intent.category.BROWSABLE"],
                    "is_uri_intent": True,
                    "uri_patterns": ["example://open"],
                }
            ],
        )
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "flows": [
                {
                    "flow_id": "FLOW-0001",
                    "status": "confirmed-unvalidated",
                    "sources": [
                        {
                            "api": "Intent.getStringExtra",
                            "source_kind": "untrusted_input",
                        }
                    ],
                    "sink": {
                        "api": "WebView.loadUrl",
                        "line": sink["line"],
                        "tainted_registers": ["v1"],
                    },
                    "tainted_registers_at_sink": ["v1"],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["rule_id"], "RISK-FLOW-001")
        self.assertEqual(candidate["correlation_basis"], "confirmed-data-flow")
        self.assertEqual(candidate["severity"], "high")
        self.assertEqual(candidate["confidence"], "high")
        self.assertEqual(
            candidate["contributing_rule_ids"],
            ["RISK-FLOW-001", "RISK-CODE-001", "RISK-URI-001"],
        )
        self.assertEqual(candidate["merged_candidate_count"], 3)
        self.assertEqual(len(item["risk_candidates"]), 1)
        self.assertEqual(result["proposal_count"], 3)
        self.assertEqual(result["absorbed_candidate_count"], 2)

    def test_interface_input_does_not_create_exported_component_flow_risk(
        self,
    ) -> None:
        item = component(
            [
                evidence(
                    "TextView.getText",
                    "external_source",
                    source_kind="user_input",
                ),
                evidence("Toast.makeText", "sensitive_operation"),
                evidence("startActivity", "sensitive_operation"),
            ],
            component_type="activity",
            intent_filters=[
                {
                    "actions": ["android.intent.action.MAIN"],
                    "categories": ["android.intent.category.LAUNCHER"],
                    "is_uri_intent": False,
                }
            ],
        )

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 0)

    def test_critical_api_requires_taint_in_sensitive_argument_for_high(
        self,
    ) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        sink = evidence(
            "Runtime.exec",
            "sensitive_operation",
            operation_kind="command_execution",
            severity="high",
        )
        sink["risk_relevant"] = True
        item = component([source, sink], component_type="activity")
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "flows": [
                {
                    "flow_id": "FLOW-0001",
                    "status": "confirmed-unvalidated",
                    "sources": [
                        {
                            "api": "Intent.getStringExtra",
                            "source_kind": "untrusted_input",
                        }
                    ],
                    "sink": {"api": "Runtime.exec"},
                    "tainted_registers_at_sink": [],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["correlation_basis"], "source-sink-co-occurrence")
        self.assertEqual(candidate["confirmed_flow_count"], 0)
        self.assertEqual(candidate["severity"], "medium")
        self.assertEqual(candidate["confidence"], "low")
        self.assertEqual(candidate["data_flow_count"], 0)

    def test_untainted_critical_api_does_not_raise_confirmed_medium_flow(
        self,
    ) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        medium_sink = evidence(
            "startActivity",
            "sensitive_operation",
            operation_kind="ipc_activity",
            severity="medium",
        )
        critical_sink = evidence(
            "Runtime.exec",
            "sensitive_operation",
            operation_kind="command_execution",
            severity="high",
        )
        critical_sink["risk_relevant"] = True
        item = component([source, medium_sink, critical_sink])
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "flows": [
                {
                    "flow_id": "FLOW-0001",
                    "status": "confirmed-unvalidated",
                    "sources": [
                        {
                            "api": "Intent.getStringExtra",
                            "source_kind": "untrusted_input",
                        }
                    ],
                    "sink": {
                        "api": "startActivity",
                        "line": medium_sink["line"],
                        "tainted_registers": ["v1"],
                    },
                    "tainted_registers_at_sink": ["v1"],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        candidate = result["candidates"][0]
        self.assertEqual(candidate["rule_id"], "RISK-FLOW-001")
        self.assertEqual(candidate["severity"], "medium")
        self.assertEqual(candidate["sensitive_apis"], ["startActivity"])
        self.assertEqual(
            candidate["reachable_sensitive_apis"],
            ["Runtime.exec", "startActivity"],
        )

    def test_constant_critical_argument_removes_risk_correlations(self) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        sink = evidence(
            "WebView.loadUrl",
            "sensitive_operation",
            operation_kind="web_content_loading",
            severity="high",
        )
        sink["risk_relevant"] = True
        item = component([source, sink], component_type="activity")
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "flows": [],
            "sensitive_argument_assessments": [
                {
                    "api": "WebView.loadUrl",
                    "line": sink["line"],
                    "classification": "constant",
                    "arguments": [
                        {
                            "position": 1,
                            "register": "v1",
                            "classification": "constant",
                            "constant_values": ['"https://safe.example"'],
                        }
                    ],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(result["proposal_count"], 0)

    def test_unknown_critical_argument_reduces_severity(self) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        sink = evidence(
            "Runtime.exec",
            "sensitive_operation",
            operation_kind="command_execution",
            severity="high",
        )
        sink["risk_relevant"] = True
        item = component([source, sink], component_type="activity")
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "flows": [],
            "sensitive_argument_assessments": [
                {
                    "api": "Runtime.exec",
                    "line": sink["line"],
                    "classification": "unknown",
                    "arguments": [
                        {
                            "position": 1,
                            "register": "v1",
                            "classification": "unknown",
                        }
                    ],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["severity"], "low")
        self.assertEqual(candidate["confidence"], "low")
        self.assertEqual(
            candidate["critical_argument_classification"],
            "unknown",
        )

    def test_field_propagation_confirms_indirect_external_flow(self) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        sink = evidence(
            "Runtime.exec",
            "sensitive_operation",
            operation_kind="command_execution",
            severity="high",
        )
        sink["risk_relevant"] = True
        item = component([source, sink], component_type="service")
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "sensitive_argument_assessments": [
                {
                    "api": "Runtime.exec",
                    "line": sink["line"],
                    "classification": "external-tainted",
                }
            ],
            "flows": [
                {
                    "flow_id": "FLOW-0001",
                    "status": "confirmed-unvalidated",
                    "sources": [
                        {
                            "api": "Intent.getStringExtra",
                            "source_kind": "untrusted_input",
                        }
                    ],
                    "sink": {
                        "api": "Runtime.exec",
                        "line": sink["line"],
                        "tainted_registers": ["v1"],
                    },
                    "tainted_registers_at_sink": ["v1"],
                    "tracking_precision": "field-or-array-dependency",
                    "storage_propagation": [
                        "instance-field-write",
                        "instance-field-read",
                    ],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        candidate = result["candidates"][0]
        self.assertEqual(candidate["correlation_basis"], "confirmed-data-flow")
        self.assertEqual(candidate["severity"], "high")
        self.assertEqual(candidate["indirect_storage_flow_count"], 1)
        self.assertEqual(
            candidate["flow_tracking_precisions"],
            ["field-or-array-dependency"],
        )

    def test_explicit_internal_constant_intent_does_not_create_candidate(
        self,
    ) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        sink = evidence(
            "startActivity",
            "sensitive_operation",
            operation_kind="ipc_activity",
            severity="medium",
        )
        item = component([source, sink], component_type="activity")
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "flows": [],
            "sensitive_argument_assessments": [
                {
                    "api": "startActivity",
                    "line": sink["line"],
                    "classification": "external-tainted",
                    "ipc_transition": {
                        "intent_kind": "explicit",
                        "selector_classification": "constant",
                        "destination_internal": True,
                        "explicit_internal_constant": True,
                    },
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(result["proposal_count"], 0)

    def test_implicit_external_intent_creates_flow_limited_candidate(self) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        sink = evidence(
            "sendBroadcast",
            "sensitive_operation",
            operation_kind="ipc_broadcast",
            severity="medium",
        )
        item = component([source, sink], component_type="service")
        transition = {
            "intent_kind": "implicit",
            "selector_classification": "external-tainted",
            "selector_controllable": True,
            "explicit_internal_constant": False,
            "api": "sendBroadcast",
            "line": sink["line"],
        }
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "sensitive_argument_assessments": [
                {
                    "api": "sendBroadcast",
                    "line": sink["line"],
                    "classification": "external-tainted",
                    "ipc_transition": transition,
                }
            ],
            "flows": [
                {
                    "flow_id": "FLOW-0001",
                    "status": "confirmed-unvalidated",
                    "confidence": "medium",
                    "sources": [
                        {
                            "api": "Intent.getStringExtra",
                            "source_kind": "untrusted_input",
                        }
                    ],
                    "sink": {
                        "api": "sendBroadcast",
                        "line": sink["line"],
                        "tainted_registers": ["v2"],
                    },
                    "tainted_registers_at_sink": ["v2"],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["rule_id"], "RISK-FLOW-001")
        self.assertEqual(candidate["confidence"], "medium")
        self.assertEqual(candidate["ipc_transitions"][0]["intent_kind"], "implicit")

    def test_interface_only_critical_argument_does_not_create_candidate(
        self,
    ) -> None:
        source = evidence(
            "TextView.getText",
            "external_source",
            source_kind="user_input",
        )
        sink = evidence(
            "WebView.loadUrl",
            "sensitive_operation",
            operation_kind="web_content_loading",
            severity="high",
        )
        sink["risk_relevant"] = True
        item = component([source, sink], component_type="activity")
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "flows": [],
            "sensitive_argument_assessments": [
                {
                    "api": "WebView.loadUrl",
                    "line": sink["line"],
                    "classification": "interface-tainted",
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 0)

    def test_notify_change_does_not_receive_high_severity(self) -> None:
        source = evidence(
            "Intent.getData",
            "external_source",
            source_kind="untrusted_input",
        )
        sink = evidence(
            "ContentResolver.notifyChange",
            "sensitive_operation",
            operation_kind="content_provider_notification",
            severity="low",
        )
        sink["risk_relevant"] = True
        item = component([source, sink], component_type="receiver")
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "sensitive_argument_assessments": [
                {
                    "api": "ContentResolver.notifyChange",
                    "line": sink["line"],
                    "classification": "external-tainted",
                }
            ],
            "flows": [
                {
                    "flow_id": "FLOW-0001",
                    "status": "confirmed-unvalidated",
                    "confidence": "high",
                    "sources": [
                        {
                            "api": "Intent.getData",
                            "source_kind": "untrusted_input",
                        }
                    ],
                    "sink": {
                        "api": "ContentResolver.notifyChange",
                        "line": sink["line"],
                        "tainted_registers": ["v1"],
                    },
                    "tainted_registers_at_sink": ["v1"],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["candidates"][0]["severity"], "low")

    def test_unconfirmed_toast_only_correlation_is_suppressed(self) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        toast = evidence(
            "Toast.makeText",
            "sensitive_operation",
            operation_kind="observable_output",
            severity="low",
        )
        toast["risk_relevant"] = True
        item = component([source, toast], component_type="activity")
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "flows": [],
            "sensitive_argument_assessments": [
                {
                    "api": "Toast.makeText",
                    "line": toast["line"],
                    "classification": "unknown",
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 0)
        self.assertEqual(result["proposal_count"], 0)

    def test_confirmed_external_flow_to_toast_is_preserved(self) -> None:
        source = evidence(
            "Intent.getStringExtra",
            "external_source",
            source_kind="untrusted_input",
        )
        toast = evidence(
            "Toast.makeText",
            "sensitive_operation",
            operation_kind="observable_output",
            severity="low",
        )
        toast["risk_relevant"] = True
        item = component([source, toast], component_type="receiver")
        item["code_analysis"]["entry_points"][0]["data_flow_analysis"] = {
            "status": "analyzed",
            "source_count": 1,
            "sensitive_argument_assessments": [
                {
                    "api": "Toast.makeText",
                    "line": toast["line"],
                    "classification": "external-tainted",
                }
            ],
            "flows": [
                {
                    "flow_id": "FLOW-0001",
                    "status": "confirmed-unvalidated",
                    "confidence": "high",
                    "sources": [
                        {
                            "api": "Intent.getStringExtra",
                            "source_kind": "untrusted_input",
                        }
                    ],
                    "sink": {
                        "api": "Toast.makeText",
                        "line": toast["line"],
                        "tainted_registers": ["v1"],
                    },
                    "tainted_registers_at_sink": ["v1"],
                }
            ],
        }

        result = RiskCorrelator().analyze(analysis_for(item))

        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(
            result["candidates"][0]["correlation_basis"],
            "confirmed-data-flow",
        )


if __name__ == "__main__":
    unittest.main()
