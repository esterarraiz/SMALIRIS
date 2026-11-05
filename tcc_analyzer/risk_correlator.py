"""Correlação conservadora entre Manifest e evidências de código Smali."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .api_catalog import ApiCatalog


CALLER_VALIDATION_APIS = {
    "checkCallingPermission",
    "enforceCallingPermission",
    "checkCallingOrSelfPermission",
    "enforceCallingOrSelfPermission",
    "Binder.getCallingUid",
    "Binder.getCallingPid",
    "PackageManager.checkSignatures",
}
URI_VALIDATION_APIS = {
    "Uri.getScheme",
    "Uri.getHost",
    "Uri.getAuthority",
    "Uri.isHierarchical",
}
HIGH_IMPACT_APIS = {
    "ContentResolver.callOrApplyBatch",
    "ContentResolver.delete",
    "ContentResolver.insert",
    "ContentResolver.openFile",
    "ContentResolver.query",
    "ContentResolver.update",
    "DownloadManager.enqueue",
    "DownloadManager.Request.setDestinationInExternalPublicDir",
    "FileOutputStream",
    "HttpURLConnection",
    "Runtime.exec",
    "SQLiteDatabase.compileStatement",
    "SQLiteDatabase.delete",
    "SQLiteDatabase.execSQL",
    "SQLiteDatabase.insert",
    "SQLiteDatabase.query",
    "SQLiteDatabase.rawQuery",
    "SQLiteDatabase.update",
    "WebView.loadUrl",
}
MEDIUM_IMPACT_APIS = {
    "sendBroadcast",
    "startActivity",
    "startService",
}
OBSERVABLE_APIS = {
    "Toast.makeText",
}
USER_INTERFACE_SOURCE_KINDS = {
    "user_input",
    "ui_input",
    "interface_input",
}
MEANINGFUL_SENSITIVE_APIS = (
    HIGH_IMPACT_APIS
    | MEDIUM_IMPACT_APIS
    | OBSERVABLE_APIS
)
SEVERITY_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
    "info": 3,
}
EXTERNAL_TAINTED = "external-tainted"
INTERFACE_TAINTED = "interface-tainted"
CONSTANT = "constant"
UNKNOWN = "unknown"
IPC_OPERATION_KINDS = {
    "ipc_activity",
    "ipc_service",
    "ipc_broadcast",
}
CONFIDENCE_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
}


class RiskCorrelator:
    """Gera candidatos de risco sem afirmar exploração ou vulnerabilidade."""

    def __init__(self, catalog: ApiCatalog | None = None) -> None:
        self.catalog = catalog or ApiCatalog()

    def analyze(self, analysis: dict[str, Any]) -> dict[str, Any]:
        candidates: list[dict[str, Any]] = []
        proposal_count = 0
        application_permission = (
            analysis.get("application", {}).get("permission")
        )

        for component in analysis.get("components", []):
            component_candidates: list[dict[str, Any]] = []
            component["risk_candidates"] = component_candidates

            if not self._eligible_component(component):
                continue

            unprotected = not self._has_manifest_protection(
                component,
                application_permission,
            )
            uri_filters = [
                intent_filter
                for intent_filter in component.get("intent_filters", [])
                if intent_filter.get("is_uri_intent")
            ]

            for entry_point in component["code_analysis"]["entry_points"]:
                entry_point_candidates: list[dict[str, Any]] = []
                evidence = entry_point.get("evidence", [])
                all_sources = self._evidence_by_category(
                    evidence, "external_source"
                )
                external_sources = self._external_evidence_sources(all_sources)
                interface_sources = self._interface_evidence_sources(all_sources)
                validations = self._evidence_by_category(
                    evidence,
                    "possible_validation",
                )
                sensitive = self._risk_relevant_sensitive_evidence(
                    entry_point,
                    self._meaningful_sensitive_evidence(evidence),
                )
                confirmed_flows = self._relevant_data_flows(
                    entry_point,
                    sensitive,
                )
                if (
                    sensitive
                    and not confirmed_flows
                    and self._only_observable_operations(sensitive)
                ):
                    # Toast e saídas equivalentes continuam no inventário de
                    # evidências, mas coocorrência sem fluxo não sustenta um
                    # candidato de risco por si só.
                    sensitive = []
                caller_validations = [
                    item
                    for item in validations
                    if item.get("validation_kind") == "caller_identity"
                    or item.get("api") in CALLER_VALIDATION_APIS
                ]
                uri_validations = [
                    item
                    for item in validations
                    if item.get("validation_kind") == "uri_structure"
                    or item.get("api") in URI_VALIDATION_APIS
                ]

                if (
                    unprotected
                    and sensitive
                    and not caller_validations
                    and not self._launcher_only_navigation(
                        component,
                        sensitive,
                    )
                ):
                    candidate = self._unprotected_component_candidate(
                        component,
                        entry_point,
                        sensitive,
                    )
                    entry_point_candidates.append(candidate)

                if (
                    unprotected
                    and uri_filters
                    and sensitive
                    and not uri_validations
                ):
                    candidate = self._unvalidated_uri_candidate(
                        component,
                        entry_point,
                        uri_filters,
                        sensitive,
                    )
                    entry_point_candidates.append(candidate)

                if sensitive and (external_sources or confirmed_flows):
                    candidate = self._source_and_sink_candidate(
                        component,
                        entry_point,
                        external_sources,
                        interface_sources,
                        validations,
                        sensitive,
                        confirmed_flows,
                    )
                    entry_point_candidates.append(candidate)

                candidate = self._consolidate_entry_point_candidates(
                    entry_point_candidates
                )
                proposal_count += len(entry_point_candidates)
                if candidate is not None:
                    candidates.append(candidate)
                    component_candidates.append(candidate)

        candidates.sort(key=self._candidate_sort_key)
        for index, candidate in enumerate(candidates, start=1):
            candidate["candidate_id"] = f"RISK-{index:04d}"

        severity_counts = Counter(
            candidate["severity"] for candidate in candidates
        )
        by_severity = {
            severity: severity_counts.get(severity, 0)
            for severity in ("high", "medium", "low", "info")
        }
        analysis.setdefault("summary", {}).update(
            {
                "risk_candidate_count": len(candidates),
                "risk_candidate_proposal_count": proposal_count,
                "risk_candidate_absorbed_count": proposal_count - len(candidates),
                "risk_candidates_by_severity": by_severity,
            }
        )
        return {
            "phase": "static-risk-correlation",
            "assessment_type": "candidate-only",
            "proposal_count": proposal_count,
            "candidate_count": len(candidates),
            "absorbed_candidate_count": proposal_count - len(candidates),
            "candidates_by_severity": by_severity,
            "candidates": candidates,
            "candidate_assessments_generated": True,
            "definitive_security_verdicts_generated": False,
            "limitations": [
                "A alcançabilidade é estática e não comprova execução em tempo real.",
                "A ausência de uma API conhecida não comprova ausência de validação customizada.",
                "Quando o fluxo não é confirmado, fonte e operação no mesmo subgrafo continuam sendo apenas uma correlação.",
                "Entradas da própria interface são separadas de entradas externas e não geram, isoladamente, risco de abuso de componente exportado.",
                "Transições IPC só geram candidato isolado quando action, data, component ou destino são classificados como controláveis externamente.",
                "Intent explícito com destino interno constante é registrado como transição, mas não como candidato isolado.",
                "Operações críticas sem dado externo confirmado em seus argumentos têm severidade limitada para evitar inferir injeção ou manipulação.",
                "Operações cujo argumento crítico foi comprovado como constante não geram correlação de fluxo ou exposição de código.",
                "Argumentos críticos desconhecidos permanecem para revisão com severidade reduzida.",
                "Um fluxo de registradores confirmado não comprova exploração prática.",
                "Permissões existentes ainda precisam ter seu nível de proteção interpretado no contexto do aplicativo.",
            ],
        }

    @staticmethod
    def _eligible_component(component: dict[str, Any]) -> bool:
        code_analysis = component.get("code_analysis") or {}
        return (
            component.get("exported") is True
            and component.get("enabled") is not False
            and code_analysis.get("status") == "analyzed"
            and bool(code_analysis.get("entry_points"))
        )

    @staticmethod
    def _has_manifest_protection(
        component: dict[str, Any],
        application_permission: str | None,
    ) -> bool:
        permissions = {
            component.get("permission"),
            component.get("read_permission"),
            component.get("write_permission"),
            application_permission,
        }
        return any(permission for permission in permissions)

    @staticmethod
    def _evidence_by_category(
        evidence: list[dict[str, Any]],
        category: str,
    ) -> list[dict[str, Any]]:
        return [
            item
            for item in evidence
            if item.get("category") == category
        ]

    @classmethod
    def _external_evidence_sources(
        cls,
        evidence: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [item for item in evidence if cls._is_external_source(item)]

    @classmethod
    def _interface_evidence_sources(
        cls,
        evidence: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [item for item in evidence if not cls._is_external_source(item)]

    @staticmethod
    def _is_external_source(source: dict[str, Any]) -> bool:
        """Distingue IPC/URI de valores digitados na própria interface."""
        source_kind = source.get("source_kind")
        if source_kind in USER_INTERFACE_SOURCE_KINDS:
            return False
        if source.get("kind") == "entry_point_parameter":
            return True
        # Catálogos anteriores não informavam source_kind. Mantemos esses
        # registros como externos para preservar compatibilidade.
        return source_kind is None or bool(source_kind)

    @staticmethod
    def _meaningful_sensitive_evidence(
        evidence: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        return [
            item
            for item in evidence
            if item.get("category") == "sensitive_operation"
            and RiskCorrelator._is_meaningful_sensitive(item)
        ]

    @classmethod
    def _risk_relevant_sensitive_evidence(
        cls,
        entry_point: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Mantém apenas operações cujos argumentos justificam correlação."""
        result = []
        for item in evidence:
            classification = cls._argument_classification(entry_point, item)
            if classification in {CONSTANT, INTERFACE_TAINTED}:
                continue
            if item.get("operation_kind") in IPC_OPERATION_KINDS:
                transition = cls._ipc_transition_for_evidence(
                    entry_point,
                    item,
                )
                # Relatórios antigos não possuem o modelo IPC; mantemos a
                # compatibilidade somente nesse caso.
                if transition is not None and (
                    transition.get("selector_classification")
                    != EXTERNAL_TAINTED
                    or transition.get("explicit_internal_constant") is True
                ):
                    continue
            result.append(item)
        return result

    @classmethod
    def _argument_classification(
        cls,
        entry_point: dict[str, Any],
        evidence: dict[str, Any],
    ) -> str | None:
        data_flow = entry_point.get("data_flow_analysis") or {}
        assessments = data_flow.get("sensitive_argument_assessments", [])
        matching = [
            assessment
            for assessment in assessments
            if cls._sink_matches_evidence(assessment, evidence)
        ]
        if not matching:
            return None
        classifications = set()
        for assessment in matching:
            transition = assessment.get("ipc_transition")
            if isinstance(transition, dict):
                classifications.add(
                    transition.get("selector_classification", UNKNOWN)
                )
            else:
                classifications.add(
                    assessment.get("classification", UNKNOWN)
                )
        if EXTERNAL_TAINTED in classifications:
            return EXTERNAL_TAINTED
        if INTERFACE_TAINTED in classifications:
            return INTERFACE_TAINTED
        if classifications == {CONSTANT}:
            return CONSTANT
        return UNKNOWN

    @classmethod
    def _combined_argument_classification(
        cls,
        entry_point: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> str | None:
        classifications = {
            cls._argument_classification(entry_point, item)
            for item in evidence
        }
        classifications.discard(None)
        if not classifications:
            return None
        if EXTERNAL_TAINTED in classifications:
            return EXTERNAL_TAINTED
        if INTERFACE_TAINTED in classifications:
            return INTERFACE_TAINTED
        if classifications == {CONSTANT}:
            return CONSTANT
        return UNKNOWN

    @staticmethod
    def _is_meaningful_sensitive(evidence: dict[str, Any]) -> bool:
        if "risk_relevant" in evidence:
            return evidence.get("risk_relevant") is True
        return evidence.get("api") in MEANINGFUL_SENSITIVE_APIS

    @staticmethod
    def _only_observable_operations(
        evidence: list[dict[str, Any]],
    ) -> bool:
        return bool(evidence) and all(
            item.get("operation_kind") == "observable_output"
            or item.get("api") in OBSERVABLE_APIS
            for item in evidence
        )

    def _unprotected_component_candidate(
        self,
        component: dict[str, Any],
        entry_point: dict[str, Any],
        sensitive: list[dict[str, Any]],
    ) -> dict[str, Any]:
        argument_classification = self._combined_argument_classification(
            entry_point,
            sensitive,
        )
        severity = self._operation_severity(
            sensitive,
            component.get("type"),
            argument_classification=argument_classification,
        )
        confidence = self._reachability_confidence(
            entry_point,
            sensitive,
        )
        apis = self._unique_apis(sensitive)
        return self._base_candidate(
            rule_id="RISK-CODE-001",
            title="Componente exportado alcança operação sem proteção identificada",
            severity=severity,
            confidence=confidence,
            component=component,
            entry_point=entry_point,
            reasons=[
                "O componente está habilitado e exportado.",
                "Nenhuma permissão de proteção foi identificada no componente ou na aplicação.",
                "Nenhuma validação conhecida do chamador foi encontrada no caminho analisado.",
                f"Operações alcançáveis: {', '.join(apis)}.",
            ],
            evidence=sensitive,
            recommendation=(
                "Restringir a exportação ou aplicar permissão adequada e validar "
                "explicitamente a identidade do chamador antes da operação."
            ),
            specific_limitations=self._graph_limitations(entry_point),
            extra={
                "correlation_basis": "static-reachability",
                "critical_argument_classification": argument_classification,
            },
        )

    def _unvalidated_uri_candidate(
        self,
        component: dict[str, Any],
        entry_point: dict[str, Any],
        uri_filters: list[dict[str, Any]],
        sensitive: list[dict[str, Any]],
    ) -> dict[str, Any]:
        patterns = sorted(
            {
                pattern
                for intent_filter in uri_filters
                for pattern in intent_filter.get("uri_patterns", [])
            }
        )
        argument_classification = self._combined_argument_classification(
            entry_point,
            sensitive,
        )
        severity = self._operation_severity(
            sensitive,
            component.get("type"),
            argument_classification=argument_classification,
        )
        if severity == "low":
            severity = "medium"
        reasons = [
            "O componente possui filtro de URI acionável por Intent compatível.",
            "Nenhuma leitura e validação conhecida de scheme ou host foi encontrada.",
            f"Operações alcançáveis: {', '.join(self._unique_apis(sensitive))}.",
        ]
        if patterns:
            reasons.insert(1, f"Padrões declarados: {', '.join(patterns)}.")

        return self._base_candidate(
            rule_id="RISK-URI-001",
            title="Filtro de URI aciona operação sem validação identificada",
            severity=severity,
            confidence=self._reachability_confidence(
                entry_point,
                sensitive,
            ),
            component=component,
            entry_point=entry_point,
            reasons=reasons,
            evidence=sensitive,
            recommendation=(
                "Validar scheme, host, caminho e parâmetros recebidos antes de "
                "executar ações; preferir App Links verificados quando aplicável."
            ),
            specific_limitations=self._graph_limitations(entry_point),
            extra={
                "uri_patterns": patterns,
                "correlation_basis": "uri-context",
                "critical_argument_classification": argument_classification,
            },
        )

    def _source_and_sink_candidate(
        self,
        component: dict[str, Any],
        entry_point: dict[str, Any],
        sources: list[dict[str, Any]],
        interface_sources: list[dict[str, Any]],
        validations: list[dict[str, Any]],
        sensitive: list[dict[str, Any]],
        confirmed_flows: list[dict[str, Any]],
    ) -> dict[str, Any]:
        flow_sources = [
            source
            for flow in confirmed_flows
            for source in flow.get("sources", [])
        ]
        external_flow_sources = [
            source for source in flow_sources if self._is_external_source(source)
        ]
        interface_flow_sources = [
            source for source in flow_sources if not self._is_external_source(source)
        ]
        flow_source_apis = sorted(
            {
                source.get("api")
                for source in external_flow_sources
                if source.get("api")
            }
        )
        source_apis = sorted(
            set(self._unique_apis(sources)) | set(flow_source_apis)
        )
        interface_source_apis = self._unique_apis(interface_sources)
        interface_source_apis = sorted(
            set(interface_source_apis)
            | {
                source["api"]
                for source in interface_flow_sources
                if source.get("api")
            }
        )
        confirmed_sensitive = [
            item
            for item in sensitive
            if any(
                self._sink_matches_evidence(flow.get("sink") or {}, item)
                for flow in confirmed_flows
            )
        ]
        risk_sensitive = confirmed_sensitive if confirmed_flows else sensitive
        sensitive_apis = self._unique_apis(risk_sensitive)
        reachable_sensitive_apis = self._unique_apis(sensitive)
        argument_classification = (
            EXTERNAL_TAINTED
            if confirmed_flows
            else self._combined_argument_classification(
                entry_point,
                risk_sensitive,
            )
        )
        storage_flows = [
            flow
            for flow in confirmed_flows
            if flow.get("storage_propagation")
            or flow.get("tracking_precision")
            in {
                "field-or-array-dependency",
                "approximate-object-propagation",
            }
        ]
        if confirmed_flows:
            unvalidated_flows = [
                flow
                for flow in confirmed_flows
                if flow.get("status") == "confirmed-unvalidated"
            ]
            reasons = [
                f"Fontes externas rastreadas: {', '.join(source_apis)}.",
                f"Operações alcançadas pelo valor: {', '.join(sensitive_apis)}.",
                (
                    "O rastreamento confirmou dependência entre registradores "
                    f"em {len(confirmed_flows)} fluxo(s)."
                ),
            ]
            if storage_flows:
                reasons.append(
                    "O fluxo indireto foi preservado por campo de objeto, "
                    "campo estático, array ou captura de callback."
                )
            if unvalidated_flows:
                reasons.append(
                    "Há fluxo confirmado sem possível validação no caminho textual rastreado."
                )
            else:
                reasons.append(
                    "Todos os fluxos confirmados passaram por ao menos uma possível validação."
                )
            title = "Dado externo alcança operação sensível"
            confidence = "high" if unvalidated_flows else "medium"
            confidence = self._cap_confidence(
                confidence,
                self._flow_confidence_limit(confirmed_flows),
            )
            limitations = [
                *self._graph_limitations(entry_point),
                "O fluxo de registradores não comprova exploração prática.",
                "A eficácia das possíveis validações exige revisão manual.",
            ]
        else:
            reasons = [
                f"Fontes externas no subgrafo: {', '.join(source_apis)}.",
                f"Operações sensíveis no subgrafo: {', '.join(sensitive_apis)}.",
                "O mesmo fluxo entre fonte e operação não foi confirmado.",
            ]
            if validations:
                reasons.append(
                    "Foram encontradas possíveis validações, mas sua eficácia ainda não foi confirmada."
                )
            else:
                reasons.append(
                    "Nenhuma possível validação foi encontrada no subgrafo."
                )
            title = "Fonte externa e operação sensível no mesmo subgrafo"
            confidence = "low"
            limitations = [
                *self._graph_limitations(entry_point),
                "O fluxo entre fonte e operação ainda não foi confirmado.",
            ]

        combined_evidence = [*sources, *risk_sensitive]
        return self._base_candidate(
            rule_id="RISK-FLOW-001",
            title=title,
            severity=self._operation_severity(
                risk_sensitive,
                component.get("type"),
                confirmed_taint=bool(confirmed_flows),
                argument_classification=argument_classification,
            ),
            confidence=confidence,
            component=component,
            entry_point=entry_point,
            reasons=reasons,
            evidence=combined_evidence,
            recommendation=(
                "Rastrear os registradores da fonte até a operação e confirmar se "
                "uma validação domina todos os caminhos possíveis."
            ),
            specific_limitations=limitations,
            extra={
                "source_apis": source_apis,
                "sensitive_apis": sensitive_apis,
                "reachable_sensitive_apis": reachable_sensitive_apis,
                "possible_validation_apis": self._unique_apis(validations),
                "confirmed_flow_count": len(confirmed_flows),
                "indirect_storage_flow_count": len(storage_flows),
                "critical_argument_classification": argument_classification,
                "flow_tracking_precisions": sorted(
                    {
                        flow.get("tracking_precision")
                        for flow in confirmed_flows
                        if flow.get("tracking_precision")
                    }
                ),
                "external_source_apis": source_apis,
                "interface_source_apis": interface_source_apis,
                "source_profile": {
                    "external_count": self._unique_source_count(
                        [*sources, *external_flow_sources]
                    ),
                    "interface_count": self._unique_source_count(
                        [*interface_sources, *interface_flow_sources]
                    ),
                    "external_kinds": self._source_kinds(
                        [*sources, *external_flow_sources]
                    ),
                    "interface_kinds": self._source_kinds(
                        [*interface_sources, *interface_flow_sources]
                    ),
                },
                "correlation_basis": (
                    "confirmed-data-flow"
                    if confirmed_flows
                    else "source-sink-co-occurrence"
                ),
            },
        )

    @classmethod
    def _consolidate_entry_point_candidates(
        cls,
        candidates: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        """Emite um único candidato por componente e entry point.

        As regras secundárias continuam registradas em contributing_rule_ids,
        mas fluxo confirmado prevalece sobre URI, coocorrência e alcance.
        """
        if not candidates:
            return None

        primary = max(candidates, key=cls._candidate_precedence)
        ordered = [primary, *(item for item in candidates if item is not primary)]
        primary["contributing_rule_ids"] = list(
            dict.fromkeys(item["rule_id"] for item in ordered)
        )
        primary["merged_candidate_count"] = len(candidates)
        primary["reasons"] = cls._unique_strings(
            reason for item in ordered for reason in item.get("reasons", [])
        )
        primary["limitations"] = cls._unique_strings(
            limitation
            for item in ordered
            for limitation in item.get("limitations", [])
        )
        primary["evidence"] = cls._unique_evidence(
            evidence
            for item in ordered
            for evidence in item.get("evidence", [])
        )
        additional_recommendations = cls._unique_strings(
            item.get("recommendation")
            for item in ordered[1:]
            if item.get("recommendation")
            and item.get("recommendation") != primary.get("recommendation")
        )
        if additional_recommendations:
            primary["additional_recommendations"] = additional_recommendations
        return primary

    @staticmethod
    def _candidate_precedence(candidate: dict[str, Any]) -> tuple[int, int]:
        basis = candidate.get("correlation_basis")
        priority = {
            "confirmed-data-flow": 4,
            "uri-context": 3,
            "source-sink-co-occurrence": 2,
            "static-reachability": 1,
        }.get(basis, 0)
        return priority, -SEVERITY_ORDER.get(candidate.get("severity"), 99)

    @staticmethod
    def _unique_strings(values: Any) -> list[str]:
        return list(dict.fromkeys(value for value in values if value))

    @staticmethod
    def _unique_evidence(values: Any) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for item in values:
            key = (
                item.get("rule_id"),
                item.get("api"),
                item.get("smali_path"),
                item.get("method_signature"),
                item.get("line"),
                item.get("instruction"),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    @staticmethod
    def _unique_source_count(sources: list[dict[str, Any]]) -> int:
        return len(
            {
                (
                    source.get("api"),
                    source.get("source_kind") or source.get("kind"),
                    source.get("smali_path"),
                    source.get("line"),
                    source.get("register"),
                )
                for source in sources
            }
        )

    @staticmethod
    def _source_kinds(sources: list[dict[str, Any]]) -> list[str]:
        return sorted(
            {
                source.get("source_kind") or source.get("kind") or "legacy-unknown"
                for source in sources
            }
        )

    @staticmethod
    def _base_candidate(
        rule_id: str,
        title: str,
        severity: str,
        confidence: str,
        component: dict[str, Any],
        entry_point: dict[str, Any],
        reasons: list[str],
        evidence: list[dict[str, Any]],
        recommendation: str,
        specific_limitations: list[str],
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = {
            "candidate_id": None,
            "rule_id": rule_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "assessment": "candidate",
            "definitive_verdict": False,
            "component": component.get("name"),
            "component_type": component.get("type"),
            "entry_point": entry_point.get("signature"),
            "analysis_priority": entry_point.get("analysis_priority"),
            "exported_source": component.get("exported_source"),
            "permission_assessment": component.get(
                "permission_assessment"
            ),
            "reasons": reasons,
            "evidence": [
                RiskCorrelator._evidence_reference(item)
                for item in evidence
            ],
            "recommendation": recommendation,
            "limitations": list(dict.fromkeys(specific_limitations)),
        }
        result.update(
            RiskCorrelator._data_flow_assessment(
                entry_point,
                evidence,
            )
        )
        ipc_transitions = RiskCorrelator._ipc_transitions_for_evidence(
            entry_point,
            evidence,
        )
        if ipc_transitions:
            result["ipc_transitions"] = ipc_transitions
        if extra:
            result.update(extra)
        return result

    @classmethod
    def _relevant_data_flows(
        cls,
        entry_point: dict[str, Any],
        sensitive: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        data_flow = entry_point.get("data_flow_analysis") or {}
        return [
            flow
            for flow in data_flow.get("flows", [])
            if cls._flow_reaches_sensitive_argument(flow)
            and cls._flow_has_external_source(flow)
            and any(
                cls._sink_matches_evidence(flow.get("sink") or {}, item)
                for item in sensitive
            )
        ]

    @staticmethod
    def _flow_reaches_sensitive_argument(flow: dict[str, Any]) -> bool:
        return bool(
            flow.get("tainted_registers_at_sink")
            or (flow.get("sink") or {}).get("tainted_registers")
        )

    @classmethod
    def _flow_has_external_source(cls, flow: dict[str, Any]) -> bool:
        return any(
            cls._is_external_source(source)
            for source in flow.get("sources", [])
        )

    @staticmethod
    def _sink_matches_evidence(
        sink: dict[str, Any],
        evidence: dict[str, Any],
    ) -> bool:
        if sink.get("api") != evidence.get("api"):
            return False
        comparable_fields = ("rule_id", "smali_path", "method_signature", "line")
        for field in comparable_fields:
            sink_value = sink.get(field)
            evidence_value = evidence.get(field)
            if (
                sink_value is not None
                and evidence_value is not None
                and sink_value != evidence_value
            ):
                return False
        return True

    @classmethod
    def _ipc_transition_for_evidence(
        cls,
        entry_point: dict[str, Any],
        evidence: dict[str, Any],
    ) -> dict[str, Any] | None:
        data_flow = entry_point.get("data_flow_analysis") or {}
        for assessment in data_flow.get("sensitive_argument_assessments", []):
            if not cls._sink_matches_evidence(assessment, evidence):
                continue
            transition = assessment.get("ipc_transition")
            if isinstance(transition, dict):
                return transition
        return None

    @classmethod
    def _ipc_transitions_for_evidence(
        cls,
        entry_point: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for item in evidence:
            transition = cls._ipc_transition_for_evidence(entry_point, item)
            if transition is None:
                continue
            key = (
                transition.get("smali_path"),
                transition.get("line"),
                transition.get("api"),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(transition)
        return result

    @classmethod
    def _data_flow_assessment(
        cls,
        entry_point: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        sensitive = [
            item
            for item in evidence
            if item.get("category") == "sensitive_operation"
            and cls._is_meaningful_sensitive(item)
        ]
        flows = cls._relevant_data_flows(
            entry_point,
            sensitive,
        )
        data_flow = entry_point.get("data_flow_analysis") or {}
        external_sources = cls._external_evidence_sources(
            [
                item
                for item in evidence
                if item.get("category") == "external_source"
            ]
        )

        if any(
            flow.get("status") == "confirmed-unvalidated"
            for flow in flows
        ):
            status = "confirmed-unvalidated"
        elif flows:
            status = "confirmed-with-possible-validation"
        elif data_flow.get("status") != "analyzed":
            status = "not-analyzed"
        elif external_sources:
            status = "source-and-operation-unconfirmed"
        else:
            status = "no-external-source"

        return {
            "data_flow_status": status,
            "data_flow_count": len(flows),
            "data_flow_ids": [
                flow.get("flow_id")
                for flow in flows
                if flow.get("flow_id")
            ],
        }

    @staticmethod
    def _evidence_reference(evidence: dict[str, Any]) -> dict[str, Any]:
        fields = (
            "rule_id",
            "api",
            "category",
            "source_kind",
            "validation_kind",
            "operation_kind",
            "severity",
            "risk_relevant",
            "catalog_origin",
            "taint_behavior",
            "sensitive_arguments",
            "origin",
            "depth",
            "class_name",
            "method_signature",
            "smali_path",
            "line",
            "instruction",
            "call_chain",
        )
        return {
            field: evidence.get(field)
            for field in fields
            if field in evidence
        }

    @staticmethod
    def _operation_severity(
        evidence: list[dict[str, Any]],
        component_type: str | None,
        confirmed_taint: bool = False,
        argument_classification: str | None = None,
    ) -> str:
        apis = {item.get("api") for item in evidence}
        declared = {
            item.get("severity")
            for item in evidence
            if item.get("severity")
        }
        if "high" in declared or apis & HIGH_IMPACT_APIS:
            # Sem dado externo rastreado até um argumento sensível, a presença
            # da API comprova alcance, mas não injeção/manipulação de dados.
            if confirmed_taint:
                return "high"
            return "low" if argument_classification == UNKNOWN else "medium"
        if "medium" in declared or apis & MEDIUM_IMPACT_APIS:
            return "low" if argument_classification == UNKNOWN else "medium"
        if apis & OBSERVABLE_APIS and component_type == "receiver":
            return "medium"
        if "low" in declared:
            return "low"
        if "info" in declared:
            return "info"
        return "low"

    @staticmethod
    def _reachability_confidence(
        entry_point: dict[str, Any],
        sensitive: list[dict[str, Any]],
    ) -> str:
        call_graph = entry_point.get("call_graph") or {}
        incomplete = any(
            call_graph.get(field, 0)
            for field in (
                "unresolved_call_count",
                "truncated_call_count",
            )
        )
        only_observable = all(
            item.get("api") in OBSERVABLE_APIS
            for item in sensitive
        )
        return "medium" if incomplete or only_observable else "high"

    @staticmethod
    def _flow_confidence_limit(flows: list[dict[str, Any]]) -> str:
        confidences = [
            flow.get("confidence", "high")
            for flow in flows
        ]
        return min(
            confidences,
            key=lambda value: CONFIDENCE_ORDER.get(value, 0),
            default="low",
        )

    @staticmethod
    def _cap_confidence(confidence: str, limit: str) -> str:
        return min(
            (confidence, limit),
            key=lambda value: CONFIDENCE_ORDER.get(value, 0),
        )

    @staticmethod
    def _graph_limitations(entry_point: dict[str, Any]) -> list[str]:
        call_graph = entry_point.get("call_graph") or {}
        limitations = [
            "A alcançabilidade estática não comprova que a operação será executada em tempo real."
        ]
        if call_graph.get("unresolved_call_count"):
            limitations.append(
                "Há chamadas internas não resolvidas neste subgrafo."
            )
        if call_graph.get("truncated_call_count"):
            limitations.append(
                "Parte do subgrafo excedeu o limite de profundidade."
            )
        if call_graph.get("cycle_count"):
            limitations.append(
                "Ciclos foram interrompidos durante a travessia."
            )
        return limitations

    @staticmethod
    def _unique_apis(evidence: list[dict[str, Any]]) -> list[str]:
        return sorted(
            {
                item["api"]
                for item in evidence
                if item.get("api")
            }
        )

    @staticmethod
    def _launcher_only_navigation(
        component: dict[str, Any],
        sensitive: list[dict[str, Any]],
    ) -> bool:
        apis = {item.get("api") for item in sensitive}
        if not apis or not apis.issubset(
            {"startActivity", "Toast.makeText"}
        ):
            return False

        filters = component.get("intent_filters", [])
        if not filters:
            return False
        return all(
            "android.intent.action.MAIN" in intent_filter.get("actions", [])
            and "android.intent.category.LAUNCHER"
            in intent_filter.get("categories", [])
            and not intent_filter.get("is_uri_intent")
            for intent_filter in filters
        )

    @staticmethod
    def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
        priority = candidate.get("analysis_priority")
        return (
            priority is None,
            priority or 0,
            SEVERITY_ORDER.get(candidate.get("severity"), 99),
            candidate.get("rule_id", ""),
            candidate.get("component", ""),
        )
