"""Geração de relatório HTML autocontido para revisão dos resultados."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any


SEVERITY_LABELS = {
    "high": "Alto",
    "medium": "Médio",
    "low": "Baixo",
    "info": "Informativo",
}
CONFIDENCE_LABELS = {
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
}
DATA_FLOW_LABELS = {
    "confirmed-unvalidated": "Fluxo confirmado sem possível validação",
    "confirmed-with-possible-validation": (
        "Fluxo confirmado com possível validação"
    ),
    "source-and-operation-unconfirmed": (
        "Fonte e operação presentes; fluxo não confirmado"
    ),
    "source-and-sink-unconfirmed": (
        "Fonte e operação presentes; fluxo não confirmado"
    ),
    "no-external-source": "Nenhuma fonte externa identificada",
    "not-analyzed": "Fluxo não analisado",
}
CORRELATION_LABELS = {
    "confirmed-data-flow": "Fluxo de dados confirmado",
    "uri-context": "Contexto de URI",
    "source-sink-co-occurrence": "Fonte e operação no mesmo subgrafo",
    "static-reachability": "Alcançabilidade estática",
}
ARGUMENT_CLASSIFICATION_LABELS = {
    "external-tainted": "Contaminado externamente",
    "interface-tainted": "Contaminado pela interface",
    "constant": "Constante comprovada",
    "unknown": "Desconhecido",
}

CWE_REFERENCES = {
    "CWE-20": {
        "title": "Improper Input Validation",
        "url": "https://cwe.mitre.org/data/definitions/20.html",
    },
    "CWE-319": {
        "title": "Cleartext Transmission of Sensitive Information",
        "url": "https://cwe.mitre.org/data/definitions/319.html",
    },
    "CWE-489": {
        "title": "Active Debug Code",
        "url": "https://cwe.mitre.org/data/definitions/489.html",
    },
    "CWE-732": {
        "title": "Incorrect Permission Assignment for Critical Resource",
        "url": "https://cwe.mitre.org/data/definitions/732.html",
    },
    "CWE-926": {
        "title": "Improper Export of Android Application Components",
        "url": "https://cwe.mitre.org/data/definitions/926.html",
    },
    "CWE-939": {
        "title": "Improper Authorization in Handler for Custom URL Scheme",
        "url": "https://cwe.mitre.org/data/definitions/939.html",
    },
}

MASVS_URL = "https://mas.owasp.org/MASVS/"

RULE_MAPPINGS = {
    "APP-DEBUG-001": ("CWE-489", "MASVS-RESILIENCE"),
    "MANIFEST-001": ("CWE-926", "MASVS-PLATFORM"),
    "COMPONENT-001": ("CWE-926", "MASVS-PLATFORM"),
    "COMPONENT-002": ("CWE-732", "MASVS-PLATFORM"),
    "PROVIDER-001": ("CWE-926", "MASVS-PLATFORM"),
    "DEEPLINK-001": ("CWE-939", "MASVS-PLATFORM"),
    "DEEPLINK-002": ("CWE-939", "MASVS-PLATFORM"),
    "DEEPLINK-003": ("CWE-319", "MASVS-NETWORK"),
    "DEEPLINK-004": ("CWE-939", "MASVS-PLATFORM"),
    "DEEPLINK-005": ("CWE-20", "MASVS-PLATFORM"),
    "DEEPLINK-006": ("CWE-20", "MASVS-PLATFORM"),
    "URI-INFO-001": ("CWE-939", "MASVS-PLATFORM"),
    "RISK-CODE-001": ("CWE-926", "MASVS-PLATFORM"),
    "RISK-URI-001": ("CWE-939", "MASVS-PLATFORM"),
    "RISK-FLOW-001": ("CWE-20", "MASVS-CODE"),
}


class ReportGenerator:
    """Transforma a estrutura de análise em um HTML legível e imprimível."""

    def __init__(self, generated_at: datetime | None = None) -> None:
        self.generated_at = generated_at or datetime.now(timezone.utc)

    def generate(
        self,
        analysis: dict[str, Any],
        output_path: str | Path,
    ) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self.render(analysis),
            encoding="utf-8",
        )
        return output_path

    def render(self, analysis: dict[str, Any]) -> str:
        summary = analysis.get("summary", {})
        package = analysis.get("package") or "Pacote não identificado"
        generated = self.generated_at.astimezone(timezone.utc).strftime(
            "%d/%m/%Y %H:%M UTC"
        )
        title = f"Relatório de análise estática — {package}"

        sections = [
            self._header(analysis, title, generated),
            self._executive_summary(summary),
            self._scope(analysis),
            self._risk_candidates(analysis),
            self._manifest_findings(analysis),
            self._exported_components(analysis),
            self._data_flow(analysis),
            self._ipc_transitions(analysis),
            self._limitations(analysis),
        ]
        return "".join(
            [
                "<!doctype html><html lang=\"pt-BR\"><head>",
                "<meta charset=\"utf-8\">",
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
                f"<title>{escape(title)}</title>",
                f"<style>{self._css()}</style>",
                "</head><body><main class=\"container\">",
                *sections,
                "<footer>Relatório produzido pela SMALIRIS. "
                "Confirme os candidatos por revisão manual e testes autorizados.</footer>",
                "</main></body></html>",
            ]
        )

    def _header(
        self,
        analysis: dict[str, Any],
        title: str,
        generated: str,
    ) -> str:
        return "".join(
            [
                "<header class=\"hero\">",
                "<div><p class=\"eyebrow\">SMALIRIS · Analisador estático de APK</p>",
                f"<h1>{escape(title)}</h1>",
                f"<p>Gerado em {escape(generated)} · Schema "
                f"{escape(str(analysis.get('schema_version', '—')))}</p></div>",
                "<span class=\"verdict\">Candidatos, não vereditos</span>",
                "</header>",
                "<div class=\"notice\"><strong>Como interpretar:</strong> "
                "a ferramenta identifica exposição, evidências alcançáveis e "
                "dependências entre registradores. Nenhum item comprova "
                "exploração prática de forma isolada.</div>",
            ]
        )

    def _executive_summary(self, summary: dict[str, Any]) -> str:
        cards = (
            ("Componentes", summary.get("component_count", 0)),
            ("Exportados", summary.get("exported_component_count", 0)),
            ("Achados do Manifesto", summary.get("finding_count", 0)),
            ("Candidatos de risco", summary.get("risk_candidate_count", 0)),
            ("Evidências no código", summary.get("code_evidence_count", 0)),
            ("Fontes de entrada", summary.get("code_input_source_count", 0)),
            ("Fluxos confirmados", summary.get("data_flow_confirmed_count", 0)),
            ("Transições IPC", summary.get("ipc_transition_count", 0)),
        )
        card_html = "".join(
            "<article class=\"metric\">"
            f"<strong>{escape(str(value))}</strong><span>{escape(label)}</span>"
            "</article>"
            for label, value in cards
        )
        risk_counts = summary.get("risk_candidates_by_severity", {})
        finding_counts = summary.get("findings_by_severity", {})
        return "".join(
            [
                self._section_title("Resumo executivo", "Visão geral da análise"),
                f"<div class=\"metrics\">{card_html}</div>",
                "<div class=\"grid two\">",
                self._severity_panel("Candidatos por severidade", risk_counts),
                self._severity_panel("Achados por severidade", finding_counts),
                "</div></section>",
            ]
        )

    def _scope(self, analysis: dict[str, Any]) -> str:
        sdk = analysis.get("sdk", {})
        source = sdk.get("source", {})
        catalog = analysis.get("api_catalog", {})
        reproducibility = analysis.get("reproducibility", {})
        rows = (
            ("APK", analysis.get("apk_path") or "—"),
            ("SHA-256 do APK", reproducibility.get("apk_sha256") or "—"),
            ("Manifesto", analysis.get("manifest_path") or "—"),
            ("Pacote", analysis.get("package") or "—"),
            (
                "SDK mínimo",
                f"{sdk.get('min', '—')} ({source.get('min', 'origem desconhecida')})",
            ),
            (
                "SDK alvo",
                f"{sdk.get('target', '—')} ({source.get('target', 'origem desconhecida')})",
            ),
            (
                "Profundidade do grafo",
                reproducibility.get("max_call_depth", "—"),
            ),
            ("Versão da SMALIRIS", reproducibility.get("tool_version", "—")),
            ("Versão do Apktool", reproducibility.get("apktool_version") or "—"),
            (
                "Catálogo de APIs",
                (
                    f"{catalog.get('catalog_version', '—')} · "
                    f"{catalog.get('rule_count', 0)} regras"
                ),
            ),
            (
                "Duração da descompilação",
                f"{reproducibility.get('decompilation_duration_seconds', '—')} s",
            ),
            (
                "Duração da análise",
                f"{reproducibility.get('analysis_duration_seconds', '—')} s",
            ),
            (
                "Chamadas truncadas",
                reproducibility.get("truncated_call_count", 0),
            ),
        )
        body = "".join(
            "<tr>"
            f"<th>{escape(str(label))}</th><td>{escape(str(value))}</td>"
            "</tr>"
            for label, value in rows
        )
        return "".join(
            [
                self._section_title("Escopo", "Arquivos e parâmetros utilizados"),
                f"<div class=\"table-wrap\"><table><tbody>{body}</tbody></table></div>",
                "</section>",
            ]
        )

    def _risk_candidates(self, analysis: dict[str, Any]) -> str:
        candidates = analysis.get("risk_analysis", {}).get("candidates", [])
        content = [
            self._section_title(
                "Candidatos de risco",
                "Correlação entre Manifesto, código e fluxo de dados",
                section_id="risk-candidates",
            )
        ]
        if not candidates:
            content.append(self._empty("Nenhum candidato de risco foi gerado."))
        else:
            content.extend(self._candidate_card(item) for item in candidates)
        content.append("</section>")
        return "".join(content)

    def _candidate_card(self, candidate: dict[str, Any]) -> str:
        severity = candidate.get("severity", "info")
        confidence = candidate.get("confidence", "low")
        candidate_id = candidate.get("candidate_id") or "Sem identificador"
        reasons = self._list(candidate.get("reasons", []))
        recommendations = self._list(
            [
                candidate.get("recommendation"),
                *candidate.get("additional_recommendations", []),
            ]
        )
        limitations = self._list(candidate.get("limitations", []))
        evidence = self._evidence_table(candidate.get("evidence", []))
        mapping = self._mapping(candidate.get("rule_id"))
        data_flow_status = candidate.get("data_flow_status", "not-analyzed")
        flow_ids = candidate.get("data_flow_ids", [])
        flow_details = (
            f" · Fluxos: {', '.join(escape(str(item)) for item in flow_ids)}"
            if flow_ids
            else ""
        )
        contributing_rules = candidate.get("contributing_rule_ids", [])
        consolidation_details = (
            " · Regras correlacionadas: "
            + ", ".join(escape(str(item)) for item in contributing_rules)
            if len(contributing_rules) > 1
            else ""
        )
        correlation_basis = candidate.get("correlation_basis")
        argument_classification = candidate.get(
            "critical_argument_classification"
        )
        return "".join(
            [
                f"<article class=\"finding severity-{escape(severity)}\">",
                "<div class=\"finding-head\"><div>",
                f"<p class=\"rule\">{escape(str(candidate_id))} · "
                f"{escape(str(candidate.get('rule_id', '—')))}</p>",
                f"<h3>{escape(str(candidate.get('title', 'Candidato sem título')))}</h3>",
                "</div><div class=\"badges\">",
                self._severity_badge(severity),
                self._badge(
                    f"Confiança {CONFIDENCE_LABELS.get(confidence, confidence)}",
                    "neutral",
                ),
                "</div></div>",
                "<div class=\"metadata\">",
                self._meta("Componente", candidate.get("component")),
                self._meta("Tipo", candidate.get("component_type")),
                self._meta("Entry point", candidate.get("entry_point")),
                self._meta(
                    "Base",
                    CORRELATION_LABELS.get(correlation_basis, correlation_basis),
                ),
                self._meta(
                    "Argumento crítico",
                    ARGUMENT_CLASSIFICATION_LABELS.get(
                        argument_classification,
                        argument_classification,
                    ),
                ),
                "</div>",
                f"<p class=\"flow-status\"><strong>Fluxo:</strong> "
                f"{escape(DATA_FLOW_LABELS.get(data_flow_status, data_flow_status))}"
                f"{flow_details}{consolidation_details}</p>",
                mapping,
                "<div class=\"grid two details-grid\">",
                f"<div><h4>Motivos</h4>{reasons}</div>",
                f"<div><h4>Recomendações</h4>{recommendations}</div>",
                "</div>",
                f"<details><summary>Evidências Smali ({len(candidate.get('evidence', []))})"
                f"</summary>{evidence}</details>",
                f"<details><summary>Limitações</summary>{limitations}</details>",
                "</article>",
            ]
        )

    def _manifest_findings(self, analysis: dict[str, Any]) -> str:
        findings = analysis.get("findings", [])
        content = [
            self._section_title(
                "Achados do Manifesto",
                "Configurações e informações que merecem revisão",
            )
        ]
        if not findings:
            content.append(self._empty("Nenhum achado foi registrado."))
        else:
            for finding in findings:
                severity = finding.get("severity", "info")
                confidence = finding.get("confidence", "low")
                content.append(
                    "".join(
                        [
                            f"<article class=\"finding compact severity-{escape(severity)}\">",
                            "<div class=\"finding-head\"><div>",
                            f"<p class=\"rule\">{escape(str(finding.get('rule_id', '—')))}</p>",
                            f"<h3>{escape(str(finding.get('title', 'Achado sem título')))}</h3>",
                            "</div><div class=\"badges\">",
                            self._severity_badge(severity),
                            self._badge(
                                f"Confiança {CONFIDENCE_LABELS.get(confidence, confidence)}",
                                "neutral",
                            ),
                            "</div></div>",
                            "<div class=\"metadata\">",
                            self._meta("Componente", finding.get("component")),
                            self._meta("Tipo", finding.get("component_type")),
                            "</div>",
                            self._mapping(finding.get("rule_id")),
                            "<div class=\"grid two details-grid\">",
                            "<div><h4>Evidência</h4>"
                            f"<p>{escape(str(finding.get('evidence', '—')))}</p></div>",
                            "<div><h4>Recomendação</h4>"
                            f"<p>{escape(str(finding.get('recommendation', '—')))}</p></div>",
                            "</div></article>",
                        ]
                    )
                )
        content.append("</section>")
        return "".join(content)

    def _exported_components(self, analysis: dict[str, Any]) -> str:
        components = [
            component
            for component in analysis.get("components", [])
            if component.get("exported") is True
        ]
        rows = []
        for component in components:
            uri_patterns = [
                pattern
                for intent_filter in component.get("intent_filters", [])
                for pattern in intent_filter.get("uri_patterns", [])
            ]
            permission = (
                component.get("permission")
                or component.get("read_permission")
                or component.get("write_permission")
                or "Ausente"
            )
            smali = component.get("smali") or {}
            code = component.get("code_analysis") or {}
            rows.append(
                "<tr>"
                f"<td><code>{escape(str(component.get('name', '—')))}</code></td>"
                f"<td>{escape(str(component.get('type', '—')))}</td>"
                f"<td>{escape(str(component.get('exported_source', '—')))}</td>"
                f"<td>{escape(str(permission))}</td>"
                f"<td>{escape(', '.join(uri_patterns) if uri_patterns else '—')}</td>"
                f"<td>{escape('Encontrado' if smali.get('found') else 'Ausente')}</td>"
                f"<td>{escape(str(code.get('status', '—')))}</td>"
                "</tr>"
            )
        table = self._table(
            (
                "Componente",
                "Tipo",
                "Origem da exportação",
                "Permissão",
                "URIs",
                "Smali",
                "Código",
            ),
            rows,
        )
        return "".join(
            [
                self._section_title(
                    "Componentes exportados",
                    "Superfície de entrada identificada no Manifesto",
                ),
                table if rows else self._empty("Nenhum componente exportado."),
                "</section>",
            ]
        )

    def _data_flow(self, analysis: dict[str, Any]) -> str:
        summary = analysis.get("data_flow_analysis", {})
        rows = []
        for component in analysis.get("components", []):
            for entry_point in component.get("code_analysis", {}).get(
                "entry_points",
                [],
            ):
                flow = entry_point.get("data_flow_analysis") or {}
                status = flow.get("data_flow_status", "not-analyzed")
                argument_counts = flow.get(
                    "argument_classification_counts",
                    {},
                )
                argument_summary = ", ".join(
                    f"{ARGUMENT_CLASSIFICATION_LABELS[key]}: {value}"
                    for key, value in argument_counts.items()
                    if value and key in ARGUMENT_CLASSIFICATION_LABELS
                ) or "—"
                rows.append(
                    "<tr>"
                    f"<td><code>{escape(str(component.get('name', '—')))}</code></td>"
                    f"<td><code>{escape(str(entry_point.get('signature', '—')))}</code></td>"
                    f"<td>{escape(DATA_FLOW_LABELS.get(status, status))}</td>"
                    f"<td>{escape(str(flow.get('source_count', 0)))}</td>"
                    f"<td>{escape(str(flow.get('touched_validation_count', 0)))}</td>"
                    f"<td>{escape(str(flow.get('flow_count', 0)))}</td>"
                    f"<td>{escape(argument_summary)}</td>"
                    "</tr>"
                )
        cards = (
            ("Métodos analisados", summary.get("analyzed_method_count", 0)),
            ("Fluxos confirmados", summary.get("confirmed_flow_count", 0)),
            ("Sem possível validação", summary.get("unvalidated_flow_count", 0)),
            ("Com possível validação", summary.get("validated_flow_count", 0)),
        )
        card_html = "".join(
            "<article class=\"metric small\">"
            f"<strong>{escape(str(value))}</strong><span>{escape(label)}</span>"
            "</article>"
            for label, value in cards
        )
        return "".join(
            [
                self._section_title(
                    "Fluxo de dados",
                    "Rastreamento conservador de registradores Smali",
                ),
                f"<div class=\"metrics compact-metrics\">{card_html}</div>",
                self._table(
                    (
                        "Componente",
                        "Entry point",
                        "Situação",
                        "Fontes",
                        "Validações tocadas",
                        "Fluxos",
                        "Argumentos críticos",
                    ),
                    rows,
                )
                if rows
                else self._empty("Nenhum entry point teve fluxo analisado."),
                "</section>",
            ]
        )

    def _ipc_transitions(self, analysis: dict[str, Any]) -> str:
        transitions = analysis.get("data_flow_analysis", {}).get(
            "ipc_transitions",
            [],
        )
        rows = []
        for transition in transitions:
            destinations = (
                transition.get("destination_components")
                or transition.get("destination_candidates")
                or transition.get("destination_values")
                or []
            )
            internal = transition.get("destination_internal")
            internal_label = (
                "Sim" if internal is True else "Não" if internal is False else "Indeterminado"
            )
            rows.append(
                "<tr>"
                f"<td>{escape(str(transition.get('transition_id') or '—'))}</td>"
                f"<td><code>{escape(str(transition.get('source_component') or '—'))}</code></td>"
                f"<td>{escape(str(transition.get('api') or '—'))}</td>"
                f"<td>{escape(str(transition.get('intent_kind') or 'unknown'))}</td>"
                f"<td>{escape(ARGUMENT_CLASSIFICATION_LABELS.get(transition.get('selector_classification'), str(transition.get('selector_classification') or '—')))}</td>"
                f"<td>{escape(', '.join(str(item) for item in destinations) or '—')}</td>"
                f"<td>{escape(internal_label)}</td>"
                "</tr>"
            )
        return "".join(
            [
                self._section_title(
                    "Transições IPC",
                    "Intents enviados entre atividades, serviços e receivers",
                ),
                self._table(
                    (
                        "ID",
                        "Origem",
                        "API",
                        "Intent",
                        "Seletor",
                        "Destino",
                        "Interno",
                    ),
                    rows,
                )
                if rows
                else self._empty("Nenhuma transição IPC foi identificada."),
                "</section>",
            ]
        )

    def _limitations(self, analysis: dict[str, Any]) -> str:
        values = list(analysis.get("limitations", []))
        values.extend(
            analysis.get("data_flow_analysis", {}).get("limitations", [])
        )
        values.extend(
            analysis.get("risk_analysis", {}).get("limitations", [])
        )
        unique_values = list(dict.fromkeys(str(item) for item in values))
        return "".join(
            [
                self._section_title(
                    "Limitações gerais",
                    "Condições que devem acompanhar a interpretação",
                ),
                self._list(unique_values),
                "<p class=\"standards-note\">As associações CWE e OWASP MASVS "
                "são referências de triagem baseadas na natureza da regra; não "
                "substituem classificação manual da causa raiz.</p>",
                "</section>",
            ]
        )

    def _mapping(self, rule_id: Any) -> str:
        mapping = RULE_MAPPINGS.get(str(rule_id))
        if mapping is None:
            return "<p class=\"mapping\"><strong>Referências:</strong> não associadas automaticamente.</p>"
        cwe_id, masvs_group = mapping
        cwe = CWE_REFERENCES[cwe_id]
        return "".join(
            [
                "<p class=\"mapping\"><strong>Possível associação:</strong> ",
                f"<a href=\"{escape(cwe['url'])}\" target=\"_blank\" rel=\"noreferrer\">"
                f"{escape(cwe_id)} · {escape(cwe['title'])}</a>",
                " · ",
                f"<a href=\"{MASVS_URL}\" target=\"_blank\" rel=\"noreferrer\">"
                f"OWASP {escape(masvs_group)}</a></p>",
            ]
        )

    @staticmethod
    def _section_title(
        title: str,
        subtitle: str,
        section_id: str | None = None,
    ) -> str:
        id_attribute = f" id=\"{escape(section_id)}\"" if section_id else ""
        return (
            f"<section{id_attribute}><div class=\"section-title\">"
            f"<div><p class=\"eyebrow\">{escape(subtitle)}</p>"
            f"<h2>{escape(title)}</h2></div></div>"
        )

    @staticmethod
    def _severity_panel(title: str, counts: dict[str, Any]) -> str:
        rows = "".join(
            "<div class=\"severity-row\">"
            f"<span class=\"dot {escape(severity)}\"></span>"
            f"<span>{escape(SEVERITY_LABELS[severity])}</span>"
            f"<strong>{escape(str(counts.get(severity, 0)))}</strong></div>"
            for severity in ("high", "medium", "low", "info")
        )
        return f"<article class=\"panel\"><h3>{escape(title)}</h3>{rows}</article>"

    @staticmethod
    def _severity_badge(severity: str) -> str:
        label = SEVERITY_LABELS.get(severity, severity)
        return ReportGenerator._badge(label, severity)

    @staticmethod
    def _badge(label: str, css_class: str) -> str:
        return (
            f"<span class=\"badge badge-{escape(css_class)}\">"
            f"{escape(label)}</span>"
        )

    @staticmethod
    def _meta(label: str, value: Any) -> str:
        return (
            "<span><strong>"
            f"{escape(label)}:</strong> {escape(str(value or '—'))}</span>"
        )

    @staticmethod
    def _list(values: list[Any]) -> str:
        if not values:
            return "<p>—</p>"
        return "<ul>" + "".join(
            f"<li>{escape(str(value))}</li>" for value in values
        ) + "</ul>"

    @staticmethod
    def _evidence_table(evidence: list[dict[str, Any]]) -> str:
        if not evidence:
            return ReportGenerator._empty("Nenhuma referência Smali disponível.")
        rows = []
        for item in evidence:
            path = item.get("smali_path") or "—"
            line = item.get("line")
            location = f"{path}:{line}" if line is not None else path
            origin = item.get("origin") or "—"
            if item.get("depth") is not None:
                origin = f"{origin} (profundidade {item['depth']})"
            rows.append(
                "<tr>"
                f"<td><code>{escape(str(item.get('api', '—')))}</code></td>"
                f"<td>{escape(str(item.get('category', '—')))}</td>"
                f"<td>{escape(str(origin))}</td>"
                f"<td><code>{escape(str(location))}</code></td>"
                f"<td><code class=\"instruction\">{escape(str(item.get('instruction', '—')))}</code></td>"
                "</tr>"
            )
        return ReportGenerator._table(
            ("API", "Categoria", "Origem", "Local", "Instrução"),
            rows,
        )

    @staticmethod
    def _table(headers: tuple[str, ...], rows: list[str]) -> str:
        header_html = "".join(f"<th>{escape(header)}</th>" for header in headers)
        return (
            "<div class=\"table-wrap\"><table><thead><tr>"
            f"{header_html}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        )

    @staticmethod
    def _empty(message: str) -> str:
        return f"<p class=\"empty\">{escape(message)}</p>"

    @staticmethod
    def _css() -> str:
        return """
:root{--bg:#f3f6fb;--surface:#fff;--ink:#172033;--muted:#637083;--line:#dbe2ea;--brand:#2357d9;--high:#c62828;--medium:#e86f00;--low:#b38600;--info:#1976a3}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}.container{width:min(1180px,calc(100% - 32px));margin:32px auto}.hero{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;padding:32px;border-radius:18px;background:linear-gradient(135deg,#17377c,#2357d9);color:#fff;box-shadow:0 16px 34px #17377c26}.hero h1{font-size:clamp(25px,4vw,40px);line-height:1.15;margin:4px 0 8px}.hero p{margin:0;color:#dce7ff}.eyebrow{text-transform:uppercase;letter-spacing:.09em;font-size:11px;font-weight:800;margin:0;color:var(--brand)}.hero .eyebrow{color:#bcd0ff}.verdict{white-space:nowrap;border:1px solid #ffffff55;background:#ffffff18;border-radius:999px;padding:8px 12px;font-weight:700}.notice{margin:18px 0 0;padding:14px 18px;border:1px solid #b9cdfd;border-left:5px solid var(--brand);border-radius:10px;background:#edf3ff}section{margin-top:28px;padding:26px;border:1px solid var(--line);border-radius:16px;background:var(--surface);box-shadow:0 8px 24px #1720330b}.section-title{display:flex;justify-content:space-between;align-items:end;margin-bottom:18px}.section-title h2{font-size:24px;margin:2px 0 0}.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}.metric{padding:18px;border:1px solid var(--line);border-radius:12px;background:#f9fbfe}.metric strong{display:block;font-size:28px;line-height:1.1}.metric span{display:block;color:var(--muted);margin-top:5px}.metric.small strong{font-size:22px}.compact-metrics{grid-template-columns:repeat(4,1fr);margin-bottom:18px}.grid.two{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}.panel{border:1px solid var(--line);border-radius:12px;padding:16px}.panel h3{margin:0 0 10px}.severity-row{display:grid;grid-template-columns:14px 1fr auto;gap:9px;align-items:center;padding:7px 0;border-bottom:1px solid #edf0f4}.severity-row:last-child{border-bottom:0}.dot{width:10px;height:10px;border-radius:50%}.dot.high{background:var(--high)}.dot.medium{background:var(--medium)}.dot.low{background:var(--low)}.dot.info{background:var(--info)}.finding{margin-top:16px;padding:20px;border:1px solid var(--line);border-left:6px solid var(--info);border-radius:12px;background:#fff}.finding.severity-high{border-left-color:var(--high)}.finding.severity-medium{border-left-color:var(--medium)}.finding.severity-low{border-left-color:var(--low)}.finding-head{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.finding h3{margin:2px 0 0;font-size:19px}.rule{margin:0;color:var(--muted);font:700 12px/1.4 ui-monospace,SFMono-Regular,Consolas,monospace}.badges{display:flex;flex-wrap:wrap;gap:7px;justify-content:flex-end}.badge{padding:5px 9px;border-radius:999px;font-size:12px;font-weight:800}.badge-high{background:#ffebee;color:#a81717}.badge-medium{background:#fff0df;color:#a54f00}.badge-low{background:#fff8d8;color:#755900}.badge-info{background:#e6f5fb;color:#0e668b}.badge-neutral{background:#eef1f5;color:#4e5969}.metadata{display:flex;flex-wrap:wrap;gap:8px 22px;margin:13px 0;color:var(--muted)}.mapping,.flow-status{margin:10px 0;padding:10px 12px;border-radius:8px;background:#f5f7fa}.mapping a{color:var(--brand);font-weight:700;text-decoration:none}.mapping a:hover{text-decoration:underline}.details-grid{margin-top:12px!important}.details-grid h4,details h4{margin:0 0 6px}.details-grid p{margin:0}.details-grid ul{margin-top:6px}details{margin-top:12px;padding:10px 12px;border:1px solid var(--line);border-radius:8px}summary{cursor:pointer;font-weight:750}ul{padding-left:20px}li+li{margin-top:5px}.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px}table{width:100%;border-collapse:collapse;min-width:680px}th,td{padding:11px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}th{background:#f0f4f9;font-size:12px;text-transform:uppercase;letter-spacing:.03em}tbody tr:last-child td,tbody tr:last-child th{border-bottom:0}code{font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}.instruction{white-space:pre-wrap;word-break:break-word}.empty{padding:20px;border:1px dashed var(--line);border-radius:10px;text-align:center;color:var(--muted)}.standards-note{margin-top:16px;color:var(--muted)}footer{padding:24px 6px;text-align:center;color:var(--muted)}
@media(max-width:900px){.metrics{grid-template-columns:repeat(3,1fr)}.grid.two{grid-template-columns:1fr}.hero{flex-direction:column}.verdict{white-space:normal}}
@media(max-width:560px){.container{width:min(100% - 18px,1180px);margin:10px auto}section,.hero{padding:18px}.metrics,.compact-metrics{grid-template-columns:repeat(2,1fr)}.finding-head{flex-direction:column}.badges{justify-content:flex-start}.metadata{display:grid;gap:5px}}
@media print{body{background:#fff}.container{width:100%;margin:0}.hero,section{box-shadow:none;break-inside:avoid}.finding{break-inside:avoid}details{break-inside:avoid}a{color:inherit;text-decoration:none}.notice{background:#fff}}
"""
