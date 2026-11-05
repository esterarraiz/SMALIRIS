"""Entrada de linha de comando da ferramenta."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tcc_analyzer import AnalysisPipeline, __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smaliris",
        description=(
            "SMALIRIS: descompila um APK e analisa componentes exportados, "
            "intent-filters, deep links e evidências alcançáveis em Smali."
        )
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"SMALIRIS {__version__}",
    )
    parser.add_argument(
        "apk",
        nargs="?",
        help="Caminho do arquivo APK. Se omitido, será solicitado no terminal.",
    )
    parser.add_argument(
        "--apktool",
        default="apktool",
        help="Executável ou caminho do Apktool (padrão: apktool).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output"),
        help="Diretório base para os resultados (padrão: output).",
    )
    parser.add_argument(
        "--no-force",
        action="store_true",
        help="Não passa -f ao Apktool.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Também exibe o JSON completo no terminal.",
    )
    parser.add_argument(
        "--max-call-depth",
        type=int,
        default=7,
        help=(
            "Profundidade máxima para seguir chamadas Smali internas "
            "(padrão: 7)."
        ),
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        help=(
            "Catálogo JSON alternativo. Quando omitido, usa o catálogo "
            "incluído na ferramenta."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    apk_path = args.apk or input("Caminho do APK: ").strip()
    if not apk_path:
        print("[-] Nenhum APK foi informado.")
        return 2

    try:
        pipeline = AnalysisPipeline(
            apktool_path=args.apktool,
            output_base=args.output,
            max_call_depth=args.max_call_depth,
            catalog_path=args.catalog,
        )
        result = pipeline.analyze_apk(
            apk_path,
            force=not args.no_force,
        )
    except (FileNotFoundError, ValueError, RuntimeError) as error:
        print(f"[-] {error}")
        return 1

    summary = result.analysis["summary"]
    print(f"\n[+] SMALIRIS v{__version__} — análise concluída")
    print(f"    Manifesto: {result.manifest_path}")
    print(f"    Relatório JSON: {result.report_path}")
    print(f"    Relatório HTML: {result.html_report_path}")
    print(f"    Componentes: {summary['component_count']}")
    print(f"    Exportados: {summary['exported_component_count']}")
    print(f"    Filtros de URI: {summary['uri_intent_filter_count']}")
    print(
        "    Deep links navegáveis: "
        f"{summary['browsable_deep_link_count']}"
    )
    print(
        "    Candidatos a App Link: "
        f"{summary['app_link_candidate_count']}"
    )
    if result.analysis.get("application", {}).get("debuggable") is True:
        print("    Aplicação debugável: sim (APP-DEBUG-001)")
    print(
        "    Classes Smali encontradas: "
        f"{summary['smali_found_count']}/"
        f"{summary['smali_component_count']}"
    )
    if summary["smali_missing_count"]:
        print(f"    Classes Smali ausentes: {summary['smali_missing_count']}")
    print(
        "    Código Smali analisado: "
        f"{summary['code_analyzed_count']}/"
        f"{summary['code_component_count']}"
    )
    print(f"    Entry points encontrados: {summary['code_entry_point_count']}")
    print(
        "    Métodos alcançados indiretamente: "
        f"{summary['code_reachable_method_count']}"
    )
    print(f"    Evidências no código: {summary['code_evidence_count']}")
    catalog = result.analysis.get("api_catalog", {})
    print(
        "    Catálogo de APIs: "
        f"{catalog.get('rule_count', 0)} regras "
        f"({catalog.get('reportable_rule_count', 0)} reportáveis)"
    )
    print(f"      Diretas: {summary['code_direct_evidence_count']}")
    print(f"      Indiretas: {summary['code_indirect_evidence_count']}")
    print(f"      Fontes de entrada: {summary['code_input_source_count']}")
    print(f"        Externas: {summary['code_external_source_count']}")
    print(f"        Interface: {summary['code_interface_source_count']}")
    print(
        "      Possíveis validações: "
        f"{summary['code_possible_validation_count']}"
    )
    print(
        "      Operações sensíveis: "
        f"{summary['code_sensitive_operation_count']}"
    )
    print(
        "    Fluxos de dados confirmados: "
        f"{summary['data_flow_confirmed_count']}"
    )
    print(
        "      Sem possível validação: "
        f"{summary['data_flow_unvalidated_count']}"
    )
    print(
        "      Com possível validação: "
        f"{summary['data_flow_validated_count']}"
    )
    argument_counts = summary.get("sensitive_argument_classifications", {})
    if sum(argument_counts.values()):
        print("    Argumentos críticos de operações sensíveis:")
        print(
            "      Contaminados externamente: "
            f"{argument_counts.get('external-tainted', 0)}"
        )
        print(
            "      Contaminados pela interface: "
            f"{argument_counts.get('interface-tainted', 0)}"
        )
        print(
            "      Constantes comprovadas: "
            f"{argument_counts.get('constant', 0)}"
        )
        print(
            "      Desconhecidos: "
            f"{argument_counts.get('unknown', 0)}"
        )
    if summary["code_unresolved_call_count"]:
        print(
            "    Chamadas internas não resolvidas: "
            f"{summary['code_unresolved_call_count']}"
        )
    if summary["code_truncated_call_count"]:
        print(
            "    Chamadas interrompidas pelo limite: "
            f"{summary['code_truncated_call_count']}"
        )
        print(
            "      AVISO: o grafo ficou parcial; repita com maior "
            "--max-call-depth se o protocolo experimental permitir."
        )
    print(f"    Profundidade máxima: {summary.get('max_call_depth', args.max_call_depth)}")
    if summary["code_error_count"]:
        print(f"    Erros na análise de código: {summary['code_error_count']}")
    print(f"    Achados do Manifesto: {summary['finding_count']}")
    print(f"    Candidatos de risco: {summary['risk_candidate_count']}")
    if summary.get("risk_candidate_absorbed_count"):
        print(
            "      Correlações absorvidas pela consolidação: "
            f"{summary['risk_candidate_absorbed_count']}"
        )
    risk_counts = summary["risk_candidates_by_severity"]
    if summary["risk_candidate_count"]:
        print(f"      Altos: {risk_counts['high']}")
        print(f"      Médios: {risk_counts['medium']}")
        print(f"      Baixos: {risk_counts['low']}")
        print(f"      Informativos: {risk_counts['info']}")

    if args.json:
        print(json.dumps(result.analysis, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
