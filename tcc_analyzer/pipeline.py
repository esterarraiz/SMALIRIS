"""Orquestração das etapas de descompilação e análise do manifesto."""

from __future__ import annotations

import json
import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__

from .api_catalog import ApiCatalog
from .code_analyzer import CodeAnalyzer, ENTRY_POINT_ANALYSIS_PRIORITY
from .data_flow_analyzer import DataFlowAnalyzer
from .manifest_analyzer import ManifestAnalyzer
from .reverse_engineer import APKReverseEngineer
from .report_generator import ReportGenerator
from .report_schema import validate_report
from .risk_correlator import RiskCorrelator
from .smali_locator import SmaliLocator


@dataclass(frozen=True)
class PipelineResult:
    """Caminhos e dados produzidos por uma execução completa."""

    apk_path: Path
    decompiled_dir: Path
    manifest_path: Path
    report_path: Path
    html_report_path: Path
    analysis: dict[str, Any]


class AnalysisPipeline:
    """Caso de uso principal, reutilizável pela CLI ou pelo Streamlit."""

    def __init__(
        self,
        apktool_path: str = "apktool",
        output_base: str | Path = "output",
        max_call_depth: int = 7,
        catalog_path: str | Path | None = None,
    ) -> None:
        if max_call_depth < 0:
            raise ValueError("max_call_depth não pode ser negativo.")
        self.reverse_engineer = APKReverseEngineer(
            apktool_path=apktool_path,
            output_base=output_base,
        )
        self.max_call_depth = max_call_depth
        self.catalog_path = Path(catalog_path) if catalog_path else None

    def analyze_apk(
        self,
        apk_path: str | Path,
        force: bool = True,
    ) -> PipelineResult:
        apk_path = Path(apk_path)
        apk_sha256 = self._sha256_file(apk_path)
        decompilation_started = time.perf_counter()
        decompiled_dir = self.reverse_engineer.decompile(
            apk_path,
            force=force,
        )
        if decompiled_dir is None:
            raise RuntimeError("O Apktool não conseguiu descompilar o APK.")
        decompilation_duration = time.perf_counter() - decompilation_started

        manifest_path = self.reverse_engineer.get_manifest_path(decompiled_dir)
        if manifest_path is None:
            raise FileNotFoundError(
                f"AndroidManifest.xml não encontrado em {decompiled_dir}."
            )

        analysis_started = time.perf_counter()
        analysis = ManifestAnalyzer(
            manifest_path,
            apktool_yml_path=decompiled_dir / "apktool.yml",
        ).analyze()
        catalog = ApiCatalog(getattr(self, "catalog_path", None))
        analysis["api_catalog"] = catalog.metadata()
        analysis["apk_path"] = str(apk_path)
        analysis["smali_lookup"] = self._attach_smali_locations(
            analysis,
            decompiled_dir,
        )
        analysis["code_analysis_summary"] = self._attach_code_analysis(
            analysis,
            decompiled_dir,
            max_call_depth=getattr(self, "max_call_depth", 7),
            catalog=catalog,
        )
        analysis["data_flow_analysis"] = DataFlowAnalyzer(
            decompiled_dir,
            catalog=catalog,
        ).analyze(analysis)
        analysis["risk_analysis"] = RiskCorrelator(
            catalog=catalog
        ).analyze(analysis)

        analysis_duration = time.perf_counter() - analysis_started
        apktool_version_getter = getattr(
            self.reverse_engineer,
            "version",
            None,
        )
        apktool_version = (
            apktool_version_getter()
            if callable(apktool_version_getter)
            else None
        )
        truncated_call_count = analysis["summary"].get(
            "code_truncated_call_count",
            0,
        )
        analysis["tool"] = {
            "name": "SMALIRIS",
            "version": __version__,
            "full_name": (
                "Static Manifest Analysis and Low-level Instruction "
                "Risk Inspection System"
            ),
        }
        analysis["report_schema"] = {
            "name": "smaliris-analysis-report",
            "version": analysis.get("schema_version"),
            "file": "tcc_analyzer/schemas/analysis_report.schema.json",
        }
        analysis["reproducibility"] = {
            "tool_version": __version__,
            "catalog_version": catalog.catalog_version,
            "report_schema_version": analysis.get("schema_version"),
            "apk_sha256": apk_sha256,
            "max_call_depth": getattr(self, "max_call_depth", 7),
            "apktool_version": apktool_version,
            "decompilation_duration_seconds": round(
                decompilation_duration,
                6,
            ),
            "analysis_duration_seconds": round(analysis_duration, 6),
            "truncated_call_count": truncated_call_count,
            "configuration": {
                "force_decompile": force,
                "max_call_depth": getattr(self, "max_call_depth", 7),
                "catalog_path": (
                    str(self.catalog_path)
                    if getattr(self, "catalog_path", None)
                    else None
                ),
                "output_base": str(
                    getattr(self.reverse_engineer, "output_base", "output")
                ),
                "apktool_executable": str(
                    getattr(self.reverse_engineer, "apktool_path", "apktool")
                ),
            },
        }
        analysis["summary"]["max_call_depth"] = getattr(
            self,
            "max_call_depth",
            7,
        )

        report_path = decompiled_dir / "manifest_analysis.json"
        html_report_path = decompiled_dir / "analysis_report.html"
        analysis["reports"] = {
            "json": str(report_path),
            "html": str(html_report_path),
        }
        validate_report(analysis)
        report_path.write_text(
            json.dumps(analysis, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        ReportGenerator().generate(analysis, html_report_path)

        return PipelineResult(
            apk_path=apk_path,
            decompiled_dir=decompiled_dir,
            manifest_path=manifest_path,
            report_path=report_path,
            html_report_path=html_report_path,
            analysis=analysis,
        )

    @staticmethod
    def _sha256_file(path: Path) -> str | None:
        """Calcula o identificador do artefato analisado sem carregá-lo inteiro."""
        if not path.is_file():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as apk_file:
            for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _attach_smali_locations(
        analysis: dict[str, Any],
        decompiled_dir: Path,
    ) -> dict[str, Any]:
        """Adiciona a localização Smali aos componentes exportados."""
        locator = SmaliLocator(decompiled_dir)
        attempted_count = 0
        found_count = 0
        missing_components: list[dict[str, str | None]] = []

        for component in analysis["components"]:
            if component["exported"] is not True:
                component["smali"] = {
                    "attempted": False,
                    "class_name": None,
                    "descriptor": None,
                    "found": None,
                    "path": None,
                    "dex_directory": None,
                    "reason": "component-not-exported",
                }
                continue

            attempted_count += 1
            class_name = component["name"]
            if component["type"] == "activity-alias":
                class_name = component.get("target_activity")

            if not class_name:
                reason = "activity-alias-without-target"
                component["smali"] = {
                    "attempted": True,
                    "class_name": None,
                    "descriptor": None,
                    "found": False,
                    "path": None,
                    "dex_directory": None,
                    "reason": reason,
                }
                missing_components.append(
                    {
                        "component": component["name"],
                        "class_name": None,
                        "reason": reason,
                    }
                )
                continue

            try:
                descriptor = locator.class_descriptor(class_name)
                smali_file = locator.locate(class_name)
            except ValueError:
                descriptor = None
                smali_file = None
                reason = "invalid-class-name"
            else:
                reason = None if smali_file is not None else "class-not-found"

            if smali_file is not None:
                relative_path = locator.relative_path(smali_file)
                found_count += 1
                component["smali"] = {
                    "attempted": True,
                    "class_name": class_name,
                    "descriptor": descriptor,
                    "found": True,
                    "path": relative_path.as_posix(),
                    "dex_directory": relative_path.parts[0],
                    "reason": None,
                }
            else:
                component["smali"] = {
                    "attempted": True,
                    "class_name": class_name,
                    "descriptor": descriptor,
                    "found": False,
                    "path": None,
                    "dex_directory": None,
                    "reason": reason,
                }
                missing_components.append(
                    {
                        "component": component["name"],
                        "class_name": class_name,
                        "reason": reason,
                    }
                )

        missing_count = attempted_count - found_count
        analysis["summary"].update(
            {
                "smali_component_count": attempted_count,
                "smali_found_count": found_count,
                "smali_missing_count": missing_count,
            }
        )
        return {
            "attempted_component_count": attempted_count,
            "found_component_count": found_count,
            "missing_component_count": missing_count,
            "missing_components": missing_components,
        }

    @staticmethod
    def _attach_code_analysis(
        analysis: dict[str, Any],
        decompiled_dir: Path,
        max_call_depth: int = 7,
        catalog: ApiCatalog | None = None,
    ) -> dict[str, Any]:
        """Extrai métodos e entry points dos componentes exportados localizados."""
        analyzer = CodeAnalyzer(
            decompiled_dir,
            application_package=analysis.get("package"),
            max_call_depth=max_call_depth,
            catalog=catalog,
        )
        component_count = 0
        analyzed_count = 0
        unavailable_count = 0
        error_count = 0
        entry_point_count = 0
        reachable_method_count = 0
        direct_evidence_count = 0
        indirect_evidence_count = 0
        evidence_count = 0
        input_source_count = 0
        external_source_count = 0
        interface_source_count = 0
        possible_validation_count = 0
        sensitive_operation_count = 0
        unresolved_call_count = 0
        cycle_count = 0
        truncated_call_count = 0
        components_without_entry_points: list[str] = []
        problem_components: list[dict[str, str | None]] = []
        prioritized_entry_points: list[dict[str, Any]] = []

        components_in_analysis_order = sorted(
            analysis["components"],
            key=AnalysisPipeline._component_code_priority,
        )
        for component in components_in_analysis_order:
            result = analyzer.analyze_component(component)
            component["code_analysis"] = result

            if component["exported"] is not True:
                continue

            component_count += 1
            status = result["status"]
            if status == "analyzed":
                analyzed_count += 1
                entry_point_count += result["entry_point_count"]
                reachable_method_count += result["reachable_method_count"]
                direct_evidence_count += result["direct_evidence_count"]
                indirect_evidence_count += result["indirect_evidence_count"]
                evidence_count += result["evidence_count"]
                unresolved_call_count += result["unresolved_call_count"]
                cycle_count += result["cycle_count"]
                truncated_call_count += result["truncated_call_count"]
                evidence_summary = result["evidence_summary"]
                input_source_count += evidence_summary[
                    "input_source_count"
                ]
                external_source_count += evidence_summary[
                    "external_source_count"
                ]
                interface_source_count += evidence_summary[
                    "interface_source_count"
                ]
                possible_validation_count += evidence_summary[
                    "possible_validation_count"
                ]
                sensitive_operation_count += evidence_summary[
                    "sensitive_operation_count"
                ]
                for entry_point in result["entry_points"]:
                    priority = entry_point["analysis_priority"]
                    if priority is not None:
                        prioritized_entry_points.append(
                            {
                                "priority": priority,
                                "component": component["name"],
                                "method": entry_point["name"],
                                "signature": entry_point["signature"],
                                "reachable_method_count": entry_point[
                                    "call_graph"
                                ]["reachable_method_count"],
                                "direct_evidence_count": entry_point[
                                    "direct_evidence_count"
                                ],
                                "indirect_evidence_count": entry_point[
                                    "indirect_evidence_count"
                                ],
                                "evidence_count": entry_point[
                                    "evidence_count"
                                ],
                            }
                        )
                if result["entry_point_count"] == 0:
                    components_without_entry_points.append(component["name"])
            elif status == "unavailable":
                unavailable_count += 1
                problem_components.append(
                    {
                        "component": component["name"],
                        "status": status,
                        "reason": result["reason"],
                    }
                )
            elif status == "error":
                error_count += 1
                problem_components.append(
                    {
                        "component": component["name"],
                        "status": status,
                        "reason": result["reason"],
                    }
                )

        analysis["summary"].update(
            {
                "code_component_count": component_count,
                "code_analyzed_count": analyzed_count,
                "code_unavailable_count": unavailable_count,
                "code_error_count": error_count,
                "code_entry_point_count": entry_point_count,
                "code_reachable_method_count": reachable_method_count,
                "code_direct_evidence_count": direct_evidence_count,
                "code_indirect_evidence_count": indirect_evidence_count,
                "code_evidence_count": evidence_count,
                "code_input_source_count": input_source_count,
                "code_external_source_count": external_source_count,
                "code_interface_source_count": interface_source_count,
                "code_possible_validation_count": possible_validation_count,
                "code_sensitive_operation_count": sensitive_operation_count,
                "code_unresolved_call_count": unresolved_call_count,
                "code_cycle_count": cycle_count,
                "code_truncated_call_count": truncated_call_count,
            }
        )
        prioritized_entry_points.sort(key=lambda item: item["priority"])
        return {
            "component_count": component_count,
            "analyzed_component_count": analyzed_count,
            "unavailable_component_count": unavailable_count,
            "error_component_count": error_count,
            "entry_point_count": entry_point_count,
            "max_call_depth": max_call_depth,
            "reachable_method_count": reachable_method_count,
            "direct_evidence_count": direct_evidence_count,
            "indirect_evidence_count": indirect_evidence_count,
            "evidence_count": evidence_count,
            "input_source_count": input_source_count,
            "external_source_count": external_source_count,
            "interface_source_count": interface_source_count,
            "possible_validation_count": possible_validation_count,
            "sensitive_operation_count": sensitive_operation_count,
            "unresolved_call_count": unresolved_call_count,
            "cycle_count": cycle_count,
            "truncated_call_count": truncated_call_count,
            "prioritized_entry_points": prioritized_entry_points,
            "components_without_entry_points": components_without_entry_points,
            "problem_components": problem_components,
            "phase": "bounded-call-graph-evidence-detection",
            "api_catalog": analyzer.catalog.metadata(),
            "security_verdicts_generated": False,
        }

    @staticmethod
    def _component_code_priority(component: dict[str, Any]) -> int:
        """Ordena a execução pela menor prioridade conhecida do componente."""
        component_name = component.get("name")
        simple_name = (
            component_name.rsplit(".", maxsplit=1)[-1]
            if component_name
            else ""
        )
        priorities = [
            priority
            for (class_name, _), priority in ENTRY_POINT_ANALYSIS_PRIORITY.items()
            if class_name == simple_name
        ]
        return min(priorities, default=10_000)
