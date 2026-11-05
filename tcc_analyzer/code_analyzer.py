"""Extração de entry points e evidências de segurança em arquivos Smali."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .api_catalog import (
    EXTERNAL_SOURCE,
    POSSIBLE_VALIDATION,
    REPORTABLE_CATEGORIES,
    SENSITIVE_OPERATION,
    ApiCatalog,
)
from .call_graph_analyzer import CallGraphAnalyzer


ENTRY_POINTS: dict[str, set[str]] = {
    "activity": {"onCreate", "onNewIntent"},
    "activity-alias": {"onCreate", "onNewIntent"},
    "service": {"onStartCommand", "onBind"},
    "receiver": {"onReceive"},
    "provider": {
        "query",
        "insert",
        "update",
        "delete",
        "call",
        "openFile",
    },
}

METHOD_START_PATTERN = re.compile(r"^\s*\.method\s+(?P<declaration>.+?)\s*$")
METHOD_END_PATTERN = re.compile(r"^\s*\.end\s+method\s*$")
METHOD_SIGNATURE_PATTERN = re.compile(
    r"(?P<signature>[^\s(]+\([^)]*\)\S+)\s*$"
)
CLASS_DESCRIPTOR_PATTERN = re.compile(
    r"^\s*\.class\b.*\s(?P<descriptor>L[^;]+;)\s*$"
)

EVIDENCE_CATEGORIES = REPORTABLE_CATEGORIES

# Esta ordem reproduz a prioridade definida para a análise atual do AndroGoat.
# Entry points de outros aplicativos continuam sendo analisados, depois destes.
ENTRY_POINT_ANALYSIS_PRIORITY: dict[tuple[str, str], int] = {
    ("DownloadInvoiceService", "onStartCommand"): 1,
    ("DownloadInvoiceService", "onBind"): 2,
    ("AccessControl1ViewActivity", "onCreate"): 3,
    ("ShowDataReceiver", "onReceive"): 4,
    ("SplashActivity", "onCreate"): 5,
}
USER_INTERFACE_SOURCE_KINDS = {
    "user_input",
    "ui_input",
    "interface_input",
}

class CodeAnalyzer:
    """Analisa a estrutura de classes Smali associadas a componentes Android."""

    def __init__(
        self,
        decompiled_dir: str | Path,
        application_package: str | None = None,
        max_call_depth: int = 7,
        catalog: ApiCatalog | None = None,
        catalog_path: str | Path | None = None,
    ) -> None:
        self.decompiled_dir = Path(decompiled_dir)
        if not self.decompiled_dir.is_dir():
            raise FileNotFoundError(
                f"Diretório descompilado não encontrado: {self.decompiled_dir}"
            )
        self.decompiled_dir_resolved = self.decompiled_dir.resolve()
        self.application_package = application_package
        self.max_call_depth = max_call_depth
        if catalog is not None and catalog_path is not None:
            raise ValueError("Informe catalog ou catalog_path, não ambos.")
        self.catalog = catalog or ApiCatalog(catalog_path)
        self.call_graph_analyzer = CallGraphAnalyzer(
            self.decompiled_dir,
            evidence_detector=self.detect_evidence,
            method_extractor=self.extract_methods,
            application_package=application_package,
            max_depth=max_call_depth,
        )

    def analyze_component(self, component: dict[str, Any]) -> dict[str, Any]:
        """Extrai métodos e entry points do Smali localizado para um componente."""
        component_type = component.get("type", "unknown")
        smali = component.get("smali") or {}

        if not smali.get("attempted"):
            return self._empty_result(
                component_type,
                status="skipped",
                reason=smali.get("reason", "smali-location-not-attempted"),
            )

        if not smali.get("found") or not smali.get("path"):
            return self._empty_result(
                component_type,
                status="unavailable",
                reason=smali.get("reason", "smali-file-not-found"),
                smali_path=smali.get("path"),
            )

        smali_path = str(smali["path"])
        try:
            smali_file = self._resolve_smali_file(smali_path)
        except ValueError as error:
            return self._empty_result(
                component_type,
                status="error",
                reason="invalid-smali-path",
                smali_path=smali_path,
                warnings=[str(error)],
            )

        if not smali_file.is_file():
            return self._empty_result(
                component_type,
                status="unavailable",
                reason="smali-file-not-found",
                smali_path=smali_path,
            )

        try:
            methods, warnings, line_count = self.extract_methods(
                smali_file,
                component_type,
            )
        except OSError as error:
            return self._empty_result(
                component_type,
                status="error",
                reason="smali-read-error",
                smali_path=smali_path,
                warnings=[str(error)],
            )

        class_descriptor = smali.get("descriptor") or self.extract_class_descriptor(
            smali_file
        )
        class_name = (
            smali.get("class_name")
            or component.get("name")
            or (
                CallGraphAnalyzer.descriptor_to_class_name(class_descriptor)
                if class_descriptor
                else None
            )
        )
        entry_points = []
        try:
            for method in methods:
                if not method["is_entry_point"]:
                    continue

                priority = self.entry_point_priority(
                    component.get("name"),
                    method["name"],
                )
                raw_direct_evidence = self.detect_evidence(
                    smali_file,
                    method["start_line"],
                    method["end_line"],
                )
                root_label = (
                    f"{class_name}->{method['signature']}"
                    if class_name
                    else method["signature"]
                )
                direct_evidence = [
                    self.enrich_direct_evidence(
                        item,
                        class_name,
                        method["signature"],
                        smali_path,
                        root_label,
                    )
                    for item in raw_direct_evidence
                ]
                if class_descriptor:
                    call_graph = self.call_graph_analyzer.analyze(
                        smali_file,
                        class_descriptor,
                        method,
                    )
                else:
                    call_graph = CallGraphAnalyzer.empty_result(
                        status="unavailable",
                        reason="class-descriptor-not-found",
                        max_depth=self.max_call_depth,
                    )
                indirect_evidence = call_graph["indirect_evidence"]
                evidence = [*direct_evidence, *indirect_evidence]
                entry_points.append(
                    {
                        "name": method["name"],
                        "signature": method["signature"],
                        "modifiers": method.get("modifiers", []),
                        "start_line": method["start_line"],
                        "end_line": method["end_line"],
                        "analysis_priority": priority,
                        "direct_evidence_count": len(direct_evidence),
                        "indirect_evidence_count": len(indirect_evidence),
                        "evidence_count": len(evidence),
                        "evidence_summary": self.summarize_evidence(evidence),
                        "direct_evidence": direct_evidence,
                        "indirect_evidence": indirect_evidence,
                        "evidence": evidence,
                        "call_graph": call_graph,
                    }
                )
        except OSError as error:
            return self._empty_result(
                component_type,
                status="error",
                reason="smali-read-error",
                smali_path=smali_path,
                warnings=[str(error)],
            )

        entry_points.sort(
            key=lambda entry_point: (
                entry_point["analysis_priority"] is None,
                entry_point["analysis_priority"] or 0,
                entry_point["start_line"],
            )
        )
        component_evidence = [
            item
            for entry_point in entry_points
            for item in entry_point["evidence"]
        ]
        direct_evidence_count = sum(
            entry_point["direct_evidence_count"]
            for entry_point in entry_points
        )
        indirect_evidence_count = sum(
            entry_point["indirect_evidence_count"]
            for entry_point in entry_points
        )
        reachable_method_count = sum(
            entry_point["call_graph"]["reachable_method_count"]
            for entry_point in entry_points
        )
        unresolved_call_count = sum(
            entry_point["call_graph"]["unresolved_call_count"]
            for entry_point in entry_points
        )
        cycle_count = sum(
            entry_point["call_graph"]["cycle_count"]
            for entry_point in entry_points
        )
        truncated_call_count = sum(
            entry_point["call_graph"]["truncated_call_count"]
            for entry_point in entry_points
        )

        return {
            "status": "analyzed",
            "reason": None,
            "component_type": component_type,
            "smali_path": smali_path,
            "line_count": line_count,
            "method_count": len(methods),
            "entry_point_count": len(entry_points),
            "direct_evidence_count": direct_evidence_count,
            "indirect_evidence_count": indirect_evidence_count,
            "evidence_count": len(component_evidence),
            "evidence_summary": self.summarize_evidence(component_evidence),
            "reachable_method_count": reachable_method_count,
            "unresolved_call_count": unresolved_call_count,
            "cycle_count": cycle_count,
            "truncated_call_count": truncated_call_count,
            "methods": methods,
            "entry_points": entry_points,
            "warnings": warnings,
        }

    def detect_evidence(
        self,
        smali_file: str | Path,
        start_line: int,
        end_line: int,
    ) -> list[dict[str, Any]]:
        """Detecta APIs somente no intervalo inclusivo de um entry point."""
        lines = Path(smali_file).read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        evidence: list[dict[str, Any]] = []

        first_index = max(start_line - 1, 0)
        last_index = min(end_line, len(lines))
        for line_number in range(first_index + 1, last_index + 1):
            instruction = lines[line_number - 1].strip()
            if not instruction or instruction.startswith("#"):
                continue

            _, rules = self.catalog.match_instruction(
                instruction,
                reportable_only=True,
            )
            for rule in rules:
                evidence.append(
                    {
                        **rule.evidence_metadata(),
                        "line": line_number,
                        "instruction": instruction,
                    }
                )

        return evidence

    @staticmethod
    def enrich_direct_evidence(
        evidence: dict[str, Any],
        class_name: str | None,
        method_signature: str,
        smali_path: str,
        root_label: str,
    ) -> dict[str, Any]:
        return {
            **evidence,
            "origin": "direct",
            "depth": 0,
            "class_name": class_name,
            "method_signature": method_signature,
            "smali_path": smali_path,
            "call_chain": [root_label],
        }

    @staticmethod
    def summarize_evidence(
        evidence: list[dict[str, Any]],
    ) -> dict[str, int]:
        counts = {category: 0 for category in EVIDENCE_CATEGORIES}
        for item in evidence:
            category = item.get("category")
            if category in counts:
                counts[category] += 1
        input_sources = [
            item
            for item in evidence
            if item.get("category") == EXTERNAL_SOURCE
        ]
        interface_source_count = sum(
            item.get("source_kind") in USER_INTERFACE_SOURCE_KINDS
            for item in input_sources
        )
        external_source_count = len(input_sources) - interface_source_count
        return {
            "total": len(evidence),
            "input_source_count": counts[EXTERNAL_SOURCE],
            "external_source_count": external_source_count,
            "interface_source_count": interface_source_count,
            "possible_validation_count": counts[POSSIBLE_VALIDATION],
            "sensitive_operation_count": counts[SENSITIVE_OPERATION],
        }

    @staticmethod
    def entry_point_priority(
        component_name: str | None,
        method_name: str | None,
    ) -> int | None:
        if not component_name or not method_name:
            return None
        simple_class_name = component_name.rsplit(".", maxsplit=1)[-1]
        return ENTRY_POINT_ANALYSIS_PRIORITY.get(
            (simple_class_name, method_name)
        )

    @staticmethod
    def extract_methods(
        smali_file: str | Path,
        component_type: str,
    ) -> tuple[list[dict[str, Any]], list[str], int]:
        """Extrai blocos ``.method`` usando linhas numeradas a partir de 1."""
        lines = Path(smali_file).read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        expected_entry_points = ENTRY_POINTS.get(component_type, set())
        methods: list[dict[str, Any]] = []
        warnings: list[str] = []
        current_method: dict[str, Any] | None = None

        for line_number, line in enumerate(lines, start=1):
            start_match = METHOD_START_PATTERN.match(line)
            if start_match is not None:
                if current_method is not None:
                    current_method["end_line"] = line_number - 1
                    methods.append(current_method)
                    warnings.append(
                        "Método iniciado antes do fechamento do método da linha "
                        f"{current_method['start_line']}."
                    )

                declaration = start_match.group("declaration")
                signature_match = METHOD_SIGNATURE_PATTERN.search(declaration)
                if signature_match is None:
                    signature = declaration
                    name = None
                    modifiers: list[str] = []
                    warnings.append(
                        f"Assinatura de método não reconhecida na linha {line_number}."
                    )
                else:
                    signature = signature_match.group("signature")
                    name = signature.split("(", maxsplit=1)[0]
                    modifiers_text = declaration[: signature_match.start()].strip()
                    modifiers = modifiers_text.split() if modifiers_text else []

                current_method = {
                    "name": name,
                    "signature": signature,
                    "modifiers": modifiers,
                    "start_line": line_number,
                    "end_line": None,
                    "is_entry_point": name in expected_entry_points,
                }
                continue

            if METHOD_END_PATTERN.match(line) is not None:
                if current_method is None:
                    warnings.append(
                        f".end method sem .method correspondente na linha {line_number}."
                    )
                    continue
                current_method["end_line"] = line_number
                methods.append(current_method)
                current_method = None

        if current_method is not None:
            current_method["end_line"] = len(lines)
            methods.append(current_method)
            warnings.append(
                "Método iniciado na linha "
                f"{current_method['start_line']} sem .end method."
            )

        return methods, warnings, len(lines)

    @staticmethod
    def extract_class_descriptor(smali_file: str | Path) -> str | None:
        for line in Path(smali_file).read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines():
            match = CLASS_DESCRIPTOR_PATTERN.match(line)
            if match is not None:
                return match.group("descriptor")
        return None

    def _resolve_smali_file(self, relative_path: str) -> Path:
        path = Path(relative_path)
        if path.is_absolute():
            raise ValueError("O caminho Smali deve ser relativo ao diretório analisado.")

        resolved = (self.decompiled_dir / path).resolve()
        try:
            resolved.relative_to(self.decompiled_dir_resolved)
        except ValueError as error:
            raise ValueError(
                "O caminho Smali aponta para fora do diretório analisado."
            ) from error
        return resolved

    @staticmethod
    def _empty_result(
        component_type: str,
        status: str,
        reason: str | None,
        smali_path: str | None = None,
        warnings: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "reason": reason,
            "component_type": component_type,
            "smali_path": smali_path,
            "line_count": 0,
            "method_count": 0,
            "entry_point_count": 0,
            "direct_evidence_count": 0,
            "indirect_evidence_count": 0,
            "evidence_count": 0,
            "evidence_summary": CodeAnalyzer.summarize_evidence([]),
            "reachable_method_count": 0,
            "unresolved_call_count": 0,
            "cycle_count": 0,
            "truncated_call_count": 0,
            "methods": [],
            "entry_points": [],
            "warnings": warnings or [],
        }
