"""Catálogo versionado de APIs e semântica de taint para instruções Smali."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable


EXTERNAL_SOURCE = "external_source"
POSSIBLE_VALIDATION = "possible_validation"
SENSITIVE_OPERATION = "sensitive_operation"
PROPAGATOR = "propagator"

REPORTABLE_CATEGORIES = (
    EXTERNAL_SOURCE,
    POSSIBLE_VALIDATION,
    SENSITIVE_OPERATION,
)
ALLOWED_CATEGORIES = {*REPORTABLE_CATEGORIES, PROPAGATOR}
ALLOWED_TAINT_BEHAVIORS = {
    "none",
    "return",
    "receiver_to_return",
    "arguments_to_return",
    "receiver_and_arguments_to_return",
    "receiver_and_arguments_to_receiver_and_return",
    "sink",
}
ALLOWED_SEVERITIES = {"high", "medium", "low", "info"}

INVOKE_PATTERN = re.compile(
    r"^\s*(?P<opcode>invoke-\S+)\s+\{(?P<registers>[^}]*)\},\s*"
    r"(?P<owner>L[^;]+;)->(?P<method>[^\s(]+)"
    r"(?P<descriptor>\([^)]*\)\S+)"
)


@dataclass(frozen=True)
class SmaliInvocation:
    """Partes relevantes de uma instrução ``invoke-*`` Smali."""

    opcode: str
    registers: str
    owner: str
    method: str
    descriptor: str

    @property
    def signature(self) -> str:
        return f"{self.method}{self.descriptor}"

    @property
    def is_static(self) -> bool:
        return self.opcode.startswith("invoke-static")


@dataclass(frozen=True)
class ApiRule:
    """Regra declarativa carregada do catálogo JSON."""

    id: str
    api: str
    owners: tuple[str, ...]
    methods: tuple[str, ...]
    descriptors: tuple[str, ...]
    category: str
    taint_behavior: str = "none"
    sensitive_arguments: tuple[int | str, ...] = ()
    source_kind: str | None = None
    validation_kind: str | None = None
    operation_kind: str | None = None
    severity: str | None = None
    risk_relevant: bool = False
    report: bool = True
    catalog_origin: str = "manual"

    def matches(self, owner: str, method: str, descriptor: str) -> bool:
        """Compara uma chamada usando padrões ``*`` no estilo shell."""
        return (
            any(fnmatchcase(owner, pattern) for pattern in self.owners)
            and any(fnmatchcase(method, pattern) for pattern in self.methods)
            and any(
                fnmatchcase(descriptor, pattern)
                for pattern in self.descriptors
            )
        )

    def evidence_metadata(self) -> dict[str, Any]:
        """Converte a regra para os campos persistidos em uma evidência."""
        result: dict[str, Any] = {
            "rule_id": self.id,
            "api": self.api,
            "category": self.category,
            "taint_behavior": self.taint_behavior,
            "sensitive_arguments": list(self.sensitive_arguments),
            "risk_relevant": self.risk_relevant,
            "catalog_origin": self.catalog_origin,
        }
        optional = {
            "source_kind": self.source_kind,
            "validation_kind": self.validation_kind,
            "operation_kind": self.operation_kind,
            "severity": self.severity,
        }
        result.update(
            {key: value for key, value in optional.items() if value is not None}
        )
        return result


class ApiCatalog:
    """Carrega, valida e consulta as regras de APIs usadas pelos analisadores."""

    DEFAULT_PATH = Path(__file__).with_name("catalog") / "api_catalog.json"
    DEFAULT_OVERRIDE_PATH = (
        Path(__file__).with_name("catalog") / "api_overrides.json"
    )

    def __init__(
        self,
        catalog_path: str | Path | None = None,
        override_paths: Iterable[str | Path] | None = None,
    ) -> None:
        primary_path = (
            Path(catalog_path) if catalog_path is not None else self.DEFAULT_PATH
        )
        paths = [primary_path]
        if override_paths is not None:
            paths.extend(Path(path) for path in override_paths)
        elif catalog_path is None and self.DEFAULT_OVERRIDE_PATH.is_file():
            paths.append(self.DEFAULT_OVERRIDE_PATH)

        self.paths = tuple(paths)
        self.schema_version: str | None = None
        self.catalog_version: str | None = None
        self.rules = self._load_documents(self.paths)

    @classmethod
    def parse_instruction(cls, instruction: str) -> SmaliInvocation | None:
        match = INVOKE_PATTERN.match(instruction)
        if match is None:
            return None
        return SmaliInvocation(
            opcode=match.group("opcode"),
            registers=match.group("registers"),
            owner=match.group("owner"),
            method=match.group("method"),
            descriptor=match.group("descriptor"),
        )

    def match(
        self,
        owner: str,
        method: str,
        descriptor: str,
        *,
        reportable_only: bool = False,
    ) -> list[ApiRule]:
        return [
            rule
            for rule in self.rules
            if (not reportable_only or rule.report)
            and rule.matches(owner, method, descriptor)
        ]

    def match_instruction(
        self,
        instruction: str,
        *,
        reportable_only: bool = False,
    ) -> tuple[SmaliInvocation | None, list[ApiRule]]:
        invocation = self.parse_instruction(instruction)
        if invocation is None:
            return None, []
        return invocation, self.match(
            invocation.owner,
            invocation.method,
            invocation.descriptor,
            reportable_only=reportable_only,
        )

    def metadata(self) -> dict[str, Any]:
        categories = Counter(rule.category for rule in self.rules)
        origins = Counter(rule.catalog_origin for rule in self.rules)
        return {
            "schema_version": self.schema_version,
            "catalog_version": self.catalog_version,
            "rule_count": len(self.rules),
            "reportable_rule_count": sum(rule.report for rule in self.rules),
            "categories": dict(sorted(categories.items())),
            "origins": dict(sorted(origins.items())),
            "files": [path.name for path in self.paths],
        }

    def _load_documents(self, paths: tuple[Path, ...]) -> tuple[ApiRule, ...]:
        rules_by_id: dict[str, ApiRule] = {}
        for index, path in enumerate(paths):
            if not path.is_file():
                raise FileNotFoundError(f"Catálogo de APIs não encontrado: {path}")
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"JSON inválido no catálogo {path}: {error}"
                ) from error
            if not isinstance(document, dict):
                raise ValueError(f"Catálogo {path} deve conter um objeto JSON.")

            schema_version = document.get("schema_version")
            if index == 0:
                self.schema_version = str(schema_version or "")
                self.catalog_version = str(
                    document.get("catalog_version") or ""
                )
            elif schema_version and str(schema_version) != self.schema_version:
                raise ValueError(
                    f"Schema incompatível em {path}: {schema_version}."
                )

            disabled = document.get("disabled_rule_ids", [])
            if not isinstance(disabled, list):
                raise ValueError(
                    f"disabled_rule_ids deve ser uma lista em {path}."
                )
            for rule_id in disabled:
                rules_by_id.pop(str(rule_id), None)

            raw_rules = document.get("rules", [])
            if not isinstance(raw_rules, list):
                raise ValueError(f"rules deve ser uma lista em {path}.")
            seen_in_document: set[str] = set()
            for raw_rule in raw_rules:
                rule = self._parse_rule(raw_rule, path)
                if rule.id in seen_in_document:
                    raise ValueError(
                        f"Id de regra duplicado em {path}: {rule.id}."
                    )
                seen_in_document.add(rule.id)
                # Arquivos posteriores funcionam como overrides intencionais.
                rules_by_id[rule.id] = rule

        if not rules_by_id:
            raise ValueError("O catálogo de APIs não possui regras ativas.")
        return tuple(rules_by_id.values())

    @staticmethod
    def _parse_rule(raw: Any, path: Path) -> ApiRule:
        if not isinstance(raw, dict):
            raise ValueError(f"Regra inválida em {path}: esperado objeto JSON.")
        required = ("id", "api", "owners", "methods", "category")
        missing = [field for field in required if not raw.get(field)]
        if missing:
            raise ValueError(
                f"Regra em {path} sem campos obrigatórios: {', '.join(missing)}."
            )

        owners = ApiCatalog._string_tuple(raw["owners"], "owners", path)
        methods = ApiCatalog._string_tuple(raw["methods"], "methods", path)
        descriptors = ApiCatalog._string_tuple(
            raw.get("descriptors", ["*"]),
            "descriptors",
            path,
        )
        category = str(raw["category"])
        if category not in ALLOWED_CATEGORIES:
            raise ValueError(
                f"Categoria desconhecida '{category}' na regra {raw['id']}."
            )
        taint_behavior = str(raw.get("taint_behavior", "none"))
        if taint_behavior not in ALLOWED_TAINT_BEHAVIORS:
            raise ValueError(
                f"Comportamento de taint desconhecido '{taint_behavior}' "
                f"na regra {raw['id']}."
            )
        severity = raw.get("severity")
        if severity is not None and severity not in ALLOWED_SEVERITIES:
            raise ValueError(
                f"Severidade desconhecida '{severity}' na regra {raw['id']}."
            )

        sensitive_arguments = raw.get("sensitive_arguments", [])
        if not isinstance(sensitive_arguments, list) or any(
            not (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
            )
            and value != "*"
            for value in sensitive_arguments
        ):
            raise ValueError(
                f"sensitive_arguments inválido na regra {raw['id']}."
            )

        report = bool(raw.get("report", True))
        if category == PROPAGATOR and report:
            raise ValueError(
                f"Propagador {raw['id']} deve usar report=false."
            )

        return ApiRule(
            id=str(raw["id"]),
            api=str(raw["api"]),
            owners=owners,
            methods=methods,
            descriptors=descriptors,
            category=category,
            taint_behavior=taint_behavior,
            sensitive_arguments=tuple(sensitive_arguments),
            source_kind=ApiCatalog._optional_string(raw.get("source_kind")),
            validation_kind=ApiCatalog._optional_string(
                raw.get("validation_kind")
            ),
            operation_kind=ApiCatalog._optional_string(
                raw.get("operation_kind")
            ),
            severity=ApiCatalog._optional_string(severity),
            risk_relevant=bool(raw.get("risk_relevant", False)),
            report=report,
            catalog_origin=str(raw.get("origin", "manual")),
        )

    @staticmethod
    def _string_tuple(value: Any, field: str, path: Path) -> tuple[str, ...]:
        if (
            not isinstance(value, list)
            or not value
            or any(not isinstance(item, str) or not item for item in value)
        ):
            raise ValueError(f"{field} deve ser uma lista de textos em {path}.")
        return tuple(value)

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        return str(value) if value is not None else None
